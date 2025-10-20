/*
Copyright 2025 DenktMit eG and contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"
	"net/netip"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
)

const (
	// InterfaceOwnerMarker is used to mark the interface IP itself as reserved in the trie
	InterfaceOwnerMarker = "interface"
)

// IPNetToIPAddress converts wgov1alpha1.IPBlock to ipaddress-go IPAddress
// Supports:
//   - Single IPs: "192.168.1.1" or "2001:db8::1"
//   - CIDR notation: "192.168.0.0/24" or "2001:db8::/32"
//   - Segment ranges: "192.168.1.1-5" or "2001:db8::1-a" (last segment only)
//
// Note: Full-address ranges like "10.0.0.1-10.0.0.33" are NOT supported by ipaddress-go.
func IPNetToIPAddress(n wgov1alpha1.IPBlock) (*ipaddr.IPAddress, error) {
	if n == "" {
		return nil, fmt.Errorf("not a valid IP or CIDR")
	}

	// Use centralized parser for consistent behavior
	addr, err := ParseIPAddress(string(n))
	if err != nil {
		return nil, fmt.Errorf("not a valid IP or CIDR: %w", err)
	}

	// Validate segment ranges: Only last segment can be a range
	// ipaddress-go automatically validates this during parsing
	// IsMultiple() returns true for both CIDR blocks and segment ranges
	if addr.IsMultiple() && !addr.IsPrefixed() {
		// This is a segment range (e.g., 192.168.1.1-5)
		// Ensure it's valid by checking we can get the count
		if addr.GetCount() == nil {
			return nil, fmt.Errorf("invalid IP range: cannot determine range size")
		}
	}

	return addr, nil
}

// IPBlockToIP converts an IPAddress to an IP-only address (stripping prefix to get network range)
// This is a public helper to convert parsed addresses for reuse in validation logic
func IPBlockToIP(addr *ipaddr.IPAddress) (*ipaddr.IPAddress, error) {
	ipAddr := addr.ToIP()
	if ipAddr == nil {
		return nil, fmt.Errorf("failed to convert address to IP-only format")
	}
	return ipAddr, nil
}

// ValidateIPBlockAsNetworkAddress validates that an IPBlock is a valid network address
// Returns the parsed ipaddr.IPAddress for reuse
// For non-CIDR (single IPs, ranges): returns as-is
// For CIDR: validates it's the network address (not host IP like 192.168.1.5/24)
func ValidateIPBlockAsNetworkAddress(block wgov1alpha1.IPBlock) (*ipaddr.IPAddress, error) {
	addr, err := IPNetToIPAddress(block)
	if err != nil {
		return nil, err
	}

	// Only check network address for CIDR notation
	if addr.IsPrefixed() {
		prefixLen := addr.GetNetworkPrefixLen()
		if prefixLen != nil && prefixLen.Len() < addr.GetBitCount() {
			// It's a CIDR (not /32 or /128)
			prefixBlock := addr.ToPrefixBlock()
			if !addr.Equal(prefixBlock) {
				return nil, fmt.Errorf("invalid CIDR %s - IP is not the network address (should be %s)",
					addr.String(), prefixBlock.String())
			}
		}
	}

	return addr, nil
}

// checkOverlapInTrie checks if a network overlaps with any existing entries in the trie
// Returns the conflicting node if overlap is found, nil otherwise
func checkOverlapInTrie[T any](
	trie *ipaddr.DualIPv4v6AssociativeTries[T],
	network *ipaddr.IPAddress,
) *ipaddr.AssociativeTrieNode[*ipaddr.IPAddress, T] {
	// Check if any existing entry contains this network
	if trie.ElementContains(network) {
		node := trie.LongestPrefixMatchNode(network)
		if node != nil && node.IsAdded() {
			return node
		}
	}

	// Check if this network contains any existing entries
	containedNode := trie.ElementsContainedBy(network)
	if containedNode != nil {
		iter := containedNode.ContainedFirstIterator(true)
		if iter.HasNext() {
			node := iter.Next()
			if node.IsAdded() {
				return node
			}
		}
	}

	return nil
}

// BuildTrieFromPeers constructs an IP address trie from all peer AllowedIPs
func BuildTrieFromPeers(peers []wgov1alpha1.WireGuardPeer) (*ipaddr.DualIPv4v6AssociativeTries[any], error) {
	trie := &ipaddr.DualIPv4v6AssociativeTries[any]{}

	for _, peer := range peers {
		for _, allowedIP := range peer.Spec.AllowedIPs {
			addr, err := IPNetToIPAddress(allowedIP)
			if err != nil {
				return nil, fmt.Errorf("peer %s/%s: failed to parse AllowedIP %s: %w",
					peer.Namespace, peer.Name, string(allowedIP), err)
			}

			// Convert to IPAddress for the dual trie
			ipAddr, err := IPBlockToIP(addr)
			if err != nil {
				return nil, fmt.Errorf("peer %s/%s AllowedIP: %w", peer.Namespace, peer.Name, err)
			}

			// Add to trie with peer identifier as value
			owner := fmt.Sprintf("%s/%s", peer.Namespace, peer.Name)
			trie.Put(ipAddr.ToPrefixBlock(), owner)
		}
	}

	return trie, nil
}

// CheckInterfaceAddressOverlap checks if any interface addresses overlap
func CheckInterfaceAddressOverlap(addresses wgov1alpha1.InterfaceCIDRs) error {
	if len(addresses) <= 1 {
		return nil
	}

	trie := &ipaddr.DualIPv4v6AssociativeTries[int]{}

	for i, addr := range addresses {
		ipAddr, err := InterfaceAddressToIPAddress(addr)
		if err != nil {
			return fmt.Errorf("failed to parse InterfaceCIDR[%d] %s: %w", i, string(addr), err)
		}

		network := ipAddr.ToPrefixBlock()

		// Check for overlaps using generic function
		if conflictNode := checkOverlapInTrie(trie, network); conflictNode != nil {
			existingIdx := conflictNode.GetValue()
			existingAddr := addresses[existingIdx]
			return fmt.Errorf("overlapping interface addresses: %s and %s (networks must not overlap for routing)",
				string(addr), string(existingAddr))
		}

		// Add to trie with index as value
		trie.Put(network, i)
	}

	return nil
}

// CheckIPBlocksOverlapParsed checks if parsed IP addresses overlap using Trie
func CheckIPBlocksOverlapParsed(addresses []*ipaddr.IPAddress, original wgov1alpha1.IPBlocks) error {
	if len(addresses) <= 1 {
		return nil
	}

	trie := &ipaddr.DualIPv4v6AssociativeTries[int]{}

	for i, addr := range addresses {
		ipAddr, err := IPBlockToIP(addr)
		if err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}

		if conflictNode := checkOverlapInTrie(trie, ipAddr); conflictNode != nil {
			existingIdx := conflictNode.GetValue()
			return fmt.Errorf("overlapping IP blocks: %s and %s", string(original[i]), string(original[existingIdx]))
		}

		trie.Put(ipAddr.ToPrefixBlock(), i)
	}

	return nil
}

// CheckPeerIPOverlapParsed checks parsed IP addresses against existing peers using Trie
func CheckPeerIPOverlapParsed(newAddrs []*ipaddr.IPAddress, existingPeers []wgov1alpha1.WireGuardPeer) error {
	if len(newAddrs) == 0 {
		return nil
	}

	trie := &ipaddr.DualIPv4v6AssociativeTries[string]{}

	for _, peer := range existingPeers {
		for _, allowedIP := range peer.Spec.AllowedIPs {
			addr, err := IPNetToIPAddress(allowedIP)
			if err != nil {
				return fmt.Errorf("peer %s/%s: failed to parse AllowedIP %s: %w",
					peer.Namespace, peer.Name, string(allowedIP), err)
			}

			ipAddr, err := IPBlockToIP(addr)
			if err != nil {
				return fmt.Errorf("peer %s/%s AllowedIP: %w", peer.Namespace, peer.Name, err)
			}

			owner := fmt.Sprintf("%s/%s", peer.Namespace, peer.Name)
			trie.Put(ipAddr.ToPrefixBlock(), owner)
		}
	}

	for i, addr := range newAddrs {
		ipAddr, err := IPBlockToIP(addr)
		if err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}

		if trie.ElementContains(ipAddr) {
			node := trie.LongestPrefixMatchNode(ipAddr)
			if node != nil && node.IsAdded() {
				existingOwner := node.GetValue()
				existingRange := node.GetKey().String()
				return fmt.Errorf("[%d] overlaps with peer %s range %s", i, existingOwner, existingRange)
			}
		}

		containedNode := trie.ElementsContainedBy(ipAddr)
		if containedNode != nil {
			iter := containedNode.ContainedFirstIterator(true)
			if iter.HasNext() {
				node := iter.Next()
				if node.IsAdded() {
					existingOwner := node.GetValue()
					existingRange := node.GetKey().String()
					return fmt.Errorf("[%d] contains peer %s range %s", i, existingOwner, existingRange)
				}
			}
		}
	}

	return nil
}

// FindNextAvailableIP finds the next available IP in a CIDR range using Trie
func FindNextAvailableIP(cidr wgov1alpha1.InterfaceCIDR, existingPeers []wgov1alpha1.WireGuardPeer) (netip.Addr, error) {
	// Parse CIDR as IPAddress using helper
	cidrIPAddr, err := InterfaceAddressToIPAddress(cidr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid CIDR: %w", err)
	}

	// Convert to prefix block to get the full network range
	// This converts "10.219.3.1/24" to "10.219.3.0/24" so we iterate all IPs in the network
	cidrIPAddr = cidrIPAddr.ToPrefixBlock()

	// Build trie from existing peers
	trie, err := BuildTrieFromPeers(existingPeers)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to build IP trie: %w", err)
	}

	// Mark the interface IP itself as used
	// Extract the host IP (without prefix block conversion)
	interfaceIPAddr, err := InterfaceAddressToIPAddress(cidr)
	if err == nil {
		trie.Put(interfaceIPAddr.ToIP(), InterfaceOwnerMarker)
	}

	// Iterator that automatically skips network and broadcast addresses for IPv4
	// For IPv4: skips first (network) and last (broadcast) unless /31 or /32
	// For IPv6: iterates all addresses
	prefixLen := cidrIPAddr.GetNetworkPrefixLen()
	if prefixLen == nil {
		return netip.Addr{}, fmt.Errorf("CIDR %s must have a prefix length", string(cidr))
	}

	iter := cidrIPAddr.Iterator()

	// Skip network and broadcast for IPv4 (except /31, /32)
	if cidrIPAddr.IsIPv4() && prefixLen.Len() < 31 {
		// Skip first (network address)
		if iter.HasNext() {
			iter.Next()
		}

		// Iterate but skip last (broadcast address)
		for addr := iter.Next(); iter.HasNext(); addr = iter.Next() {
			if !trie.ElementContains(addr) {
				return parseIPAddressToNetIP(addr)
			}
		}
	} else {
		// IPv6 or /31, /32 - use all addresses
		for iter.HasNext() {
			addr := iter.Next()
			if !trie.ElementContains(addr) {
				return parseIPAddressToNetIP(addr)
			}
		}
	}

	return netip.Addr{}, fmt.Errorf("no available IPs in CIDR %s (trie has %d entries)",
		string(cidr), trie.Size())
}

// parseIPAddressToNetIP converts ipaddress-go IPAddress to netip.Addr
func parseIPAddressToNetIP(addr *ipaddr.IPAddress) (netip.Addr, error) {
	if addr == nil {
		return netip.Addr{}, fmt.Errorf("nil IP address")
	}

	// Get string representation without prefix
	ipStr := addr.WithoutPrefixLen().String()
	parsed, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to parse IP %s: %w", ipStr, err)
	}

	return parsed, nil
}

// InterfaceAddressToIPAddress converts wgov1alpha1.InterfaceCIDR to ipaddress-go IPAddress
// Interface addresses require stricter validation (no ranges, only valid CIDR)
func InterfaceAddressToIPAddress(addr wgov1alpha1.InterfaceCIDR) (*ipaddr.IPAddress, error) {
	if addr == "" {
		return nil, fmt.Errorf("invalid InterfaceCIDR: empty string")
	}

	// Use strict parser for interface addresses (no ranges allowed)
	ipAddr, err := ParseIPAddressStrict(string(addr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse InterfaceCIDR %s: %w", string(addr), err)
	}

	return ipAddr, nil
}
