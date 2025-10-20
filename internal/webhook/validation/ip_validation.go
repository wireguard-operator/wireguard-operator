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

package validation

import (
	"fmt"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
	"github.com/wireguard-operator/wireguard-operator/internal/utils"
)

// ParseAndValidateIPBlocks parses and validates IP blocks in a single pass
// Returns parsed addresses for reuse in further validation
func ParseAndValidateIPBlocks(blocks wgov1alpha1.IPBlocks, expectedFamily wgov1alpha1.IPFamily) ([]*ipaddr.IPAddress, error) {
	if len(blocks) == 0 {
		return nil, nil
	}

	addresses := make([]*ipaddr.IPAddress, len(blocks))
	seen := make(map[string]bool, len(blocks))

	for i, block := range blocks {
		addr, err := utils.ValidateIPBlockAsNetworkAddress(block)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}

		if expectedFamily != "" {
			switch expectedFamily {
			case wgov1alpha1.IPFamilyIPv4:
				if !addr.IsIPv4() {
					return nil, fmt.Errorf("[%d] %s: IPv6 address in IPv4 flow", i, string(block))
				}
			case wgov1alpha1.IPFamilyIPv6:
				if !addr.IsIPv6() {
					return nil, fmt.Errorf("[%d] %s: IPv4 address in IPv6 flow", i, string(block))
				}
			default:
				return nil, fmt.Errorf("unknown IP family: %s", expectedFamily)
			}
		}

		canonical := addr.ToCanonicalString()
		if seen[canonical] {
			return nil, fmt.Errorf("duplicate IP block: %s (canonical: %s)", string(block), canonical)
		}
		seen[canonical] = true

		addresses[i] = addr
	}

	if err := utils.CheckIPBlocksOverlapParsed(addresses, blocks); err != nil {
		return nil, err
	}

	return addresses, nil
}

// ValidateTransformTargetFamily validates that NAT target IP matches the flow's IP family
func ValidateTransformTargetFamily(transformation *wgov1alpha1.TransformAction, expectedFamily wgov1alpha1.IPFamily) error {
	if transformation == nil {
		return nil
	}

	if transformation.Type != wgov1alpha1.TransformTypeDNAT {
		if transformation.Target == "" {
			return nil
		}
		return fmt.Errorf("transform.target can only be specified with DNAT (got %s)", transformation.Type)
	}

	ipStr, _, err := ParseHostPort(transformation.Target)
	if err != nil {
		return fmt.Errorf("invalid DNAT target: %w", err)
	}

	_, err = ParseAndValidateIPBlocks(wgov1alpha1.IPBlocks{wgov1alpha1.IPBlock(ipStr)}, expectedFamily)
	if err != nil {
		return fmt.Errorf("invalid DNAT target IP: %w", err)
	}

	return nil
}

// ValidateInterfaceAddresses validates interface addresses are not network or broadcast addresses
// and checks that networks don't overlap
func ValidateInterfaceAddresses(addresses wgov1alpha1.InterfaceCIDRs) error {
	if len(addresses) == 0 {
		return fmt.Errorf("at least one address is required")
	}

	// First pass: validate individual addresses
	for i, addr := range addresses {
		if err := validateSingleInterfaceAddress(addr, i); err != nil {
			return err
		}
	}

	// Second pass: check for overlapping networks
	return utils.CheckInterfaceAddressOverlap(addresses)
}

// validateSingleInterfaceAddress validates a single interface address for correctness
func validateSingleInterfaceAddress(addr wgov1alpha1.InterfaceCIDR, index int) error {
	ipAddr, err := utils.InterfaceAddressToIPAddress(addr)
	if err != nil {
		return fmt.Errorf("address[%d] is invalid: %w", index, err)
	}

	prefixLen := ipAddr.GetNetworkPrefixLen()
	if prefixLen == nil {
		return fmt.Errorf("address[%d] %s must have a prefix length", index, string(addr))
	}

	lowerAddr := ipAddr.GetLower()

	// Check special addresses that are invalid for WireGuard interface addresses
	switch {
	case lowerAddr.IsMulticast():
		return fmt.Errorf("address[%d] %s cannot be a multicast address", index, string(addr))
	case lowerAddr.IsLoopback():
		return fmt.Errorf("address[%d] %s cannot be a loopback address", index, string(addr))
	case lowerAddr.IsLinkLocal():
		return fmt.Errorf("address[%d] %s cannot be a link-local address", index, string(addr))
	case lowerAddr.IsZero():
		return fmt.Errorf("address[%d] %s cannot be an unspecified address (0.0.0.0 or ::)", index, string(addr))
	}

	// Check network and broadcast addresses
	isIPv4 := ipAddr.IsIPv4()
	prefixBits := prefixLen.Len()
	// Check network address (except /31, /32 for IPv4, /127, /128 for IPv6)
	if lowerAddr.IsZeroHost() {
		if isIPv4 && prefixBits < 31 {
			nextAddr := lowerAddr.Increment(1)
			return fmt.Errorf("address[%d] %s cannot be the network address for an interface (use a host IP like %s/%d)",
				index, string(addr), nextAddr.WithoutPrefixLen().String(), prefixBits)
		}
		if ipAddr.IsIPv6() && prefixBits < 127 {
			return fmt.Errorf("address[%d] %s cannot be the network address for an interface", index, string(addr))
		}
	}

	// Check broadcast addresses (IPv4 only, except /31, /32)
	if isIPv4 {
		// Check for 255.255.255.255 (limited broadcast address)
		if lowerAddr.IsMax() {
			return fmt.Errorf("address[%d] %s cannot be the broadcast address for an interface", index, string(addr))
		}

		// Check for subnet broadcast address (last IP in subnet)
		if lowerAddr.IsMaxHost() && prefixBits < 31 {
			return fmt.Errorf("address[%d] %s cannot be the broadcast address for an interface", index, string(addr))
		}
	}

	return nil
}

// CompareIPNets checks if two IPBlock slices are equal (order-independent)
func CompareIPNets(a, b wgov1alpha1.IPBlocks) bool {
	if len(a) != len(b) {
		return false
	}

	aSet := make(map[string]int, len(a))
	for _, ip := range a {
		aSet[string(ip)]++
	}

	for _, ip := range b {
		count, exists := aSet[string(ip)]
		if !exists || count == 0 {
			return false
		}
		aSet[string(ip)]--
	}

	return true
}
