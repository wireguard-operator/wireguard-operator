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

package v1alpha1

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// +kubebuilder:validation:Type=string

// IPNet represents an IP address, CIDR range, or IP range
// Supports:
//   - Single IP: "192.168.1.1" or "2001:db8::1"
//   - CIDR: "192.168.0.0/24" or "2001:db8::/32"
//   - Range: "192.168.1.1-192.168.1.40" or "2001:db8::1-2001:db8::10"
type IPNet struct {
	// For a single IP (without mask)
	addr *netip.Addr
	// For CIDR (with mask)
	prefix *netip.Prefix
	// For IP ranges
	start *netip.Addr
	end   *netip.Addr
}

func NewIpNetFromAddr(addr netip.Addr) IPNet {
	return IPNet{addr: &addr}
}
func NewIpNetFromString(raw string) (IPNet, error) {
	var ipnet IPNet
	if err := ipnet.UnmarshalJSON([]byte(`"` + raw + `"`)); err != nil {
		return IPNet{}, fmt.Errorf("failed to parse IPNet %q: %w", raw, err)
	}
	return ipnet, nil
}

// IsValid returns true if the IPNet contains valid data
func (n *IPNet) IsValid() bool {
	if n == nil {
		return false
	}
	return n.addr != nil || n.prefix != nil || (n.start != nil && n.end != nil)
}

// IsRange returns true if this is an IP range (not a single IP or CIDR)
func (n *IPNet) IsRange() bool {
	return n.start != nil && n.end != nil
}

// IsSingle returns true if this is a single IP address (no range, /32 or /128)
func (n *IPNet) IsSingle() bool {
	if n.addr != nil {
		return true
	}
	if n.prefix != nil {
		return (n.prefix.Addr().Is4() && n.prefix.Bits() == 32) ||
			(n.prefix.Addr().Is6() && n.prefix.Bits() == 128)
	}
	if n.IsRange() {
		return n.start.Compare(*n.end) == 0
	}
	return false
}

// IsIPv4 returns true if this contains IPv4 addresses
func (n *IPNet) IsIPv4() bool {
	if n.addr != nil {
		return n.addr.Is4()
	}
	if n.prefix != nil {
		return n.prefix.Addr().Is4()
	}
	if n.IsRange() {
		return n.start.Is4()
	}
	return false
}

// IsIPv6 returns true if this contains IPv6 addresses
func (n *IPNet) IsIPv6() bool {
	if n.addr != nil {
		return n.addr.Is6() && !n.addr.Is4In6()
	}
	if n.prefix != nil {
		return n.prefix.Addr().Is6() && !n.prefix.Addr().Is4In6()
	}
	if n.IsRange() {
		return n.start.Is6() && !n.start.Is4In6()
	}
	return false
}

// FirstAndLastIP returns the first and last IP addresses
func (n *IPNet) FirstAndLastIP() (netip.Addr, netip.Addr, error) {
	if !n.IsValid() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid IPNet")
	}

	// For ranges, return as-is
	if n.IsRange() {
		return *n.start, *n.end, nil
	}

	// For single IP without mask
	if n.addr != nil {
		return *n.addr, *n.addr, nil
	}

	// For prefix/CIDR
	if n.prefix != nil {
		return NetFirstAndLastIP(*n.prefix)
	}

	return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid IPNet state")
}

// String returns the string representation
func (n *IPNet) String() string {
	if n.IsRange() {
		return fmt.Sprintf("%s-%s", n.start, n.end)
	}
	if n.addr != nil {
		return n.addr.String()
	}
	if n.prefix != nil {
		return n.prefix.String()
	}
	return ""
}

func (n *IPNet) MarshalJSON() ([]byte, error) {
	if n == nil || !n.IsValid() {
		return nil, fmt.Errorf("invalid IPNet")
	}
	return json.Marshal(n.String())
}

func (n *IPNet) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	// Try to parse as a range (contains "-")
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid IP range: %s", s)
		}

		start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid start IP in range: %s", parts[0])
		}

		end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err != nil {
			return fmt.Errorf("invalid end IP in range: %s", parts[1])
		}

		// Validate same family
		if start.Is4() != end.Is4() {
			return fmt.Errorf("IP range mixes IPv4 and IPv6: %s", s)
		}

		// Validate start <= end
		if start.Compare(end) > 0 {
			return fmt.Errorf("invalid IP range: start (%s) is greater than end (%s)", start, end)
		}

		n.start = &start
		n.end = &end
		return nil
	}

	// Try to parse as CIDR prefix
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("invalid CIDR: %s", s)
		}
		n.prefix = &p
		return nil
	}

	// Try to parse as a single IP
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("invalid IP address: %s", s)
	}

	// Store as single addr without mask
	n.addr = &addr
	return nil
}

// NetFirstAndLastIP returns the first and last IP addresses for a prefix
func NetFirstAndLastIP(prefix netip.Prefix) (first, last netip.Addr, err error) {
	if !prefix.IsValid() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid prefix")
	}

	addr := prefix.Addr()
	bits := prefix.Bits()

	if addr.Is4() {
		// IPv4
		ip := addr.As4()
		ipInt := binary.BigEndian.Uint32(ip[:])

		// Calculate mask
		mask := uint32(0xFFFFFFFF << (32 - bits))

		// First IP is network address (IP & mask)
		firstInt := ipInt & mask

		// Last IP is broadcast address (IP | ~mask)
		lastInt := firstInt | (^mask)

		var firstBytes, lastBytes [4]byte
		binary.BigEndian.PutUint32(firstBytes[:], firstInt)
		binary.BigEndian.PutUint32(lastBytes[:], lastInt)

		first = netip.AddrFrom4(firstBytes)
		last = netip.AddrFrom4(lastBytes)
	} else {
		// IPv6
		ip := addr.As16()

		// For IPv6, we need to work with two uint64s
		ip1 := binary.BigEndian.Uint64(ip[:8])
		ip2 := binary.BigEndian.Uint64(ip[8:])

		// Calculate masks for both halves
		var mask1, mask2 uint64
		if bits <= 64 {
			mask1 = uint64(0xFFFFFFFFFFFFFFFF << (64 - bits))
			mask2 = 0
		} else {
			mask1 = 0xFFFFFFFFFFFFFFFF
			mask2 = uint64(0xFFFFFFFFFFFFFFFF << (128 - bits))
		}

		// First IP
		first1 := ip1 & mask1
		first2 := ip2 & mask2

		// Last IP
		last1 := first1 | (^mask1)
		last2 := first2 | (^mask2)

		var firstBytes, lastBytes [16]byte
		binary.BigEndian.PutUint64(firstBytes[:8], first1)
		binary.BigEndian.PutUint64(firstBytes[8:], first2)
		binary.BigEndian.PutUint64(lastBytes[:8], last1)
		binary.BigEndian.PutUint64(lastBytes[8:], last2)

		first = netip.AddrFrom16(firstBytes)
		last = netip.AddrFrom16(lastBytes)
	}

	return first, last, nil
}

// ToNetIPNet converts the IPNet to net.IPNet for use with legacy APIs like netlink
// Only works for CIDR prefixes, not ranges
func (n *IPNet) ToNetIPNet() *net.IPNet {
	if n == nil || !n.IsValid() || n.IsRange() {
		return nil
	}

	if n.prefix == nil {
		return nil
	}

	a := n.prefix.Addr()
	if a.Is4In6() {
		a = a.Unmap()
	}

	var ip net.IP
	var bits int

	if a.Is4() {
		ip4 := a.As4()
		ip = make(net.IP, 4)
		copy(ip, ip4[:])
		bits = 32
	} else {
		ip16 := a.As16()
		ip = make(net.IP, 16)
		copy(ip, ip16[:])
		bits = 128
	}

	mask := net.CIDRMask(n.prefix.Bits(), bits)
	return &net.IPNet{IP: ip, Mask: mask}
}

// Prefix returns the underlying netip.Prefix if this is not a range
// Returns invalid prefix if this is a range
func (n *IPNet) Prefix() netip.Prefix {
	if n.prefix != nil {
		return *n.prefix
	}
	return netip.Prefix{}
}

// SetPrefix sets the prefix for testing purposes
// WARNING: This bypasses validation and should only be used in tests
func (n *IPNet) SetPrefix(p netip.Prefix) {
	n.prefix = &p
}

// Addr returns the address part (for single IPs or CIDR)
// Returns invalid addr if this is a range
func (n *IPNet) Addr() netip.Addr {
	if n.prefix != nil {
		return n.prefix.Addr()
	}
	return netip.Addr{}
}

// Bits return the prefix length (for CIDR)
// Returns -1 if this is a range or invalid
func (n *IPNet) Bits() int {
	if n.prefix != nil {
		return n.prefix.Bits()
	}
	return -1
}

func (n *IPNet) DeepCopyInto(out *IPNet) {
	if n == nil {
		return
	}
	// Copy pointer fields properly
	if n.addr != nil {
		addrCopy := *n.addr
		out.addr = &addrCopy
	} else {
		out.addr = nil
	}

	if n.prefix != nil {
		prefixCopy := *n.prefix
		out.prefix = &prefixCopy
	} else {
		out.prefix = nil
	}

	if n.start != nil {
		startCopy := *n.start
		out.start = &startCopy
	} else {
		out.start = nil
	}

	if n.end != nil {
		endCopy := *n.end
		out.end = &endCopy
	} else {
		out.end = nil
	}
}

func (n *IPNet) DeepCopy() *IPNet {
	if n == nil {
		return nil
	}
	out := new(IPNet)
	n.DeepCopyInto(out)
	return out
}

// Contains returns true if the given IP or IPNet is contained within this IPNet
func (n *IPNet) Contains(ip IPNet) bool {
	if !n.IsValid() || !ip.IsValid() {
		return false
	}

	// Get the boundaries of both networks
	nFirst, nLast, err := n.FirstAndLastIP()
	if err != nil {
		return false
	}

	ipFirst, ipLast, err := ip.FirstAndLastIP()
	if err != nil {
		return false
	}

	// Check that they're the same IP family
	if nFirst.Is4() != ipFirst.Is4() {
		return false
	}

	// Check if ipFirst >= nFirst and ipLast <= nLast
	return nFirst.Compare(ipFirst) <= 0 && nLast.Compare(ipLast) >= 0
}

// +kubebuilder:validation:MaxItems=100
// +listType=set

// IPNets is a list of IPNet blocks
type IPNets []IPNet

// +kubebuilder:validation:MinItems=1
// +kubebuilder:validation:MaxItems=100
// +listType=set

// IPNetsRequired is a list of IPNet blocks that requires at least one entry.
type IPNetsRequired []IPNet

// MustParseIPNet parses a string as IPNet and panics on error
func MustParseIPNet(s string) IPNet {
	var ipnet IPNet
	if err := ipnet.UnmarshalJSON([]byte(`"` + s + `"`)); err != nil {
		panic(fmt.Errorf("failed to parse IPNet %q: %w", s, err))
	}
	return ipnet
}
