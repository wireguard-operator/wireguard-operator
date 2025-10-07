/*
Copyright 2025.

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
	"encoding/json"
	"fmt"
	"net"
)

// +kubebuilder:validation:Type=string

// InterfaceAddress represents an IP address with subnet mask for network interfaces
// It wraps net.IPNet and marshals to a single CIDR string like "192.168.1.1/24"
// Unlike routes, interface addresses use specific host IPs (not network addresses)
type InterfaceAddress struct {
	net.IPNet `json:",inline"`
}

// InterfaceAddresses is a slice of InterfaceAddress
type InterfaceAddresses []InterfaceAddress

// MarshalJSON serializes the InterfaceAddress as a CIDR string
func (a *InterfaceAddress) MarshalJSON() ([]byte, error) {
	if a.IP == nil {
		return json.Marshal("")
	}
	return json.Marshal(a.String())
}

// UnmarshalJSON parses a CIDR string into the embedded net.IPNet
func (a *InterfaceAddress) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	if s == "" {
		return fmt.Errorf("interface address cannot be empty")
	}

	// Parse as CIDR - this accepts any IP with mask like "192.168.1.1/24"
	// net.ParseCIDR returns both the IP and the network
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("invalid interface address %q: %w", s, err)
	}

	// IMPORTANT: Store the actual IP provided (not the network address)
	// For interface addresses we want "192.168.1.1/24", not "192.168.1.0/24"
	ipnet.IP = ip
	a.IPNet = *ipnet
	return nil
}

// IsValid returns true if this is a valid interface address
func (a *InterfaceAddress) IsValid() bool {
	return a.IP != nil && a.Mask != nil
}

// Network returns the network address for this interface address
func (a *InterfaceAddress) Network() *net.IPNet {
	if a.IP == nil || a.Mask == nil {
		return nil
	}
	return &net.IPNet{
		IP:   a.IP.Mask(a.Mask),
		Mask: a.Mask,
	}
}

// IsNetworkAddress returns true if this is the network address (all host bits zero)
func (a *InterfaceAddress) IsNetworkAddress() bool {
	if a.IP == nil || a.Mask == nil {
		return false
	}
	// Use the Mask method which handles both IPv4 and IPv6 correctly
	network := a.IP.Mask(a.Mask)
	return a.IP.Equal(network)
}

// IsBroadcastAddress returns true if this is the broadcast address (all host bits one) for IPv4
func (a *InterfaceAddress) IsBroadcastAddress() bool {
	if a.IP == nil || a.Mask == nil {
		return false
	}

	// Only IPv4 has broadcast addresses
	ip4 := a.IP.To4()
	if ip4 == nil {
		return false
	}

	// Ensure we work with 4-byte representation
	if len(a.Mask) != 4 {
		return false
	}

	// Calculate broadcast address for IPv4
	broadcast := make(net.IP, 4)
	for i := range broadcast {
		broadcast[i] = ip4[i] | ^a.Mask[i]
	}

	return ip4.Equal(broadcast)
}

// GetIPNet returns the underlying net.IPNet
func (a *InterfaceAddress) GetIPNet() *net.IPNet {
	if a.IP == nil || a.Mask == nil {
		return nil
	}
	return &a.IPNet
}

// DeepCopyInto is a deepcopy function
func (a *InterfaceAddress) DeepCopyInto(out *InterfaceAddress) {
	if a == nil {
		return
	}
	*out = *a
	if a.IP != nil {
		out.IP = make(net.IP, len(a.IP))
		copy(out.IP, a.IP)
	}
	if a.Mask != nil {
		out.Mask = make(net.IPMask, len(a.Mask))
		copy(out.Mask, a.Mask)
	}
}

// DeepCopy is a deepcopy function
func (a *InterfaceAddress) DeepCopy() *InterfaceAddress {
	if a == nil {
		return nil
	}
	out := new(InterfaceAddress)
	a.DeepCopyInto(out)
	return out
}

// MustParseInterfaceAddress parses a string as InterfaceAddress and panics on error
func MustParseInterfaceAddress(s string) InterfaceAddress {
	var addr InterfaceAddress
	if err := addr.UnmarshalJSON([]byte(`"` + s + `"`)); err != nil {
		panic(fmt.Sprintf("failed to parse InterfaceAddress %q: %v", s, err))
	}
	return addr
}
