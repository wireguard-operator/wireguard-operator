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

	"github.com/seancfoley/ipaddress-go/ipaddr"
)

// ParseIPAddress parses an IP address string using ipaddress-go
// This is the centralized parsing function that ensures consistent behavior
// across all validators and webhooks.
//
// Supports:
//   - IPv4 and IPv6 addresses
//   - CIDR notation (e.g., 192.168.1.0/24)
//   - Segment ranges (e.g., 192.168.1.1-5)
//
// The ipaddress-go library automatically handles various formats and validation.
func ParseIPAddress(str string) (*ipaddr.IPAddress, error) {
	if str == "" {
		return nil, fmt.Errorf("IP address string cannot be empty")
	}

	addrStr := ipaddr.NewIPAddressString(str)
	addr := addrStr.GetAddress()
	if addr == nil {
		// GetAddress returns nil if parsing fails
		// We construct a helpful error message
		return nil, fmt.Errorf("invalid IP address format: %s", str)
	}

	return addr, nil
}

// ParseIPAddressStrict parses an IP address string with strict validation
// This version is more restrictive and is used for interface addresses
// where ranges and certain formats should not be allowed.
func ParseIPAddressStrict(str string) (*ipaddr.IPAddress, error) {
	addr, err := ParseIPAddress(str)
	if err != nil {
		return nil, err
	}

	// Additional strict validation
	// For interface addresses, we don't want segment ranges without prefix
	if addr.IsMultiple() && !addr.IsPrefixed() {
		return nil, fmt.Errorf("interface addresses cannot use segment ranges: %s", str)
	}

	return addr, nil
}
