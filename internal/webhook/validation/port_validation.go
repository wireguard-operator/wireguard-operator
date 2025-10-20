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
	"net"
	"strconv"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
)

// ValidatePorts validates PolicyPort specifications:
// - Ensures each port has either 'port' or 'name' set
// - Validates port ranges (start <= end)
// - Checks that port ranges don't overlap (overlapping ranges cause nftables set errors)
func ValidatePorts(ports []wgov1alpha1.PolicyPort) error {
	if len(ports) == 0 {
		return nil
	}

	type portRange struct {
		start uint16
		end   uint16
	}

	ranges := make([]portRange, 0, len(ports))
	for _, p := range ports {
		// PolicyPort must have either Port or Name set
		if p.Port == nil {
			if p.Name == "" {
				return fmt.Errorf("port must specify either 'port' or 'name'")
			}
			// Named ports are skipped in overlap validation
			continue
		}

		start, end, err := validatePortRange(p)
		if err != nil {
			return err
		}

		ranges = append(ranges, portRange{
			start: start,
			end:   end,
		})
	}

	// Check each pair for overlap
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			r1, r2 := ranges[i], ranges[j]

			// Ranges overlap if: r1.start <= r2.end AND r2.start <= r1.end
			if r1.start <= r2.end && r2.start <= r1.end {
				// Format range display
				r1Str := fmt.Sprintf("%d", r1.start)
				if r1.start != r1.end {
					r1Str = fmt.Sprintf("%d-%d", r1.start, r1.end)
				}
				r2Str := fmt.Sprintf("%d", r2.start)
				if r2.start != r2.end {
					r2Str = fmt.Sprintf("%d-%d", r2.start, r2.end)
				}

				return fmt.Errorf("overlapping port ranges: %s and %s (nftables does not allow overlapping intervals in sets)",
					r1Str, r2Str)
			}
		}
	}

	return nil
}

func validatePortRange(p wgov1alpha1.PolicyPort) (uint16, uint16, error) {
	start := uint16(*p.Port)
	end := start
	if p.EndPort != nil {
		end = uint16(*p.EndPort)
	}

	// Validate that start <= end
	if start > end {
		return 0, 0, fmt.Errorf("invalid port range: port %d > endPort %d", start, end)
	}

	return start, end, nil
}

// ParseHostPort parses and validates a host:port string
// Returns the host, port as uint16, and any error
func ParseHostPort(hostport string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, fmt.Errorf("invalid host:port format: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port: %s. Allowed range is between 1 - 65535", portStr)
	}

	return host, uint16(port), nil
}

// ValidateEndpoint validates the endpoint format (host:port or [ipv6]:port)
// Accepts IP addresses (IPv4/IPv6) and hostnames
// The validation is intentionally permissive to support various WireGuard use cases
func ValidateEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}

	// ParseHostPort does the heavy lifting:
	// - Validates host:port format
	// - Handles IPv6 bracket notation [::1]:port
	// - Validates port range (1-65535)
	host, _, err := ParseHostPort(endpoint)
	if err != nil {
		return err
	}

	// Optional lightweight validation using ipaddress-go
	// If it's an IP address, we validate it; if it's a hostname, we accept it
	hostName := ipaddr.NewHostName(host)
	if hostName.IsAddress() {
		// It's an IP address - do basic validation
		addr := hostName.AsAddress()
		// Only reject 0.0.0.0 or :: as they don't make sense for remote endpoints
		// Note: Loopback is allowed for testing (localhost:51820, 127.0.0.1:51820, [::1]:51820)
		if addr.IsZero() {
			return fmt.Errorf("endpoint cannot use unspecified address (0.0.0.0 or ::): %s", host)
		}
	}
	// If it's not an IP address, it's treated as a hostname - which is valid
	// Examples: vpn.example.com:51820, my-server.local:51820

	return nil
}
