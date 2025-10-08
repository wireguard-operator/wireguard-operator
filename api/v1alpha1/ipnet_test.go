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
	"encoding/json"
	"testing"
)

func TestIPNet_UnmarshalMarshal_RoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string // Expected output after marshal (may differ from input)
		shouldParse bool
	}{
		// Happy path - IPv4
		{
			name:        "IPv4 CIDR /24",
			input:       `"192.168.1.0/24"`,
			expected:    `"192.168.1.0/24"`,
			shouldParse: true,
		},
		{
			name:        "IPv4 CIDR /16",
			input:       `"10.0.0.0/16"`,
			expected:    `"10.0.0.0/16"`,
			shouldParse: true,
		},
		{
			name:        "IPv4 CIDR /8",
			input:       `"10.0.0.0/8"`,
			expected:    `"10.0.0.0/8"`,
			shouldParse: true,
		},
		{
			name:        "single IPv4 address without mask",
			input:       `"192.168.1.32"`,
			expected:    `"192.168.1.32"`, // Single IP without /32
			shouldParse: true,
		},
		{
			name:        "single IPv4 with /32",
			input:       `"10.0.0.1/32"`,
			expected:    `"10.0.0.1/32"`,
			shouldParse: true,
		},
		{
			name:        "IPv4 range",
			input:       `"10.0.0.1-10.0.0.33"`,
			expected:    `"10.0.0.1-10.0.0.33"`,
			shouldParse: true,
		},
		{
			name:        "IPv4 range single IP",
			input:       `"192.168.1.1-192.168.1.1"`,
			expected:    `"192.168.1.1-192.168.1.1"`,
			shouldParse: true,
		},
		{
			name:        "IPv4 range full subnet",
			input:       `"192.168.1.0-192.168.1.255"`,
			expected:    `"192.168.1.0-192.168.1.255"`,
			shouldParse: true,
		},

		// Happy path - IPv6
		{
			name:        "IPv6 CIDR /32",
			input:       `"2001:db8::/32"`,
			expected:    `"2001:db8::/32"`,
			shouldParse: true,
		},
		{
			name:        "IPv6 CIDR /64",
			input:       `"2001:db8:abcd::/64"`,
			expected:    `"2001:db8:abcd::/64"`,
			shouldParse: true,
		},
		{
			name:        "IPv6 CIDR /128",
			input:       `"2001:db8::1/128"`,
			expected:    `"2001:db8::1/128"`,
			shouldParse: true,
		},
		{
			name:        "single IPv6 address without mask",
			input:       `"2001:db8::1"`,
			expected:    `"2001:db8::1"`,
			shouldParse: true,
		},
		{
			name:        "IPv6 loopback",
			input:       `"::1"`,
			expected:    `"::1"`,
			shouldParse: true,
		},
		{
			name:        "IPv6 any address",
			input:       `"::"`,
			expected:    `"::"`,
			shouldParse: true,
		},
		{
			name:        "IPv6 range",
			input:       `"2001:db8::1-2001:db8::10"`,
			expected:    `"2001:db8::1-2001:db8::10"`,
			shouldParse: true,
		},
		{
			name:        "IPv6 range single",
			input:       `"fe80::1-fe80::1"`,
			expected:    `"fe80::1-fe80::1"`,
			shouldParse: true,
		},

		// Unhappy path - Invalid inputs
		{
			name:        "invalid IPv4 range (start > end)",
			input:       `"10.0.0.33-10.0.0.20"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "invalid IPv6 range (start > end)",
			input:       `"2001:db8::10-2001:db8::1"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "mixed IPv4/IPv6 range",
			input:       `"192.168.1.1-2001:db8::1"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "invalid IPv4 address",
			input:       `"192.168.256.1"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "invalid IPv4 CIDR - bad IP",
			input:       `"192.168.256.0/24"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "invalid IPv4 CIDR - bad mask",
			input:       `"192.168.1.0/33"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "invalid IPv6 address",
			input:       `"gggg::1"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "invalid IPv6 CIDR - bad mask",
			input:       `"2001:db8::/129"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "empty string",
			input:       `""`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "malformed range - missing end",
			input:       `"192.168.1.1-"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "malformed range - missing start",
			input:       `"-192.168.1.1"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "malformed range - too many parts",
			input:       `"192.168.1.1-192.168.1.2-192.168.1.3"`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "not a string",
			input:       `123`,
			expected:    "",
			shouldParse: false,
		},
		{
			name:        "empty value",
			input:       `""`,
			expected:    `""`,
			shouldParse: false,
		},
		{
			name:        "mixed ranges ipv4/ipv6",
			input:       `"192.168.1.1-2001:db8::10"`,
			expected:    `""`,
			shouldParse: false,
		},
		{
			name:        "mixed ranges ipv6/ipv4",
			input:       `"2001:db8::10-192.168.1.1"`,
			expected:    `""`,
			shouldParse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ipnet IPNet

			// Test unmarshal
			err := json.Unmarshal([]byte(tt.input), &ipnet)
			if tt.shouldParse {
				if err != nil {
					t.Errorf("Unmarshal failed unexpectedly: %v", err)
					return
				}

				// Test marshal
				got, err := json.Marshal(&ipnet)
				if err != nil {
					t.Errorf("Marshal failed: %v", err)
					return
				}

				if string(got) != tt.expected {
					t.Errorf("Marshal output = %v, want %v", string(got), tt.expected)
				}
			} else {
				if err == nil {
					t.Errorf("Expected unmarshal to fail for %s, but it succeeded", tt.input)
				}
			}
		})
	}
}
