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
	"k8s.io/apimachinery/pkg/api/resource"
)

// +kubebuilder:validation:Type=integer
// +kubebuilder:validation:Minimum=1
// +kubebuilder:validation:Maximum=65535

// Port is a network port number.
type Port int32

// +kubebuilder:validation:Type=integer
// +kubebuilder:validation:Minimum=68
// +kubebuilder:validation:Maximum=9000

// MTU is the Maximum Transmission Unit size.
type MTU int

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,14}$`
// +kubebuilder:validation:MaxLength=15

// InterfaceName is a network interface name.
type InterfaceName string

// +kubebuilder:validation:MaxItems=20
// +listType=set

// InterfaceNames is a list of interface names with duplicate prevention.
type InterfaceNames []InterfaceName

// +kubebuilder:validation:Enum=Allow;Drop;Reject
// +kubebuilder:default=Allow

// PolicyAction defines the action to take.
type PolicyAction string

const (
	PolicyActionAllow  PolicyAction = "Allow"
	PolicyActionDrop   PolicyAction = "Drop"
	PolicyActionReject PolicyAction = "Reject"
)

// SecretRefBase is the base struct for all secret references.
// It contains only the secret name without a default key.
type SecretRefBase struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253

	// Name specifies the name of the Kubernetes Secret resource.
	// The secret must exist in the same namespace as the referencing resource.
	Name string `json:"name"`
}

// PrivateKeySecretRef references a Kubernetes Secret containing a WireGuard private key.
// The Key field defaults to "privateKey" if not specified.
type PrivateKeySecretRef struct {
	SecretRefBase `json:",inline"`

	// +optional
	// +kubebuilder:default="privateKey"
	// +kubebuilder:validation:MaxLength=253

	// Key specifies the data key within the Secret that contains the private key.
	// Defaults to "privateKey" if not specified.
	// The value must be base64-encoded in the Secret data field.
	Key string `json:"key,omitempty"`
}

// PresharedKeySecretRef references a Kubernetes Secret containing a WireGuard preshared key.
// The Key field defaults to "presharedKey" if not specified.
type PresharedKeySecretRef struct {
	SecretRefBase `json:",inline"`

	// +optional
	// +kubebuilder:default="presharedKey"
	// +kubebuilder:validation:MaxLength=253

	// Key specifies the data key within the Secret that contains the preshared key.
	// Defaults to "presharedKey" if not specified.
	// The value must be base64-encoded in the Secret data field.
	Key string `json:"key,omitempty"`
}

// ConfigSecretRef references a Kubernetes Secret containing a WireGuard configuration file.
// The Key field defaults to "wg.conf" if not specified.
type ConfigSecretRef struct {
	SecretRefBase `json:",inline"`

	// +optional
	// +kubebuilder:default="wg.conf"
	// +kubebuilder:validation:MaxLength=253

	// Key specifies the data key within the Secret that contains the configuration file.
	// Defaults to "wg.conf" if not specified.
	Key string `json:"key,omitempty"`
}

// SecretRef is a generic secret reference for cases where no default key is needed.
// Used for other generic secret references.
type SecretRef struct {
	SecretRefBase `json:",inline"`

	// +optional
	// +kubebuilder:validation:MaxLength=253

	// Key specifies the data key within the Secret that contains the desired value.
	// The value must be base64-encoded in the Secret data field.
	Key string `json:"key,omitempty"`
}

// WireGuardReferenceSpec is embedded in resources that reference a WireGuard instance.
// This creates a relationship between the resource and a specific WireGuard configuration.
type WireGuardReferenceSpec struct {
	// WireGuardRef identifies the WireGuard instance this resource belongs to.
	// This reference is immutable once set to ensure a consistent configuration.
	WireGuardRef WireGuardRef `json:"wireguardRef"`
}

// +kubebuilder:object:generate=false

// WireGuardRefHolder interface for types that have a WireGuardRef
type WireGuardRefHolder interface {
	GetWireGuardRef() WireGuardRef
}

func (p *WireGuardPeer) GetWireGuardRef() WireGuardRef {
	return p.Spec.WireGuardRef
}

func (p *WireGuardTrafficFlow) GetWireGuardRef() WireGuardRef {
	return p.Spec.WireGuardRef
}

// +kubebuilder:validation:XValidation:rule="!has(oldSelf.name) || has(self.name)",message="wireguardRef cannot be removed once set"

// WireGuardRef references a WireGuard resource in the same namespace.
// This reference is immutable once set to maintain configuration consistency.
type WireGuardRef struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="wireguardRef.name is immutable once set"

	// Name identifies the WireGuard resource in the same namespace.
	// This field is immutable after creation to prevent accidental reassignment.
	// The referenced WireGuard must exist for the resource to become active.
	Name string `json:"name"`
}

// +kubebuilder:default=Any
// +kubebuilder:validation:Enum=TCP;UDP;ICMP;ICMPv6;Any

// Protocol defines network protocols.
type Protocol string

const (
	ProtocolTCP    Protocol = "TCP"
	ProtocolUDP    Protocol = "UDP"
	ProtocolICMP   Protocol = "ICMP"
	ProtocolICMPv6 Protocol = "ICMPv6"
	ProtocolAny    Protocol = "Any"
)

// +kubebuilder:validation:Enum=Pending;Running;Active;Inactive;Failed

// Phase defines the phase of a resource.
type Phase string

const (
	PhasePending  Phase = "Pending"
	PhaseRunning  Phase = "Running"
	PhaseActive   Phase = "Active"
	PhaseInactive Phase = "Inactive"
	PhaseFailed   Phase = "Failed"
)

// +kubebuilder:validation:Enum=second;minute;hour;day;week

// RateLimitPer defines the time unit for rate limiting.
type RateLimitPer string

const (
	RateLimitPerSecond RateLimitPer = "second"
	RateLimitPerMinute RateLimitPer = "minute"
	RateLimitPerHour   RateLimitPer = "hour"
	RateLimitPerDay    RateLimitPer = "day"
	RateLimitPerWeek   RateLimitPer = "week"
)

// +kubebuilder:validation:Enum=global;per-source;per-destination

// RateLimitScope defines the scope for rate limiting.
type RateLimitScope string

const (
	RateLimitScopeGlobal         RateLimitScope = "global"
	RateLimitScopePerSource      RateLimitScope = "per-source"
	RateLimitScopePerDestination RateLimitScope = "per-destination"
)

// +kubebuilder:validation:Enum=new;established;related;invalid;untracked

// ConnTrackState defines connection tracking states for stateful firewall rules.
// Connection tracking (conntrack) enables stateful packet filtering in NFTables.
type ConnTrackState string

const (
	// ConnTrackStateNew matches packets creating a new connection (SYN packets for TCP).
	ConnTrackStateNew ConnTrackState = "new"
	// ConnTrackStateEstablished matches packets belonging to established connections.
	ConnTrackStateEstablished ConnTrackState = "established"
	// ConnTrackStateRelated matches packets related to existing connections (e.g., ICMP errors, FTP data).
	ConnTrackStateRelated ConnTrackState = "related"
	// ConnTrackStateInvalid matches packets that don't match any connection or violate protocol rules.
	ConnTrackStateInvalid ConnTrackState = "invalid"
	// ConnTrackStateUntracked matches packets explicitly excluded from connection tracking.
	ConnTrackStateUntracked ConnTrackState = "untracked"
)

// +kubebuilder:validation:Enum=IPv4;IPv6
// +kubebuilder:default=IPv4

// IPFamily defines the IP protocol family for rules.
type IPFamily string

const (
	IPFamilyIPv4 IPFamily = "IPv4"
	IPFamilyIPv6 IPFamily = "IPv6"
)

// +kubebuilder:validation:XValidation:rule="(has(self.packets) && !has(self.bytes)) || (!has(self.packets) && has(self.bytes))",message="exactly one of packets or bytes must be set"

// RateLimitSpec defines rate limiting parameters for NFTables rules using token bucket algorithm.
// Rate limiting helps protect against DoS attacks and control traffic flow.
// Either Packets or Bytes must be specified, but not both.
type RateLimitSpec struct {
	// +optional

	// Packets specifies the maximum number of packets allowed per time unit.
	// Mutually exclusive with Bytes. Use for connection-oriented rate limiting.
	// Examples:
	// - "100" = 100 packets
	// - "1k" = 1,000 packets
	// - "10k" = 10,000 packets
	Packets *resource.Quantity `json:"packets,omitempty"`

	// +optional

	// Bytes specifies the maximum data volume allowed per time unit.
	// Mutually exclusive with Packets. Use for bandwidth-based rate limiting.
	// Examples:
	// - "10Mi" = 10 mebibytes
	// - "1Gi" = 1 gibibyte
	// - "100M" = 100 megabytes
	Bytes *resource.Quantity `json:"bytes,omitempty"`

	// +kubebuilder:validation:Required

	// Per defines the time unit for the rate limit.
	// The limit resets after each time period.
	// Options: second, minute, hour, day, week
	Per RateLimitPer `json:"per"`

	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=5

	// Burst specifies the maximum tokens that can accumulate in the bucket.
	// Allows temporary traffic spikes above the rate limit.
	// Set to 0 for strict rate limiting without burst allowance.
	// Default of 5 provides reasonable burst tolerance.
	Burst int32 `json:"burst,omitempty"`

	// +optional
	// +kubebuilder:default=false

	// Over inverts the rate limit match logic.
	// When false (default): Match packets within the rate limit.
	// When true: Match packets that exceed the rate limit (useful for logging or dropping excess traffic).
	Over bool `json:"over,omitempty"`

	// +optional
	// +kubebuilder:default=global

	// Scope defines how the rate limit is applied:
	// - global: Single limit shared by all traffic
	// - per-source: Separate limit for each source IP address
	// - per-destination: Separate limit for each destination IP address
	// Use per-source to prevent single IPs from consuming all bandwidth.
	Scope RateLimitScope `json:"scope,omitempty"`
}
