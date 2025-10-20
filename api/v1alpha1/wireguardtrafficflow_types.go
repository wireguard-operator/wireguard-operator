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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WireGuardTrafficFlowSpec defines traffic flows with unified filter and NAT operations.
type WireGuardTrafficFlowSpec struct {
	WireGuardReferenceSpec `json:",inline"`

	// +optional
	// +kubebuilder:validation:Minimum=-32768
	// +kubebuilder:validation:Maximum=32767
	// +kubebuilder:default=0

	// Priority determines the evaluation order among multiple WireGuardTrafficFlow resources.
	// Lower values are evaluated first. This priority applies to the entire flow resource.
	// Rules within a flow maintain their array order.
	// Common values:
	// - -100: High priority (evaluated early, e.g., critical security rules)
	// - 0: Default priority
	// - 100: Low priority (evaluated late, e.g., catch-all rules)
	Priority int32 `json:"priority,omitempty"`

	// +optional
	// +kubebuilder:validation:MaxItems=50

	// Flows define individual traffic flow rules.
	// Each flow describes a complete traffic pattern including source, destination,
	// filtering action, and optional NAT transformation.
	// Flows are evaluated in array order within this resource.
	// Use multiple flows for different protocols, IP families, or NAT requirements.
	Flows []FlowRule `json:"flows,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.protocol) || self.protocol != 'ICMPv6' || self.ipFamily == 'IPv6'",message="ICMPv6 protocol requires ipFamily: IPv6"
// +kubebuilder:validation:XValidation:rule="!has(self.protocol) || self.protocol != 'ICMP' || self.ipFamily == 'IPv4'",message="ICMP protocol requires ipFamily: IPv4"
// +kubebuilder:validation:XValidation:rule="!has(self.to) || !has(self.to.ports) || has(self.protocol) && self.protocol in ['TCP','UDP','Any']",message="to.ports can only be specified with TCP, UDP, or Any protocol"
// +kubebuilder:validation:XValidation:rule="!has(self.from) || !has(self.from.ports) || has(self.protocol) && self.protocol in ['TCP','UDP','Any']",message="from.ports can only be specified with TCP, UDP, or Any protocol"
// +kubebuilder:validation:XValidation:rule="!has(self.filter) || !has(self.filter.rateLimit) || self.filter.action == 'Allow'",message="rateLimit is only supported with filter.action=Allow"
// +kubebuilder:validation:XValidation:rule="!has(self.transform) || self.transform.type != 'dnat' || (!has(self.to) || !self.to.self) && (!has(self.from) || !self.from.self)",message="DNAT cannot be used with to.self or from.self (DNAT happens in PREROUTING before routing decision)"
// +kubebuilder:validation:XValidation:rule="!has(self.transform) || self.transform.type != 'masquerade' || !has(self.from) || !self.from.self",message="Masquerade cannot be used with from.self (OUTPUT chain conflicts with POSTROUTING)"
// +kubebuilder:validation:XValidation:rule="!has(self.transform) || self.transform.type != 'dnat' || has(self.transform.target)",message="DNAT requires transform.target to be specified"
// +kubebuilder:validation:XValidation:rule="!has(self.transform) || self.transform.type != 'masquerade' || has(self.transform.interface) || (has(self.to) && has(self.to.interfaces) && self.to.interfaces.size() > 0)",message="Masquerade requires transform.interface or to.interfaces[0]"

// FlowRule defines a single traffic flow with source, destination, filtering, and optional NAT.
// The flow-based pattern makes network configuration more intuitive by describing traffic
// in natural language: "Traffic flows from A to B with optional transformation C".
type FlowRule struct {
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._:+-]{1,63}$`

	// Name uniquely identifies this flow rule within the resource.
	// Used for logging, status reporting, and debugging.
	// Must be DNS-1123 compatible.
	Name string `json:"name,omitempty"`

	// +optional

	// IPFamily restricts this flow to IPv4 or IPv6 traffic.
	// This is crucial for NAT operations as NFTables requires separate tables
	// for IPv4 (ip) and IPv6 (ip6) NAT rules.
	// Filter rules can use inet table for dual-stack, but NAT must be family-specific.
	IPFamily IPFamily `json:"ipFamily,omitempty"`

	// +optional

	// Protocol specifies the network protocol for this flow.
	// This is the single source of truth for protocol matching.
	// Port matching is only valid with TCP, UDP, or Any.
	// ICMP requires IPv4, ICMPv6 requires IPv6.
	Protocol Protocol `json:"protocol,omitempty"`

	// +optional

	// From identifies the traffic source for this flow.
	// Can specify pods, peers, IPs, interfaces, or use 'self' for traffic from this pod.
	// If not specified, matches traffic from any source.
	// The 'self' field enables intuitive pod-centric rules:
	// - from.self=true → Traffic FROM this pod (OUTPUT chain)
	From *FlowTrafficSelector `json:"from,omitempty"`

	// +optional

	// To identifies the traffic destination for this flow.
	// Can specify pods, peers, IPs, interfaces, or use 'self' for traffic to this pod.
	// If not specified, matches traffic to any destination.
	// The 'self' field enables intuitive pod-centric rules:
	// - to.self=true → Traffic TO this pod (INPUT chain)
	To *FlowTrafficSelector `json:"to,omitempty"`

	// +optional

	// Filter defines the filtering action for this flow.
	// Determines whether traffic is allowed, dropped, or rejected.
	// Can include logging, rate limiting, and connection tracking.
	// If not specified, traffic matching this flow is allowed by default.
	Filter *FilterAction `json:"filter,omitempty"`

	// +optional

	// Transform defines optional NAT transformation for this flow.
	// Supports masquerading and DNAT operations.
	// NAT is applied in addition to filtering, not instead of.
	// Transform type determines the NAT chain automatically:
	// - masquerade → POSTROUTING chain
	// - dnat → PREROUTING chain
	//
	// For masquerade, the interface is used as:
	// 1. Match condition: oifname "eth0" (packets going out via eth0)
	// 2. IP source: Masquerade uses eth0's IP automatically
	//
	// Example: from.ipBlocks=["10.0.0.0/8"] to.interfaces=["eth0"] transform.type=masquerade
	// Generates NFTables rule: ip saddr 10.0.0.0/8 oifname "eth0" masquerade
	Transform *TransformAction `json:"transform,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.self) || self.self != true || ((has(self.ipBlocks)?1:0) + (has(self.podSelector)?1:0) + (has(self.peerSelector)?1:0) + (has(self.serviceSelector)?1:0) == 0)",message="when self is true, cannot specify ipBlocks, podSelector, peerSelector, or serviceSelector"
// +kubebuilder:validation:XValidation:rule="((has(self.ipBlocks) && size(self.ipBlocks) > 0)?1:0) + (has(self.podSelector)?1:0) + (has(self.peerSelector)?1:0) + (has(self.serviceSelector)?1:0) <= 1",message="specify at most one of ipBlocks, podSelector, peerSelector, or serviceSelector"
// +kubebuilder:validation:XValidation:rule="!has(self.multusNetwork) || has(self.podSelector)",message="multusNetwork requires podSelector to be specified"

// FlowTrafficSelector identifies traffic sources or destinations in a flow.
// The 'self' selector is the key innovation of the flow-based pattern:
// - self=true identifies traffic to/from the pod itself
// - self can be combined with interfaces and ports for interface-specific rules
// - self is mutually exclusive with IP/pod/peer/service selectors
type FlowTrafficSelector struct {
	// +optional
	// +kubebuilder:default=false

	// Self indicates traffic to/from the pod itself.
	// This is the primary selector for determining packet flow direction:
	// - When true in 'to': Matches INPUT chain (traffic TO this pod)
	// - When true in 'from': Matches OUTPUT chain (traffic FROM this pod)
	// - When false/absent in both: Matches FORWARD chain (traffic THROUGH this pod)
	//
	// Self can be combined with:
	// - interfaces: Restrict to specific network interfaces (e.g., to.self + interfaces=["wg0"])
	// - ports: Restrict to specific ports (e.g., to.self + ports=[{port: 80}])
	//
	// Self cannot be combined with:
	// - ipBlocks, podSelector, peerSelector, serviceSelector (mutually exclusive)
	//
	// Examples:
	// - DNS server: to.self=true, ports=[{port: 53}], interfaces=["wg0"]
	// - Pod egress: from.self=true, to.interfaces=["eth0"]
	Self bool `json:"self,omitempty"`

	// +optional

	// IPBlocks matches traffic by IP address ranges.
	// Supports CIDR notation, IP ranges, and single IPs for both IPv4 and IPv6.
	// Examples: ["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"]
	// Mutually exclusive with podSelector, peerSelector, serviceSelector when self=true.
	IPBlocks IPBlocks `json:"ipBlocks,omitempty"`

	// +optional

	// PodSelector matches Kubernetes pods by labels.
	// The selector is evaluated in the same namespace as this resource.
	// Matched pods' IPs are dynamically updated as pods come and go.
	// Useful for allowing traffic between specific application tiers.
	// Mutually exclusive with ipBlocks, peerSelector, serviceSelector when self=true.
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// +optional

	// PeerSelector matches WireGuardPeer resources by labels.
	// Useful for creating rules that apply to specific peer groups.
	// The matched peers' AllowedIPs are used for rule generation.
	// Example: Allow traffic from all peers with label wireguard-location=office
	// Mutually exclusive with ipBlocks, podSelector, serviceSelector when self=true.
	PeerSelector *metav1.LabelSelector `json:"peerSelector,omitempty"`

	// +optional

	// ServiceSelector matches Kubernetes services by labels.
	// The service's ClusterIP and endpoints are used for matching.
	// Useful for allowing traffic to/from specific services.
	// Mutually exclusive with ipBlocks, podSelector, peerSelector when self=true.
	ServiceSelector *metav1.LabelSelector `json:"serviceSelector,omitempty"`

	// +optional
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(/[a-z0-9]([-a-z0-9]*[a-z0-9])?)?$`

	// MultusNetwork specifies which Multus NetworkAttachmentDefinition to use
	// when resolving podSelector IPs. Only IPs from this network are included.
	//
	// The annotation k8s.v1.cni.cncf.io/network-status is parsed to find the
	// network by name. Format: "name" (same namespace) or "namespace/name".
	//
	// Example: podSelector matches pods with net1 (10.219.2.22) and eth0 (10.44.0.25)
	//   multusNetwork: "kube-system/wireguard-routed"
	//   → Resolves only 10.219.2.22 (net1), ignores 10.44.0.25 (eth0)
	//
	// Only valid when podSelector is specified.
	MultusNetwork string `json:"multusNetwork,omitempty"`

	// +optional

	// Interfaces matches traffic on specific network interfaces.
	// Can be combined with self for interface-specific pod rules.
	// Examples: ["wg0", "eth0", "net1"]
	//
	// Semantics:
	// - In 'from' selector: iifname (input interface)
	// - In 'to' selector: oifname (output interface)
	//
	// Use cases:
	// - DNS only via WireGuard: to.self=true, interfaces=["wg0"]
	// - Multus to WireGuard: from.interfaces=["net1"], to.interfaces=["wg0"]
	Interfaces InterfaceNames `json:"interfaces,omitempty"`

	// +optional
	// +kubebuilder:validation:MaxItems=10

	// Ports specifies TCP/UDP port matching criteria.
	// Can define single ports, port ranges, or named ports.
	// Only valid when protocol is TCP, UDP, or Any.
	// The protocol is defined at the FlowRule level, not per port.
	Ports []PolicyPort `json:"ports,omitempty"`
}

// FilterAction defines the filtering behavior and additional options for a flow.
// Controls whether traffic is accepted, dropped, or rejected, plus logging and rate limiting.
type FilterAction struct {
	// +optional

	// Action determines what happens to matching packets:
	// - Allow: Accept the packet (NFTables 'accept')
	// - Drop: Silently discard the packet (NFTables 'drop')
	// - Reject: Drop with ICMP/TCP RST response (NFTables 'reject')
	Action PolicyAction `json:"action,omitempty"`

	// +optional
	// +kubebuilder:default=false

	// Log enables packet logging for this flow.
	// Logged packets appear in kernel log (dmesg/journald) with the specified prefix.
	// Use sparingly as excessive logging impacts performance.
	// Logs include packet counters for traffic analysis.
	Log bool `json:"log,omitempty"`

	// +optional
	// +kubebuilder:validation:MaxLength=63

	// LogPrefix adds a custom prefix to log messages.
	// Useful for distinguishing between different flows in logs.
	// If not specified, defaults to "flow:<name>".
	// Maximum length: 63 characters
	LogPrefix string `json:"logPrefix,omitempty"`

	// +optional

	// RateLimit applies rate limiting to this flow using token bucket algorithm.
	// Only valid with action=Allow. Excess packets are dropped.
	// Useful for DDoS protection and bandwidth management.
	// Can be applied globally, per-source, or per-destination.
	RateLimit *RateLimitSpec `json:"rateLimit,omitempty"`
}

// +kubebuilder:validation:Enum=masquerade;dnat

// TransformType defines the type of NAT transformation.
type TransformType string

const (
	// TransformTypeMasquerade dynamically uses the outgoing interface's IP as source.
	// Common for providing internet access to private networks.
	// Maps to POSTROUTING chain in NFTables.
	TransformTypeMasquerade TransformType = "masquerade"

	// TransformTypeDNAT changes destination IP/port for incoming packets (port forwarding).
	// Used for exposing internal services through WireGuard.
	// Maps to PREROUTING chain in NFTables.
	TransformTypeDNAT TransformType = "dnat"
)

// TransformAction defines NAT transformation for a flow.
// The transform type automatically determines the NFTables chain:
// - masquerade → POSTROUTING (after routing decision, before egress)
// - dnat → PREROUTING (before routing decision, for incoming traffic)
type TransformAction struct {
	// +kubebuilder:validation:Required

	// Type specifies the NAT operation mode.
	// This determines which NFTables NAT chain is used:
	// - masquerade: POSTROUTING chain, dynamic source NAT using interface IP
	// - dnat: PREROUTING chain, destination NAT for port forwarding
	Type TransformType `json:"type"`

	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]{1,5})?$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(:[0-9]{1,5})?$`

	// Target specifies the NAT target address.
	// Format depends on transform type:
	// - DNAT: "IP:Port" (e.g., "10.0.0.5:80" for port forwarding to internal service)
	// - Masquerade: Not used (masquerade uses the matched output interface's IP automatically)
	//
	// Required for DNAT, ignored for masquerade.
	Target string `json:"target,omitempty"`

	// +optional

	// Interface specifies the output interface for NAT operations.
	// Used for masquerade and optionally for DNAT.
	//
	// For masquerade:
	// - Required (explicit or from to.interfaces[0])
	// - Used as match condition (oifname) before masquerade action
	// - Masquerade automatically uses this interface's IP for source NAT
	//
	// For DNAT:
	// - Optional: Can be used to restrict NAT to specific interface
	//
	// Resolution order for masquerade:
	// 1. Explicit transform.interface
	// 2. Implicit to.interfaces[0]
	// 3. Error if neither available
	//
	// Examples: "eth0" for main network, "wg0" for WireGuard
	Interface InterfaceName `json:"interface,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.endPort) || has(self.port)",message="endPort requires port"
// +kubebuilder:validation:XValidation:rule="!has(self.endPort) || int(self.endPort) >= int(self.port)",message="endPort must be >= port"

// PolicyPort describes TCP/UDP port matching criteria.
// Supports single ports, port ranges, and named ports from services.
type PolicyPort struct {
	// +optional

	// Port specifies a single port number or start of a range.
	// Valid range: 1-65535
	Port *Port `json:"port,omitempty"`

	// +optional

	// EndPort defines the inclusive end of a port range.
	// Must be >= Port. If not specified, only Port is matched.
	// Example: Port=8080, EndPort=8090 matches ports 8080-8090.
	EndPort *Port `json:"endPort,omitempty"`

	// +optional

	// Name references a named port from a service.
	// When ServiceSelector is used, this resolves to the actual port number.
	// Example: "http", "https", "grpc"
	Name string `json:"name,omitempty"`
}

// ChainAssignment shows which NFTables chains a flow rule was assigned to.
// This information is useful for debugging and understanding the actual packet processing path.
type ChainAssignment struct {
	// FlowName identifies which flow rule this assignment belongs to.
	FlowName string `json:"flowName"`

	// +optional

	// FilterChain indicates which filter chain processes this flow:
	// - "input": Traffic TO this pod (to.self=true)
	// - "output": Traffic FROM this pod (from.self=true)
	// - "forward": Traffic THROUGH this pod (neither from nor to has self=true)
	FilterChain string `json:"filterChain,omitempty"`

	// +optional

	// NATChain indicates which NAT chain processes this flow:
	// - "prerouting": DNAT operations (before routing decision)
	// - "postrouting": Masquerade operations (after routing decision)
	// - Empty if no NAT transformation is configured
	NATChain string `json:"natChain,omitempty"`
}

// AppliedEntity represents a resource affected by this policy.
// Shows the result of selector evaluation for troubleshooting.
type AppliedEntity struct {
	// Type identifies the kind of Kubernetes resource:
	// - Pod: Kubernetes pod
	// - Peer: WireGuardPeer resource
	// - Service: Kubernetes service
	Type string `json:"type"`

	// Name of the Kubernetes resource.
	Name string `json:"name"`

	// +optional

	// Namespace of the resource (empty for cluster-scoped resources).
	Namespace string `json:"namespace,omitempty"`

	// +optional
	// +listType=set

	// ResolvedIPs shows the IP addresses this entity resolved to.
	// For pods: Pod IP
	// For services: ClusterIP and endpoint IPs
	// For peers: AllowedIPs from the peer configuration
	ResolvedIPs []string `json:"resolvedIPs,omitempty"`
}

// WireGuardTrafficFlowStatus represents the current state of the traffic flow.
type WireGuardTrafficFlowStatus struct {
	// +optional

	// Phase indicates the lifecycle state:
	// - Pending: Flow is being processed
	// - Active: Flow rules are applied and enforced
	// - Failed: Flow application encountered errors
	Phase Phase `json:"phase,omitempty"`

	// +optional

	// FilterRuleCount shows how many NFTables filter rules were generated.
	// This may be higher than the number of flows if selectors expand to multiple IPs.
	FilterRuleCount int32 `json:"filterRuleCount,omitempty"`

	// +optional

	// NATRuleCount shows how many NFTables NAT rules were generated.
	// Only flows with transform configured contribute to this count.
	NATRuleCount int32 `json:"natRuleCount,omitempty"`

	// +optional

	// ChainAssignments shows which NFTables chains each flow was assigned to.
	// Useful for understanding the packet processing path and debugging.
	// Each entry corresponds to one flow in the spec.
	ChainAssignments []ChainAssignment `json:"chainAssignments,omitempty"`

	// +optional

	// AppliedTo lists all entities (pods, peers, services) affected by this flow.
	// Shows the result of selector expansion for troubleshooting.
	// Includes resolved IP addresses for each entity.
	AppliedTo []AppliedEntity `json:"appliedTo,omitempty"`

	// +optional

	// Warnings contains non-fatal issues encountered during flow processing.
	// Examples:
	// - Selector matched no resources
	// - WireGuard reference not found (non-blocking)
	// - Interface not found (falls back to default)
	Warnings []string `json:"warnings,omitempty"`

	// +optional

	// Conditions provide detailed status information:
	// - Ready: Flow is successfully applied
	// - SelectorResolved: All selectors resolved to IPs
	// - RulesGenerated: NFTables rules created successfully
	// - Applied: Rules are active in the kernel
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=wgflow
// +kubebuilder:selectablefield:JSONPath=`.spec.wireguardRef.name`
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Filter Rules",type="integer",JSONPath=".status.filterRuleCount"
// +kubebuilder:printcolumn:name="NAT Rules",type="integer",JSONPath=".status.natRuleCount"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// WireGuardTrafficFlow is the Schema for unified traffic flow configuration.
//
// Examples:
// - DNS server: to.self + interfaces=["wg0"]
// - Multus routing: from.interfaces=["net1"] to.interfaces=["wg0"] + masquerade
// - Port forwarding: DNAT with explicit target
type WireGuardTrafficFlow struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WireGuardTrafficFlowSpec   `json:"spec,omitempty"`
	Status WireGuardTrafficFlowStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WireGuardTrafficFlowList contains a list of WireGuardTrafficFlow.
type WireGuardTrafficFlowList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WireGuardTrafficFlow `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WireGuardTrafficFlow{}, &WireGuardTrafficFlowList{})
}
