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
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WireGuardSpec defines the desired state of WireGuard server.
// A WireGuard server manages a secure VPN tunnel interface and its associated peers.
type WireGuardSpec struct {
	// +optional
	// +kubebuilder:default="wg0"

	// Interface specifies the WireGuard network interface name.
	// This interface will be created in the controller pod's network namespace.
	// Must be a valid Linux interface name (max 15 characters).
	// Once set, this field is immutable to prevent configuration drift.
	Interface InterfaceName `json:"interface,omitempty"`

	// Endpoint is the discovered or configured external endpoint.
	// Format: "<ip-or-hostname>:<port>"
	// Example: "203.0.113.1:51820" or "vpn.example.com:51820"
	// Populated from Service LoadBalancer or spec.endpoint if manually configured.
	Endpoint string `json:"endpoint,omitempty"`

	// +optional
	// +kubebuilder:default=51820

	// ListenPort specifies the UDP port WireGuard will listen on for incoming connections.
	// Peers must connect to this port to establish the VPN tunnel.
	// Common values: 51820 (default)
	ListenPort Port `json:"listenPort,omitempty"`

	// Addresses defines the IP addresses assigned to the WireGuard interface.
	// These addresses become the tunnel endpoints for this WireGuard instance.
	// Examples:
	// - "10.219.3.1/24" for IPv4 VPN network
	// - "fd00::1/64" for IPv6 VPN network
	// Multiple addresses can be specified for dual-stack configurations.
	Addresses InterfaceAddresses `json:"addresses"`

	// +optional
	// +kubebuilder:validation:MaxItems=10
	// +listType=set

	// Dns specifies DNS configuration to be pushed to WireGuard peers.
	// Can contain:
	// - DNS server IPs: "8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"
	// - Search domains: "example.com", "internal.local"
	// This configuration is included in peer config files for client setup.
	Dns []string `json:"dns,omitempty"`

	// +optional

	// Mtu sets the Maximum Transmission Unit for the WireGuard interface.
	// Lower MTU can help with networks that have overhead (e.g., PPPoE).
	// Common values:
	// - 1420: Default for WireGuard (1500 - 80 bytes overhead)
	// - 1380: Conservative for problematic networks
	// - 1280: Minimum for IPv6 compatibility
	Mtu MTU `json:"mtu,omitempty"`

	// +optional

	// PrivateKeySecret references an existing secret containing the WireGuard private key.
	// If not specified, the operator will auto-generate a new key pair and store it in a secret.
	// The secret must contain the base64-encoded private key in the specified key field.
	// Auto-generated secrets are named: "<wireguard-name>-private-key"
	PrivateKeySecret *PrivateKeySecretRef `json:"privateKeySecret,omitempty"`

	// +optional

	// Service configures how the WireGuard endpoint is exposed.
	// Defaults to LoadBalancer type for external access.
	// The service exposes the WireGuard UDP port for peer connections.
	Service *ServiceSpec `json:"service,omitempty"`

	// +optional

	// PeerSelector enables automatic peer discovery and management.
	// WireGuardPeer resources matching these labels will be automatically
	// configured as peers for this WireGuard instance.
	// If not specified, peers must reference this WireGuard explicitly.
	PeerSelector *metav1.LabelSelector `json:"peerSelector,omitempty"`

	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295

	// FwMark sets the firewall mark for outgoing WireGuard packets.
	// Used for policy-based routing to prevent routing loops.
	// The mark allows iptables/nftables rules to identify WireGuard traffic.
	// Common use: Exclude WireGuard packets from being routed back through the tunnel.
	// Example: FwMark=51820 with "ip rule add fwmark 51820 table 51820"
	FwMark *int32 `json:"fwMark,omitempty"`

	// +optional
	// +kubebuilder:validation:Enum=debug;info;warn;error
	// +kubebuilder:default=info

	// LogLevel sets the logging verbosity for the WireGuard controller process.
	// This controls the detail level of operational logs, not packet logs.
	// Lower levels include all higher level messages:
	// - debug: Detailed debugging information
	// - info: Normal operational messages (default)
	// - warn: Warning conditions
	// - error: Error conditions only
	LogLevel string `json:"logLevel,omitempty"`

	// +optional

	// PodSpec provides complete control over the controller pod specification.
	// When set, this overrides all pod-related defaults except replica count.
	// Use cases:
	// - Add sidecar containers for monitoring or logging
	// - Mount additional volumes for scripts or configs
	// - Set resource limits, node selectors, or tolerations
	// - Configure init containers for pre-setup tasks
	// Note: The main WireGuard container name must be "wireguard-controller"
	PodSpec *corev1.PodSpec `json:"podSpec,omitempty"`

	// +optional

	// PodAnnotations allows setting custom annotations on the controller pod.
	// Common uses:
	// - Multus CNI networks: "k8s.v1.cni.cncf.io/networks"
	// - Service mesh injection: "sidecar.istio.io/inject"
	// - Cloud provider integration
	// Example: {"k8s.v1.cni.cncf.io/networks": "macvlan-conf"}
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// +optional

	// UI configures the optional web-based self-service portal
	// for peer management. When enabled, a separate UI server deployment
	// is created for managing peers through a web interface.
	// The UI runs in a separate deployment with minimal RBAC and no access
	// to the WireGuard network namespace for security isolation.
	UI *UISpec `json:"ui,omitempty"`
}

// ServiceSpec defines how the WireGuard endpoint is exposed for peer connections.
type ServiceSpec struct {
	// +optional
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	// +kubebuilder:default=LoadBalancer

	// Type determines how the service is exposed:
	// - ClusterIP: Internal cluster access only
	// - NodePort: Accessible via node IP and static port
	// - LoadBalancer: External load balancer (recommended for production)
	Type corev1.ServiceType `json:"type,omitempty"`

	// +optional

	// Annotations to add to the service resource.
	// Common uses:
	// - Cloud provider load balancer configuration
	// - External DNS integration
	// - Service mesh configuration
	// Example: "service.beta.kubernetes.io/aws-load-balancer-type: "nlb""
	Annotations map[string]string `json:"annotations,omitempty"`

	// +optional

	// ExternalTrafficPolicy denotes if this Service desires to route external
	// traffic to node-local or cluster-wide endpoints.
	ExternalTrafficPolicy corev1.ServiceExternalTrafficPolicy `json:"externalTrafficPolicy,omitempty"`

	// +optional

	// IPFamilies is a list of IP families (e.g. IPv4, IPv6) assigned to this
	// service. This field is usually assigned automatically based on cluster
	// configuration and the ipFamilyPolicy field.
	IPFamilies []corev1.IPFamily `json:"ipFamilies,omitempty"`

	// +optional

	// IPFamilyPolicy represents the dual-stack-ness requested or required by
	// this Service. If there is no value provided, then this field will be set
	// to SingleStack. Services can be "SingleStack" (a single IP family),
	// "PreferDualStack" (two IP families on dual-stack configured clusters or
	// a single IP family on single-stack clusters), or "RequireDualStack"
	// (two IP families on dual-stack configured clusters, otherwise fail).
	IPFamilyPolicy *corev1.IPFamilyPolicy `json:"ipFamilyPolicy,omitempty"`

	// +optional

	// InternalTrafficPolicy denotes if this Service desires to route internal
	// traffic to node-local or cluster-wide endpoints.
	InternalTrafficPolicy *corev1.ServiceInternalTrafficPolicy `json:"internalTrafficPolicy,omitempty"`
}

// UISpec configures the self-service web UI for peer management.
// The UI server runs as a separate deployment with minimal RBAC permissions
// and no access to the WireGuard network namespace.
type UISpec struct {
	// +optional
	// +kubebuilder:default=true

	// Enabled controls whether the UI server deployment is created.
	// When false, any existing UI deployment will be deleted.
	Enabled bool `json:"enabled,omitempty"`

	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1

	// Replicas specifies the number of UI server replicas.
	// Multiple replicas can be used for high availability.
	// Default: 1
	Replicas *int32 `json:"replicas,omitempty"`

	// +optional
	// +kubebuilder:default=8080
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=65535

	// Port is the HTTP port the UI server listens on.
	// This port is exposed via the UI Service.
	// Default: 8080
	Port int32 `json:"port,omitempty"`

	// +optional

	// Resources defines resource requirements for the UI container.
	// Recommended: 100m CPU / 128Mi Memory
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// +optional

	// NodeSelector constrains UI pods to nodes with specific labels.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// +optional

	// Tolerations allows UI pods to schedule on tainted nodes.
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// +optional

	// Affinity defines scheduling constraints for UI pods.
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// +optional

	// Service configures how the UI is exposed.
	Service *UIServiceSpec `json:"service,omitempty"`

	// +optional

	// Ingress configures external HTTPS access to the UI.
	Ingress *UIIngressSpec `json:"ingress,omitempty"`

	// +optional

	// Annotations to add to the UI deployment.
	Annotations map[string]string `json:"annotations,omitempty"`

	// +optional

	// PodAnnotations to add to the UI pods.
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// +optional

	// Auth configures OIDC/OAuth2 authentication for the UI.
	// When enabled, users must authenticate via an OIDC provider (e.g., Keycloak)
	// before accessing the management interface. Supports role-based access control
	// with expression-based group-to-role mapping.
	Auth *AuthSpec `json:"auth,omitempty"`
}

// UIServiceSpec configures the Kubernetes Service for UI access.
type UIServiceSpec struct {
	// +optional
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	// +kubebuilder:default=ClusterIP

	// Type determines how the UI service is exposed:
	// - ClusterIP: Internal cluster access only (use with Ingress)
	// - NodePort: Accessible via node IP and static port
	// - LoadBalancer: External load balancer (creates public IP)
	// Default: ClusterIP (recommended with Ingress)
	Type corev1.ServiceType `json:"type,omitempty"`

	// +optional

	// Annotations to add to the UI service resource.
	// Common uses:
	// - Cloud provider load balancer configuration
	// - External DNS integration
	// Example: "service.beta.kubernetes.io/aws-load-balancer-type: nlb"
	Annotations map[string]string `json:"annotations,omitempty"`

	// +optional
	// +kubebuilder:validation:Minimum=30000
	// +kubebuilder:validation:Maximum=32767

	// NodePort specifies the static node port for NodePort service type.
	// If not specified, Kubernetes assigns a random port.
	NodePort *int32 `json:"nodePort,omitempty"`
}

// UIIngressSpec configures Ingress for HTTPS access to the UI.
type UIIngressSpec struct {
	// +optional
	// +kubebuilder:default=true

	// Enabled controls whether an Ingress resource is created.
	// When true, the UI is accessible via HTTPS through the specified hostname.
	// Requires an Ingress controller in the cluster.
	Enabled bool `json:"enabled,omitempty"`

	// +optional

	// Host is the DNS hostname for the UI.
	// Example: "wg-ui.example.com"
	// Required when ingress is enabled.
	Host string `json:"host,omitempty"`

	// +optional

	// IngressClassName specifies which Ingress controller to use.
	// Examples: "nginx", "traefik", "haproxy"
	IngressClassName *string `json:"ingressClassName,omitempty"`

	// +optional

	// Annotations for the Ingress resource.
	// Common uses:
	// - TLS/SSL configuration: cert-manager.io/cluster-issuer
	// - Authentication: nginx.ingress.kubernetes.io/auth-url
	// - Rate limiting: nginx.ingress.kubernetes.io/limit-rps
	// Example:
	//   cert-manager.io/cluster-issuer: "letsencrypt-prod"
	//   nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
	Annotations map[string]string `json:"annotations,omitempty"`

	// +optional

	// TLS configuration for HTTPS.
	// The secret must contain tls.crt and tls.key.
	// Can be managed by cert-manager via annotations.
	TLS []networkingv1.IngressTLS `json:"tls,omitempty"`
}

// WireGuardStatus represents the current state of the WireGuard instance.
type WireGuardStatus struct {
	// +optional

	// Phase indicates the current lifecycle phase of the WireGuard server:
	// - Pending: Resources are being created
	// - Running: WireGuard is active and accepting connections
	// - Failed: Configuration or deployment error occurred
	Phase Phase `json:"phase,omitempty"`

	// +optional

	// PublicKey is the WireGuard public key derived from the private key.
	// Peers need this key to establish secure connections.
	// Format: Base64-encoded 32-byte key
	PublicKey string `json:"publicKey,omitempty"`

	// +optional

	// Endpoint is the discovered or configured external endpoint.
	// Format: "<ip-or-hostname>:<port>"
	// Example: "203.0.113.1:51820" or "vpn.example.com:51820"
	// Populated from Service LoadBalancer or spec.endpoint if manually configured.
	Endpoint string `json:"endpoint,omitempty"`

	// +optional

	// PrivateKeySecretName identifies the secret containing the private key.
	// This secret is either user-provided or auto-generated by the operator.
	PrivateKeySecretName string `json:"privateKeySecretName"`

	// +optional

	// PrivateKeySecretKey specifies which key in the secret contains the private key.
	// Default is "privateKey" for auto-generated secrets.
	PrivateKeySecretKey string `json:"privateKeySecretKey"`

	// +optional

	// UIEndpoint is the URL where the UI is accessible.
	// Populated from Ingress host or Service LoadBalancer IP.
	// Examples:
	// - "https://wg-ui.example.com" (Ingress)
	// - "http://203.0.113.1:8080" (LoadBalancer)
	// - "http://10.96.0.1:8080" (ClusterIP - internal only)
	UIEndpoint string `json:"uiEndpoint,omitempty"`

	// +optional

	// Conditions provide detailed status information about the WireGuard resource.
	// Standard conditions include:
	// - Ready: Overall resource readiness
	// - SecretReady: Private key secret exists and is valid
	// - ServiceReady: Service is created and has endpoint
	// - DeploymentReady: Controller pod is running
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=wg
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Endpoint",type="string",JSONPath=".status.endpoint"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// WireGuard is the Schema for the wireguards API.
type WireGuard struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WireGuardSpec   `json:"spec,omitempty"`
	Status WireGuardStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WireGuardList contains a list of WireGuard.
type WireGuardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WireGuard `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WireGuard{}, &WireGuardList{})
}
