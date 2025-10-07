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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:XValidation:rule="!self.enabled || (has(self.oidc) != has(self.basicAuth))",message="exactly one of oidc or basicAuth must be set when auth is enabled"

// AuthSpec configures authentication for the UI.
// Supports three modes:
// - Disabled: auth.enabled=false or auth not specified
// - OIDC: auth.enabled=true with auth.oidc configured
// - BasicAuth: auth.enabled=true with auth.basicAuth configured (for reverse proxy auth)
type AuthSpec struct {
	// +optional
	// +kubebuilder:default=false

	// Enabled controls whether authentication is required.
	// When false, the UI is publicly accessible (not recommended for production).
	// When true, either oidc or basicAuth must be configured.
	Enabled bool `json:"enabled,omitempty"`

	// +optional

	// OIDC configures OpenID Connect authentication (e.g., Keycloak, Auth0).
	// When set, users authenticate via OAuth2/OIDC flow.
	// Mutually exclusive with basicAuth.
	OIDC *OIDCAuthSpec `json:"oidc,omitempty"`

	// +optional

	// BasicAuth configures header-based authentication via reverse proxy.
	// The reverse proxy (e.g., nginx with auth_request) handles authentication
	// and forwards user information via HTTP headers.
	// Mutually exclusive with oidc.
	BasicAuth *BasicAuthSpec `json:"basicAuth,omitempty"`

	// +optional

	// RoleMappings define how user groups are mapped to application roles with permissions.
	// Each mapping evaluates an expression against user claims to assign roles.
	// Expressions are evaluated using expr-lang syntax.
	// Multiple roles can be assigned if multiple expressions match.
	// Applies to both OIDC and BasicAuth modes.
	RoleMappings []RoleMapping `json:"roleMappings,omitempty"`
}

// OIDCAuthSpec configures OpenID Connect authentication.
type OIDCAuthSpec struct {
	// +kubebuilder:validation:Required

	// IssuerURL is the OIDC provider's issuer URL.
	// For Keycloak: https://keycloak.example.com/realms/{realm-name}
	// This URL is used for OIDC discovery (.well-known/openid-configuration)
	IssuerURL string `json:"issuerURL"`

	// +kubebuilder:validation:Required

	// ClientID is the OAuth2 client identifier registered with the OIDC provider.
	// This must match the client configuration in your OIDC provider.
	ClientID string `json:"clientID"`

	// +kubebuilder:validation:Required

	// ClientSecret references a Kubernetes Secret containing the OAuth2 client secret.
	// The secret must exist in the same namespace as the WireGuard resource.
	// Example: kubectl create secret generic wg-oidc-secret --from-literal=clientSecret=<secret>
	ClientSecret *SecretRef `json:"clientSecret"`

	// +kubebuilder:validation:Required

	// RedirectURL is the OAuth2 callback URL where users are redirected after authentication.
	// Must match one of the redirect URIs configured in the OIDC provider.
	// Format: https://{ui-host}/api/v1/auth/callback
	RedirectURL string `json:"redirectURL"`

	// +kubebuilder:validation:Required

	// JWTSecret references a Kubernetes Secret containing the key for signing session JWTs.
	// The JWT is stored in an HTTP-only cookie for stateless session management.
	// Example: kubectl create secret generic wg-jwt-secret --from-literal=secret=$(openssl rand -base64 32)
	JWTSecret *SecretRef `json:"jwtSecret"`

	// +optional
	// +kubebuilder:default="groups"

	// GroupsClaim specifies the OIDC claim name that contains user group memberships.
	// This claim is used for role mapping via expressions.
	// Common values: "groups", "roles", "memberOf"
	// Default: "groups"
	GroupsClaim string `json:"groupsClaim,omitempty"`

	// +optional

	// SessionMaxAge defines how long a session JWT remains valid.
	// After this duration, users must re-authenticate.
	// Format: Go duration string (e.g., "15m", "1h", "24h")
	// Default: 15 minutes
	// Recommended: 15m-1h for security, longer for convenience
	SessionMaxAge *metav1.Duration `json:"sessionMaxAge,omitempty"`

	// +optional

	// Scopes specifies additional OAuth2 scopes to request beyond "openid" and "profile".
	// Common scopes: "email", "groups", "offline_access"
	// Default: ["openid", "profile", "email", "groups"]
	Scopes []string `json:"scopes,omitempty"`
}

// BasicAuthSpec configures header-based authentication via reverse proxy.
// The reverse proxy (e.g., nginx with auth_request or auth_basic) authenticates
// users and forwards identity information via HTTP headers.
type BasicAuthSpec struct {
	// +optional
	// +kubebuilder:default="X-Forwarded-User"

	// UserHeader specifies the HTTP header containing the authenticated username.
	// Default: X-Forwarded-User
	UserHeader string `json:"userHeader,omitempty"`

	// +optional
	// +kubebuilder:default="X-Forwarded-Email"

	// EmailHeader specifies the HTTP header containing the user's email address.
	// Default: X-Forwarded-Email
	EmailHeader string `json:"emailHeader,omitempty"`

	// +optional
	// +kubebuilder:default="X-Forwarded-Groups"

	// GroupsHeader specifies the HTTP header containing comma-separated group memberships.
	// Used for role mapping via expressions.
	// Default: X-Forwarded-Groups
	// Example: "admin,users,developers"
	GroupsHeader string `json:"groupsHeader,omitempty"`
}

// RoleMapping defines how OIDC groups/claims are mapped to application roles.
// Uses expression-based evaluation for flexible role assignment.
type RoleMapping struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1

	// Role is the application role name assigned when the expression evaluates to true.
	// Examples: "Admin", "PeerManager", "Viewer"
	Role string `json:"role"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1

	// Expression is evaluated to determine if this role should be assigned.
	// Available context variables:
	// - groups ([]string): User's OIDC groups from groupsClaim
	// - email (string): User's email address
	// - authenticated (bool): Always true for authenticated users
	//
	// Expression syntax (expr-lang):
	// - contains(groups, "GroupName"): Check if user is in group
	// - groups contains "GroupName": Alternative syntax
	// - authenticated: Match all authenticated users
	// - email endsWith "@example.com": Match by email domain
	//
	// Examples:
	// - 'contains(groups, "WireGuard-Admins")'
	// - 'groups contains "Admins" || email == "admin@example.com"'
	// - 'authenticated' (matches all authenticated users)
	Expression string `json:"expression"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=set

	// Permissions lists the permissions granted to this role.
	// Permissions follow the format: "resource:action"
	// Wildcard "*" can be used for all actions on a resource.
	//
	// Available permissions:
	// - "peer:read-all": View peer list and details
	// - "peer:read-self": View peer list and details
	// - "peer:create": Create new peers
	// - "peer:delete": Delete existing peers
	//
	// Examples:
	// - ["peer:*", "flow:read"]: Full peer access, read-only flows
	// - ["peer:read", "flow:read"]: Read-only access
	Permissions []string `json:"permissions"`
}
