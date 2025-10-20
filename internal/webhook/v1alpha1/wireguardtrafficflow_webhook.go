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
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
	"github.com/wireguard-operator/wireguard-operator/internal/webhook/validation"
)

// log is for logging in this package.
var wireguardtrafficflowlog = logf.Log.WithName("wireguardtrafficflow-resource")

// SetupWireGuardTrafficFlowWebhookWithManager registers the webhook for WireGuardTrafficFlow in the manager.
func SetupWireGuardTrafficFlowWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&wgov1alpha1.WireGuardTrafficFlow{}).
		WithValidator(&WireGuardTrafficFlowCustomValidator{
			Client: mgr.GetClient(),
		}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-wireguard-operator-io-v1alpha1-wireguardtrafficflow,mutating=false,failurePolicy=fail,sideEffects=None,groups=wireguard-operator.io,resources=wireguardtrafficflows,verbs=create;update,versions=v1alpha1,name=vwireguardtrafficflow-v1alpha1.kb.io,admissionReviewVersions=v1

// WireGuardTrafficFlowCustomValidator struct is responsible for validating the WireGuardTrafficFlow resource
// when it is created, updated, or deleted.
type WireGuardTrafficFlowCustomValidator struct {
	Client client.Client
}

var _ webhook.CustomValidator = &WireGuardTrafficFlowCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type WireGuardTrafficFlow.
func (v *WireGuardTrafficFlowCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	flow, ok := obj.(*wgov1alpha1.WireGuardTrafficFlow)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuardTrafficFlow object but got %T", obj)
	}
	wireguardtrafficflowlog.Info("Validation for WireGuardTrafficFlow upon creation", "name", flow.GetName())

	return v.validateWireGuardTrafficFlow(ctx, flow)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type WireGuardTrafficFlow.
func (v *WireGuardTrafficFlowCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	_, ok := oldObj.(*wgov1alpha1.WireGuardTrafficFlow)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuardTrafficFlow object for the oldObj but got %T", oldObj)
	}

	newFlow, ok := newObj.(*wgov1alpha1.WireGuardTrafficFlow)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuardTrafficFlow object for the newObj but got %T", newObj)
	}
	wireguardtrafficflowlog.Info("Validation for WireGuardTrafficFlow upon update", "name", newFlow.GetName())

	return v.ValidateCreate(ctx, newFlow)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type WireGuardTrafficFlow.
func (v *WireGuardTrafficFlowCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// validateWireGuardTrafficFlow performs comprehensive validation of WireGuardTrafficFlow
func (v *WireGuardTrafficFlowCustomValidator) validateWireGuardTrafficFlow(ctx context.Context, flow *wgov1alpha1.WireGuardTrafficFlow) (admission.Warnings, error) {
	// Validate that the referenced WireGuard resource exists
	warnings, err := validation.ValidateWireGuardRef(ctx, v.Client, flow, flow.Namespace)
	if err != nil {
		return warnings, err
	}

	var allErrors []string

	flowNames := make(map[string]bool)

	// Validate each flow rule
	for i, flowRule := range flow.Spec.Flows {
		// Check duplicate names
		if flowNames[flowRule.Name] {
			allErrors = append(allErrors, fmt.Sprintf("duplicate flow name: %s", flowRule.Name))
		}
		flowNames[flowRule.Name] = true

		// Validate flow rule
		if err := v.validateFlowRule(&flowRule); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("flow[%d]: %v", i, err))
		}

		if err := v.validateTrafficSelector(flowRule.From); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("flow[%d].from: %v", i, err))
		}

		if err := v.validateTrafficSelector(flowRule.To); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("flow[%d].to: %v", i, err))
		}

		if err := v.validateTransform(&flowRule); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("flow[%d].transform: %v", i, err))
		}

		if err := v.validateFilter(flowRule.Filter); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("flow[%d].filter: %v", i, err))
		}

		if err := v.validateProtocolPortConsistency(&flowRule); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("flow[%d]: %v", i, err))
		}

		if err := v.validateIPFamilyConsistency(&flowRule); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("flow[%d]: %v", i, err))
		}
	}

	// Combine all errors
	if len(allErrors) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(allErrors, "; "))
	}

	return warnings, nil
}

// validateFlowRule validates a single flow rule for consistency
func (v *WireGuardTrafficFlowCustomValidator) validateFlowRule(flow *wgov1alpha1.FlowRule) error {
	// Protocol and IP Family consistency is already covered by CEL validations
	// This is just an additional safety check

	// ICMP validation
	if flow.Protocol == wgov1alpha1.ProtocolICMP && flow.IPFamily == wgov1alpha1.IPFamilyIPv6 {
		return fmt.Errorf("ICMP protocol requires ipFamily: IPv4")
	}

	// ICMPv6 validation
	if flow.Protocol == wgov1alpha1.ProtocolICMPv6 && flow.IPFamily == wgov1alpha1.IPFamilyIPv4 {
		return fmt.Errorf("ICMPv6 protocol requires ipFamily: IPv6")
	}

	return nil
}

// validateTrafficSelector validates a traffic selector
func (v *WireGuardTrafficFlowCustomValidator) validateTrafficSelector(selector *wgov1alpha1.FlowTrafficSelector) error {
	if selector == nil {
		return nil
	}

	selectorCount := 0
	if len(selector.IPBlocks) > 0 {
		selectorCount++
	}
	if selector.PodSelector != nil {
		selectorCount++
	}
	if selector.PeerSelector != nil {
		selectorCount++
	}
	if selector.ServiceSelector != nil {
		selectorCount++
	}

	if selector.Self && selectorCount > 0 {
		return fmt.Errorf("when self is true, cannot specify ipBlocks, podSelector, peerSelector, or serviceSelector")
	}

	if selectorCount > 1 {
		return fmt.Errorf("specify at most one of ipBlocks, podSelector, peerSelector, or serviceSelector")
	}

	if selector.MultusNetwork != "" && selector.PodSelector == nil {
		return fmt.Errorf("multusNetwork requires podSelector to be specified")
	}

	return validation.ValidatePorts(selector.Ports)
}

// validateTransform validates NAT transformation configuration
func (v *WireGuardTrafficFlowCustomValidator) validateTransform(flow *wgov1alpha1.FlowRule) error {
	if flow.Transform == nil {
		return nil
	}

	transform := flow.Transform

	switch transform.Type {
	case wgov1alpha1.TransformTypeDNAT:
		if transform.Target == "" {
			return fmt.Errorf("DNAT requires transform.target to be specified")
		}

		if (flow.To != nil && flow.To.Self) || (flow.From != nil && flow.From.Self) {
			return fmt.Errorf("DNAT cannot be used with to.self or from.self (DNAT happens in PREROUTING before routing decision)")
		}

	case wgov1alpha1.TransformTypeMasquerade:
		// Masquerade requires interface (explicit or from to.interfaces[0])
		hasExplicitInterface := transform.Interface != ""
		hasToInterfaces := flow.To != nil && len(flow.To.Interfaces) > 0

		if !hasExplicitInterface && !hasToInterfaces {
			return fmt.Errorf("%s requires transform.interface or to.interfaces[0] to be specified", wgov1alpha1.TransformTypeMasquerade)
		}

		// Masquerade cannot be used with from.self (CEL validation backup)
		if flow.From != nil && flow.From.Self {
			return fmt.Errorf("%s cannot be used with from.self (OUTPUT chain conflicts with POSTROUTING)", wgov1alpha1.TransformTypeMasquerade)
		}

	default:
		return fmt.Errorf("unknown transform type: %s", transform.Type)
	}

	return nil
}

// validateFilter validates filter action configuration
func (v *WireGuardTrafficFlowCustomValidator) validateFilter(filter *wgov1alpha1.FilterAction) error {
	if filter == nil {
		return nil
	}

	// Rate limit only valid with Allow action (CEL validation backup)
	if filter.RateLimit != nil && filter.Action != wgov1alpha1.PolicyActionAllow {
		return fmt.Errorf("rateLimit is only supported with filter.action=Allow")
	}

	return nil
}

// validateIPFamilyConsistency validates that IP addresses in selectors match the flow's ipFamily
func (v *WireGuardTrafficFlowCustomValidator) validateIPFamilyConsistency(flow *wgov1alpha1.FlowRule) error {
	if flow.From != nil && len(flow.From.IPBlocks) > 0 {
		if _, err := validation.ParseAndValidateIPBlocks(flow.From.IPBlocks, flow.IPFamily); err != nil {
			return fmt.Errorf("from.ipBlocks: %w", err)
		}
	}

	if flow.To != nil && len(flow.To.IPBlocks) > 0 {
		if _, err := validation.ParseAndValidateIPBlocks(flow.To.IPBlocks, flow.IPFamily); err != nil {
			return fmt.Errorf("to.ipBlocks: %w", err)
		}
	}

	if err := validation.ValidateTransformTargetFamily(flow.Transform, flow.IPFamily); err != nil {
		return fmt.Errorf("transform.target: %w", err)
	}

	return nil
}

// validateProtocolPortConsistency validates protocol and port configuration consistency
func (v *WireGuardTrafficFlowCustomValidator) validateProtocolPortConsistency(flow *wgov1alpha1.FlowRule) error {
	isFromPortsEmpty := flow.From == nil || len(flow.From.Ports) == 0
	isToPortsEmpty := flow.To == nil || len(flow.To.Ports) == 0

	if isFromPortsEmpty && isToPortsEmpty {
		return nil
	}

	// Check if protocol supports ports
	switch flow.Protocol {
	case wgov1alpha1.ProtocolTCP, wgov1alpha1.ProtocolUDP, wgov1alpha1.ProtocolAny:
		// Valid protocols for port matching
	case wgov1alpha1.ProtocolICMP, wgov1alpha1.ProtocolICMPv6:
		return fmt.Errorf("ports cannot be specified with ICMP or ICMPv6 protocol")
	default:
		return fmt.Errorf("ports can only be specified with TCP, UDP, or Any protocol")
	}

	return nil
}
