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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
	"github.com/wireguard-operator/wireguard-operator/internal/webhook/validation"
)

// log is for logging in this package.
var wireguardlog = logf.Log.WithName("wireguard-resource")

// SetupWireGuardWebhookWithManager registers the webhook for WireGuard in the manager.
func SetupWireGuardWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&wgov1alpha1.WireGuard{}).
		WithValidator(&WireGuardCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-wireguard-operator-io-v1alpha1-wireguard,mutating=false,failurePolicy=fail,sideEffects=None,groups=wireguard-operator.io,resources=wireguards,verbs=create;update,versions=v1alpha1,name=vwireguard-v1alpha1.kb.io,admissionReviewVersions=v1
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get

// WireGuardCustomValidator struct is responsible for validating the WireGuard resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type WireGuardCustomValidator struct{}

var _ webhook.CustomValidator = &WireGuardCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type WireGuard.
func (v *WireGuardCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	wireguard, ok := obj.(*wgov1alpha1.WireGuard)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuard object but got %T", obj)
	}
	wireguardlog.Info("Validation for WireGuard upon creation", "name", wireguard.GetName())

	return nil, validation.ValidateInterfaceAddresses(wireguard.Spec.Addresses)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type WireGuard.
func (v *WireGuardCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldWireGuard, ok := oldObj.(*wgov1alpha1.WireGuard)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuard object for the oldObj but got %T", oldObj)
	}

	newWireGuard, ok := newObj.(*wgov1alpha1.WireGuard)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuard object for the newObj but got %T", newObj)
	}

	wireguardlog.Info("Validation for WireGuard upon update", "name", newWireGuard.GetName())

	var warnings admission.Warnings

	warnings, err := v.ValidateCreate(ctx, newObj)
	if err != nil {
		return warnings, err
	}

	// Check if PrivateKeySecret is being changed after it was already established
	// If status has a secret name, the secret is already in use and cannot be changed
	if oldWireGuard.Status.PrivateKeySecretName != "" {
		// Determine what the new secret name would be
		var newSecretName string
		if newWireGuard.Spec.PrivateKeySecret != nil && newWireGuard.Spec.PrivateKeySecret.Name != "" {
			newSecretName = newWireGuard.Spec.PrivateKeySecret.Name
		} else {
			// Would be auto-generated - use the pattern from controller
			newSecretName = fmt.Sprintf("%s-privatekey", newWireGuard.Name)
		}

		// If the established secret name differs from what would be used, reject the change
		if oldWireGuard.Status.PrivateKeySecretName != newSecretName {
			return warnings, fmt.Errorf("privateKeySecret cannot be changed after secret has been created (current: %s)",
				oldWireGuard.Status.PrivateKeySecretName)
		}
	}

	// Warn about port changes
	if int32(oldWireGuard.Spec.ListenPort) != int32(newWireGuard.Spec.ListenPort) {
		warnings = append(warnings, fmt.Sprintf("Changing listen port from %d to %d will require updating all peer configurations",
			oldWireGuard.Spec.ListenPort, newWireGuard.Spec.ListenPort))
	}

	return warnings, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type WireGuard.
func (v *WireGuardCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}
