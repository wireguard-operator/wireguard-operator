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

	wireguardoperatoriov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
)

// log is for logging in this package.
var wireguardlog = logf.Log.WithName("wireguard-resource")

// SetupWireGuardWebhookWithManager registers the webhook for WireGuard in the manager.
func SetupWireGuardWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&wireguardoperatoriov1alpha1.WireGuard{}).
		WithValidator(&WireGuardCustomValidator{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-wireguard-operator-io-v1alpha1-wireguard,mutating=false,failurePolicy=fail,sideEffects=None,groups=wireguard-operator.io,resources=wireguards,verbs=create;update,versions=v1alpha1,name=vwireguard-v1alpha1.kb.io,admissionReviewVersions=v1

// WireGuardCustomValidator struct is responsible for validating the WireGuard resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type WireGuardCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &WireGuardCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type WireGuard.
func (v *WireGuardCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	wireguard, ok := obj.(*wireguardoperatoriov1alpha1.WireGuard)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuard object but got %T", obj)
	}
	wireguardlog.Info("Validation for WireGuard upon creation", "name", wireguard.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type WireGuard.
func (v *WireGuardCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	wireguard, ok := newObj.(*wireguardoperatoriov1alpha1.WireGuard)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuard object for the newObj but got %T", newObj)
	}
	wireguardlog.Info("Validation for WireGuard upon update", "name", wireguard.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type WireGuard.
func (v *WireGuardCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	wireguard, ok := obj.(*wireguardoperatoriov1alpha1.WireGuard)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuard object but got %T", obj)
	}
	wireguardlog.Info("Validation for WireGuard upon deletion", "name", wireguard.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
