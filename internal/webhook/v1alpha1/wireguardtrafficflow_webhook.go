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
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wireguardoperatoriov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var wireguardtrafficflowlog = logf.Log.WithName("wireguardtrafficflow-resource")

// SetupWireGuardTrafficFlowWebhookWithManager registers the webhook for WireGuardTrafficFlow in the manager.
func SetupWireGuardTrafficFlowWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&wireguardoperatoriov1alpha1.WireGuardTrafficFlow{}).
		WithValidator(&WireGuardTrafficFlowCustomValidator{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-wireguard-operator-io-v1alpha1-wireguardtrafficflow,mutating=false,failurePolicy=fail,sideEffects=None,groups=wireguard-operator.io,resources=wireguardtrafficflows,verbs=create;update,versions=v1alpha1,name=vwireguardtrafficflow-v1alpha1.kb.io,admissionReviewVersions=v1

// WireGuardTrafficFlowCustomValidator struct is responsible for validating the WireGuardTrafficFlow resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type WireGuardTrafficFlowCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &WireGuardTrafficFlowCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type WireGuardTrafficFlow.
func (v *WireGuardTrafficFlowCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	wireguardtrafficflow, ok := obj.(*wireguardoperatoriov1alpha1.WireGuardTrafficFlow)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuardTrafficFlow object but got %T", obj)
	}
	wireguardtrafficflowlog.Info("Validation for WireGuardTrafficFlow upon creation", "name", wireguardtrafficflow.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type WireGuardTrafficFlow.
func (v *WireGuardTrafficFlowCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	wireguardtrafficflow, ok := newObj.(*wireguardoperatoriov1alpha1.WireGuardTrafficFlow)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuardTrafficFlow object for the newObj but got %T", newObj)
	}
	wireguardtrafficflowlog.Info("Validation for WireGuardTrafficFlow upon update", "name", wireguardtrafficflow.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type WireGuardTrafficFlow.
func (v *WireGuardTrafficFlowCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	wireguardtrafficflow, ok := obj.(*wireguardoperatoriov1alpha1.WireGuardTrafficFlow)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuardTrafficFlow object but got %T", obj)
	}
	wireguardtrafficflowlog.Info("Validation for WireGuardTrafficFlow upon deletion", "name", wireguardtrafficflow.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
