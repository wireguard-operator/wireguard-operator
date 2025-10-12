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
	"context"
	"fmt"

	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// ValidateWireGuardRef validates that the referenced WireGuard resource exists.
// Returns a warning if the resource is not found (NotFound error), allowing the controller to handle it.
// Returns an error for other API errors (permissions, schema issues, etc.).
func ValidateWireGuardRef(ctx context.Context, c client.Client, ref wgov1alpha1.WireGuardRefHolder, namespace string) (admission.Warnings, error) {
	var wg wgov1alpha1.WireGuard
	err := c.Get(ctx, types.NamespacedName{
		Name:      ref.GetWireGuardRef().Name,
		Namespace: namespace,
	}, &wg)

	if err != nil {
		if apierrors.IsNotFound(err) {
			return admission.Warnings{
				fmt.Sprintf("Referenced WireGuard resource '%s' not found yet. Controller will wait for it to be created.", ref.GetWireGuardRef().Name),
			}, nil
		}
		return nil, fmt.Errorf("failed to validate WireGuardRef: %w", err)
	}

	return nil, nil
}
