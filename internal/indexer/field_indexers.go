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

package indexer

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
)

// WireGuardRef is the field index name for the WireGuard reference, defined as a constant to avoid typos.
const WireGuardRef = "spec.wireguardRef.name"

// SetupFieldIndexers registers all field indexers for the WireGuard CRDs.
// This centralizes index registration for both operator and controller modes.
func SetupFieldIndexers(ctx context.Context, mgr manager.Manager) error {
	types := []client.Object{
		&wgov1alpha1.WireGuardPeer{},
		&wgov1alpha1.WireGuardTrafficFlow{},
	}

	for _, obj := range types {
		if err := mgr.GetFieldIndexer().IndexField(
			ctx,
			obj,
			WireGuardRef,
			func(obj client.Object) []string {
				refHolder, ok := obj.(wgov1alpha1.WireGuardRefHolder)
				if !ok {
					return nil
				}
				name := refHolder.GetWireGuardRef().Name
				if name == "" {
					return nil
				}
				return []string{name}
			},
		); err != nil {
			return err
		}
	}

	return nil
}

// ListOptionsByWireGuardRef creates client.ListOptions for querying resources by WireGuard reference
func ListOptionsByWireGuardRef(namespace, wireguardName string) []client.ListOption {
	return []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingFields{WireGuardRef: wireguardName},
	}
}
