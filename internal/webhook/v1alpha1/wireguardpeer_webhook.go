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

	"github.com/wireguard-operator/wireguard-operator/internal/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
	"github.com/wireguard-operator/wireguard-operator/internal/indexer"
	"github.com/wireguard-operator/wireguard-operator/internal/webhook/validation"
)

// log is for logging in this package.
var wireguardpeerlog = logf.Log.WithName("wireguardpeer-resource")

// SetupWireGuardPeerWebhookWithManager registers the webhook for WireGuardPeer in the manager.
func SetupWireGuardPeerWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&wgov1alpha1.WireGuardPeer{}).
		WithValidator(&WireGuardPeerCustomValidator{
			Client: mgr.GetClient(),
		}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-wireguard-operator-io-v1alpha1-wireguardpeer,mutating=false,failurePolicy=fail,sideEffects=None,groups=wireguard-operator.io,resources=wireguardpeers,verbs=create;update,versions=v1alpha1,name=vwireguardpeer-v1alpha1.kb.io,admissionReviewVersions=v1

// +kubebuilder:rbac:groups=wireguard.denktmit.de,resources=wireguards,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get

// WireGuardPeerCustomValidator struct is responsible for validating the WireGuardPeer resource
// when it is created, updated, or deleted.
type WireGuardPeerCustomValidator struct {
	Client client.Client
}

var _ webhook.CustomValidator = &WireGuardPeerCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type WireGuardPeer.
func (v *WireGuardPeerCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	peer, ok := obj.(*wgov1alpha1.WireGuardPeer)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuardPeer object but got %T", obj)
	}
	wireguardpeerlog.Info("Validation for WireGuardPeer upon creation", "name", peer.GetName())

	// Validate that the referenced WireGuard resource exists
	warnings, err := validation.ValidateWireGuardRef(ctx, v.Client, peer, peer.Namespace)
	if err != nil {
		return warnings, err
	}

	existingPeers, err := v.loadExistingPeers(ctx, peer)
	if err != nil {
		return warnings, err
	}

	if peer.Spec.PublicKey != nil {
		if _, err := wgtypes.ParseKey(*peer.Spec.PublicKey); err != nil {
			return warnings, fmt.Errorf("invalid PublicKey: %w", err)
		}

		for _, existing := range existingPeers {
			if existing.Spec.PublicKey != nil && *existing.Spec.PublicKey == *peer.Spec.PublicKey {
				return warnings, fmt.Errorf("PublicKey already in use by peer %s/%s", existing.Namespace, existing.Name)
			}
		}
	}

	parsedIPs, err := validation.ParseAndValidateIPBlocks(peer.Spec.AllowedIPs, "")
	if err != nil {
		return warnings, fmt.Errorf("allowedIPs: %w", err)
	}

	if err = utils.CheckPeerIPOverlapParsed(parsedIPs, existingPeers); err != nil {
		return warnings, fmt.Errorf("IP overlap detected: %w", err)
	}

	if err = validation.ValidateEndpoint(peer.Spec.Endpoint); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type WireGuardPeer.
func (v *WireGuardPeerCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldPeer, ok := oldObj.(*wgov1alpha1.WireGuardPeer)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuardPeer object for the oldObj but got %T", oldObj)
	}

	newPeer, ok := newObj.(*wgov1alpha1.WireGuardPeer)
	if !ok {
		return nil, fmt.Errorf("expected a WireGuardPeer object for the newObj but got %T", newObj)
	}

	wireguardpeerlog.Info("Validation for WireGuardPeer upon update", "name", newPeer.GetName())

	warnings, err := v.ValidateCreate(ctx, newObj)
	if err != nil {
		return warnings, err
	}

	if !validation.CompareIPNets(oldPeer.Spec.AllowedIPs, newPeer.Spec.AllowedIPs) {
		warnings = append(warnings, "Changing AllowedIPs will update routing rules")
	}

	return warnings, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type WireGuardPeer.
func (v *WireGuardPeerCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// loadExistingPeers loads all peers for the same WireGuard instance
func (v *WireGuardPeerCustomValidator) loadExistingPeers(ctx context.Context, peer *wgov1alpha1.WireGuardPeer) ([]wgov1alpha1.WireGuardPeer, error) {
	listOpts := indexer.ListOptionsByWireGuardRef(peer.Namespace, peer.Spec.WireGuardRef.Name)

	peerList := &wgov1alpha1.WireGuardPeerList{}
	if err := v.Client.List(ctx, peerList, listOpts...); err != nil {
		return nil, fmt.Errorf("failed to list existing peers: %w", err)
	}

	return peerList.Items, nil
}
