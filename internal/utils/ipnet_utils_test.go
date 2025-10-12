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

package utils

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("IPBlock Utils", func() {
	Describe("FindNextAvailableIP", func() {
		It("should find the next available IP in a CIDR", func() {
			cidr := wgov1alpha1.InterfaceCIDR("10.0.0.1/24")
			existingPeers := []wgov1alpha1.WireGuardPeer{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "peer1",
						Namespace: "default",
					},
					Spec: wgov1alpha1.WireGuardPeerSpec{
						AllowedIPs: wgov1alpha1.IPBlocks{
							wgov1alpha1.IPBlock("10.0.0.2/32"),
						},
					},
				},
			}

			nextIP, err := FindNextAvailableIP(cidr, existingPeers)
			Expect(err).NotTo(HaveOccurred())
			Expect(nextIP.String()).To(Equal("10.0.0.3"))
		})

		It("should skip network and broadcast addresses for IPv4", func() {
			cidr := wgov1alpha1.InterfaceCIDR("10.0.0.1/24")
			var existingPeers []wgov1alpha1.WireGuardPeer

			nextIP, err := FindNextAvailableIP(cidr, existingPeers)
			Expect(err).NotTo(HaveOccurred())
			// Should skip 10.0.0.0 (network) and 10.0.0.1 (interface) and return 10.0.0.2
			Expect(nextIP.String()).To(Equal("10.0.0.2"))
		})

		It("should return error when no IPs available", func() {
			cidr := wgov1alpha1.InterfaceCIDR("10.0.0.1/30")
			existingPeers := []wgov1alpha1.WireGuardPeer{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "peer1",
						Namespace: "default",
					},
					Spec: wgov1alpha1.WireGuardPeerSpec{
						AllowedIPs: wgov1alpha1.IPBlocks{
							wgov1alpha1.IPBlock("10.0.0.2/32"),
						},
					},
				},
			}

			_, err := FindNextAvailableIP(cidr, existingPeers)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no available IPs"))
		})

		It("should work with /31 networks", func() {
			cidr := wgov1alpha1.InterfaceCIDR("10.0.0.0/31")
			var existingPeers []wgov1alpha1.WireGuardPeer

			nextIP, err := FindNextAvailableIP(cidr, existingPeers)
			Expect(err).NotTo(HaveOccurred())
			// With /31, both IPs are usable, interface is 10.0.0.0, so next is 10.0.0.1
			Expect(nextIP.String()).To(Equal("10.0.0.1"))
		})

		It("should handle large IPv6 ranges efficiently", func() {
			cidr := wgov1alpha1.InterfaceCIDR("2001:db8::1/64")
			var existingPeers []wgov1alpha1.WireGuardPeer

			// This should work without memory issues even for large IPv6 ranges
			nextIP, err := FindNextAvailableIP(cidr, existingPeers)
			Expect(err).NotTo(HaveOccurred())
			Expect(nextIP.Is6()).To(BeTrue())
		})
	})

	Describe("BuildTrieFromPeers", func() {
		It("should build trie from peers with single IPs", func() {
			peers := []wgov1alpha1.WireGuardPeer{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "peer1",
						Namespace: "default",
					},
					Spec: wgov1alpha1.WireGuardPeerSpec{
						AllowedIPs: wgov1alpha1.IPBlocks{
							wgov1alpha1.IPBlock("10.0.0.2/32"),
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "peer2",
						Namespace: "default",
					},
					Spec: wgov1alpha1.WireGuardPeerSpec{
						AllowedIPs: wgov1alpha1.IPBlocks{
							wgov1alpha1.IPBlock("10.0.0.3/32"),
						},
					},
				},
			}

			trie, err := BuildTrieFromPeers(peers)
			Expect(err).NotTo(HaveOccurred())
			Expect(trie).NotTo(BeNil())
			Expect(trie.Size()).To(Equal(2))
		})

		It("should handle IP ranges efficiently", func() {
			peers := []wgov1alpha1.WireGuardPeer{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "peer1",
						Namespace: "default",
					},
					Spec: wgov1alpha1.WireGuardPeerSpec{
						AllowedIPs: wgov1alpha1.IPBlocks{
							wgov1alpha1.IPBlock("10.0.0.0/24"),
						},
					},
				},
			}

			trie, err := BuildTrieFromPeers(peers)
			Expect(err).NotTo(HaveOccurred())
			Expect(trie).NotTo(BeNil())
			// Trie stores ranges efficiently, not as individual IPs
			Expect(trie.Size()).To(Equal(1))
		})

		It("should handle large IPv6 ranges without memory issues", func() {
			peers := []wgov1alpha1.WireGuardPeer{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "peer1",
						Namespace: "default",
					},
					Spec: wgov1alpha1.WireGuardPeerSpec{
						AllowedIPs: wgov1alpha1.IPBlocks{
							wgov1alpha1.IPBlock("2001:db8::/32"), // Huge range!
						},
					},
				},
			}

			trie, err := BuildTrieFromPeers(peers)
			Expect(err).NotTo(HaveOccurred())
			Expect(trie).NotTo(BeNil())
			// Should store as a single range, not billions of IPs
			Expect(trie.Size()).To(Equal(1))
		})
	})
})
