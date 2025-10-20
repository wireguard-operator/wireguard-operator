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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	testWireGuardName = "test-wg"
)

// Test helpers for building WireGuardPeer objects
func testPeer(name string, opts ...func(*wgov1alpha1.WireGuardPeer)) *wgov1alpha1.WireGuardPeer {
	peer := &wgov1alpha1.WireGuardPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: wgov1alpha1.WireGuardPeerSpec{
			WireGuardReferenceSpec: wgov1alpha1.WireGuardReferenceSpec{
				WireGuardRef: wgov1alpha1.WireGuardRef{
					Name: testWireGuardName,
				},
			},
		},
	}
	for _, opt := range opts {
		opt(peer)
	}
	return peer
}

func peer(opts ...func(*wgov1alpha1.WireGuardPeer)) *wgov1alpha1.WireGuardPeer {
	return testPeer("test-peer", opts...)
}

func withPublicKey(key string) func(*wgov1alpha1.WireGuardPeer) {
	return func(p *wgov1alpha1.WireGuardPeer) {
		p.Spec.PublicKey = &key
	}
}

func withAllowedIPs(ips ...string) func(*wgov1alpha1.WireGuardPeer) {
	return func(p *wgov1alpha1.WireGuardPeer) {
		ipBlocks := make(wgov1alpha1.IPBlocks, len(ips))
		for i, ip := range ips {
			ipBlocks[i] = wgov1alpha1.IPBlock(ip)
		}
		p.Spec.AllowedIPs = ipBlocks
	}
}

func withEndpoint(endpoint string) func(*wgov1alpha1.WireGuardPeer) {
	return func(p *wgov1alpha1.WireGuardPeer) {
		p.Spec.Endpoint = endpoint
	}
}

var _ = Describe("WireGuardPeer Webhook", func() {
	var validator WireGuardPeerCustomValidator

	BeforeEach(func() {
		validator = WireGuardPeerCustomValidator{Client: k8sClient}

		// Create a WireGuard resource for testing
		testWG := &wgov1alpha1.WireGuard{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testWireGuardName,
				Namespace: "default",
			},
			Spec: wgov1alpha1.WireGuardSpec{
				Addresses: wgov1alpha1.InterfaceCIDRs{"172.0.0.1/24"},
			},
		}
		_ = k8sClient.Create(ctx, testWG)
	})

	AfterEach(func() {
		// Clean up all WireGuardPeer resources in namespace
		_ = k8sClient.DeleteAllOf(ctx, &wgov1alpha1.WireGuardPeer{}, client.InNamespace("default"))

		// Clean up all WireGuard resources in namespace
		_ = k8sClient.DeleteAllOf(ctx, &wgov1alpha1.WireGuard{}, client.InNamespace("default"))

		// Wait for resources to be deleted to avoid race conditions
		Eventually(func() int {
			peerList := &wgov1alpha1.WireGuardPeerList{}
			_ = k8sClient.List(ctx, peerList, client.InNamespace("default"))
			return len(peerList.Items)
		}, "5s", "100ms").Should(Equal(0))
	})

	DescribeTable("PublicKey validation - valid keys",
		func(p *wgov1alpha1.WireGuardPeer) {
			_, err := validator.ValidateCreate(ctx, p)
			Expect(err).ShouldNot(HaveOccurred())
		},
		Entry("accept valid base64 public key", peer(withPublicKey("BBNXLB4MkrPn5xBr31qiv5T+w4EHXGsw6OADCt3Sb0M="))),
		Entry("accept peer without public key (auto-generated)", peer()),
	)

	DescribeTable("PublicKey validation - invalid keys",
		func(p *wgov1alpha1.WireGuardPeer, errorSubstring string) {
			_, err := validator.ValidateCreate(ctx, p)
			Expect(err).Should(MatchError(ContainSubstring(errorSubstring)))
		},
		Entry("deny invalid public key format", peer(withPublicKey("not-a-valid-key")), "failed to parse base64-encoded"),
		Entry("deny empty public key", peer(withPublicKey("")), "incorrect key size"),
	)

	Context("PublicKey uniqueness validation", func() {
		It("should deny duplicate PublicKey", func() {
			// Create first peer with PublicKey
			peer1 := testPeer("peer1", withPublicKey("BBNXLB4MkrPn5xBr31qiv5T+w4EHXGsw6OADCt3Sb0M="))
			Expect(k8sClient.Create(ctx, peer1)).Should(Succeed())

			// Try to create second peer with same PublicKey
			peer2 := testPeer("peer2", withPublicKey("BBNXLB4MkrPn5xBr31qiv5T+w4EHXGsw6OADCt3Sb0M="))
			// Use Eventually because field indexer needs time to index peer1
			Eventually(func() error {
				_, err := validator.ValidateCreate(ctx, peer2)
				return err
			}, "2s", "100ms").Should(MatchError(ContainSubstring("PublicKey already in use")))
		})

		It("should allow different PublicKey", func() {
			// Create first peer with PublicKey
			peer1 := testPeer("peer1", withPublicKey("BBNXLB4MkrPn5xBr31qiv5T+w4EHXGsw6OADCt3Sb0M="))
			Expect(k8sClient.Create(ctx, peer1)).Should(Succeed())

			// Create second peer with different PublicKey
			peer2 := testPeer("peer2", withPublicKey("6JJHyizOjUApgc0BdJhKlj5V6w/qRFp0OG3j3xhFhFs="))
			// Use Eventually because field indexer needs time to index peer1
			Eventually(func() error {
				_, err := validator.ValidateCreate(ctx, peer2)
				return err
			}, "2s", "100ms").ShouldNot(HaveOccurred())
		})

		It("should allow nil PublicKey (auto-generated)", func() {
			// Create first peer with PublicKey
			peer1 := testPeer("peer1", withPublicKey("BBNXLB4MkrPn5xBr31qiv5T+w4EHXGsw6OADCt3Sb0M="))
			Expect(k8sClient.Create(ctx, peer1)).Should(Succeed())

			// Create second peer without PublicKey (auto-generated)
			peer2 := testPeer("peer2")
			// Use Eventually because field indexer needs time to index peer1
			Eventually(func() error {
				_, err := validator.ValidateCreate(ctx, peer2)
				return err
			}, "2s", "100ms").ShouldNot(HaveOccurred())
		})
	})

	DescribeTable("AllowedIPs validation - valid IPs",
		func(p *wgov1alpha1.WireGuardPeer) {
			_, err := validator.ValidateCreate(ctx, p)
			Expect(err).ShouldNot(HaveOccurred())
		},
		Entry("accept valid IPv4 CIDR", peer(withAllowedIPs("10.0.0.1/32"))),
		Entry("accept valid IPv6 CIDR", peer(withAllowedIPs("2001:db8::1/128"))),
		Entry("accept multiple valid CIDRs", peer(withAllowedIPs("10.0.0.1/32", "192.168.1.0/24", "2001:db8::/64"))),
		Entry("accept peer without AllowedIPs (auto-assigned)", peer()),
	)

	DescribeTable("AllowedIPs validation - invalid IPs",
		func(p *wgov1alpha1.WireGuardPeer, errorSubstring string) {
			_, err := validator.ValidateCreate(ctx, p)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(errorSubstring))
		},
		Entry("deny invalid CIDR format", peer(withAllowedIPs("not-a-cidr")), "not a valid IP"),
		Entry("deny empty AllowedIP in list", peer(withAllowedIPs("10.0.0.1/32", "", "192.168.1.0/24")), "not a valid IP"),
		Entry("deny empty AllowedIP in list", peer(withAllowedIPs("", "")), "not a valid IP"),
		Entry("deny overlapping AllowedIPs", peer(withAllowedIPs("10.0.0.0/24", "", "10.0.0.0/25")), "not a valid IP"),
		Entry("deny non-network CIDR address", peer(withAllowedIPs("10.0.0.5/24")), "is not the network address"),
		Entry("deny non-network CIDR address IPv6", peer(withAllowedIPs("2001:db8::5/64")), "is not the network address"),
	)

	DescribeTable("Endpoint validation - valid endpoints",
		func(p *wgov1alpha1.WireGuardPeer) {
			_, err := validator.ValidateCreate(ctx, p)
			Expect(err).ShouldNot(HaveOccurred())
		},
		Entry("accept valid IPv4 endpoint", peer(withEndpoint("192.168.1.1:51820"))),
		Entry("accept valid IPv6 endpoint", peer(withEndpoint("[2001:db8::1]:51820"))),
		Entry("accept valid hostname endpoint", peer(withEndpoint("vpn.example.com:51820"))),
		Entry("accept valid domain", peer(withEndpoint("vpn.example.com:51820"))),
		Entry("accept valid unknown tld", peer(withEndpoint("my-server.local:51820"))),
		Entry("accept localhost endpoint (for testing)", peer(withEndpoint("localhost:51820"))),
		Entry("accept loopback IPv4 endpoint (for testing)", peer(withEndpoint("127.0.0.1:51820"))),
		Entry("accept loopback IPv6 endpoint (for testing)", peer(withEndpoint("[::1]:51820"))),
		Entry("accept peer without endpoint", peer()),
	)

	DescribeTable("Endpoint validation - invalid endpoints",
		func(p *wgov1alpha1.WireGuardPeer, errorSubstring string) {
			_, err := validator.ValidateCreate(ctx, p)
			Expect(err).Should(MatchError(ContainSubstring(errorSubstring)))
		},
		Entry("deny endpoint without port", peer(withEndpoint("192.168.1.1")), "port"),
		Entry("deny endpoint with invalid port", peer(withEndpoint("192.168.1.1:99999")), "port"),
		Entry("deny endpoint with 0.0.0.0", peer(withEndpoint("0.0.0.0:51820")), "unspecified address"),
		Entry("deny endpoint with [::]", peer(withEndpoint("[::]:51820")), "unspecified address"),
	)

	Context("Object type validation", func() {
		It("should deny creation with wrong object type", func() {
			wg := &wgov1alpha1.WireGuard{}
			_, err := validator.ValidateCreate(ctx, wg)
			Expect(err).Should(MatchError(ContainSubstring("expected a WireGuardPeer object")))
		})

		It("should deny update with wrong oldObj type", func() {
			wg := &wgov1alpha1.WireGuard{}
			_, err := validator.ValidateUpdate(ctx, wg, peer())
			Expect(err).Should(MatchError(ContainSubstring("expected a WireGuardPeer object")))
		})

		It("should deny update with wrong newObj type", func() {
			wg := &wgov1alpha1.WireGuard{}
			_, err := validator.ValidateUpdate(ctx, peer(), wg)
			Expect(err).Should(MatchError(ContainSubstring("expected a WireGuardPeer object")))
		})

		It("should allow deletion of any object", func() {
			_, err := validator.ValidateDelete(ctx, nil)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Describe("WireGuardRef validation warnings", func() {
		It("should warn when referenced WireGuard does not exist", func() {
			p := peer()
			p.Spec.WireGuardRef.Name = "not-existing"

			warnings, err := validator.ValidateCreate(ctx, p)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(warnings).To(ContainElement(ContainSubstring("Referenced WireGuard resource 'not-existing' not found yet")))
		})
	})

	Describe("IP overlap detection between peers", func() {
		It("should reject peer with overlapping AllowedIPs", func() {
			// Create first peer with AllowedIPs
			peer1 := testPeer("peer1", withAllowedIPs("10.0.0.0/24"))
			Expect(k8sClient.Create(ctx, peer1)).Should(Succeed())

			// Try to create second peer with overlapping IPs
			// Use Eventually because field indexer needs time to index peer1
			peer2 := testPeer("peer2", withAllowedIPs("10.0.0.1/32"))
			Eventually(func() error {
				_, err := validator.ValidateCreate(ctx, peer2)
				return err
			}, "2s", "100ms").Should(MatchError(ContainSubstring("IP overlap detected")))
		})

		It("should accept peer with non-overlapping AllowedIPs", func() {
			// Create first peer with AllowedIPs
			peer1 := testPeer("peer1", withAllowedIPs("10.0.0.0/24"))
			Expect(k8sClient.Create(ctx, peer1)).Should(Succeed())

			// Create second peer with non-overlapping IPs
			// Use Eventually because field indexer needs time to index peer1
			peer2 := testPeer("peer2", withAllowedIPs("10.0.1.0/24"))
			Eventually(func() error {
				_, err := validator.ValidateCreate(ctx, peer2)
				return err
			}, "2s", "100ms").ShouldNot(HaveOccurred())
		})

		It("should accept peer without AllowedIPs (auto-assign)", func() {
			// Create first peer with AllowedIPs
			peer1 := testPeer("peer1", withAllowedIPs("10.0.0.0/24"))
			Expect(k8sClient.Create(ctx, peer1)).Should(Succeed())

			// Create second peer without AllowedIPs (will be auto-assigned)
			// Use Eventually because field indexer needs time to index peer1
			peer2 := testPeer("peer2")
			Eventually(func() error {
				_, err := validator.ValidateCreate(ctx, peer2)
				return err
			}, "2s", "100ms").ShouldNot(HaveOccurred())
		})

		It("should return error for non-NotFound API errors (e.g. scheme issues)", func() {
			// Using empty scheme causes API error when trying to Get WireGuard
			// This tests that non-NotFound errors are returned as validation errors, not warnings
			scheme := runtime.NewScheme()
			validator = WireGuardPeerCustomValidator{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}

			peer1 := testPeer("peer1", withAllowedIPs("10.0.0.0/24"))
			_, err := validator.ValidateCreate(ctx, peer1)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to validate WireGuardRef"))
		})

		It("should only warn for NotFound errors (not return error)", func() {
			// Create a peer referencing a non-existing WireGuard
			// This should only produce a warning, not an error
			peer1 := testPeer("peer1")
			peer1.Spec.WireGuardRef.Name = "non-existing-wg"

			warnings, err := validator.ValidateCreate(ctx, peer1)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(warnings).To(HaveLen(1))
			Expect(warnings[0]).To(ContainSubstring("not found yet"))
		})

		It("should return error when listing peers fails", func() {
			// Register only WireGuard type, not WireGuardPeerList
			// This causes List to fail but Get to succeed
			scheme := runtime.NewScheme()
			_ = wgov1alpha1.AddToScheme(scheme)

			// Create a fake client with WireGuard object but no WireGuardPeerList support
			testWG := &wgov1alpha1.WireGuard{
				ObjectMeta: metav1.ObjectMeta{Name: testWireGuardName, Namespace: "default"},
				Spec:       wgov1alpha1.WireGuardSpec{Addresses: wgov1alpha1.InterfaceCIDRs{"172.0.0.1/24"}},
			}
			validator = WireGuardPeerCustomValidator{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(testWG).Build()}

			peer1 := testPeer("peer1", withAllowedIPs("10.0.0.0/24"))
			_, err := validator.ValidateCreate(ctx, peer1)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to list existing peers"))
		})
	})

	Describe("ValidateUpdate runs create validations", func() {
		It("should reject update with invalid PublicKey", func() {
			_, err := validator.ValidateUpdate(ctx,
				peer(),
				peer(withPublicKey("invalid-key")))
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("base64"))
		})

		It("should reject update with invalid AllowedIPs", func() {
			_, err := validator.ValidateUpdate(ctx,
				peer(withAllowedIPs("10.0.0.1/32")),
				peer(withAllowedIPs("not-a-cidr")))
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not a valid IP"))
		})

		It("should reject update with invalid Endpoint", func() {
			_, err := validator.ValidateUpdate(ctx,
				peer(),
				peer(withEndpoint("192.168.1.1")))
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("port"))
		})

		It("should reject update with overlapping AllowedIPs", func() {
			// Create first peer with AllowedIPs
			peer1 := testPeer("peer1", withAllowedIPs("10.0.0.0/24"))
			Expect(k8sClient.Create(ctx, peer1)).Should(Succeed())

			peer2 := testPeer("peer2", withAllowedIPs("192.168.1.0/24"))
			Expect(k8sClient.Create(ctx, peer2)).Should(Succeed())

			peer2Updated := peer2.DeepCopy()
			peer2Updated.Spec.AllowedIPs = wgov1alpha1.IPBlocks{"10.0.0.1/32"}

			Eventually(func() error {
				_, err := validator.ValidateUpdate(ctx, peer2, peer2Updated)
				return err
			}, "2s", "100ms").Should(MatchError(ContainSubstring("IP overlap detected")))
		})
	})

	DescribeTable("AllowedIPs change warnings",
		func(oldIPs, newIPs []string, shouldWarn bool) {
			var warnings admission.Warnings
			var err error
			// Use Eventually to wait for previous test cleanup to complete
			Eventually(func() error {
				warnings, err = validator.ValidateUpdate(ctx,
					peer(withAllowedIPs(oldIPs...)),
					peer(withAllowedIPs(newIPs...)))
				return err
			}, "2s", "100ms").ShouldNot(HaveOccurred())

			if shouldWarn {
				Expect(warnings).To(ContainElement(ContainSubstring("routing rules")))
			} else {
				Expect(warnings).To(BeNil())
			}
		},
		Entry("warn when AllowedIP replaced", []string{"10.0.0.1/32"}, []string{"10.0.0.2/32"}, true),
		Entry("warn when AllowedIP added", []string{"10.0.0.1/32"}, []string{"10.0.0.2/32", "10.0.0.1/32"}, true),
		Entry("no warning when order changed", []string{"10.0.0.4/32", "10.0.0.9/32"}, []string{"10.0.0.9/32", "10.0.0.4/32"}, false),
	)

	Describe("AllowedIPs should not overlap", func() {
		It("should warn when AllowedIPs are changed", func() {
			var err error
			// Use Eventually to wait for previous test cleanup to complete
			Eventually(func() error {
				_, err = validator.ValidateCreate(ctx, peer(withAllowedIPs("10.0.0.1/32", "10.0.0.1/32")))
				return err
			}, "2s", "100ms").Should(MatchError(ContainSubstring("duplicate IP block")))
		})
	})
})
