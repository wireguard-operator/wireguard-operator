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
	wgov1alpha1 "github.com/wireguard-operator/wireguard-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Test helpers for building WireGuard objects
func testWG(name string, addrs []string, opts ...func(*wgov1alpha1.WireGuard)) *wgov1alpha1.WireGuard {
	// Convert []string to InterfaceCIDRs
	interfaceAddrs := make(wgov1alpha1.InterfaceCIDRs, len(addrs))
	for i, addr := range addrs {
		interfaceAddrs[i] = wgov1alpha1.InterfaceCIDR(addr)
	}

	wg := &wgov1alpha1.WireGuard{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: wgov1alpha1.WireGuardSpec{
			Addresses: interfaceAddrs,
		},
	}
	for _, opt := range opts {
		opt(wg)
	}
	return wg
}

func withPort(port wgov1alpha1.Port) func(*wgov1alpha1.WireGuard) {
	return func(wg *wgov1alpha1.WireGuard) {
		wg.Spec.ListenPort = port
	}
}

func withSecret(name string) func(*wgov1alpha1.WireGuard) {
	return func(wg *wgov1alpha1.WireGuard) {
		wg.Spec.PrivateKeySecret = &wgov1alpha1.PrivateKeySecretRef{
			SecretRefBase: wgov1alpha1.SecretRefBase{Name: name},
		}
	}
}

func withStatus(secretName string) func(*wgov1alpha1.WireGuard) {
	return func(wg *wgov1alpha1.WireGuard) {
		wg.Status.PrivateKeySecretName = secretName
	}
}

// Shorthand for standard test WireGuard with default name and address
func wg(opts ...func(*wgov1alpha1.WireGuard)) *wgov1alpha1.WireGuard {
	return testWG("test-wg", []string{"10.0.0.1/24"}, opts...)
}

func wgWithAddr(addr string, opts ...func(*wgov1alpha1.WireGuard)) *wgov1alpha1.WireGuard {
	return testWG("test-wg", []string{addr}, opts...)
}

var _ = Describe("WireGuard Webhook", func() {
	var (
		obj       *wgov1alpha1.WireGuard
		oldObj    *wgov1alpha1.WireGuard
		validator WireGuardCustomValidator
	)

	BeforeEach(func() {
		obj = &wgov1alpha1.WireGuard{}
		oldObj = &wgov1alpha1.WireGuard{}
		validator = WireGuardCustomValidator{}
	})

	DescribeTable("Address validation on creation - valid addresses",
		func(addresses wgov1alpha1.InterfaceCIDRs) {
			obj.Spec = wgov1alpha1.WireGuardSpec{Addresses: addresses}
			_, err := validator.ValidateCreate(ctx, obj)
			Expect(err).ShouldNot(HaveOccurred())
		},
		Entry("accept valid IPv4 and IPv6 hosts", wgov1alpha1.InterfaceCIDRs{"10.0.0.1/24", "2001:db8::1/32"}),
		Entry("allow /31 point-to-point (RFC 3021)", wgov1alpha1.InterfaceCIDRs{"10.0.0.0/31"}),
		Entry("allow /32 single host", wgov1alpha1.InterfaceCIDRs{"10.0.0.0/32"}),
		Entry("allow /127 IPv6 point-to-point", wgov1alpha1.InterfaceCIDRs{"2001:db8::/127"}),
		Entry("accept valid IPv6 host", wgov1alpha1.InterfaceCIDRs{"2001:db8::1/64"}),
		Entry("accept multiple valid addresses", wgov1alpha1.InterfaceCIDRs{"10.0.0.1/24", "192.168.1.1/24", "2001:db8::1/64", "fd00::1/48"}),
	)

	DescribeTable("Address validation on creation - invalid addresses",
		func(addresses wgov1alpha1.InterfaceCIDRs, errorSubstring string) {
			obj.Spec = wgov1alpha1.WireGuardSpec{Addresses: addresses}
			_, err := validator.ValidateCreate(ctx, obj)
			Expect(err).Should(MatchError(ContainSubstring(errorSubstring)))
		},
		Entry("deny IPv4 network address", wgov1alpha1.InterfaceCIDRs{"10.0.0.0/24"}, "network address"),
		Entry("deny IPv4 broadcast address", wgov1alpha1.InterfaceCIDRs{"10.0.0.255/24"}, "broadcast address"),
		Entry("deny IPv4 limited broadcast", wgov1alpha1.InterfaceCIDRs{"255.255.255.255/32"}, "broadcast"),
		Entry("deny IPv4 unspecified address", wgov1alpha1.InterfaceCIDRs{"0.0.0.0/32"}, "unspecified"),
		Entry("deny IPv4 loopback address", wgov1alpha1.InterfaceCIDRs{"127.0.0.1/32"}, "loopback"),
		Entry("deny IPv4 link-local address", wgov1alpha1.InterfaceCIDRs{"169.254.0.1/16"}, "link-local"),
		Entry("deny IPv4 multicast address", wgov1alpha1.InterfaceCIDRs{"224.0.0.1/32"}, "multicast"),
		Entry("deny IPv6 unspecified address", wgov1alpha1.InterfaceCIDRs{"::/128"}, "unspecified"),
		Entry("deny IPv6 loopback address", wgov1alpha1.InterfaceCIDRs{"::1/128"}, "loopback"),
		Entry("deny IPv6 link-local address", wgov1alpha1.InterfaceCIDRs{"fe80::1/64"}, "link-local"),
		Entry("deny IPv6 multicast address", wgov1alpha1.InterfaceCIDRs{"ff02::1/128"}, "multicast"),
		Entry("deny invalid address format", wgov1alpha1.InterfaceCIDRs{"funny:<3"}, "invalid"),
		Entry("deny duplicate networks", wgov1alpha1.InterfaceCIDRs{"10.0.0.1/24", "10.0.0.2/24"}, "overlapping interface addresses"),
		Entry("deny empty address list", wgov1alpha1.InterfaceCIDRs{}, "at least one address"),
		Entry("deny address without prefix", wgov1alpha1.InterfaceCIDRs{"192.168.0.1"}, "prefix length"),
		Entry("deny IPv6 network address", wgov1alpha1.InterfaceCIDRs{"2001:db8::/64"}, "network address"),
		Entry("deny broadcast in middle of list", wgov1alpha1.InterfaceCIDRs{"10.0.0.1/24", "192.168.1.255/24", "2001:db8::1/64"}, "broadcast address"),
		Entry("deny overlapping IPv4 networks (same IP, different prefix)", wgov1alpha1.InterfaceCIDRs{"10.0.0.1/24", "10.0.0.1/25"}, "overlapping interface addresses"),
		Entry("deny overlapping IPv6 networks (same IP, different prefix)", wgov1alpha1.InterfaceCIDRs{"2001:db8::1/64", "2001:db8::1/65"}, "overlapping interface addresses"),
		Entry("deny overlapping IPv4 networks (different IPs, same /24)", wgov1alpha1.InterfaceCIDRs{"10.0.0.50/24", "10.0.0.100/24"}, "overlapping interface addresses"),
		Entry("deny overlapping IPv6 networks (different IPs, same /64)", wgov1alpha1.InterfaceCIDRs{"2001:db8::50/64", "2001:db8::100/64"}, "overlapping interface addresses"),
	)

	Context("Object type validation", func() {
		It("should deny creation with wrong object type", func() {
			peer := &wgov1alpha1.WireGuardPeer{}
			_, err := validator.ValidateCreate(ctx, peer)
			Expect(err).Should(MatchError(ContainSubstring("expected a WireGuard object")))
		})

		It("should deny update with wrong oldObj type", func() {
			peer := &wgov1alpha1.WireGuardPeer{}
			_, err := validator.ValidateUpdate(ctx, peer, obj)
			Expect(err).Should(MatchError(ContainSubstring("expected a WireGuard object")))
		})

		It("should deny update with wrong newObj type", func() {
			peer := &wgov1alpha1.WireGuardPeer{}
			_, err := validator.ValidateUpdate(ctx, oldObj, peer)
			Expect(err).Should(MatchError(ContainSubstring("expected a WireGuard object")))
		})

		It("should allow deletion of any object", func() {
			_, err := validator.ValidateDelete(ctx, nil)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("Address validation on update", func() {
		It("should allow valid address changes", func() {
			_, err := validator.ValidateUpdate(ctx,
				wg(),
				wgWithAddr("10.0.0.2/24"))
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should deny update to network address", func() {
			_, err := validator.ValidateUpdate(ctx,
				wg(),
				wgWithAddr("10.0.0.0/24"))
			Expect(err).Should(MatchError(ContainSubstring("network address")))
		})
	})

	DescribeTable("PrivateKeySecret immutability - allowed changes",
		func(old, new *wgov1alpha1.WireGuard) {
			_, err := validator.ValidateUpdate(ctx, old, new)
			Expect(err).ShouldNot(HaveOccurred())
		},
		Entry("allow change before status is set",
			wg(withSecret("old-secret")),
			wg(withSecret("new-secret"))),
		Entry("allow keeping same secret",
			wg(withSecret("my-secret"), withStatus("my-secret")),
			wgWithAddr("10.0.0.2/24", withSecret("my-secret"))),
		Entry("allow auto-generated secret unchanged",
			wg(withStatus("test-wg-privatekey")),
			wg()),
	)

	DescribeTable("PrivateKeySecret immutability - denied changes",
		func(old, new *wgov1alpha1.WireGuard, errorSubstring string) {
			_, err := validator.ValidateUpdate(ctx, old, new)
			Expect(err).Should(MatchError(ContainSubstring(errorSubstring)))
		},
		Entry("deny change after secret created",
			wg(withSecret("old-secret"), withStatus("old-secret")),
			wg(withSecret("new-secret")),
			"privateKeySecret cannot be changed"),
		Entry("deny removing secret after creation",
			wg(withSecret("my-secret"), withStatus("my-secret")),
			wg(),
			"privateKeySecret cannot be changed"),
		Entry("deny change from auto-generated to explicit",
			wg(withStatus("test-wg-privatekey")),
			wg(withSecret("custom-secret")),
			"privateKeySecret cannot be changed"),
	)

	Describe("ListenPort warnings", func() {
		It("should warn when changing port", func() {
			warnings, err := validator.ValidateUpdate(ctx,
				wg(withPort(51820)),
				wg(withPort(51821)))
			Expect(err).ShouldNot(HaveOccurred())
			Expect(warnings).To(HaveLen(1))
			Expect(warnings[0]).To(ContainSubstring("Changing listen port"))
		})
	})
})
