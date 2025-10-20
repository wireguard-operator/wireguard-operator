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
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Test helpers for building WireGuardTrafficFlow objects
func testFlow(name string, flows []wgov1alpha1.FlowRule) *wgov1alpha1.WireGuardTrafficFlow {
	return &wgov1alpha1.WireGuardTrafficFlow{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: wgov1alpha1.WireGuardTrafficFlowSpec{
			WireGuardReferenceSpec: wgov1alpha1.WireGuardReferenceSpec{
				WireGuardRef: wgov1alpha1.WireGuardRef{
					Name: "test-wg",
				},
			},
			Flows: flows,
		},
	}
}

func flow(flows []wgov1alpha1.FlowRule) *wgov1alpha1.WireGuardTrafficFlow {
	return testFlow("test", flows)
}

func flowRule(name string, opts ...func(*wgov1alpha1.FlowRule)) wgov1alpha1.FlowRule {
	rule := wgov1alpha1.FlowRule{
		Name:     name,
		Protocol: wgov1alpha1.ProtocolAny,
		IPFamily: wgov1alpha1.IPFamilyIPv4,
	}
	for _, opt := range opts {
		opt(&rule)
	}
	return rule
}

func withProtocol(proto wgov1alpha1.Protocol) func(*wgov1alpha1.FlowRule) {
	return func(f *wgov1alpha1.FlowRule) {
		f.Protocol = proto
	}
}

func withIPFamily(family wgov1alpha1.IPFamily) func(*wgov1alpha1.FlowRule) {
	return func(f *wgov1alpha1.FlowRule) {
		f.IPFamily = family
	}
}

func withFrom(selector *wgov1alpha1.FlowTrafficSelector) func(*wgov1alpha1.FlowRule) {
	return func(f *wgov1alpha1.FlowRule) {
		f.From = selector
	}
}

func withTo(selector *wgov1alpha1.FlowTrafficSelector) func(*wgov1alpha1.FlowRule) {
	return func(f *wgov1alpha1.FlowRule) {
		f.To = selector
	}
}

func withTransform(transform *wgov1alpha1.TransformAction) func(*wgov1alpha1.FlowRule) {
	return func(f *wgov1alpha1.FlowRule) {
		f.Transform = transform
	}
}

func withFilter(filter *wgov1alpha1.FilterAction) func(*wgov1alpha1.FlowRule) {
	return func(f *wgov1alpha1.FlowRule) {
		f.Filter = filter
	}
}

func selector(opts ...func(*wgov1alpha1.FlowTrafficSelector)) *wgov1alpha1.FlowTrafficSelector {
	sel := &wgov1alpha1.FlowTrafficSelector{}
	for _, opt := range opts {
		opt(sel)
	}
	return sel
}

func withSelf() func(*wgov1alpha1.FlowTrafficSelector) {
	return func(s *wgov1alpha1.FlowTrafficSelector) {
		s.Self = true
	}
}

func withIPBlocks(blocks ...string) func(*wgov1alpha1.FlowTrafficSelector) {
	return func(s *wgov1alpha1.FlowTrafficSelector) {
		ipBlocks := make(wgov1alpha1.IPBlocks, len(blocks))
		for i, b := range blocks {
			ipBlocks[i] = wgov1alpha1.IPBlock(b)
		}
		s.IPBlocks = ipBlocks
	}
}

func withPodSelector(labels map[string]string) func(*wgov1alpha1.FlowTrafficSelector) {
	return func(s *wgov1alpha1.FlowTrafficSelector) {
		s.PodSelector = &metav1.LabelSelector{
			MatchLabels: labels,
		}
	}
}

func withPeerSelector(labels map[string]string) func(*wgov1alpha1.FlowTrafficSelector) {
	return func(s *wgov1alpha1.FlowTrafficSelector) {
		s.PeerSelector = &metav1.LabelSelector{
			MatchLabels: labels,
		}
	}
}

func withServiceSelector(labels map[string]string) func(*wgov1alpha1.FlowTrafficSelector) {
	return func(s *wgov1alpha1.FlowTrafficSelector) {
		s.ServiceSelector = &metav1.LabelSelector{
			MatchLabels: labels,
		}
	}
}

func withMultusNetwork(network string) func(*wgov1alpha1.FlowTrafficSelector) {
	return func(s *wgov1alpha1.FlowTrafficSelector) {
		s.MultusNetwork = network
	}
}

func withPorts(ports ...wgov1alpha1.PolicyPort) func(*wgov1alpha1.FlowTrafficSelector) {
	return func(s *wgov1alpha1.FlowTrafficSelector) {
		s.Ports = ports
	}
}

func withInterfaces(interfaces ...string) func(*wgov1alpha1.FlowTrafficSelector) {
	return func(s *wgov1alpha1.FlowTrafficSelector) {
		ifnames := make(wgov1alpha1.InterfaceNames, len(interfaces))
		for i, iface := range interfaces {
			ifnames[i] = wgov1alpha1.InterfaceName(iface)
		}
		s.Interfaces = ifnames
	}
}

func policyPort(port, endPort wgov1alpha1.Port) wgov1alpha1.PolicyPort {
	return wgov1alpha1.PolicyPort{Port: &port, EndPort: &endPort}
}

var _ = Describe("WireGuardTrafficFlow Webhook", func() {
	var validator WireGuardTrafficFlowCustomValidator

	BeforeEach(func() {
		validator = WireGuardTrafficFlowCustomValidator{Client: k8sClient}

		// Create a WireGuard resource for testing
		testWG := &wgov1alpha1.WireGuard{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-wg",
				Namespace: "default",
			},
			Spec: wgov1alpha1.WireGuardSpec{
				Addresses: wgov1alpha1.InterfaceCIDRs{"172.0.0.1/24"},
			},
		}
		_ = k8sClient.Create(ctx, testWG)
	})

	AfterEach(func() {
		// Clean up all WireGuard resources in namespace
		_ = k8sClient.DeleteAllOf(ctx, &wgov1alpha1.WireGuard{}, client.InNamespace("default"))
	})

	Context("Object type validation", func() {
		It("should deny creation with wrong object type", func() {
			wg := &wgov1alpha1.WireGuard{}
			_, err := validator.ValidateCreate(ctx, wg)
			Expect(err).Should(MatchError(ContainSubstring("expected a WireGuardTrafficFlow object")))
		})

		It("should deny update with wrong oldObj type", func() {
			wg := &wgov1alpha1.WireGuard{}
			flow := flow(nil)
			_, err := validator.ValidateUpdate(ctx, wg, flow)
			Expect(err).Should(MatchError(ContainSubstring("expected a WireGuardTrafficFlow object")))
		})

		It("should deny update with wrong newObj type", func() {
			wg := &wgov1alpha1.WireGuard{}
			flow := flow(nil)
			_, err := validator.ValidateUpdate(ctx, flow, wg)
			Expect(err).Should(MatchError(ContainSubstring("expected a WireGuardTrafficFlow object")))
		})

		It("should allow deletion of any object", func() {
			_, err := validator.ValidateDelete(ctx, nil)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Describe("WireGuardRef validation", func() {
		It("should warn when referenced WireGuard does not exist", func() {
			f := flow([]wgov1alpha1.FlowRule{flowRule("test")})
			f.Spec.WireGuardRef.Name = "non-existing-wg"

			warnings, err := validator.ValidateCreate(ctx, f)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(warnings).To(HaveLen(1))
			Expect(warnings[0]).To(ContainSubstring("not found yet"))
		})

		It("should return error for non-NotFound API errors", func() {
			// Using empty scheme causes API error when trying to Get WireGuard
			scheme := runtime.NewScheme()
			validator = WireGuardTrafficFlowCustomValidator{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}

			f := flow([]wgov1alpha1.FlowRule{flowRule("test")})
			_, err := validator.ValidateCreate(ctx, f)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to validate WireGuardRef"))
		})
	})

	Describe("Duplicate flow names", func() {
		It("should accept flows with unique names", func() {
			flow := flow([]wgov1alpha1.FlowRule{
				flowRule("flow1"),
				flowRule("flow2"),
				flowRule("flow3"),
			})
			_, err := validator.ValidateCreate(ctx, flow)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should reject flows with duplicate names", func() {
			flow := flow([]wgov1alpha1.FlowRule{
				flowRule("flow1"),
				flowRule("flow2"),
				flowRule("flow1"), // duplicate
			})
			_, err := validator.ValidateCreate(ctx, flow)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("duplicate flow name: flow1"))
		})
	})

	DescribeTable("ICMP/ICMPv6 protocol validation",
		func(rule wgov1alpha1.FlowRule, shouldSucceed bool, errorSubstring string) {
			flow := flow([]wgov1alpha1.FlowRule{rule})
			_, err := validator.ValidateCreate(ctx, flow)
			if shouldSucceed {
				Expect(err).ShouldNot(HaveOccurred())
			} else {
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(errorSubstring))
			}
		},
		Entry("accept ICMP with IPv4", flowRule("test", withProtocol(wgov1alpha1.ProtocolICMP), withIPFamily(wgov1alpha1.IPFamilyIPv4)), true, ""),
		Entry("deny ICMP with IPv6", flowRule("test", withProtocol(wgov1alpha1.ProtocolICMP), withIPFamily(wgov1alpha1.IPFamilyIPv6)), false, "ICMP protocol requires ipFamily: IPv4"),
		Entry("accept ICMPv6 with IPv6", flowRule("test", withProtocol(wgov1alpha1.ProtocolICMPv6), withIPFamily(wgov1alpha1.IPFamilyIPv6)), true, ""),
		Entry("deny ICMPv6 with IPv4", flowRule("test", withProtocol(wgov1alpha1.ProtocolICMPv6), withIPFamily(wgov1alpha1.IPFamilyIPv4)), false, "ICMPv6 protocol requires ipFamily: IPv6"),
	)

	Describe("Traffic selector validation", func() {
		DescribeTable("Mutual exclusive selectors - valid",
			func(sel *wgov1alpha1.FlowTrafficSelector) {
				// Test from selector
				fFrom := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withFrom(sel)),
				})
				_, err := validator.ValidateCreate(ctx, fFrom)
				Expect(err).ShouldNot(HaveOccurred())

				// Test to selector
				fTo := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withTo(sel)),
				})
				_, err = validator.ValidateCreate(ctx, fTo)
				Expect(err).ShouldNot(HaveOccurred())
			},
			Entry("ipBlocks only", selector(withIPBlocks("10.0.0.0/24"))),
			Entry("podSelector only", selector(withPodSelector(map[string]string{"app": "test"}))),
			Entry("peerSelector only", selector(withPeerSelector(map[string]string{"app": "test"}))),
			Entry("serviceSelector only", selector(withServiceSelector(map[string]string{"app": "test"}))),
			Entry("self only", selector(withSelf())),
		)

		DescribeTable("Mutual exclusive selectors - invalid",
			func(sel *wgov1alpha1.FlowTrafficSelector, errorSubstring string) {
				// Test from selector
				fFrom := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withFrom(sel)),
				})
				_, err := validator.ValidateCreate(ctx, fFrom)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(errorSubstring))

				// Test to selector
				fTo := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withTo(sel)),
				})
				_, err = validator.ValidateCreate(ctx, fTo)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(errorSubstring))
			},
			Entry("ipBlocks + podSelector", selector(withIPBlocks("10.0.0.0/24"), withPodSelector(map[string]string{"app": "test"})), "at most one of"),
			Entry("podSelector + peerSelector", selector(withPodSelector(map[string]string{"app": "test"}), withPeerSelector(map[string]string{"app": "test"})), "at most one of"),
			Entry("self + ipBlocks", selector(withSelf(), withIPBlocks("10.0.0.0/24")), "when self is true"),
			Entry("self + podSelector", selector(withSelf(), withPodSelector(map[string]string{"app": "test"})), "when self is true"),
		)

		DescribeTable("multusNetwork validation",
			func(sel *wgov1alpha1.FlowTrafficSelector, shouldSucceed bool) {
				// Test from selector
				fFrom := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withFrom(sel)),
				})
				_, err := validator.ValidateCreate(ctx, fFrom)
				if shouldSucceed {
					Expect(err).ShouldNot(HaveOccurred())
				} else {
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("multusNetwork requires podSelector"))
				}

				// Test to selector
				fTo := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withTo(sel)),
				})
				_, err = validator.ValidateCreate(ctx, fTo)
				if shouldSucceed {
					Expect(err).ShouldNot(HaveOccurred())
				} else {
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("multusNetwork requires podSelector"))
				}
			},
			Entry("accept multusNetwork with podSelector", selector(withPodSelector(map[string]string{"app": "test"}), withMultusNetwork("multus-net1")), true),
			Entry("reject multusNetwork without podSelector", selector(withIPBlocks("10.0.0.0/24"), withMultusNetwork("net-invalid")), false),
		)

		DescribeTable("overlapping IP blocks",
			func(sel *wgov1alpha1.FlowTrafficSelector) {
				// Test from selector
				fFrom := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withFrom(sel)),
				})
				_, err := validator.ValidateCreate(ctx, fFrom)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("overlap"))

				// Test to selector
				fTo := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withTo(sel)),
				})
				_, err = validator.ValidateCreate(ctx, fTo)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("overlap"))
			},
			Entry("overlapping IP blocks", selector(withIPBlocks("10.0.0.0/24", "10.0.0.0/25"))),
		)

		DescribeTable("overlapping port ranges",
			func(sel *wgov1alpha1.FlowTrafficSelector) {
				// Test from selector
				fFrom := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withFrom(sel)),
				})
				_, err := validator.ValidateCreate(ctx, fFrom)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("overlap"))

				// Test to selector
				fTo := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withTo(sel)),
				})
				_, err = validator.ValidateCreate(ctx, fTo)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("overlap"))
			},
			Entry("overlapping port ranges", selector(withPorts(policyPort(80, 90), policyPort(85, 95)))),
		)

		Describe("Port range edge cases", func() {
			It("rejects endPort < port", func() {
				p1, p2 := wgov1alpha1.Port(100), wgov1alpha1.Port(80)
				sel := selector(withPorts(wgov1alpha1.PolicyPort{Port: &p1, EndPort: &p2}))
				f := flow([]wgov1alpha1.FlowRule{flowRule("r", withProtocol(wgov1alpha1.ProtocolTCP), withFrom(sel))})
				_, err := validator.ValidateCreate(ctx, f)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("endPort"))
			})

			It("accepts adjacent non-overlapping ranges", func() {
				p1a, p1b := wgov1alpha1.Port(80), wgov1alpha1.Port(90)
				p2a, p2b := wgov1alpha1.Port(91), wgov1alpha1.Port(100)
				sel := selector(withPorts(
					wgov1alpha1.PolicyPort{Port: &p1a, EndPort: &p1b},
					wgov1alpha1.PolicyPort{Port: &p2a, EndPort: &p2b},
				))
				f := flow([]wgov1alpha1.FlowRule{flowRule("r", withProtocol(wgov1alpha1.ProtocolUDP), withFrom(sel))})
				_, err := validator.ValidateCreate(ctx, f)
				Expect(err).NotTo(HaveOccurred())
			})

			It("accepts nil port with named port", func() {
				// PolicyPort with Port=nil is valid when Name is specified
				// Named ports are skipped during overlap validation
				p := wgov1alpha1.Port(80)
				sel := selector(withPorts(
					wgov1alpha1.PolicyPort{Port: nil, Name: "http"}, // Named port, no numeric port
					wgov1alpha1.PolicyPort{Port: &p},                // Numeric port
				))
				f := flow([]wgov1alpha1.FlowRule{flowRule("r", withProtocol(wgov1alpha1.ProtocolTCP), withFrom(sel))})
				_, err := validator.ValidateCreate(ctx, f)
				Expect(err).NotTo(HaveOccurred())
			})

			It("rejects port=nil and name empty", func() {
				// PolicyPort must have either Port or Name set
				sel := selector(withPorts(wgov1alpha1.PolicyPort{Port: nil, Name: ""}))
				f := flow([]wgov1alpha1.FlowRule{flowRule("r", withProtocol(wgov1alpha1.ProtocolTCP), withFrom(sel))})
				_, err := validator.ValidateCreate(ctx, f)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("port must specify either 'port' or 'name'"))
			})

			It("rejects single port with endPort < port", func() {
				// Single PolicyPort with swapped values should fail
				p2a, p2b := wgov1alpha1.Port(91), wgov1alpha1.Port(100)
				sel := selector(withPorts(
					wgov1alpha1.PolicyPort{Port: &p2b, EndPort: &p2a}, // 100-91 is invalid
				))
				f := flow([]wgov1alpha1.FlowRule{flowRule("r", withProtocol(wgov1alpha1.ProtocolTCP), withFrom(sel))})
				_, err := validator.ValidateCreate(ctx, f)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("endPort"))
			})
		})
	})

	Describe("Transform validation", func() {
		DescribeTable("DNAT validation",
			func(transform *wgov1alpha1.TransformAction, ipFamily wgov1alpha1.IPFamily, from, to *wgov1alpha1.FlowTrafficSelector, shouldSucceed bool, errorSubstring string) {
				flow := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withIPFamily(ipFamily), withTransform(transform), withFrom(from), withTo(to)),
				})
				_, err := validator.ValidateCreate(ctx, flow)
				if shouldSucceed {
					Expect(err).ShouldNot(HaveOccurred())
				} else {
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorSubstring))
				}
			},
			Entry("accept valid DNAT", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeDNAT, Target: "192.168.1.1:8080"}, wgov1alpha1.IPFamilyIPv4, nil, nil, true, ""),
			Entry("accept valid DNAT with IPv6", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeDNAT, Target: "[2001:db8::1]:8080"}, wgov1alpha1.IPFamilyIPv6, nil, nil, true, ""),
			Entry("deny DNAT without target", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeDNAT}, wgov1alpha1.IPFamilyIPv4, nil, nil, false, "DNAT requires transform.target"),
			Entry("deny DNAT with invalid target", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeDNAT, Target: "192.168.1.1"}, wgov1alpha1.IPFamilyIPv4, nil, nil, false, "invalid DNAT target"),
			Entry("deny DNAT with to.self", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeDNAT, Target: "192.168.1.1:8080"}, wgov1alpha1.IPFamilyIPv4, nil, selector(withSelf()), false, "DNAT cannot be used with to.self"),
			Entry("deny DNAT with from.self", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeDNAT, Target: "192.168.1.1:8080"}, wgov1alpha1.IPFamilyIPv4, selector(withSelf()), nil, false, "DNAT cannot be used with"),
		)

		DescribeTable("Masquerade validation",
			func(transform *wgov1alpha1.TransformAction, from, to *wgov1alpha1.FlowTrafficSelector, shouldSucceed bool, errorSubstring string) {
				flow := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withTransform(transform), withFrom(from), withTo(to)),
				})
				_, err := validator.ValidateCreate(ctx, flow)
				if shouldSucceed {
					Expect(err).ShouldNot(HaveOccurred())
				} else {
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorSubstring))
				}
			},
			Entry("accept Masquerade with explicit interface", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeMasquerade, Interface: "wg0"}, nil, nil, true, ""),
			Entry("accept Masquerade with to.interfaces", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeMasquerade}, nil, selector(withInterfaces("wg0")), true, ""),
			Entry("deny Masquerade without interface", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeMasquerade}, nil, nil, false, "requires transform.interface or to.interfaces"),
			Entry("deny Masquerade with from.self", &wgov1alpha1.TransformAction{Type: wgov1alpha1.TransformTypeMasquerade, Interface: "wg0"}, selector(withSelf()), nil, false, "cannot be used with from.self"),
			Entry("deny invalid transform type", &wgov1alpha1.TransformAction{Type: "invalid"}, selector(withSelf()), nil, false, "unknown transform type: invalid"),
		)
	})

	Describe("Filter validation", func() {
		It("should accept rateLimit with Allow action", func() {
			flow := flow([]wgov1alpha1.FlowRule{
				flowRule("test", withFilter(&wgov1alpha1.FilterAction{
					Action:    wgov1alpha1.PolicyActionAllow,
					RateLimit: &wgov1alpha1.RateLimitSpec{},
				})),
			})
			_, err := validator.ValidateCreate(ctx, flow)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should reject rateLimit with Drop action", func() {
			flow := flow([]wgov1alpha1.FlowRule{
				flowRule("test", withFilter(&wgov1alpha1.FilterAction{
					Action:    wgov1alpha1.PolicyActionDrop,
					RateLimit: &wgov1alpha1.RateLimitSpec{},
				})),
			})
			_, err := validator.ValidateCreate(ctx, flow)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("rateLimit is only supported with filter.action=Allow"))
		})
	})

	Describe("IP family consistency", func() {
		DescribeTable("from.ipBlocks IP family consistency",
			func(ipFamily wgov1alpha1.IPFamily, ipBlocks []string, shouldSucceed bool, errorSubstring string) {
				flow := flow([]wgov1alpha1.FlowRule{
					flowRule("test",
						withIPFamily(ipFamily),
						withFrom(selector(withIPBlocks(ipBlocks...)))),
				})
				_, err := validator.ValidateCreate(ctx, flow)
				if shouldSucceed {
					Expect(err).ShouldNot(HaveOccurred())
				} else {
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorSubstring))
				}
			},
			Entry("accept IPv4 with IPv4 family", wgov1alpha1.IPFamilyIPv4, []string{"10.0.0.0/24"}, true, ""),
			Entry("deny IPv6 with IPv4 family", wgov1alpha1.IPFamilyIPv4, []string{"2001:db8::/64"}, false, "from.ipBlocks"),
			Entry("accept IPv6 with IPv6 family", wgov1alpha1.IPFamilyIPv6, []string{"2001:db8::/64"}, true, ""),
			Entry("deny IPv4 with IPv6 family", wgov1alpha1.IPFamilyIPv6, []string{"10.0.0.0/24"}, false, "from.ipBlocks"),
			Entry("deny invalid IP address", wgov1alpha1.IPFamilyIPv4, []string{"invalid-ip"}, false, "not a valid IP"),
			Entry("deny unknown IP family", wgov1alpha1.IPFamily("UnknownFamily"), []string{"10.0.0.0/24"}, false, "unknown IP family"),
		)

		DescribeTable("to.ipBlocks IP family consistency",
			func(ipFamily wgov1alpha1.IPFamily, ipBlocks []string, shouldSucceed bool, errorSubstring string) {
				flow := flow([]wgov1alpha1.FlowRule{
					flowRule("test",
						withIPFamily(ipFamily),
						withTo(selector(withIPBlocks(ipBlocks...)))),
				})
				_, err := validator.ValidateCreate(ctx, flow)
				if shouldSucceed {
					Expect(err).ShouldNot(HaveOccurred())
				} else {
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorSubstring))
				}
			},
			Entry("accept IPv4 with IPv4 family", wgov1alpha1.IPFamilyIPv4, []string{"10.0.0.0/24"}, true, ""),
			Entry("deny IPv6 with IPv4 family", wgov1alpha1.IPFamilyIPv4, []string{"2001:db8::/64"}, false, "to.ipBlocks"),
			Entry("accept IPv6 with IPv6 family", wgov1alpha1.IPFamilyIPv6, []string{"2001:db8::/64"}, true, ""),
			Entry("deny IPv4 with IPv6 family", wgov1alpha1.IPFamilyIPv6, []string{"10.0.0.0/24"}, false, "to.ipBlocks"),
			Entry("deny invalid IP address", wgov1alpha1.IPFamilyIPv4, []string{"invalid-ip"}, false, "not a valid IP"),
			Entry("deny unknown IP family", wgov1alpha1.IPFamily("UnknownFamily"), []string{"10.0.0.0/24"}, false, "unknown IP family"),
		)

		DescribeTable("transform.target IP family consistency",
			func(ipFamily wgov1alpha1.IPFamily, target string, transformType wgov1alpha1.TransformType, shouldSucceed bool, errorSubstring string) {
				flow := flow([]wgov1alpha1.FlowRule{
					flowRule("test",
						withIPFamily(ipFamily),
						withTransform(&wgov1alpha1.TransformAction{Type: transformType, Target: target})),
				})
				_, err := validator.ValidateCreate(ctx, flow)
				if shouldSucceed {
					Expect(err).ShouldNot(HaveOccurred())
				} else {
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorSubstring))
				}
			},
			Entry("accept IPv4 DNAT with IPv4 family", wgov1alpha1.IPFamilyIPv4, "192.168.1.1:8080", wgov1alpha1.TransformTypeDNAT, true, ""),
			Entry("deny IPv6 DNAT with IPv4 family", wgov1alpha1.IPFamilyIPv4, "[2001:db8::1]:8080", wgov1alpha1.TransformTypeDNAT, false, "transform.target"),
			Entry("accept IPv6 DNAT with IPv6 family", wgov1alpha1.IPFamilyIPv6, "[2001:db8::1]:8080", wgov1alpha1.TransformTypeDNAT, true, ""),
			Entry("deny IPv4 DNAT with IPv6 family", wgov1alpha1.IPFamilyIPv6, "192.168.1.1:8080", wgov1alpha1.TransformTypeDNAT, false, "transform.target"),
			Entry("deny invalid IP in target", wgov1alpha1.IPFamilyIPv4, "invalid-ip:8080", wgov1alpha1.TransformTypeDNAT, false, "not a valid IP"),
			Entry("deny unknown IP family", wgov1alpha1.IPFamily("UnknownFamily"), "192.168.1.1:8080", wgov1alpha1.TransformTypeDNAT, false, "unknown IP family"),
			Entry("deny invalid port in target", wgov1alpha1.IPFamilyIPv4, "192.168.1.1:99999", wgov1alpha1.TransformTypeDNAT, false, "invalid port"),
			Entry("deny target with non-DNAT transform", wgov1alpha1.IPFamilyIPv4, "192.168.1.1:8080", wgov1alpha1.TransformTypeMasquerade, false, "transform.target can only be specified with DNAT"),
		)
	})

	Describe("Protocol and port consistency", func() {
		DescribeTable("Port specification with protocols",
			func(protocol wgov1alpha1.Protocol, hasPorts bool, shouldSucceed bool) {
				var sel *wgov1alpha1.FlowTrafficSelector
				if hasPorts {
					port := wgov1alpha1.Port(80)
					sel = selector(withPorts(wgov1alpha1.PolicyPort{Port: &port}))
				}
				flow := flow([]wgov1alpha1.FlowRule{
					flowRule("test", withProtocol(protocol), withFrom(sel)),
				})
				_, err := validator.ValidateCreate(ctx, flow)
				if shouldSucceed {
					Expect(err).ShouldNot(HaveOccurred())
				} else {
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("ports"))
				}
			},
			Entry("accept ports with TCP", wgov1alpha1.ProtocolTCP, true, true),
			Entry("accept ports with UDP", wgov1alpha1.ProtocolUDP, true, true),
			Entry("accept ports with Any", wgov1alpha1.ProtocolAny, true, true),
			Entry("deny ports with ICMP", wgov1alpha1.ProtocolICMP, true, false),
			Entry("deny ports with ICMPv6", wgov1alpha1.ProtocolICMPv6, true, false),
			Entry("accept no ports with ICMP", wgov1alpha1.ProtocolICMP, false, true),
		)
	})

	Describe("ValidateUpdate runs create validations", func() {
		It("should reject update with invalid flow", func() {
			oldFlow := flow([]wgov1alpha1.FlowRule{
				flowRule("test"),
			})
			newFlow := flow([]wgov1alpha1.FlowRule{
				flowRule("test", withProtocol(wgov1alpha1.ProtocolICMP), withIPFamily(wgov1alpha1.IPFamilyIPv6)),
			})
			_, err := validator.ValidateUpdate(ctx, oldFlow, newFlow)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ICMP protocol requires ipFamily: IPv4"))
		})
	})

	Describe("Validate Breaking", func() {
		It("should reject update with invalid flow", func() {
			flow := flow([]wgov1alpha1.FlowRule{
				flowRule("test", withProtocol("NotAProtocol"), withFrom(selector(withPorts(policyPort(80, 80)))))})

			_, err := validator.ValidateCreate(ctx, flow)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ports can only be specified with TCP, UDP, or Any protocol"))
		})
	})
})
