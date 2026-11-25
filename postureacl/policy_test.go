// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package postureacl

import (
	"testing"

	"tailscale.com/tailcfg"
)

func rule(srcs []string, dsts ...tailcfg.NetPortRange) tailcfg.FilterRule {
	return tailcfg.FilterRule{SrcIPs: srcs, DstPorts: dsts}
}

func dst(ip string, first, last uint16) tailcfg.NetPortRange {
	return tailcfg.NetPortRange{IP: ip, Ports: tailcfg.PortRange{First: first, Last: last}}
}

// sampleBasePolicy is a representative control-plane policy: a broad rule
// covering many ports, a narrow single-port rule, and a capability grant.
func sampleBasePolicy() []tailcfg.FilterRule {
	return []tailcfg.FilterRule{
		rule([]string{"100.64.0.1"},
			dst("100.64.0.2", 0, 65535),
		),
		rule([]string{"100.64.0.3"},
			dst("100.64.0.2", 22, 22),
			dst("100.64.0.2", 80, 80),
		),
		{
			SrcIPs:   []string{"100.64.0.4"},
			CapGrant: []tailcfg.CapGrant{{Caps: []tailcfg.PeerCapability{"foo"}}},
		},
	}
}

func TestPolicyHealthyReturnsBaseUnchanged(t *testing.T) {
	base := sampleBasePolicy()
	got := Policy{}.ApplyRules(base, StateHealthy)
	if len(got) != len(base) {
		t.Fatalf("healthy posture changed rule count: got %d want %d", len(got), len(base))
	}
	for i := range base {
		if !rulesEqual(got[i], base[i]) {
			t.Errorf("rule %d altered in healthy posture:\n got %+v\nwant %+v", i, got[i], base[i])
		}
	}
}

func TestPolicyQuarantinedWithdrawsAllRules(t *testing.T) {
	for _, state := range []State{StateQuarantined, StateUnknown} {
		t.Run(state.String(), func(t *testing.T) {
			got := Policy{}.ApplyRules(sampleBasePolicy(), state)
			if len(got) != 0 {
				t.Fatalf("%s must withdraw every inbound rule, got %d: %+v", state, len(got), got)
			}
		})
	}
}

func TestPolicyDegradedRemovesSensitivePorts(t *testing.T) {
	got := Policy{}.ApplyRules(sampleBasePolicy(), StateDegraded)

	// The pure capability-grant rule is withheld while degraded.
	for _, r := range got {
		if len(r.CapGrant) != 0 {
			t.Fatalf("capability grants must be withheld while degraded, got %+v", r)
		}
	}

	// No remaining destination may cover a sensitive port.
	for _, r := range got {
		for _, d := range r.DstPorts {
			for _, sensitive := range DefaultSensitivePorts {
				if d.Ports.First <= sensitive && sensitive <= d.Ports.Last {
					t.Fatalf("sensitive port %d still reachable via %+v in rule %+v", sensitive, d, r)
				}
			}
		}
	}

	// The narrow rule's non-sensitive port 80 survives, while its port-22
	// destination is pruned and the rule itself is retained.
	var foundPort80 bool
	for _, r := range got {
		for _, d := range r.DstPorts {
			if d.Ports.First == 80 && d.Ports.Last == 80 {
				foundPort80 = true
			}
		}
	}
	if !foundPort80 {
		t.Fatalf("non-sensitive port 80 should remain reachable, got %+v", got)
	}

	// The all-ports wildcard rule is split into ranges around the sensitive
	// ports rather than dropped wholesale.
	var sawWildcardSource bool
	for _, r := range got {
		if len(r.SrcIPs) == 1 && r.SrcIPs[0] == "100.64.0.1" {
			sawWildcardSource = true
			if len(r.DstPorts) < 2 {
				t.Fatalf("wildcard rule should be split into multiple safe ranges, got %+v", r.DstPorts)
			}
		}
	}
	if !sawWildcardSource {
		t.Fatalf("wildcard source rule should survive in restricted form")
	}
}

func TestPolicyDegradedNeverExpandsAccess(t *testing.T) {
	// Compatibility invariant: every port granted while degraded must also be
	// granted by the base policy.
	base := sampleBasePolicy()
	got := Policy{}.ApplyRules(base, StateDegraded)

	for _, rule := range got {
		for _, d := range rule.DstPorts {
			if !baseGrantsRange(base, rule.SrcIPs, d) {
				t.Fatalf("degraded profile granted %v -> %+v which the base policy does not allow", rule.SrcIPs, d)
			}
		}
	}
}

func TestPolicyDoesNotMutateBase(t *testing.T) {
	base := sampleBasePolicy()
	original := len(base[0].DstPorts)
	_ = Policy{}.ApplyRules(base, StateDegraded)
	if len(base[0].DstPorts) != original {
		t.Fatal("ApplyRules mutated the base rule slice")
	}
}

func TestPolicyCustomSensitivePorts(t *testing.T) {
	base := []tailcfg.FilterRule{rule([]string{"*"}, dst("*", 0, 1000))}
	p := Policy{SensitivePorts: []uint16{443}}
	got := p.ApplyRules(base, StateDegraded)
	if len(got) != 1 || len(got[0].DstPorts) != 2 {
		t.Fatalf("expected two ranges around port 443, got %+v", got)
	}
	for _, d := range got[0].DstPorts {
		if d.Ports.First <= 443 && 443 <= d.Ports.Last {
			t.Fatalf("custom sensitive port 443 still covered by %+v", d)
		}
	}
}

func TestSplitRangeAroundSensitiveBoundaries(t *testing.T) {
	sensitive := []uint16{10, 20}

	// Range fully before the sensitive ports is untouched.
	if got := splitRangeAroundSensitive(dst("*", 1, 9), sensitive); len(got) != 1 {
		t.Fatalf("non-overlapping range should be untouched, got %+v", got)
	}

	// Sensitive ports at both edges.
	got := splitRangeAroundSensitive(dst("*", 10, 20), sensitive)
	want := []tailcfg.NetPortRange{dst("*", 11, 19)}
	if !sameRanges(got, want) {
		t.Fatalf("edge split = %+v, want %+v", got, want)
	}

	// Sensitive port at the very top of the uint16 space must not wrap.
	top := splitRangeAroundSensitive(dst("*", 65534, 65535), []uint16{65535})
	if !sameRanges(top, []tailcfg.NetPortRange{dst("*", 65534, 65534)}) {
		t.Fatalf("uint16 top boundary split wrong: %+v", top)
	}
}

// baseGrantsRange reports whether some base rule with an overlapping source
// permits the full destination port range of d to the same destination IP.
func baseGrantsRange(base []tailcfg.FilterRule, srcs []string, d tailcfg.NetPortRange) bool {
	for _, r := range base {
		if !sameStringSet(r.SrcIPs, srcs) {
			continue
		}
		for _, bd := range r.DstPorts {
			if bd.IP == d.IP && bd.Ports.First <= d.Ports.First && d.Ports.Last <= bd.Ports.Last {
				return true
			}
		}
	}
	return false
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
	}
	return true
}

func rulesEqual(a, b tailcfg.FilterRule) bool {
	if len(a.SrcIPs) != len(b.SrcIPs) || len(a.DstPorts) != len(b.DstPorts) || len(a.CapGrant) != len(b.CapGrant) {
		return false
	}
	for i := range a.SrcIPs {
		if a.SrcIPs[i] != b.SrcIPs[i] {
			return false
		}
	}
	for i := range a.DstPorts {
		if !netPortRangeEqual(a.DstPorts[i], b.DstPorts[i]) {
			return false
		}
	}
	return true
}

func sameRanges(a, b []tailcfg.NetPortRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !netPortRangeEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func netPortRangeEqual(a, b tailcfg.NetPortRange) bool {
	return a.IP == b.IP && a.Ports == b.Ports
}
