// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

// TestTransformFilterRulesHook verifies the dynamic-ACL integration point in
// updateFilterLocked: a transform installed via the FilterHooks rewrites the
// control-plane rules before they are compiled, and rebuilding the filter
// applies a different posture's profile without any netmap change.
func TestTransformFilterRulesHook(t *testing.T) {
	lb := newLocalBackendWithTestControl(t, false, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
		return newClient(tb, opts)
	})
	if err := lb.Start(ipn.Options{}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	src := netip.MustParsePrefix("100.64.0.1/32")
	dstAddr := netip.MustParsePrefix("100.64.0.2/32")

	baseRules := []tailcfg.FilterRule{{
		SrcIPs: []string{src.Addr().String()},
		DstPorts: []tailcfg.NetPortRange{
			{IP: dstAddr.Addr().String(), Ports: tailcfg.PortRange{First: 22, Last: 22}},
			{IP: dstAddr.Addr().String(), Ports: tailcfg.PortRange{First: 80, Last: 80}},
		},
	}}
	matches, err := filter.MatchesFromFilterRules(baseRules)
	if err != nil {
		t.Fatalf("MatchesFromFilterRules: %v", err)
	}

	controlClient := lb.cc.(*mockControl)
	controlClient.send(sendOpt{nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{dstAddr},
		}).View(),
		PacketFilter:      matches,
		PacketFilterRules: views.SliceOf(baseRules),
	}})

	srcAddr := src.Addr()
	dstIP := dstAddr.Addr()

	// Without a transform, both base-policy ports are reachable.
	filt := lb.ForTest().GetFilter()
	if got := filt.Check(srcAddr, dstIP, 22, ipproto.TCP); got != filter.Accept {
		t.Fatalf("baseline port 22 = %v, want Accept", got)
	}
	if got := filt.Check(srcAddr, dstIP, 80, ipproto.TCP); got != filter.Accept {
		t.Fatalf("baseline port 80 = %v, want Accept", got)
	}

	// Install a transform that removes the SSH destination, mimicking the
	// degraded posture, and force a filter rebuild.
	restore := lb.extHost.hooks.Filter.TransformFilterRules.SetForTest(func(base []tailcfg.FilterRule) []tailcfg.FilterRule {
		out := make([]tailcfg.FilterRule, 0, len(base))
		for _, r := range base {
			r.DstPorts = filterOutPort(r.DstPorts, 22)
			if len(r.DstPorts) > 0 {
				out = append(out, r)
			}
		}
		return out
	})
	defer restore()

	lb.mu.Lock()
	lb.updateFilterLocked(lb.pm.CurrentPrefs())
	lb.mu.Unlock()

	filt = lb.ForTest().GetFilter()
	if got := filt.Check(srcAddr, dstIP, 22, ipproto.TCP); got == filter.Accept {
		t.Fatalf("transformed port 22 = Accept, want drop")
	}
	if got := filt.Check(srcAddr, dstIP, 80, ipproto.TCP); got != filter.Accept {
		t.Fatalf("transformed port 80 = %v, want Accept", got)
	}

	// A transform returning nil quarantines the node: nothing inbound is
	// accepted, but the base rules remain untouched in the netmap.
	restore2 := lb.extHost.hooks.Filter.TransformFilterRules.SetForTest(func([]tailcfg.FilterRule) []tailcfg.FilterRule {
		return nil
	})
	defer restore2()

	lb.mu.Lock()
	lb.updateFilterLocked(lb.pm.CurrentPrefs())
	lb.mu.Unlock()

	filt = lb.ForTest().GetFilter()
	for _, port := range []uint16{22, 80} {
		if got := filt.Check(srcAddr, dstIP, port, ipproto.TCP); got == filter.Accept {
			t.Fatalf("quarantined port %d = Accept, want drop", port)
		}
	}

	// Removing the transform restores the full control-plane policy.
	restore2() // back to the port-22 transform
	restore()  // back to no transform
	lb.mu.Lock()
	lb.updateFilterLocked(lb.pm.CurrentPrefs())
	lb.mu.Unlock()

	filt = lb.ForTest().GetFilter()
	if got := filt.Check(srcAddr, dstIP, 22, ipproto.TCP); got != filter.Accept {
		t.Fatalf("restored port 22 = %v, want Accept", got)
	}
}

func filterOutPort(ranges []tailcfg.NetPortRange, drop uint16) []tailcfg.NetPortRange {
	out := make([]tailcfg.NetPortRange, 0, len(ranges))
	for _, r := range ranges {
		if r.Ports.First == drop && r.Ports.Last == drop {
			continue
		}
		out = append(out, r)
	}
	return out
}
