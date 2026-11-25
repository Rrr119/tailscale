// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package postureacl

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnlocal/ipnlocaltest"
	"tailscale.com/postureacl"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

// e2eCheck is a health check whose result can be flipped at runtime to drive
// posture transitions through the real LocalBackend extension pipeline.
type e2eCheck struct {
	sync.Mutex
	err error
}

func (c *e2eCheck) Name() string   { return "e2e-check" }
func (c *e2eCheck) Critical() bool { return true }
func (c *e2eCheck) Check() postureacl.CheckResult {
	c.Lock()
	defer c.Unlock()
	return postureacl.CheckResult{Name: c.Name(), Critical: true, Healthy: c.err == nil, Err: c.err}
}
func (c *e2eCheck) fail(err error) { c.Lock(); defer c.Unlock(); c.err = err }
func (c *e2eCheck) pass()          { c.Lock(); defer c.Unlock(); c.err = nil }

// TestPostureACLEndToEnd drives a real LocalBackend with the postureacl
// extension installed and verifies the complete zero-trust loop: a device
// health change flips the posture, the change callback requests a filter
// rebuild, and the rebuilt packet filter enforces the new ACL within the
// 5-second [postureacl.MaxSwitchLatency] budget.
func TestPostureACLEndToEnd(t *testing.T) {
	check := &e2eCheck{}
	restore := postureacl.RegisterCheckProviderForTest(func() ([]postureacl.HealthCheck, error) {
		return []postureacl.HealthCheck{check}, nil
	})
	t.Cleanup(restore)

	b := ipnlocaltest.NewBackend(t)
	b.ForTest().InitExtensions()

	ext, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		t.Fatal("postureacl extension not registered on LocalBackend")
	}

	src := netip.MustParsePrefix("100.64.0.9/32")
	self := netip.MustParsePrefix("100.64.0.1/32")
	baseRules := []tailcfg.FilterRule{{
		SrcIPs: []string{src.Addr().String()},
		DstPorts: []tailcfg.NetPortRange{
			{IP: self.Addr().String(), Ports: tailcfg.PortRange{First: 0, Last: 65535}},
		},
	}}
	matches, err := filter.MatchesFromFilterRules(baseRules)
	if err != nil {
		t.Fatalf("MatchesFromFilterRules: %v", err)
	}

	if err := b.ForTest().SetPersist(&persist.Persist{}); err != nil {
		t.Fatalf("SetPersist: %v", err)
	}
	b.ForTest().ApplyNetMap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{self},
		}).View(),
		PacketFilter:      matches,
		PacketFilterRules: views.SliceOf(baseRules),
	})
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true})
	b.ForTest().SetState(ipn.Running)

	srcAddr, dstAddr := src.Addr(), self.Addr()

	// Wait for the controller's first evaluation to reach the healthy state.
	waitFor(t, time.Second, func() bool {
		return ext.controller.State() == postureacl.StateHealthy &&
			b.ForTest().GetFilter().Check(srcAddr, dstAddr, 443, ipproto.TCP) == filter.Accept
	})
	if got := b.ForTest().GetFilter().Check(srcAddr, dstAddr, 443, ipproto.TCP); got != filter.Accept {
		t.Fatalf("healthy node should reach port 443, got %v", got)
	}

	// Flip the device to an unhealthy state. The controller's next tick (1s
	// interval) must quarantine it and the OnChange callback must rebuild the
	// filter, all within MaxSwitchLatency.
	check.fail(assertErr("critical health check failed"))
	deadline := time.Now().Add(postureacl.MaxSwitchLatency)
	waitFor(t, postureacl.MaxSwitchLatency, func() bool {
		return b.ForTest().GetFilter().Check(srcAddr, dstAddr, 443, ipproto.TCP) != filter.Accept
	})
	if time.Now().After(deadline) {
		t.Fatalf("quarantine did not take effect within %v", postureacl.MaxSwitchLatency)
	}
	if state := ext.controller.State(); state != postureacl.StateQuarantined {
		t.Fatalf("state = %v, want quarantined", state)
	}

	// Recovery restores full access, again within the latency budget.
	check.pass()
	deadline = time.Now().Add(postureacl.MaxSwitchLatency)
	waitFor(t, postureacl.MaxSwitchLatency, func() bool {
		return b.ForTest().GetFilter().Check(srcAddr, dstAddr, 443, ipproto.TCP) == filter.Accept
	})
	if time.Now().After(deadline) {
		t.Fatalf("recovery did not take effect within %v", postureacl.MaxSwitchLatency)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

type stringError string

func (e stringError) Error() string { return string(e) }

func assertErr(msg string) error { return stringError(msg) }
