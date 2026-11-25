// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package postureacl

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// mutableCheck is a HealthCheck whose pass/fail result can be flipped by the
// test to simulate a device state change while the controller is running.
type mutableCheck struct {
	name     string
	critical bool
	mu       sync.Mutex
	err      error
}

func (m *mutableCheck) Name() string     { return m.name }
func (m *mutableCheck) Critical() bool   { return m.critical }
func (m *mutableCheck) setErr(err error) { m.mu.Lock(); defer m.mu.Unlock(); m.err = err }

func (m *mutableCheck) Check() CheckResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return CheckResult{Name: m.name, Critical: m.critical, Healthy: m.err == nil, Err: m.err}
}

func newTestController(t *testing.T, interval time.Duration, checks ...HealthCheck) (*Controller, *tstest.Clock) {
	t.Helper()
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(1_700_000_000, 0)})
	c, err := NewController(Config{
		Checks:   checks,
		Interval: interval,
		Clock:    clock,
		Logf:     t.Logf,
	})
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c, clock
}

func TestNewControllerValidation(t *testing.T) {
	check := &mutableCheck{name: "x", critical: true}

	if _, err := NewController(Config{}); err == nil {
		t.Error("expected error when no checks are configured")
	}
	if _, err := NewController(Config{Checks: []HealthCheck{nil}}); err == nil {
		t.Error("expected error for a nil check")
	}
	if _, err := NewController(Config{Checks: []HealthCheck{&mutableCheck{name: ""}}}); err == nil {
		t.Error("expected error for an unnamed check")
	}
	if _, err := NewController(Config{Checks: []HealthCheck{check, check}}); err == nil {
		t.Error("expected error for duplicate check names")
	}
	if _, err := NewController(Config{Checks: []HealthCheck{check}, Interval: -time.Second}); err == nil {
		t.Error("expected error for a negative interval")
	}
	if _, err := NewController(Config{Checks: []HealthCheck{check}, Interval: MaxSwitchLatency}); err == nil {
		t.Error("expected error when interval is not strictly below MaxSwitchLatency")
	}
}

func TestControllerInitialStateIsUnknownAndFailClosed(t *testing.T) {
	c, _ := newTestController(t, time.Second, &mutableCheck{name: "x", critical: true})
	if got := c.State(); got != StateUnknown {
		t.Fatalf("initial state = %v, want StateUnknown", got)
	}
	base := []tailcfg.FilterRule{rule([]string{"*"}, dst("*", 0, 65535))}
	if got := c.ApplyRules(base); len(got) != 0 {
		t.Fatalf("unknown posture must fail closed, got %+v", got)
	}
}

func TestControllerCheckOnceTransitions(t *testing.T) {
	critical := &mutableCheck{name: CheckOSUpdates, critical: true}
	optional := &mutableCheck{name: CheckDiskEncryption, critical: false}
	c, _ := newTestController(t, time.Second, critical, optional)

	// All checks pass -> healthy, base policy unchanged.
	if got := c.CheckOnce(); got != StateHealthy {
		t.Fatalf("state = %v, want healthy", got)
	}
	base := sampleBasePolicy()
	if got := c.ApplyRules(base); len(got) != len(base) {
		t.Fatalf("healthy posture must keep the full base policy")
	}

	// Non-critical failure -> degraded, sensitive ports removed.
	optional.setErr(errors.New("unencrypted"))
	if got := c.CheckOnce(); got != StateDegraded {
		t.Fatalf("state = %v, want degraded", got)
	}
	if got := c.ApplyRules(base); len(got) >= len(base) {
		t.Fatalf("degraded posture must restrict the base policy, got %d rules", len(got))
	}

	// Critical failure -> quarantined, all inbound rules withdrawn.
	critical.setErr(errors.New("unpatched"))
	if got := c.CheckOnce(); got != StateQuarantined {
		t.Fatalf("state = %v, want quarantined", got)
	}
	if got := c.ApplyRules(base); len(got) != 0 {
		t.Fatalf("quarantined posture must withdraw all rules, got %+v", got)
	}

	// Recovery restores the full policy.
	critical.setErr(nil)
	optional.setErr(nil)
	if got := c.CheckOnce(); got != StateHealthy {
		t.Fatalf("state = %v, want healthy after recovery", got)
	}
	if got := c.ApplyRules(base); len(got) != len(base) {
		t.Fatalf("recovered posture must restore the full base policy")
	}
}

func TestControllerRunEvaluatesImmediately(t *testing.T) {
	check := &mutableCheck{name: "x", critical: true}
	c, clock := newTestController(t, time.Second, check)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := c.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	// Without advancing the clock at all, the immediate first evaluation must
	// already have established the healthy posture.
	waitForState(t, c, StateHealthy, time.Second)

	check.setErr(errors.New("boom"))
	clock.Advance(time.Second)
	waitForState(t, c, StateQuarantined, time.Second)
}

func TestControllerOnChangeFiresOnTransition(t *testing.T) {
	check := &mutableCheck{name: "x", critical: false}
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(1_700_000_000, 0)})

	changes := make(chan State, 8)
	c, err := NewController(Config{
		Checks:   []HealthCheck{check},
		Interval: time.Second,
		Clock:    clock,
		Logf:     t.Logf,
		OnChange: func(state State, _ []CheckResult) { changes <- state },
	})
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	// First callback: unknown -> healthy.
	select {
	case got := <-changes:
		if got != StateHealthy {
			t.Fatalf("first transition = %v, want healthy", got)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive initial posture transition")
	}

	// No transition means no callback while the posture stays healthy.
	clock.Advance(time.Second)
	select {
	case got := <-changes:
		t.Fatalf("unexpected transition while posture unchanged: %v", got)
	case <-time.After(50 * time.Millisecond):
	}

	// A failing check transitions to degraded and fires exactly once.
	check.setErr(errors.New("degraded"))
	clock.Advance(time.Second)
	select {
	case got := <-changes:
		if got != StateDegraded {
			t.Fatalf("transition = %v, want degraded", got)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive degraded transition")
	}

	// Recovery fires a transition back to healthy.
	check.setErr(nil)
	clock.Advance(time.Second)
	select {
	case got := <-changes:
		if got != StateHealthy {
			t.Fatalf("transition = %v, want healthy", got)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive recovery transition")
	}
}

// TestControllerSwitchLatencyWithinFiveSeconds is the timing requirement from
// the feature spec: after a device-state change, the posture transition and
// its ACL adjustment must take effect within 5 seconds. With a 1s polling
// interval the worst case is one interval plus the evaluation time, which the
// fake-clock-driven loop demonstrates deterministically while the wall-clock
// guard keeps the real implementation honest.
func TestControllerSwitchLatencyWithinFiveSeconds(t *testing.T) {
	check := &mutableCheck{name: "x", critical: false}
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(1_700_000_000, 0)})

	changed := make(chan struct{}, 4)
	c, err := NewController(Config{
		Checks:   []HealthCheck{check},
		Interval: DefaultCheckInterval,
		Clock:    clock,
		Logf:     t.Logf,
		OnChange: func(State, []CheckResult) { changed <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	waitForState(t, c, StateHealthy, time.Second)

	check.setErr(errors.New("disk unencrypted"))

	// Simulated time: the posture must flip within one polling interval.
	startSim := clock.Now()
	clock.Advance(DefaultCheckInterval)
	waitForState(t, c, StateDegraded, time.Second)
	if simLatency := clock.Now().Sub(startSim); simLatency > MaxSwitchLatency {
		t.Fatalf("simulated switch latency %v exceeds %v", simLatency, MaxSwitchLatency)
	}

	// Wall-clock guard: the OnChange callback that triggers the filter rebuild
	// must have fired well inside the 5 second budget on a real machine.
	deadline := time.Now().Add(MaxSwitchLatency)
	select {
	case <-changed:
	case <-time.After(time.Until(deadline)):
		t.Fatal("ACL change callback did not fire within 5 seconds")
	}
	if time.Now().After(deadline) {
		t.Fatalf("switch took longer than %v", MaxSwitchLatency)
	}
}

func TestControllerRunTwiceAndClose(t *testing.T) {
	check := &mutableCheck{name: "x", critical: true}
	c, _ := newTestController(t, time.Second, check)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := c.Run(ctx); err != nil {
			t.Errorf("first Run: %v", err)
		}
	}()
	waitForState(t, c, StateHealthy, time.Second)

	if err := c.Run(context.Background()); err == nil {
		t.Error("second Run without Close should fail")
	}

	cancel()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Closing a stopped controller and closing twice must be safe.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func waitForState(t *testing.T, c *Controller, want State, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.State() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("controller state = %v, want %v after %v", c.State(), want, timeout)
}
