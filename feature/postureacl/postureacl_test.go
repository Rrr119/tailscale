// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package postureacl

import (
	"errors"
	"testing"
	"time"

	"tailscale.com/postureacl"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
)

// safeBackendShim is a minimal [ipnext.SafeBackend] for exercising the
// extension without standing up a full LocalBackend.
type safeBackendShim struct {
	sys     *tsd.System
	clock   *tstest.Clock
	varRoot string
}

func (b safeBackendShim) Sys() *tsd.System         { return b.sys }
func (b safeBackendShim) Clock() tstime.Clock      { return b.clock }
func (b safeBackendShim) TailscaleVarRoot() string { return b.varRoot }

// newTestExtension builds an extension whose single check can be flipped.
func newTestExtension(t *testing.T, healthy bool) (*extension, *tstest.Clock) {
	t.Helper()

	check := &flipCheck{name: "test-check", critical: true, err: nil}
	if !healthy {
		check.err = errors.New("sick")
	}
	restore := postureacl.RegisterCheckProviderForTest(func() ([]postureacl.HealthCheck, error) {
		return []postureacl.HealthCheck{check}, nil
	})
	t.Cleanup(restore)

	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(1_700_000_000, 0)})
	sys := tsd.NewSystem()

	sb := safeBackendShim{sys: sys, clock: clock, varRoot: t.TempDir()}
	ext, err := newExtension(logger.WithPrefix(t.Logf, ""), sb)
	if err != nil {
		t.Fatalf("newExtension: %v", err)
	}
	e := ext.(*extension)
	t.Cleanup(func() { e.Shutdown() })
	return e, clock
}

type flipCheck struct {
	name     string
	critical bool
	err      error
}

func (c *flipCheck) Name() string   { return c.name }
func (c *flipCheck) Critical() bool { return c.critical }
func (c *flipCheck) Check() postureacl.CheckResult {
	return postureacl.CheckResult{Name: c.name, Critical: c.critical, Healthy: c.err == nil, Err: c.err}
}

func TestExtensionTransformsRulesByPosture(t *testing.T) {
	ext, _ := newTestExtension(t, true)

	base := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.1"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.64.0.2", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
			},
		},
	}

	// Before the first evaluation the posture is unknown and must fail closed.
	if got := ext.transformRules(base); len(got) != 0 {
		t.Fatalf("unknown posture must withdraw rules, got %+v", got)
	}

	// One explicit evaluation establishes the healthy posture.
	if state := ext.controller.CheckOnce(); state != postureacl.StateHealthy {
		t.Fatalf("state = %v, want healthy", state)
	}
	if got := ext.transformRules(base); len(got) != len(base) {
		t.Fatalf("healthy posture must keep base rules, got %d want %d", len(got), len(base))
	}
}

func TestExtensionReportsHealthWarning(t *testing.T) {
	ext, _ := newTestExtension(t, false)

	if ext.health.IsUnhealthy(postureWarnable) {
		t.Fatal("warnable should start healthy")
	}

	state := ext.controller.CheckOnce()
	if state != postureacl.StateQuarantined {
		t.Fatalf("state = %v, want quarantined", state)
	}
	ext.updateHealth(state, ext.controller.Results())
	if !ext.health.IsUnhealthy(postureWarnable) {
		t.Fatal("quarantined posture must raise the health warning")
	}

	// Recovery clears the warning.
	ext.updateHealth(postureacl.StateHealthy, nil)
	if ext.health.IsUnhealthy(postureWarnable) {
		t.Fatal("healthy posture must clear the health warning")
	}
}

func TestExtensionShutdownIsSafeWithoutInit(t *testing.T) {
	ext, _ := newTestExtension(t, true)
	// Shutdown before Init must not block or panic; the controller was never
	// started but Close is documented as safe on a stopped controller.
	if err := ext.Shutdown(); err != nil {
		t.Fatalf("Shutdown without Init: %v", err)
	}
}
