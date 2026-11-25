// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package postureacl

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
)

// MaxSwitchLatency is the upper bound on how long a posture change takes to
// propagate into an ACL adjustment. The monitor polls health checks at
// [DefaultCheckInterval] and re-evaluates the filter immediately on a
// transition, so a real device change is picked up well within this window.
const MaxSwitchLatency = 5 * time.Second

// DefaultCheckInterval is how often the controller runs the registered
// health checks. It is one second, leaving comfortable headroom under
// [MaxSwitchLatency] even when a check itself takes some time.
const DefaultCheckInterval = time.Second

// ChangeFunc is notified after the device posture changes. The callback runs
// on the monitor goroutine, so it must not block: implementations should hand
// work off (for example, enqueue a filter rebuild) and return.
type ChangeFunc func(state State, results []CheckResult)

// CheckProvider builds the set of [HealthCheck]s used by a [Controller].
// Platform-specific packages (or tests) register a provider via
// [RegisterCheckProvider] to supply real device-health probes without this
// package depending on platform APIs.
type CheckProvider func() ([]HealthCheck, error)

var (
	providerMu sync.Mutex
	providers  []CheckProvider
)

// RegisterCheckProvider adds a provider of device health checks. Providers
// are consulted in registration order by [RegisteredChecks]. It is typically
// called from a platform package's init.
func RegisterCheckProvider(p CheckProvider) {
	if p == nil {
		return
	}
	providerMu.Lock()
	providers = append(providers, p)
	providerMu.Unlock()
}

// RegisteredChecks collects checks from every registered provider. A provider
// error aborts collection and is returned to the caller. When no providers are
// registered a single always-healthy check is returned so a controller can
// still run; platforms are expected to register real probes.
func RegisteredChecks() ([]HealthCheck, error) {
	providerMu.Lock()
	ps := append([]CheckProvider(nil), providers...)
	providerMu.Unlock()

	var checks []HealthCheck
	for _, p := range ps {
		provided, err := p()
		if err != nil {
			return nil, err
		}
		checks = append(checks, provided...)
	}
	if len(checks) == 0 {
		checks = []HealthCheck{
			CheckFunc{
				CheckName:  "no-platform-checks",
				IsCritical: false,
				Fn:         func() error { return nil },
			},
		}
	}
	return checks, nil
}

// Config configures a [Controller].
type Config struct {
	// Checks are the health checks used to derive the device posture.
	Checks []HealthCheck

	// Policy adjusts the base ACL rules for each posture. The zero value
	// uses [DefaultSensitivePorts].
	Policy Policy

	// Interval is the time between health-check runs. If zero,
	// [DefaultCheckInterval] is used. Values at or above
	// [MaxSwitchLatency] are rejected by [NewController].
	Interval time.Duration

	// OnChange, if non-nil, is invoked on every posture transition. This is
	// the hook the local backend uses to rebuild and install its packet
	// filter so the new ACL takes effect immediately.
	OnChange ChangeFunc

	// Clock is used for the periodic ticker. Tests inject a fake clock;
	// production code can leave it nil to use the standard clock.
	Clock tstime.Clock

	// Logf, if nil, discards logs.
	Logf logger.Logf
}

// Controller periodically evaluates the local device's health checks, tracks
// the resulting [State], and drives dynamic ACL adjustments.
//
// A Controller is safe for concurrent use.
type Controller struct {
	logf     logger.Logf
	clock    tstime.Clock
	checks   []HealthCheck
	policy   Policy
	interval time.Duration
	onChange ChangeFunc

	mu      sync.Mutex
	state   State
	results []CheckResult
	started bool

	cancel context.CancelFunc
	done   chan struct{}
}

// NewController validates cfg and returns a stopped Controller. The initial
// posture is [StateUnknown], which enforces the fail-closed profile until the
// first successful [Controller.Run] or [Controller.checkOnce].
func NewController(cfg Config) (*Controller, error) {
	if len(cfg.Checks) == 0 {
		return nil, errors.New("postureacl: at least one health check is required")
	}
	names := make(map[string]bool, len(cfg.Checks))
	for _, c := range cfg.Checks {
		if c == nil {
			return nil, errors.New("postureacl: nil health check")
		}
		if c.Name() == "" {
			return nil, errors.New("postureacl: health check has an empty name")
		}
		if names[c.Name()] {
			return nil, fmt.Errorf("postureacl: duplicate health check name %q", c.Name())
		}
		names[c.Name()] = true
	}

	interval := cfg.Interval
	if interval == 0 {
		interval = DefaultCheckInterval
	}
	if interval <= 0 {
		return nil, fmt.Errorf("postureacl: interval must be positive, got %v", interval)
	}
	if interval >= MaxSwitchLatency {
		return nil, fmt.Errorf("postureacl: interval %v must be below %v to meet the switch-latency requirement", interval, MaxSwitchLatency)
	}

	clock := cfg.Clock
	if clock == nil {
		clock = tstime.StdClock{}
	}
	logf := cfg.Logf
	if logf == nil {
		logf = logger.Discard
	}

	return &Controller{
		logf:     logf,
		clock:    clock,
		checks:   append([]HealthCheck(nil), cfg.Checks...),
		policy:   cfg.Policy,
		interval: interval,
		onChange: cfg.OnChange,
		state:    StateUnknown,
	}, nil
}

// State returns the most recently evaluated device posture.
func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Results returns a copy of the most recent health-check results.
func (c *Controller) Results() []CheckResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]CheckResult(nil), c.results...)
}

// Policy returns the policy used to adjust base rules per posture.
func (c *Controller) Policy() Policy { return c.policy }

// Clock returns the clock used by the controller's periodic loop.
func (c *Controller) Clock() tstime.Clock { return c.clock }

// Interval returns the time between health-check runs.
func (c *Controller) Interval() time.Duration { return c.interval }

// ApplyRules applies the current posture's profile to the base rules. It is
// safe to call on every filter rebuild: [StateHealthy] returns base unchanged.
func (c *Controller) ApplyRules(base []tailcfg.FilterRule) []tailcfg.FilterRule {
	return c.policy.ApplyRules(base, c.State())
}

// Run starts the periodic health-check loop and blocks until ctx is done. It
// runs an immediate check before waiting for the first tick, so the device's
// posture is established as soon as the controller starts rather than after a
// full interval. Calling Run more than once without an intervening [Close] is
// an error.
func (c *Controller) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("postureacl: controller already running")
	}
	c.started = true
	ctx, c.cancel = context.WithCancel(ctx)
	c.done = make(chan struct{})
	c.mu.Unlock()

	defer close(c.done)

	// Evaluate immediately so an unhealthy device never spends a full
	// interval with more access than its posture permits.
	c.checkOnce(ctx)

	ticker, ch := c.clock.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ch:
			c.checkOnce(ctx)
		}
	}
}

// Close stops the background loop started by [Run], if any. It is safe to
// call on a controller that was never started.
func (c *Controller) Close() error {
	c.mu.Lock()
	cancel := c.cancel
	done := c.done
	c.cancel = nil
	c.done = nil
	c.started = false
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return nil
}

// checkOnce runs every health check, evaluates the new posture, and fires the
// change callback when the posture transitions.
func (c *Controller) checkOnce(ctx context.Context) {
	results := make([]CheckResult, 0, len(c.checks))
	for _, check := range c.checks {
		if ctx.Err() != nil {
			return
		}
		r := check.Check()
		if r.Name == "" {
			r.Name = check.Name()
		}
		r.Critical = check.Critical()
		results = append(results, r)
		if !r.Healthy {
			c.logf("posture check %q failed (critical=%v): %v", r.Name, r.Critical, r.Err)
		}
	}

	newState := Evaluate(results)

	c.mu.Lock()
	oldState := c.state
	c.state = newState
	c.results = results
	onChange := c.onChange
	c.mu.Unlock()

	if newState != oldState {
		c.logf("device posture changed: %v -> %v", oldState, newState)
		if onChange != nil {
			onChange(newState, results)
		}
	}
}

// CheckOnce runs one evaluation outside the periodic loop and reports the
// resulting posture. It is primarily useful for tests and for forcing an
// immediate refresh after a notable system event.
func (c *Controller) CheckOnce() State {
	c.checkOnce(context.Background())
	return c.State()
}
