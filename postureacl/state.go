// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package postureacl

import "fmt"

// State is the security posture of the local device, as derived from its
// health checks. It determines which dynamic ACL profile is enforced.
//
// The three states are ordered from most trusted to least trusted:
// [StateHealthy] > [StateDegraded] > [StateQuarantined].
type State uint8

const (
	// StateUnknown is the initial posture before the first health check has
	// run. It is fail-closed: it enforces the same restrictive profile as
	// [StateQuarantined] until a real posture can be determined.
	StateUnknown State = iota

	// StateHealthy means every critical health check passes and no check is
	// failing. The full base ACL policy is in effect.
	StateHealthy

	// StateDegraded means one or more non-critical health checks are failing,
	// but all critical checks still pass. Sensitive destinations are removed
	// from the base ACL policy while everything else continues to work.
	StateDegraded

	// StateQuarantined means at least one critical health check is failing.
	// All inbound ACL rules are withdrawn, leaving the node able to make
	// outbound connections but unable to receive traffic from peers.
	StateQuarantined
)

// String returns the human-readable name of the posture.
func (s State) String() string {
	switch s {
	case StateHealthy:
		return "healthy"
	case StateDegraded:
		return "degraded"
	case StateQuarantined:
		return "quarantined"
	case StateUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("posture(%d)", uint8(s))
	}
}

// MarshalText implements [encoding.TextMarshaler].
func (s State) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// CheckResult is the outcome of running a single [HealthCheck].
type CheckResult struct {
	// Name is the name of the health check that produced this result.
	Name string

	// Healthy reports whether the check passed.
	Healthy bool

	// Critical reports whether a failure of this check must quarantine the
	// device. A non-critical failure only degrades the posture.
	Critical bool

	// Err is the failure detail. It is nil when Healthy is true.
	Err error
}

// HealthCheck inspects one aspect of the local device's security posture,
// such as OS patch level, disk encryption, or whether a screen lock is
// enabled. Implementations must be safe to call repeatedly and concurrently
// with [Controller] state changes.
type HealthCheck interface {
	// Name returns a stable, unique identifier for the check.
	Name() string

	// Critical reports whether a failed check must quarantine the device.
	Critical() bool

	// Check runs the check and reports whether the device passes it.
	Check() CheckResult
}

// CheckFunc adapts a plain function and a critical flag into a [HealthCheck].
type CheckFunc struct {
	CheckName  string
	IsCritical bool
	Fn         func() error
}

// Name implements [HealthCheck].
func (c CheckFunc) Name() string { return c.CheckName }

// Critical implements [HealthCheck].
func (c CheckFunc) Critical() bool { return c.IsCritical }

// Check implements [HealthCheck]. A nil error means the check passes.
func (c CheckFunc) Check() CheckResult {
	err := c.Fn()
	return CheckResult{
		Name:     c.CheckName,
		Healthy:  err == nil,
		Critical: c.IsCritical,
		Err:      err,
	}
}

// Evaluate derives the device [State] from a set of health-check results.
//
// A critical failure yields [StateQuarantined]; any other failure yields
// [StateDegraded]; if every check passes (or there are no checks at all) the
// posture is [StateHealthy]. An empty result slice represents a device whose
// posture has not yet been measured and yields [StateUnknown].
func Evaluate(results []CheckResult) State {
	if len(results) == 0 {
		return StateUnknown
	}
	anyFailure := false
	for _, r := range results {
		if r.Healthy {
			continue
		}
		if r.Critical {
			return StateQuarantined
		}
		anyFailure = true
	}
	if anyFailure {
		return StateDegraded
	}
	return StateHealthy
}
