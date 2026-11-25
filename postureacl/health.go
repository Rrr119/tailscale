// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This file provides the built-in device health checks. Platform-specific
// state collection is delegated to injectable probe functions so the same
// checks work across operating systems and are deterministic in tests.

package postureacl

import "fmt"

// Check names for the built-in checks. They are stable identifiers used in
// logs, health results, and any operator-facing posture policy.
const (
	CheckOSUpdates      = "os-updates"
	CheckScreenLock     = "screen-lock"
	CheckDiskEncryption = "disk-encryption"
)

// ProbeError describes a health check that could not collect its state. It is
// treated as a failed check rather than silently ignored, keeping posture
// evaluation fail-closed.
type ProbeError struct {
	Check string
	Err   error
}

func (e *ProbeError) Error() string {
	return fmt.Sprintf("posture check %q: %v", e.Check, e.Err)
}

func (e *ProbeError) Unwrap() error { return e.Err }

// OSUpdatesCheck verifies that the operating system has no pending security
// updates. It is critical: an unpatched device is quarantined.
//
// PendingSecurityUpdates is an injectable probe returning the number of
// unapplied security updates, allowing platform-specific code (or tests) to
// supply the value without this package depending on OS APIs.
type OSUpdatesCheck struct {
	PendingSecurityUpdates func() (int, error)
}

// Name implements [HealthCheck].
func (OSUpdatesCheck) Name() string { return CheckOSUpdates }

// Critical implements [HealthCheck].
func (OSUpdatesCheck) Critical() bool { return true }

// Check implements [HealthCheck].
func (c OSUpdatesCheck) Check() CheckResult {
	n, err := c.PendingSecurityUpdates()
	if err != nil {
		return CheckResult{Name: CheckOSUpdates, Critical: true, Err: &ProbeError{Check: CheckOSUpdates, Err: err}}
	}
	if n > 0 {
		return CheckResult{
			Name:     CheckOSUpdates,
			Critical: true,
			Healthy:  false,
			Err:      fmt.Errorf("%d pending security update(s)", n),
		}
	}
	return CheckResult{Name: CheckOSUpdates, Critical: true, Healthy: true}
}

// ScreenLockCheck verifies that the device requires authentication to unlock
// the screen. It is critical: an unlocked device is quarantined.
type ScreenLockCheck struct {
	// ScreenLockEnabled reports whether an unlock credential is required.
	ScreenLockEnabled func() (bool, error)
}

// Name implements [HealthCheck].
func (ScreenLockCheck) Name() string { return CheckScreenLock }

// Critical implements [HealthCheck].
func (ScreenLockCheck) Critical() bool { return true }

// Check implements [HealthCheck].
func (c ScreenLockCheck) Check() CheckResult {
	enabled, err := c.ScreenLockEnabled()
	if err != nil {
		return CheckResult{Name: CheckScreenLock, Critical: true, Err: &ProbeError{Check: CheckScreenLock, Err: err}}
	}
	if !enabled {
		return CheckResult{
			Name:     CheckScreenLock,
			Critical: true,
			Healthy:  false,
			Err:      fmt.Errorf("screen lock is not enabled"),
		}
	}
	return CheckResult{Name: CheckScreenLock, Critical: true, Healthy: true}
}

// DiskEncryptionCheck verifies that the device's storage is encrypted. It is
// non-critical: an unencrypted disk degrades the posture (sensitive ports are
// removed) but does not fully quarantine the device.
type DiskEncryptionCheck struct {
	// DiskEncrypted reports whether the primary storage volume is encrypted.
	DiskEncrypted func() (bool, error)
}

// Name implements [HealthCheck].
func (DiskEncryptionCheck) Name() string { return CheckDiskEncryption }

// Critical implements [HealthCheck].
func (DiskEncryptionCheck) Critical() bool { return false }

// Check implements [HealthCheck].
func (c DiskEncryptionCheck) Check() CheckResult {
	encrypted, err := c.DiskEncrypted()
	if err != nil {
		return CheckResult{Name: CheckDiskEncryption, Critical: false, Err: &ProbeError{Check: CheckDiskEncryption, Err: err}}
	}
	if !encrypted {
		return CheckResult{
			Name:     CheckDiskEncryption,
			Critical: false,
			Healthy:  false,
			Err:      fmt.Errorf("disk encryption is not enabled"),
		}
	}
	return CheckResult{Name: CheckDiskEncryption, Critical: false, Healthy: true}
}

// DefaultChecks builds the built-in set of health checks wired to the given
// platform probes. All three probes must be non-nil; platforms that cannot
// supply a probe should return an error from it rather than pass nil, so an
// unmeasurable device fails closed.
func DefaultChecks(updates func() (int, error), screenLock func() (bool, error), encryption func() (bool, error)) []HealthCheck {
	return []HealthCheck{
		OSUpdatesCheck{PendingSecurityUpdates: updates},
		ScreenLockCheck{ScreenLockEnabled: screenLock},
		DiskEncryptionCheck{DiskEncrypted: encryption},
	}
}
