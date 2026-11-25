// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package postureacl

import (
	"errors"
	"testing"
)

var errBoom = errors.New("boom")

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateUnknown, "unknown"},
		{StateHealthy, "healthy"},
		{StateDegraded, "degraded"},
		{StateQuarantined, "quarantined"},
		{State(99), "posture(99)"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", uint8(tt.state), got, tt.want)
		}
		text, err := tt.state.MarshalText()
		if err != nil || string(text) != tt.want {
			t.Errorf("MarshalText = %q, %v; want %q", text, err, tt.want)
		}
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name    string
		results []CheckResult
		want    State
	}{
		{
			name:    "no results is unknown and fail-closed",
			results: nil,
			want:    StateUnknown,
		},
		{
			name: "all healthy",
			results: []CheckResult{
				{Name: "a", Healthy: true, Critical: true},
				{Name: "b", Healthy: true, Critical: false},
			},
			want: StateHealthy,
		},
		{
			name: "non-critical failure degrades",
			results: []CheckResult{
				{Name: "a", Healthy: true, Critical: true},
				{Name: "b", Healthy: false, Critical: false, Err: errBoom},
			},
			want: StateDegraded,
		},
		{
			name: "critical failure quarantines even with other failures",
			results: []CheckResult{
				{Name: "a", Healthy: false, Critical: false, Err: errBoom},
				{Name: "b", Healthy: false, Critical: true, Err: errBoom},
			},
			want: StateQuarantined,
		},
		{
			name: "single critical failure quarantines",
			results: []CheckResult{
				{Name: "a", Healthy: false, Critical: true, Err: errBoom},
			},
			want: StateQuarantined,
		},
		{
			name: "critical pass plus non-critical pass is healthy",
			results: []CheckResult{
				{Name: "a", Healthy: true, Critical: true},
			},
			want: StateHealthy,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Evaluate(tt.results); got != tt.want {
				t.Errorf("Evaluate = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckFunc(t *testing.T) {
	errBoom := errors.New("nope")
	ok := CheckFunc{CheckName: "ok", IsCritical: true, Fn: func() error { return nil }}
	bad := CheckFunc{CheckName: "bad", IsCritical: false, Fn: func() error { return errBoom }}

	if got := ok.Check(); !got.Healthy || !got.Critical || got.Name != "ok" || got.Err != nil {
		t.Fatalf("ok check = %+v, want healthy critical result", got)
	}
	got := bad.Check()
	if got.Healthy || got.Critical || got.Name != "bad" || !errors.Is(got.Err, errBoom) {
		t.Fatalf("bad check = %+v, want unhealthy non-critical result wrapping errBoom", got)
	}
}

func TestBuiltInHealthChecks(t *testing.T) {
	t.Run("os updates", func(t *testing.T) {
		if (OSUpdatesCheck{}).Name() != CheckOSUpdates || !(OSUpdatesCheck{}).Critical() {
			t.Fatal("OSUpdatesCheck must be a critical check named os-updates")
		}
		pass := OSUpdatesCheck{PendingSecurityUpdates: func() (int, error) { return 0, nil }}.Check()
		if !pass.Healthy {
			t.Errorf("zero pending updates should pass, got %+v", pass)
		}
		fail := OSUpdatesCheck{PendingSecurityUpdates: func() (int, error) { return 3, nil }}.Check()
		if fail.Healthy || !fail.Critical {
			t.Errorf("pending updates should fail critically, got %+v", fail)
		}
		probeErr := OSUpdatesCheck{PendingSecurityUpdates: func() (int, error) { return 0, errBoom }}.Check()
		if probeErr.Healthy || !errors.Is(probeErr.Err, errBoom) {
			t.Errorf("probe error should fail and wrap the cause, got %+v", probeErr)
		}
	})

	t.Run("screen lock", func(t *testing.T) {
		if (ScreenLockCheck{}).Name() != CheckScreenLock || !(ScreenLockCheck{}).Critical() {
			t.Fatal("ScreenLockCheck must be a critical check named screen-lock")
		}
		pass := ScreenLockCheck{ScreenLockEnabled: func() (bool, error) { return true, nil }}.Check()
		if !pass.Healthy {
			t.Errorf("enabled screen lock should pass, got %+v", pass)
		}
		fail := ScreenLockCheck{ScreenLockEnabled: func() (bool, error) { return false, nil }}.Check()
		if fail.Healthy || !fail.Critical {
			t.Errorf("disabled screen lock should fail critically, got %+v", fail)
		}
	})

	t.Run("disk encryption", func(t *testing.T) {
		if (DiskEncryptionCheck{}).Name() != CheckDiskEncryption || (DiskEncryptionCheck{}).Critical() {
			t.Fatal("DiskEncryptionCheck must be a non-critical check named disk-encryption")
		}
		pass := DiskEncryptionCheck{DiskEncrypted: func() (bool, error) { return true, nil }}.Check()
		if !pass.Healthy {
			t.Errorf("encrypted disk should pass, got %+v", pass)
		}
		fail := DiskEncryptionCheck{DiskEncrypted: func() (bool, error) { return false, nil }}.Check()
		if fail.Healthy || fail.Critical {
			t.Errorf("unencrypted disk should fail non-critically, got %+v", fail)
		}
	})

	t.Run("default checks wiring", func(t *testing.T) {
		checks := DefaultChecks(
			func() (int, error) { return 0, nil },
			func() (bool, error) { return true, nil },
			func() (bool, error) { return true, nil },
		)
		if len(checks) != 3 {
			t.Fatalf("DefaultChecks returned %d checks, want 3", len(checks))
		}
		for _, c := range checks {
			if !c.Check().Healthy {
				t.Errorf("check %q should be healthy with passing probes", c.Name())
			}
		}
	})
}
