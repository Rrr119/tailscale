// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package postureacl implements zero-trust, device-posture-based dynamic
// ACLs for the local node.
//
// It combines three pieces:
//
//   - [HealthCheck]s inspect local device state (OS patch level, screen lock,
//     disk encryption, or any caller-supplied check) and [Evaluate] reduces
//     their results to one of three postures: [StateHealthy],
//     [StateDegraded], or [StateQuarantined] (with [StateUnknown] as the
//     fail-closed starting posture).
//   - [Policy] maps each posture to an adjustment of the existing
//     control-plane ACL rules. Adjustments only ever remove access, so the
//     dynamic policy stays compatible with the tailnet's base policy.
//   - [Controller] runs the checks on a sub-second-to-seconds cadence and
//     invokes a change callback the instant the posture transitions, letting
//     the local backend rebuild its packet filter so the new ACL takes
//     effect within [MaxSwitchLatency] (5 seconds).
package postureacl
