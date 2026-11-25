// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package postureacl wires device-posture-based dynamic ACLs into the local
// backend. It runs the [postureacl.Controller] health checks, installs a
// filter-rule transform that tightens the control-plane ACLs according to the
// current device posture, and triggers an immediate packet-filter rebuild on
// every posture transition so ACL changes take effect within
// [postureacl.MaxSwitchLatency].
package postureacl

import (
	"context"
	"fmt"

	"tailscale.com/feature"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/postureacl"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

const featureName = "postureacl"

func init() {
	if !feature.Register(featureName) {
		return
	}
	ipnext.RegisterExtension(featureName, newExtension)
}

var postureWarnable = health.Register(&health.Warnable{
	Code:     "posture-acl-restricted",
	Title:    "Device posture restricted network access",
	Severity: health.SeverityHigh,
	Text: func(args health.Args) string {
		return fmt.Sprintf("This device's security posture is %q; network access has been restricted. %s",
			args["posture"], args["reason"])
	},
})

func newExtension(logf logger.Logf, b ipnext.SafeBackend) (ipnext.Extension, error) {
	checks, err := postureacl.RegisteredChecks()
	if err != nil {
		return nil, fmt.Errorf("postureacl: building health checks: %w", err)
	}
	ext := &extension{
		logf:   logger.WithPrefix(logf, "postureacl: "),
		health: b.Sys().HealthTracker.Get(),
	}
	controller, err := postureacl.NewController(postureacl.Config{
		Checks: checks,
		Clock:  b.Clock(),
		Logf:   logger.WithPrefix(logf, "postureacl: "),
		OnChange: func(state postureacl.State, results []postureacl.CheckResult) {
			ext.updateHealth(state, results)
			// Rebuilding the filter re-runs the transform hook with the new
			// posture and installs the resulting filter immediately.
			if ext.host != nil {
				ext.host.RebuildPacketFilterAsync()
			}
		},
	})
	if err != nil {
		return nil, err
	}
	ext.controller = controller
	return ext, nil
}

type extension struct {
	host ipnext.Host
	logf logger.Logf

	controller *postureacl.Controller
	health     *health.Tracker

	cancel context.CancelFunc
	done   chan struct{}
}

func (*extension) Name() string { return featureName }

func (e *extension) Init(h ipnext.Host) error {
	e.host = h

	// Transform the control-plane rules according to the current posture on
	// every filter build. This is a read-only lookup of the controller's
	// current state and is safe to run with the backend mutex held.
	h.Hooks().Filter.TransformFilterRules.Set(e.transformRules)

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})

	go func() {
		defer close(e.done)
		if err := e.controller.Run(ctx); err != nil {
			e.logf("controller run: %v", err)
		}
	}()
	return nil
}

func (e *extension) Shutdown() error {
	cancel := e.cancel
	done := e.done
	e.cancel = nil
	e.done = nil

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	// Controller.Close is a no-op when Run already stopped via ctx, but call
	// it anyway to keep the state machine consistent.
	return e.controller.Close()
}

// transformRules implements the filter transform hook.
func (e *extension) transformRules(base []tailcfg.FilterRule) []tailcfg.FilterRule {
	return e.controller.ApplyRules(base)
}

func (e *extension) updateHealth(state postureacl.State, results []postureacl.CheckResult) {
	if e.health == nil {
		return
	}
	switch state {
	case postureacl.StateHealthy:
		e.health.SetHealthy(postureWarnable)
	default:
		e.health.SetUnhealthy(postureWarnable, health.Args{
			"posture": state.String(),
			"reason":  summarizeFailures(results),
		})
	}
}

func summarizeFailures(results []postureacl.CheckResult) string {
	for _, r := range results {
		if !r.Healthy && r.Err != nil {
			return r.Err.Error()
		}
	}
	return "one or more device health checks failed"
}
