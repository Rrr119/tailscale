// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package aclpolicy

import (
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

// policyTest describes one policy document and what compiling and
// analyzing it should produce.
type policyTest struct {
	name   string
	policy string

	wantCompileErr string // substring of expected compile error; "" for success
	wantWarnings   int    // expected least-privilege warnings
	wantConflicts  []Conflict

	// check, if non-nil, performs extra assertions on the compiled
	// policy.
	check func(t *testing.T, cp *CompiledPolicy)
}

// policies is the suite of 10 policies exercising compilation,
// least-privilege warnings, and conflict detection.
var policies = []policyTest{
	{
		// 1. Minimal least-privilege rule: one tag to one tag on
		// one port.
		name: "tag to tag on a single port",
		policy: `{
			"tagowners": {
				"tag:web": ["alice@example.com"],
				"tag:db":  ["alice@example.com"],
			},
			"acls": [
				{"action": "accept", "src": ["tag:web"], "dst": ["tag:db:5432"]},
			],
		}`,
		check: func(t *testing.T, cp *CompiledPolicy) {
			grants := cp.Grants()
			if len(grants) != 1 {
				t.Fatalf("got %d grants, want 1: %v", len(grants), grants)
			}
			want := Grant{Src: "tag:web", Dst: "tag:db", Ports: "5432"}
			if grants[0] != want {
				t.Errorf("got grant %v, want %v", grants[0], want)
			}
		},
	},
	{
		// 2. A tag used in src must be declared in tagowners.
		name: "src tag without tagowners entry",
		policy: `{
			"tagowners": {"tag:db": ["alice@example.com"]},
			"acls": [
				{"action": "accept", "src": ["tag:web"], "dst": ["tag:db:5432"]},
			],
		}`,
		wantCompileErr: `tag "tag:web" has no tagOwners entry`,
	},
	{
		// 3. Groups referenced by a rule must be defined.
		name: "unknown group in src",
		policy: `{
			"tagowners": {"tag:db": ["alice@example.com"]},
			"acls": [
				{"action": "accept", "src": ["group:eng"], "dst": ["tag:db:5432"]},
			],
		}`,
		wantCompileErr: `unknown group "group:eng"`,
	},
	{
		// 4. Port ranges must be ascending.
		name: "reversed port range",
		policy: `{
			"tagowners": {"tag:db": ["alice@example.com"]},
			"acls": [
				{"action": "accept", "src": ["alice@example.com"], "dst": ["tag:db:5432-123"]},
			],
		}`,
		wantCompileErr: "invalid port range",
	},
	{
		// 5. Two identical rules: the second is a duplicate.
		name: "duplicate rules",
		policy: `{
			"tagowners": {"tag:db": ["alice@example.com"]},
			"acls": [
				{"action": "accept", "src": ["alice@example.com"], "dst": ["tag:db:5432"]},
				{"action": "accept", "src": ["alice@example.com"], "dst": ["tag:db:5432"]},
			],
		}`,
		wantConflicts: []Conflict{
			{Kind: ConflictDuplicate, Rule: 1, CausedBy: 0},
		},
	},
	{
		// 6. A wildcard rule makes a later, more specific rule
		// unreachable; it also draws least-privilege warnings.
		name: "specific rule shadowed by wildcard",
		policy: `{
			"tagowners": {
				"tag:web": ["alice@example.com"],
				"tag:db":  ["alice@example.com"],
			},
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["tag:db:*"]},
				{"action": "accept", "src": ["tag:web"], "dst": ["tag:db:5432"]},
			],
		}`,
		wantWarnings: 2, // "*" src and "*" ports on rule 0
		wantConflicts: []Conflict{
			{Kind: ConflictShadowed, Rule: 1, CausedBy: 0},
		},
	},
	{
		// 7. Groups in src expand to their members.
		name: "group expansion",
		policy: `{
			"groups":    {"group:eng": ["bob@example.com", "alice@example.com"]},
			"tagowners": {"tag:db": ["alice@example.com"]},
			"acls": [
				{"action": "accept", "src": ["group:eng"], "dst": ["tag:db:5432"]},
			],
		}`,
		check: func(t *testing.T, cp *CompiledPolicy) {
			got := cp.Rules[0].Srcs
			want := []string{"alice@example.com", "bob@example.com"}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("srcs = %v, want %v", got, want)
			}
		},
	},
	{
		// 8. Host aliases in dst resolve to their addresses.
		name: "hosts alias in dst",
		policy: `{
			"hosts":     {"db": "10.0.0.1"},
			"tagowners": {"tag:web": ["alice@example.com"]},
			"acls": [
				{"action": "accept", "src": ["tag:web"], "dst": ["db:5432"]},
			],
		}`,
		check: func(t *testing.T, cp *CompiledPolicy) {
			if got := cp.Rules[0].Dsts[0].Host; got != "10.0.0.1" {
				t.Errorf("dst host = %q, want 10.0.0.1", got)
			}
		},
	},
	{
		// 9. "*:*" compiles but violates least privilege on both
		// axes.
		name: "wildcard dst and ports",
		policy: `{
			"tagowners": {"tag:web": ["alice@example.com"]},
			"acls": [
				{"action": "accept", "src": ["tag:web"], "dst": ["*:*"]},
			],
		}`,
		wantWarnings: 2, // "*" dst and all ports
	},
	{
		// 10. Protocols and multi-port specs compile into sorted,
		// merged ranges.
		name: "tcp with mixed port spec",
		policy: `{
			"tagowners": {"tag:web": ["alice@example.com"]},
			"acls": [
				{"action": "accept", "proto": "tcp", "src": ["alice@example.com"],
				 "dst": ["tag:web:443,80,8000-8002,81"]},
			],
		}`,
		check: func(t *testing.T, cp *CompiledPolicy) {
			r := cp.Rules[0]
			if r.Proto != "tcp" {
				t.Errorf("proto = %q, want tcp", r.Proto)
			}
			want := []tailcfg.PortRange{{First: 80, Last: 81}, {First: 443, Last: 443}, {First: 8000, Last: 8002}}
			got := r.Dsts[0].Ports
			if len(got) != len(want) {
				t.Fatalf("ports = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("ports[%d] = %v, want %v", i, got[i], want[i])
				}
			}
		},
	},
}

func TestPolicies(t *testing.T) {
	for _, pt := range policies {
		t.Run(pt.name, func(t *testing.T) {
			p, err := Parse([]byte(pt.policy))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cp, err := Compile(p)
			if pt.wantCompileErr != "" {
				if err == nil {
					t.Fatalf("Compile succeeded, want error containing %q", pt.wantCompileErr)
				}
				if !strings.Contains(err.Error(), pt.wantCompileErr) {
					t.Fatalf("Compile error = %q, want substring %q", err, pt.wantCompileErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if len(cp.Warnings) != pt.wantWarnings {
				t.Errorf("got %d warnings, want %d: %v",
					len(cp.Warnings), pt.wantWarnings, cp.Warnings)
			}
			conflicts := DetectConflicts(cp)
			if len(conflicts) != len(pt.wantConflicts) {
				t.Fatalf("got %d conflicts, want %d: %v",
					len(conflicts), len(pt.wantConflicts), conflicts)
			}
			for i, want := range pt.wantConflicts {
				got := conflicts[i]
				if got.Kind != want.Kind || got.Rule != want.Rule || got.CausedBy != want.CausedBy {
					t.Errorf("conflict[%d] = %+v, want %+v", i, got, want)
				}
			}
			if pt.check != nil {
				pt.check(t, cp)
			}
		})
	}
}

func TestPreviewChange(t *testing.T) {
	oldPolicy := `{
		"tagowners": {
			"tag:web": ["alice@example.com"],
			"tag:db":  ["alice@example.com"],
		},
		"acls": [
			{"action": "accept", "src": ["tag:web"], "dst": ["tag:db:5432"]},
			{"action": "accept", "src": ["alice@example.com"], "dst": ["tag:web:80"]},
		],
	}`
	// New policy: drops alice's web access, widens db access to a
	// port range, and adds bob's ssh access.
	newPolicy := `{
		"tagowners": {
			"tag:web": ["alice@example.com"],
			"tag:db":  ["alice@example.com"],
		},
		"acls": [
			{"action": "accept", "src": ["tag:web"], "dst": ["tag:db:5432-5433"]},
			{"action": "accept", "src": ["bob@example.com"], "dst": ["tag:db:22"]},
		],
	}`

	preview, err := PreviewChange([]byte(oldPolicy), []byte(newPolicy))
	if err != nil {
		t.Fatalf("PreviewChange: %v", err)
	}
	if preview.Empty() {
		t.Fatal("preview is empty, want changes")
	}

	wantAdded := []Grant{
		{Src: "bob@example.com", Dst: "tag:db", Ports: "22"},
		{Src: "tag:web", Dst: "tag:db", Ports: "5432-5433"},
	}
	wantRemoved := []Grant{
		{Src: "alice@example.com", Dst: "tag:web", Ports: "80"},
		{Src: "tag:web", Dst: "tag:db", Ports: "5432"},
	}
	if !grantsEqual(preview.AddedGrants, wantAdded) {
		t.Errorf("AddedGrants = %v, want %v", preview.AddedGrants, wantAdded)
	}
	if !grantsEqual(preview.RemovedGrants, wantRemoved) {
		t.Errorf("RemovedGrants = %v, want %v", preview.RemovedGrants, wantRemoved)
	}
	if len(preview.AddedRules) != 2 || len(preview.RemovedRules) != 2 {
		t.Errorf("rules added=%d removed=%d, want 2 and 2",
			len(preview.AddedRules), len(preview.RemovedRules))
	}

	s := preview.String()
	for _, want := range []string{
		"+ grant bob@example.com -> tag:db:22",
		"- grant alice@example.com -> tag:web:80",
		"+ rule ",
		"- rule ",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("preview summary missing %q:\n%s", want, s)
		}
	}
}

func TestPreviewNoChange(t *testing.T) {
	policy := `{
		"tagowners": {"tag:web": ["alice@example.com"]},
		"acls": [
			{"action": "accept", "src": ["alice@example.com"], "dst": ["tag:web:80"]},
		],
	}`
	preview, err := PreviewChange([]byte(policy), []byte(policy))
	if err != nil {
		t.Fatalf("PreviewChange: %v", err)
	}
	if !preview.Empty() {
		t.Errorf("preview not empty: %s", preview)
	}
}

func TestParseRejectsBadPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy string
		want   string
	}{
		{"bad hujson", `{not json`, "invalid HuJSON"},
		{"bad action", `{"acls": [{"action": "deny", "src": ["a@b.c"], "dst": ["1.2.3.4:80"]}]}`, "unsupported action"},
		{"missing src", `{"acls": [{"action": "accept", "dst": ["1.2.3.4:80"]}]}`, "missing src"},
		{"missing dst", `{"acls": [{"action": "accept", "src": ["a@b.c"]}]}`, "missing dst"},
		{"bad proto", `{"acls": [{"action": "accept", "proto": "carrier-pigeon", "src": ["a@b.c"], "dst": ["1.2.3.4:80"]}]}`, "unknown protocol"},
		{"dst without ports", `{"acls": [{"action": "accept", "src": ["a@b.c"], "dst": ["1.2.3.4"]}]}`, "host:ports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.policy))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Parse error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func grantsEqual(a, b []Grant) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
