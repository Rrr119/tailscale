// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package aclpolicy

import (
	"fmt"
	"slices"
	"strings"
)

// Grant is a single effective access grant: Src may reach Dst on
// Ports.
type Grant struct {
	Src   string
	Dst   string
	Ports string // normalized, e.g. "80,443" or "8000-8010"
}

func (g Grant) String() string {
	return fmt.Sprintf("%s -> %s:%s", g.Src, g.Dst, g.Ports)
}

// Grants returns the normalized set of effective grants in cp,
// sorted and deduplicated.
func (cp *CompiledPolicy) Grants() []Grant {
	seen := map[Grant]bool{}
	var out []Grant
	for _, r := range cp.Rules {
		for _, s := range r.Srcs {
			for _, d := range r.Dsts {
				g := Grant{Src: s, Dst: d.Host, Ports: formatPorts(d.Ports)}
				if !seen[g] {
					seen[g] = true
					out = append(out, g)
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b Grant) int {
		if c := strings.Compare(a.Src, b.Src); c != 0 {
			return c
		}
		if c := strings.Compare(a.Dst, b.Dst); c != 0 {
			return c
		}
		return strings.Compare(a.Ports, b.Ports)
	})
	return out
}

// Preview describes the effective change between two policy
// versions.
type Preview struct {
	// AddedGrants and RemovedGrants are the effective access delta:
	// source/destination/port combinations gained or lost.
	AddedGrants   []Grant
	RemovedGrants []Grant
	// AddedRules and RemovedRules are normalized rule descriptions
	// present on only one side of the change.
	AddedRules   []string
	RemovedRules []string
}

// Empty reports whether the preview contains no changes.
func (p *Preview) Empty() bool {
	return len(p.AddedGrants) == 0 && len(p.RemovedGrants) == 0 &&
		len(p.AddedRules) == 0 && len(p.RemovedRules) == 0
}

// String returns a human-readable summary of the change, one line
// per added or removed rule and grant.
func (p *Preview) String() string {
	var b strings.Builder
	for _, r := range p.AddedRules {
		fmt.Fprintf(&b, "+ rule %s\n", r)
	}
	for _, r := range p.RemovedRules {
		fmt.Fprintf(&b, "- rule %s\n", r)
	}
	for _, g := range p.AddedGrants {
		fmt.Fprintf(&b, "+ grant %s\n", g)
	}
	for _, g := range p.RemovedGrants {
		fmt.Fprintf(&b, "- grant %s\n", g)
	}
	return b.String()
}

// Diff computes the effective change from old to new.
func Diff(old, new *CompiledPolicy) *Preview {
	p := &Preview{
		AddedGrants:   grantDiff(new.Grants(), old.Grants()),
		RemovedGrants: grantDiff(old.Grants(), new.Grants()),
		AddedRules:    ruleDiff(new, old),
		RemovedRules:  ruleDiff(old, new),
	}
	return p
}

// PreviewChange parses, compiles, and diffs two policy documents,
// returning the effective change from oldSrc to newSrc.
func PreviewChange(oldSrc, newSrc []byte) (*Preview, error) {
	oldP, err := Parse(oldSrc)
	if err != nil {
		return nil, fmt.Errorf("old policy: %w", err)
	}
	newP, err := Parse(newSrc)
	if err != nil {
		return nil, fmt.Errorf("new policy: %w", err)
	}
	oldC, err := Compile(oldP)
	if err != nil {
		return nil, fmt.Errorf("old policy: %w", err)
	}
	newC, err := Compile(newP)
	if err != nil {
		return nil, fmt.Errorf("new policy: %w", err)
	}
	return Diff(oldC, newC), nil
}

// grantDiff returns the grants in a that are not in b.
func grantDiff(a, b []Grant) []Grant {
	inB := map[Grant]bool{}
	for _, g := range b {
		inB[g] = true
	}
	var out []Grant
	for _, g := range a {
		if !inB[g] {
			out = append(out, g)
		}
	}
	return out
}

// ruleDiff returns the normalized rule strings in a that are not
// in b.
func ruleDiff(a, b *CompiledPolicy) []string {
	inB := map[string]bool{}
	for _, r := range b.Rules {
		inB[r.String()] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range a.Rules {
		s := r.String()
		if !inB[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}
