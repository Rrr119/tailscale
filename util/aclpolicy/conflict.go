// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package aclpolicy

import (
	"fmt"
	"net/netip"

	"tailscale.com/tailcfg"
)

// ConflictKind describes how two rules conflict.
type ConflictKind string

const (
	// ConflictDuplicate indicates a rule that is exactly covered by
	// an earlier rule in both directions; one of them is redundant.
	ConflictDuplicate ConflictKind = "duplicate"
	// ConflictShadowed indicates a rule that is fully covered by a
	// broader earlier rule, making it unreachable in practice.
	ConflictShadowed ConflictKind = "shadowed"
)

// Conflict describes a redundancy between two compiled rules.
type Conflict struct {
	Kind     ConflictKind
	Rule     int // index of the redundant (later) rule
	CausedBy int // index of the earlier rule that covers it
	Detail   string
}

// DetectConflicts reports duplicate and shadowed rules in cp.
// ACL rules are accept-only and first-match semantics do not apply,
// so a "conflict" here means a rule that can never grant anything
// beyond what an earlier rule already grants.
func DetectConflicts(cp *CompiledPolicy) []Conflict {
	var out []Conflict
	for j := range cp.Rules {
		for i := 0; i < j; i++ {
			if !ruleCovers(&cp.Rules[i], &cp.Rules[j]) {
				continue
			}
			kind := ConflictShadowed
			if ruleCovers(&cp.Rules[j], &cp.Rules[i]) {
				kind = ConflictDuplicate
			}
			out = append(out, Conflict{
				Kind:     kind,
				Rule:     j,
				CausedBy: i,
				Detail: fmt.Sprintf("acls[%d] is %s by acls[%d]",
					j, kind, i),
			})
			break // report only the first covering rule
		}
	}
	return out
}

// ruleCovers reports whether a matches at least everything b
// matches: a's protocol, sources, destinations, and ports are all
// supersets of b's, so a makes b redundant.
func ruleCovers(a, b *CompiledRule) bool {
	return protoCovers(a.Proto, b.Proto) &&
		srcsCover(a.Srcs, b.Srcs) &&
		dstsCover(a.Dsts, b.Dsts)
}

func protoCovers(a, b string) bool {
	return a == "" || a == b
}

// srcsCover reports whether every source in b is matched by some
// source in a.
func srcsCover(a, b []string) bool {
	for _, s := range b {
		if !slicesContains(a, s) {
			return false
		}
	}
	return true
}

func slicesContains(hay []string, needle string) bool {
	for _, h := range hay {
		if hostCovers(h, needle) {
			return true
		}
	}
	return false
}

// dstsCover reports whether every destination in b is matched, host
// and ports, by some destination in a.
func dstsCover(a, b []CompiledDst) bool {
	for _, bd := range b {
		covered := false
		for _, ad := range a {
			if hostCovers(ad.Host, bd.Host) && portsCover(ad.Ports, bd.Ports) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// hostCovers reports whether host alias a matches everything b does:
// they are equal, a is the wildcard, or a is a CIDR containing b.
func hostCovers(a, b string) bool {
	if a == "*" || a == b {
		return true
	}
	pa, err := netip.ParsePrefix(a)
	if err != nil {
		return false
	}
	if addr, err := netip.ParseAddr(b); err == nil {
		return pa.Contains(addr)
	}
	if pb, err := netip.ParsePrefix(b); err == nil {
		return pa.Bits() <= pb.Bits() && pa.Contains(pb.Addr())
	}
	return false
}

// portsCover reports whether every port range in b is contained in
// some range in a. Both lists must be sorted and merged, as produced
// by parsePorts.
func portsCover(a, b []tailcfg.PortRange) bool {
	for _, br := range b {
		covered := false
		for _, ar := range a {
			if ar.First <= br.First && br.Last <= ar.Last {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}
