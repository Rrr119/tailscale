// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package aclpolicy parses, compiles, and analyzes Tailscale-style
// network ACL policies, with an emphasis on least-privilege rules
// expressed in terms of tags and ports.
//
// The package is self-contained: it does not talk to the control
// server. It provides three building blocks on top of a parsed
// policy:
//
//   - [Compile] resolves aliases (groups, hosts, tags) and port specs
//     into normalized rules, reporting errors for dangling references
//     and warnings for overly broad (non-least-privilege) rules.
//   - [DetectConflicts] finds duplicate and shadowed rules.
//   - [Diff] and [PreviewChange] compute the effective access change
//     between two policy versions, for review before rollout.
package aclpolicy

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"
	"tailscale.com/tailcfg"
)

// Policy is a parsed ACL policy document.
type Policy struct {
	Groups    map[string][]string `json:"groups,omitempty"`
	Hosts     map[string]string   `json:"hosts,omitempty"`
	TagOwners map[string][]string `json:"tagowners,omitempty"`
	ACLs      []ACL               `json:"acls,omitempty"`
}

// ACL is a single access rule in a Policy.
type ACL struct {
	Action string   `json:"action"`
	Proto  string   `json:"proto,omitempty"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

// Parse parses a HuJSON ACL policy document and validates its
// structure. References (groups, tags, hosts) are not resolved until
// [Compile].
func Parse(src []byte) (*Policy, error) {
	v, err := hujson.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("aclpolicy: invalid HuJSON: %w", err)
	}
	v.Standardize()
	var p Policy
	if err := json.Unmarshal(v.Pack(), &p); err != nil {
		return nil, fmt.Errorf("aclpolicy: invalid policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) validate() error {
	for i, acl := range p.ACLs {
		if acl.Action != "accept" {
			return fmt.Errorf("acls[%d]: unsupported action %q", i, acl.Action)
		}
		if len(acl.Src) == 0 {
			return fmt.Errorf("acls[%d]: missing src", i)
		}
		if len(acl.Dst) == 0 {
			return fmt.Errorf("acls[%d]: missing dst", i)
		}
		if err := checkProto(acl.Proto); err != nil {
			return fmt.Errorf("acls[%d]: %w", i, err)
		}
		for _, d := range acl.Dst {
			if _, _, err := splitDst(d); err != nil {
				return fmt.Errorf("acls[%d]: %w", i, err)
			}
		}
	}
	return nil
}

var knownProtos = map[string]bool{
	"tcp": true, "udp": true, "icmp": true, "igmp": true,
	"igp": true, "egp": true, "ip-in-ip": true, "ipv4": true,
	"sctp": true, "gre": true, "esp": true, "ah": true,
}

func checkProto(proto string) error {
	if proto == "" || knownProtos[proto] {
		return nil
	}
	if n, err := strconv.Atoi(proto); err == nil && n >= 0 && n <= 255 {
		return nil
	}
	return fmt.Errorf("unknown protocol %q", proto)
}

var knownAutogroups = map[string]bool{
	"autogroup:member":   true,
	"autogroup:admin":    true,
	"autogroup:owner":    true,
	"autogroup:tagged":   true,
	"autogroup:self":     true,
	"autogroup:internet": true,
}

// checkAlias reports whether a is a valid, resolvable source or
// destination alias within the policy.
func (p *Policy) checkAlias(a string) error {
	switch {
	case a == "*":
	case strings.HasPrefix(a, "autogroup:"):
		if !knownAutogroups[a] {
			return fmt.Errorf("unknown autogroup %q", a)
		}
	case strings.HasPrefix(a, "group:"):
		if _, ok := p.Groups[a]; !ok {
			return fmt.Errorf("unknown group %q", a)
		}
	case strings.HasPrefix(a, "tag:"):
		if err := tailcfg.CheckTag(a); err != nil {
			return err
		}
		if _, ok := p.TagOwners[a]; !ok {
			return fmt.Errorf("tag %q has no tagOwners entry", a)
		}
	case strings.Contains(a, "@"):
		// A user, such as alice@example.com.
	default:
		if _, ok := p.Hosts[a]; ok {
			return nil
		}
		if _, err := netip.ParseAddr(a); err == nil {
			return nil
		}
		if _, err := netip.ParsePrefix(a); err == nil {
			return nil
		}
		return fmt.Errorf("unknown alias %q", a)
	}
	return nil
}

// splitDst splits a destination of the form "host:ports".
func splitDst(dst string) (host, portSpec string, err error) {
	i := strings.LastIndex(dst, ":")
	if i < 0 {
		return "", "", fmt.Errorf("dst %q must be of the form host:ports", dst)
	}
	return dst[:i], dst[i+1:], nil
}

// parsePorts parses a port spec such as "*", "80", "80,443", or
// "8000-8010,443" into a sorted, merged list of port ranges.
func parsePorts(spec string) ([]tailcfg.PortRange, error) {
	if spec == "*" {
		return []tailcfg.PortRange{tailcfg.PortRangeAny}, nil
	}
	var ranges []tailcfg.PortRange
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		loStr, hiStr, isRange := strings.Cut(part, "-")
		lo, err := parsePort(loStr)
		if err != nil {
			return nil, err
		}
		hi := lo
		if isRange {
			if hi, err = parsePort(hiStr); err != nil {
				return nil, err
			}
		}
		if lo > hi {
			return nil, fmt.Errorf("invalid port range %q: first port exceeds last", part)
		}
		ranges = append(ranges, tailcfg.PortRange{First: lo, Last: hi})
	}
	return mergePortRanges(ranges), nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(n), nil
}

// mergePortRanges sorts ranges and merges overlapping or adjacent
// ones.
func mergePortRanges(ranges []tailcfg.PortRange) []tailcfg.PortRange {
	slices.SortFunc(ranges, func(a, b tailcfg.PortRange) int {
		return int(a.First) - int(b.First)
	})
	out := ranges[:0]
	for _, r := range ranges {
		if n := len(out); n > 0 && r.First <= out[n-1].Last+1 {
			out[n-1].Last = max(out[n-1].Last, r.Last)
			continue
		}
		out = append(out, r)
	}
	return out
}

// CompiledDst is a destination with its host alias resolved and its
// ports normalized.
type CompiledDst struct {
	Host  string
	Ports []tailcfg.PortRange
}

// CompiledRule is a single ACL rule with all aliases resolved.
type CompiledRule struct {
	Index int      // index of the rule in Policy.ACLs
	Proto string   // normalized protocol; "" means any
	Srcs  []string // expanded and sorted sources
	Dsts  []CompiledDst
}

// String returns a normalized one-line description of the rule.
func (r CompiledRule) String() string {
	proto := r.Proto
	if proto == "" {
		proto = "any"
	}
	dsts := make([]string, 0, len(r.Dsts))
	for _, d := range r.Dsts {
		dsts = append(dsts, d.Host+":"+formatPorts(d.Ports))
	}
	return fmt.Sprintf("accept %s %s -> %s", proto,
		strings.Join(r.Srcs, ","), strings.Join(dsts, ","))
}

// CompiledPolicy is the result of compiling a Policy.
type CompiledPolicy struct {
	Rules []CompiledRule
	// Warnings lists least-privilege concerns: rules that compile
	// but are broader than they likely need to be.
	Warnings []string
}

// Compile resolves all aliases in p into normalized rules. It
// returns an error for dangling references (unknown groups, tags
// without owners, bad ports) and records least-privilege warnings
// for overly broad rules.
func Compile(p *Policy) (*CompiledPolicy, error) {
	cp := new(CompiledPolicy)
	for i, acl := range p.ACLs {
		rule := CompiledRule{Index: i, Proto: acl.Proto}

		srcs := map[string]bool{}
		for _, s := range acl.Src {
			ex, err := p.expandSrc(s, map[string]bool{})
			if err != nil {
				return nil, fmt.Errorf("acls[%d]: %w", i, err)
			}
			for _, e := range ex {
				srcs[e] = true
			}
		}
		rule.Srcs = slices.Sorted(maps.Keys(srcs))

		for _, d := range acl.Dst {
			host, spec, err := splitDst(d)
			if err != nil {
				return nil, fmt.Errorf("acls[%d]: %w", i, err)
			}
			if err := p.checkAlias(host); err != nil {
				return nil, fmt.Errorf("acls[%d]: %w", i, err)
			}
			if h, ok := p.Hosts[host]; ok {
				host = h
			}
			ports, err := parsePorts(spec)
			if err != nil {
				return nil, fmt.Errorf("acls[%d]: dst %q: %w", i, d, err)
			}
			rule.Dsts = append(rule.Dsts, CompiledDst{Host: host, Ports: ports})
		}

		cp.Warnings = append(cp.Warnings, leastPrivilegeWarnings(rule)...)
		cp.Rules = append(cp.Rules, rule)
	}
	return cp, nil
}

// expandSrc expands groups (recursively) in a source alias and
// validates the result.
func (p *Policy) expandSrc(src string, seen map[string]bool) ([]string, error) {
	if strings.HasPrefix(src, "group:") {
		if seen[src] {
			return nil, fmt.Errorf("group cycle involving %q", src)
		}
		members, ok := p.Groups[src]
		if !ok {
			return nil, fmt.Errorf("unknown group %q", src)
		}
		seen[src] = true
		defer delete(seen, src)
		var out []string
		for _, m := range members {
			ex, err := p.expandSrc(m, seen)
			if err != nil {
				return nil, err
			}
			out = append(out, ex...)
		}
		return out, nil
	}
	if err := p.checkAlias(src); err != nil {
		return nil, err
	}
	return []string{src}, nil
}

// leastPrivilegeWarnings flags rules that are broader than
// least-privilege design allows: wildcard sources, wildcard
// destinations, or unrestricted ports.
func leastPrivilegeWarnings(rule CompiledRule) []string {
	var warns []string
	for _, s := range rule.Srcs {
		if s == "*" {
			warns = append(warns, fmt.Sprintf(
				"acls[%d]: src \"*\" matches every node; prefer specific tags", rule.Index))
		}
	}
	for _, d := range rule.Dsts {
		if d.Host == "*" {
			warns = append(warns, fmt.Sprintf(
				"acls[%d]: dst \"*\" matches every node; prefer specific tags", rule.Index))
		}
		if len(d.Ports) == 1 && d.Ports[0] == tailcfg.PortRangeAny {
			warns = append(warns, fmt.Sprintf(
				"acls[%d]: dst %q allows all ports; prefer an explicit port list", rule.Index, d.Host))
		}
	}
	return warns
}

func formatPorts(ports []tailcfg.PortRange) string {
	ss := make([]string, 0, len(ports))
	for _, pr := range ports {
		ss = append(ss, pr.String())
	}
	return strings.Join(ss, ",")
}
