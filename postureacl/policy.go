// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package postureacl

import (
	"slices"

	"tailscale.com/tailcfg"
)

// DefaultSensitivePorts are the destination ports removed from the base
// policy while the device is in the [StateDegraded] posture. They cover the
// common remote-administration and data-plane services that a compromised or
// not-fully-hardened device should not be able to reach over the tailnet.
var DefaultSensitivePorts = []uint16{
	22,    // SSH
	23,    // telnet
	3389,  // RDP
	5900,  // VNC
	445,   // SMB
	3306,  // MySQL
	5432,  // PostgreSQL
	6379,  // Redis
	27017, // MongoDB
	9200,  // Elasticsearch
}

// Policy maps a device [State] to the ACL adjustments applied on top of the
// existing control-plane policy.
//
// The engine never grants access that the base policy does not already grant:
// every profile is a restriction of the base rules, so the result stays
// compatible with the tailnet's existing ACLs.
type Policy struct {
	// SensitivePorts are the TCP/UDP destination ports removed from base
	// rules in [StateDegraded]. If nil, [DefaultSensitivePorts] is used.
	SensitivePorts []uint16
}

// ApplyRules returns the rules to enforce for the given device posture,
// starting from the base rules distributed by the control plane.
//
// The base slice is not modified; a new slice is returned whenever the
// posture changes the rules.
//
//   - [StateHealthy]: the base policy is enforced unchanged.
//   - [StateDegraded]: the base policy minus destinations on sensitive ports.
//   - [StateQuarantined] and [StateUnknown]: all inbound rules are withdrawn
//     (fail closed). Outbound traffic is unaffected, because outbound packets
//     are permitted by the filter's connection state rather than these rules.
func (p Policy) ApplyRules(base []tailcfg.FilterRule, state State) []tailcfg.FilterRule {
	switch state {
	case StateHealthy:
		// Fully trusted devices keep the control-plane policy as-is.
		return base
	case StateDegraded:
		return p.restrictSensitivePorts(base)
	case StateQuarantined, StateUnknown:
		fallthrough
	default:
		// Fail closed: no inbound ACL grants while untrusted or unmeasured.
		return nil
	}
}

// restrictSensitivePorts returns a copy of base in which every destination
// port range covering a sensitive port has been pruned. Rules that end up
// with no permitted destinations, and pure capability-grant rules, are
// dropped entirely.
func (p Policy) restrictSensitivePorts(base []tailcfg.FilterRule) []tailcfg.FilterRule {
	sensitive := p.SensitivePorts
	if len(sensitive) == 0 {
		sensitive = DefaultSensitivePorts
	}

	out := make([]tailcfg.FilterRule, 0, len(base))
	for _, rule := range base {
		// Capability grants are application-level authorizations rather than
		// data-plane access. Withhold them while degraded rather than leak
		// capabilities through a partially restricted rule.
		if len(rule.CapGrant) != 0 {
			continue
		}

		pruned := rule
		pruned.DstPorts = prunePortRanges(rule.DstPorts, sensitive)
		if len(pruned.DstPorts) == 0 {
			// Nothing reachable remains on this rule.
			continue
		}
		out = append(out, pruned)
	}
	return out
}

// prunePortRanges removes sensitive ports from the given destination ranges.
// A range that contains sensitive ports is split into the sub-ranges around
// them, preserving access to every non-sensitive port.
func prunePortRanges(ranges []tailcfg.NetPortRange, sensitive []uint16) []tailcfg.NetPortRange {
	out := make([]tailcfg.NetPortRange, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, splitRangeAroundSensitive(r, sensitive)...)
	}
	return out
}

// splitRangeAroundSensitive returns the portions of r whose ports do not
// overlap any sensitive port. The returned ranges share r's destination IP.
func splitRangeAroundSensitive(r tailcfg.NetPortRange, sensitive []uint16) []tailcfg.NetPortRange {
	first, last := r.Ports.First, r.Ports.Last

	// Fast path: no sensitive port intersects this range.
	hits := make([]uint16, 0, len(sensitive))
	for _, port := range sensitive {
		if port >= first && port <= last {
			hits = append(hits, port)
		}
	}
	if len(hits) == 0 {
		return []tailcfg.NetPortRange{r}
	}
	// The cursor-based splitting below assumes the excluded ports are
	// encountered in ascending order.
	slices.Sort(hits)

	var out []tailcfg.NetPortRange
	// Use uint32 for the cursor so that stepping past port 65535 cannot
	// wrap around to zero.
	cursor := uint32(first)
	for _, port := range hits {
		p := uint32(port)
		if cursor < p {
			out = append(out, netPortRange(r.IP, uint16(cursor), uint16(p-1)))
		}
		cursor = p + 1
	}
	if cursor <= uint32(last) {
		out = append(out, netPortRange(r.IP, uint16(cursor), last))
	}
	return out
}

func netPortRange(ip string, first, last uint16) tailcfg.NetPortRange {
	return tailcfg.NetPortRange{
		IP:    ip,
		Ports: tailcfg.PortRange{First: first, Last: last},
	}
}
