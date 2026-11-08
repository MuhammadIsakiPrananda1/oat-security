package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// nftNGFWLogPrefix is the kernel log marker of the NGFW. Dropped and monitored
// flows reach syslog/journald with this prefix; the agent's log parser turns
// those lines into firewall_block / firewall_log security events, closing the
// enforcement loop back to the dashboard.
const nftNGFWLogPrefix = "OAT_NGFW_"

// The NGFW log budget guards against drowning the telemetry under a flood.
const fwLogRateLimit = "limit rate 60/second"

var fwPortRangeRe = regexp.MustCompile(`^\d+\s*-\s*\d+$`)

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

// nftFirewallAction maps the dashboard ACL vocabulary onto a kernel verdict.
// An empty verdict means log-only: no decision is made, the packet falls
// through to later rules (and to the chain policy).
func nftFirewallAction(action string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "DENY", "BLOCK", "DROP", "REJECT":
		return "drop", true
	case "ALLOW", "ACCEPT", "PASS":
		return "accept", true
	case "LOG", "MONITOR":
		return "", true
	default:
		return "", false
	}
}

// wildcardAddress reports whether an ACL address field means "everywhere".
func wildcardAddress(value string) bool {
	trimmed := strings.TrimSpace(value)
	switch strings.ToLower(trimmed) {
	case "", "any", "*":
		return true
	}
	return trimmed == "0.0.0.0/0" || trimmed == "::/0"
}

// nftAddressExpr renders a source/destination match expression. The bool is
// false when the value is invalid and the whole rule must be skipped.
func nftAddressExpr(direction string, value string) (string, bool, string) {
	if wildcardAddress(value) {
		return "", true, ""
	}
	family, address, ok := nftAddress(strings.TrimSpace(value))
	if !ok {
		return "", false, fmt.Sprintf("ACL entry has an invalid %s address %q", direction, strings.TrimSpace(value))
	}
	return family + " " + direction + " " + address, true, ""
}

// nftPortSet renders a destination port expression. Multiple entries become a
// set literal and a range token becomes an nft range. Wildcards produce no
// expression. The bool is false when the rule must be skipped entirely.
func nftPortSet(value string) (string, bool, string) {
	trimmed := strings.TrimSpace(strings.ToUpper(value))
	if trimmed == "" || trimmed == "ANY" || trimmed == "*" {
		return "", true, ""
	}
	tokens := []string{}
	for _, token := range strings.Split(trimmed, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if fwPortRangeRe.MatchString(token) {
			low, high, _ := strings.Cut(token, "-")
			lowPort, lowErr := strconv.Atoi(strings.TrimSpace(low))
			highPort, highErr := strconv.Atoi(strings.TrimSpace(high))
			if lowErr != nil || highErr != nil || lowPort < 1 || highPort > 65535 || lowPort > highPort {
				return "", false, fmt.Sprintf("ACL entry has an invalid port range %q", token)
			}
			tokens = append(tokens, fmt.Sprintf("%d-%d", lowPort, highPort))
			continue
		}
		port, err := strconv.Atoi(token)
		if err != nil || port < 1 || port > 65535 {
			return "", false, fmt.Sprintf("ACL entry has an invalid port %q", token)
		}
		tokens = append(tokens, strconv.Itoa(port))
	}
	if len(tokens) == 0 {
		return "", true, ""
	}
	if len(tokens) == 1 {
		return tokens[0], true, ""
	}
	return "{ " + strings.Join(tokens, ", ") + " }", true, ""
}

// sanitizeFwComment keeps rule comments on a single line so a crafted rule ID
// cannot comment parts of the nftables script out of existence.
func sanitizeFwComment(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, value)
	cleaned = strings.TrimSpace(cleaned)
	if len(cleaned) > 80 {
		cleaned = cleaned[:80]
	}
	if cleaned == "" {
		return "unnamed rule"
	}
	return cleaned
}

// nftFirewallRuleLines expands one ACL entry into kernel statements. The second
// return value is a warning; a non-empty warning means the rule is skipped so
// the agent never enforces something other than what the operator defined.
func nftFirewallRuleLines(rule FirewallRule) ([]string, string) {
	proto := strings.ToUpper(strings.TrimSpace(rule.Protocol))
	switch proto {
	case "TCP", "UDP", "ICMP", "ANY", "":
	default:
		return nil, fmt.Sprintf("rule %s has unsupported protocol %q and was skipped", rule.ID, rule.Protocol)
	}

	source, sourceOK, sourceWarn := nftAddressExpr("saddr", rule.Source)
	if !sourceOK {
		return nil, fmt.Sprintf("rule %s: %s", rule.ID, sourceWarn)
	}
	destination, destinationOK, destinationWarn := nftAddressExpr("daddr", rule.Destination)
	if !destinationOK {
		return nil, fmt.Sprintf("rule %s: %s", rule.ID, destinationWarn)
	}

	// One expression chain carries only one address family; mixing IPv4 with
	// IPv6 in a single rule would make the kernel reject the whole script.
	sourceIsV6 := strings.HasPrefix(source, "ip6 ")
	destinationIsV6 := strings.HasPrefix(destination, "ip6 ")
	if sourceIsV6 != destinationIsV6 {
		return nil, fmt.Sprintf("rule %s mixes IPv4 and IPv6 addresses and was skipped", rule.ID)
	}
	// ICMPv6 is deliberately out of scope; the dashboard ships plain ICMP.
	if proto == "ICMP" && (sourceIsV6 || destinationIsV6) {
		return nil, fmt.Sprintf("rule %s targets ICMP over IPv6, which is not applied yet", rule.ID)
	}

	matches := []string{}
	if source != "" {
		matches = append(matches, source)
	}
	if destination != "" {
		matches = append(matches, destination)
	}

	ports, portsOK, portsWarn := nftPortSet(rule.Port)
	if !portsOK {
		return nil, fmt.Sprintf("rule %s: %s", rule.ID, portsWarn)
	}

	switch {
	case proto == "ICMP":
		if ports != "" {
			return nil, fmt.Sprintf("rule %s targets ICMP but defines port %q; ICMP has no ports and the rule was skipped", rule.ID, strings.TrimSpace(rule.Port))
		}
		matches = append(matches, "icmp")
	case proto == "ANY":
		// Without a protocol the dashboard means TCP/UDP port filtering; other
		// protocols are addresses-only and match every transport.
		if ports != "" {
			matches = append(matches, "meta l4proto { tcp, udp }", "th dport "+ports)
		}
	default:
		match := strings.ToLower(proto)
		if ports != "" {
			match += " dport " + ports
		}
		matches = append(matches, match)
	}

	verdict, actionOK := nftFirewallAction(rule.Action)
	if !actionOK {
		return nil, fmt.Sprintf("rule %s has unsupported action %q and was skipped", rule.ID, rule.Action)
	}

	dropPrefix := strconv.Quote(nftNGFWLogPrefix + "DROP: ")
	logPrefix := strconv.Quote(nftNGFWLogPrefix + "LOG: ")

	switch verdict {
	case "":
		// Log-only monitor rule. The packet continues through later rules and
		// the chain policy because no verdict is given.
		logged := append(cloneStrings(matches), "counter "+fwLogRateLimit+" log prefix "+logPrefix)
		return []string{strings.Join(logged, " ")}, ""
	case "drop":
		// Deny pairs a rate-limited log line (so a flood cannot drown the
		// telemetry) with an unlimited drop so enforcement never depends on
		// the logging budget.
		logged := append(cloneStrings(matches), "counter "+fwLogRateLimit+" log prefix "+dropPrefix)
		dropped := append(cloneStrings(matches), "counter drop")
		return []string{strings.Join(logged, " "), strings.Join(dropped, " ")}, ""
	default:
		accepted := append(cloneStrings(matches), "counter accept")
		return []string{strings.Join(accepted, " ")}, ""
	}
}

// renderNFTablesFirewall builds the kernel ACL for the perimeter NGFW as a
// self-contained nftables script. It is a pure function so it can be
// unit-tested without touching the host.
//
// The OAT table hooks input at priority -10: after the WAF's kernel blocklist
// table (priority -50) and before regular host firewalls. An `accept` in this
// chain still lets later host rules evaluate; `drop` ends the packet.
//
// An empty script means the OAT table must be removed entirely (no ACL rules
// are desired).
func renderNFTablesFirewall(policy *FirewallPolicy) (string, int, []string) {
	warnings := []string{}
	if policy == nil || len(policy.Rules) == 0 {
		return "", 0, warnings
	}

	// Server output is already sorted by priority, but sorting locally keeps
	// evaluation order deterministic (and test-stable) regardless.
	rules := make([]FirewallRule, len(policy.Rules))
	copy(rules, policy.Rules)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})

	lines := []string{
		"table inet oat_ngfw {}",
		"delete table inet oat_ngfw",
		"table inet oat_ngfw {",
		"    chain input {",
		"        type filter hook input priority -10; policy accept;",
	}

	applied := 0
	for _, rule := range rules {
		ruleLines, warn := nftFirewallRuleLines(rule)
		if warn != "" {
			warnings = append(warnings, warn)
			continue
		}
		lines = append(lines, "        # "+sanitizeFwComment(rule.ID))
		for _, line := range ruleLines {
			lines = append(lines, "        "+line)
		}
		applied++
	}
	if applied == 0 {
		return "", 0, warnings
	}

	lines = append(lines, "    }", "}")
	return strings.Join(lines, "\n"), applied, warnings
}
