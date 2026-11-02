package main

import (
	"strings"
	"testing"
)

func TestRenderNFTablesFirewallEmpty(t *testing.T) {
	script, applied, warnings := renderNFTablesFirewall(&FirewallPolicy{Revision: 3})
	if script != "" || applied != 0 || len(warnings) != 0 {
		t.Fatalf("expected an empty script for an empty policy, got %q (%d applied, %v)", script, applied, warnings)
	}
}

func TestRenderNFTablesFirewallOrderingAndShapes(t *testing.T) {
	policy := &FirewallPolicy{
		Revision: 7,
		Rules: []FirewallRule{
			{ID: "FW-100", Priority: 100, Source: "203.0.113.9", Destination: "ANY", Port: "22", Protocol: "TCP", Action: "DENY"},
			{ID: "FW-10", Priority: 10, Source: "10.0.0.0/8", Destination: "192.168.0.110", Port: "ANY", Protocol: "UDP", Action: "ALLOW"},
			{ID: "FW-50", Priority: 50, Source: "ANY", Destination: "ANY", Port: "ANY", Protocol: "ANY", Action: "LOG"},
		},
	}
	script, applied, warnings := renderNFTablesFirewall(policy)
	if applied != 3 || len(warnings) != 0 {
		t.Fatalf("expected 3 applied rules and no warnings, got %d / %v", applied, warnings)
	}

	for _, want := range []string{
		"add table inet oat_ngfw",
		"add chain inet oat_ngfw input { type filter hook input priority -10; policy accept; }",
		"flush chain inet oat_ngfw input",
		// DENY: rate-limited log line plus an unlimited drop.
		`ip saddr 203.0.113.9 tcp dport 22 counter limit rate 60/second log prefix "OAT_NGFW_DROP: "`,
		`ip saddr 203.0.113.9 tcp dport 22 counter drop`,
		// ALLOW: terminal accept with the full CIDR + UDP match.
		`ip saddr 10.0.0.0/8 ip daddr 192.168.0.110 udp counter accept`,
		// LOG: monitor line without a verdict.
		`counter limit rate 60/second log prefix "OAT_NGFW_LOG: "`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script is missing %q\n--- generated ---\n%s", want, script)
		}
	}

	// The LOG line must not carry a verdict, and lower priorities are emitted
	// before higher ones.
	logIndex := strings.Index(script, `log prefix "OAT_NGFW_LOG: "`)
	if logIndex == -1 {
		t.Fatalf("missing LOG line\n%s", script)
	}
	logLine := script[logIndex:]
	if newline := strings.Index(logLine, "\n"); newline != -1 {
		logLine = logLine[:newline]
	}
	if strings.Contains(logLine, " accept") || strings.Contains(logLine, " drop") {
		t.Fatalf("LOG rule must not decide the packet: %q", logLine)
	}
	if before, after := strings.Index(script, "# FW-10\n"), strings.Index(script, "# FW-100\n"); before == -1 || after == -1 || before > after {
		t.Fatalf("priority ordering broken (FW-10 at %d, FW-100 at %d)\n%s", before, after, script)
	}
}

func TestRenderNFTablesFirewallWildcardProtocolPorts(t *testing.T) {
	policy := &FirewallPolicy{
		Revision: 9,
		Rules: []FirewallRule{
			{ID: "FW-1", Priority: 1, Source: "ANY", Destination: "ANY", Port: "80,443", Protocol: "ANY", Action: "DENY"},
			{ID: "FW-2", Priority: 2, Source: "any", Destination: "any", Port: "80-90", Protocol: "ANY", Action: "ALLOW"},
		},
	}
	script, applied, warnings := renderNFTablesFirewall(policy)
	if applied != 2 || len(warnings) != 0 {
		t.Fatalf("expected 2 applied rules with no warnings, got %d / %v", applied, warnings)
	}
	for _, want := range []string{
		`meta l4proto { tcp, udp } th dport { 80, 443 } counter drop`,
		`th dport 80-90 counter accept`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q\n%s", want, script)
		}
	}
}

func TestRenderNFTablesFirewallSkipsBrokenRules(t *testing.T) {
	policy := &FirewallPolicy{
		Revision: 4,
		Rules: []FirewallRule{
			{ID: "FW-BADPORT", Priority: 1, Source: "ANY", Destination: "ANY", Port: "70000", Protocol: "TCP", Action: "DENY"},
			{ID: "FW-MIX", Priority: 2, Source: "203.0.113.9", Destination: "2001:db8::5", Port: "ANY", Protocol: "TCP", Action: "ALLOW"},
			{ID: "FW-ICMPPORT", Priority: 3, Source: "ANY", Destination: "ANY", Port: "8", Protocol: "ICMP", Action: "DENY"},
			{ID: "FW-PROTO", Priority: 4, Source: "ANY", Destination: "ANY", Port: "ANY", Protocol: "SCTP", Action: "DENY"},
			{ID: "FW-ACTION", Priority: 5, Source: "ANY", Destination: "ANY", Port: "ANY", Protocol: "TCP", Action: "NAT"},
			{ID: "FW-BADADDR", Priority: 6, Source: "not-an-address", Destination: "ANY", Port: "ANY", Protocol: "TCP", Action: "ALLOW"},
		},
	}
	script, applied, warnings := renderNFTablesFirewall(policy)
	if applied != 0 || script != "" {
		t.Fatalf("expected no rules applied (empty script), got %d applied\n%s", applied, script)
	}
	if count := strings.Count(strings.Join(warnings, "\n"), "skipped"); count < 4 {
		t.Fatalf("expected skip warnings, got %d: %v", count, warnings)
	}
	for _, want := range []string{
		"invalid port",
		"mixes IPv4 and IPv6",
		"ICMP has no ports",
		"unsupported protocol",
		"unsupported action",
		"invalid saddr",
	} {
		found := false
		for _, warning := range warnings {
			if strings.Contains(warning, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected a warning containing %q, got %v", want, warnings)
		}
	}
}

func TestRenderNFTablesFirewallSanitizesComment(t *testing.T) {
	if got := sanitizeFwComment("evil\r\n# deleted\n\t\t  \n"); strings.Contains(got, "\n") {
		t.Fatalf("comment leak: %q", got)
	}
}
