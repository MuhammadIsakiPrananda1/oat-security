package main

import (
	"strings"
	"testing"
)

func TestRenderApacheCustomPattern(t *testing.T) {
	policy := &WAFPolicy{
		Revision:      7,
		EngineEnabled: true,
		Mode:          "block",
		Rules: []WAFRule{{
			ID:      "r1",
			RuleID:  "OAT-CUSTOM-1",
			Name:    "Union select",
			Action:  "BLOCK",
			Pattern: `(?i)union\s+select`,
		}},
	}

	config, warnings := renderApacheWAF(policy)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	for _, want := range []string{
		"<IfModule mod_rewrite.c>",
		`RewriteCond %{THE_REQUEST} "(?i)union\s+select" [NC,OR]`,
		`RewriteCond %{HTTP_USER_AGENT} "(?i)union\s+select" [NC]`,
		"RewriteRule ^ - [F,L]",
		"# Revision: 7",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("config missing %q:\n%s", want, config)
		}
	}
}

func TestRenderApacheMonitorMode(t *testing.T) {
	policy := &WAFPolicy{
		Revision:      2,
		EngineEnabled: true,
		Mode:          "monitor",
		Rules: []WAFRule{{
			Name:    "SQL",
			Action:  "BLOCK",
			Pattern: `union`,
		}},
	}

	config, _ := renderApacheWAF(policy)
	if !strings.Contains(config, "E=OAT_WAF_MONITOR:1,L") {
		t.Fatalf("monitor rule should set an environment flag, got:\n%s", config)
	}
	if strings.Contains(config, "[F,L]") {
		t.Fatalf("monitor mode must not return 403, got:\n%s", config)
	}
}

func TestRenderApacheLogRuleDoesNotStopProcessing(t *testing.T) {
	policy := &WAFPolicy{
		Revision:      1,
		EngineEnabled: true,
		Mode:          "block",
		Rules: []WAFRule{{
			Name:    "Log scanner",
			Action:  "LOG",
			Pattern: `sqlmap`,
		}},
	}

	config, _ := renderApacheWAF(policy)
	if !strings.Contains(config, "E=OAT_WAF_LOG:1") {
		t.Fatalf("log rule was not rendered:\n%s", config)
	}
	if strings.Contains(config, "E=OAT_WAF_LOG:1,L") {
		t.Fatalf("log rule must not stop later blocking rules:\n%s", config)
	}
}

func TestRenderApacheBuiltInCategory(t *testing.T) {
	policy := &WAFPolicy{
		Revision:      1,
		EngineEnabled: true,
		Mode:          "block",
		Rules: []WAFRule{{
			Name:     "SQL injection",
			Category: "SQL Injection",
			Action:   "BLOCK",
		}},
	}

	config, _ := renderApacheWAF(policy)
	if !strings.Contains(config, "union") || !strings.Contains(config, "RewriteRule ^ - [F,L]") {
		t.Fatalf("built-in category was not rendered:\n%s", config)
	}
}

func TestRenderApacheSkipsUnsafeCustomPattern(t *testing.T) {
	policy := &WAFPolicy{
		Revision:      1,
		EngineEnabled: true,
		Mode:          "block",
		Rules: []WAFRule{{
			Name:    "Injected",
			Action:  "BLOCK",
			Pattern: "union\nselect",
		}},
	}

	config, _ := renderApacheWAF(policy)
	if strings.Contains(config, "union\nselect") {
		t.Fatalf("unsafe pattern was written to Apache config:\n%s", config)
	}
	if strings.Contains(config, "[F,L]") {
		t.Fatalf("unsafe custom rule should not add a block directive:\n%s", config)
	}
}

func TestRenderApacheSkipsTrailingBackslash(t *testing.T) {
	policy := &WAFPolicy{
		Revision:      1,
		EngineEnabled: true,
		Mode:          "block",
		Rules: []WAFRule{{
			Name:    "Broken escape",
			Action:  "BLOCK",
			Pattern: `union\`,
		}},
	}

	config, _ := renderApacheWAF(policy)
	if strings.Contains(config, "union\\") || strings.Contains(config, "[F,L]") {
		t.Fatalf("pattern ending in a lone backslash must not be rendered:\\n%s", config)
	}
}

func TestRenderNFTables(t *testing.T) {
	policy := &WAFPolicy{
		Revision:               4,
		EngineEnabled:          true,
		Mode:                   "block",
		IPBlocklist:            []string{"198.51.100.5", "203.0.113.0/24", "2001:db8::/32", "not-an-ip"},
		RateLimitRequests:      100,
		RateLimitWindowSeconds: 10,
	}

	script, warnings := renderNFTables(policy)
	for _, want := range []string{
		"add table inet oat_waf",
		"ip saddr 198.51.100.5 drop",
		"ip saddr 203.0.113.0/24 drop",
		"ip6 saddr 2001:db8::/32 drop",
		"meta l4proto tcp th dport { 80, 443 } ct state new limit rate over 10/second drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft script missing %q:\n%s", want, script)
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not-an-ip") {
		t.Fatalf("expected invalid-IP warning, got %v", warnings)
	}
}

func TestRenderDisabledEngine(t *testing.T) {
	policy := &WAFPolicy{
		Revision:               9,
		EngineEnabled:          false,
		Mode:                   "block",
		IPBlocklist:            []string{"198.51.100.5"},
		RateLimitRequests:      10,
		RateLimitWindowSeconds: 1,
	}

	config, _ := renderApacheWAF(policy)
	if !strings.Contains(config, "Engine disabled") {
		t.Fatalf("disabled config marker missing:\n%s", config)
	}
	if strings.Contains(config, "RewriteEngine On") {
		t.Fatalf("disabled engine must not enable rewriting:\n%s", config)
	}

	script, _ := renderNFTables(policy)
	if script != "" {
		t.Fatalf("disabled engine must clear nftables rules, got:\n%s", script)
	}
}

func TestRenderAllowlistWarnsForCIDR(t *testing.T) {
	policy := &WAFPolicy{
		Revision:      1,
		EngineEnabled: true,
		Mode:          "block",
		IPAllowlist:   []string{"203.0.113.10", "10.0.0.0/8"},
	}

	config, warnings := renderApacheWAF(policy)
	if !strings.Contains(config, `RewriteCond %{REMOTE_ADDR} ^203\.0\.113\.10$`) {
		t.Fatalf("exact allowlist IP missing:\n%s", config)
	}
	if !strings.Contains(config, "RewriteRule ^ - [L]") {
		t.Fatalf("allowlist bypass rule missing:\n%s", config)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "10.0.0.0/8") {
		t.Fatalf("expected CIDR allowlist warning, got %v", warnings)
	}
}
