package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// renderApacheWAF builds a self-contained Debian Apache config. It is a pure
// function so it can be unit-tested without touching the host.
func renderApacheWAF(policy *WAFPolicy) (string, []string) {
	warnings := []string{}
	lines := []string{
		"# OAT Security WAF - managed automatically by the endpoint agent.",
		fmt.Sprintf("# Revision: %d", policy.Revision),
		"# Do not edit by hand; changes are replaced on the next policy check.",
		"",
	}

	if !policy.EngineEnabled {
		lines = append(lines,
			"# Engine disabled: passthrough mode.",
			"# No inspection or blocking directives are active.",
			"",
		)
		return strings.Join(lines, "\n"), warnings
	}

	mode := strings.ToLower(strings.TrimSpace(policy.Mode))
	if mode != "monitor" {
		mode = "block"
	}

	lines = append(lines,
		"<IfModule mod_rewrite.c>",
		"  RewriteEngine On",
		fmt.Sprintf("  # Mode: %s", mode),
		"",
	)

	// IP allowlist bypass. Apache's REMOTE_ADDR condition is exact-match only,
	// so CIDRs are left to the network edge and reported as a warning.
	allowlist := make([]string, 0, len(policy.IPAllowlist))
	for _, entry := range policy.IPAllowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if net.ParseIP(entry) == nil {
			warnings = append(warnings, fmt.Sprintf("allowlist entry %q is not an exact IP (CIDR allowlisting is not applied by Apache)", entry))
			continue
		}
		allowlist = append(allowlist, regexp.QuoteMeta(entry))
	}
	if len(allowlist) > 0 {
		lines = append(lines, "  # Trusted addresses bypass all inspection.")
		for i, address := range allowlist {
			suffix := ""
			if i < len(allowlist)-1 {
				suffix = " [OR]"
			}
			lines = append(lines, fmt.Sprintf("  RewriteCond %%{REMOTE_ADDR} ^%s$%s", address, suffix))
		}
		lines = append(lines, "  RewriteRule ^ - [L]", "")
	}

	// Exact-IP blocklist. CIDR entries are enforced by nftables.
	blocklist := make([]string, 0, len(policy.IPBlocklist))
	for _, entry := range policy.IPBlocklist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if net.ParseIP(entry) == nil {
			continue
		}
		blocklist = append(blocklist, regexp.QuoteMeta(entry))
	}
	if len(blocklist) > 0 {
		lines = append(lines, "  # IP blocklist.")
		for i, address := range blocklist {
			suffix := ""
			if i < len(blocklist)-1 {
				suffix = " [OR]"
			}
			lines = append(lines, fmt.Sprintf("  RewriteCond %%{REMOTE_ADDR} ^%s$%s", address, suffix))
		}
		lines = append(lines, fmt.Sprintf("  RewriteRule ^ - %s", wafApacheAction(policy, "BLOCK")), "")
	}

	if policy.BotProtectionEnabled {
		lines = append(lines,
			"  # Automated scanner and bad-bot defense.",
			"  RewriteCond %{HTTP_USER_AGENT} (nikto|nmap|masscan|sqlmap|nessus|openvas|acunetix|burpsuite|w3af|skipfish|dirbuster|scrapy|zgrab|python-requests/|go-http-client|curl/|wget/|libwww-perl) [NC]",
			fmt.Sprintf("  RewriteRule ^ - %s", wafApacheAction(policy, "BLOCK")),
			"",
		)
	}

	for _, rule := range policy.Rules {
		action := strings.ToUpper(strings.TrimSpace(rule.Action))
		if action == "" {
			action = "BLOCK"
		}

		target, pattern, ok := wafRulePattern(rule)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("rule %q has no supported category or a safe pattern and was not applied", sanitizeApacheComment(rule.Name)))
			continue
		}

		lines = append(lines, fmt.Sprintf("  # %s (%s)", sanitizeApacheComment(rule.Name), sanitizeApacheComment(rule.RuleID)))
		if action == "CHALLENGE" {
			warnings = append(warnings, fmt.Sprintf("rule %q uses Challenge; the Apache endpoint enforces it as a block", sanitizeApacheComment(rule.Name)))
		}
		lines = appendRuleConditions(lines, target, pattern)
		if action == "LOG" {
			lines = append(lines,
				"  RewriteRule ^ - [E=OAT_WAF_LOG:1]",
				"",
			)
			continue
		}

		lines = append(lines,
			fmt.Sprintf("  RewriteRule ^ - %s", wafApacheAction(policy, action)),
			"",
		)
	}

	lines = append(lines, "</IfModule>", "")
	return strings.Join(lines, "\n"), warnings
}

// appendRuleConditions inspects both the request line and the User-Agent.
// Apache's THE_REQUEST variable does not include headers, so a rule such as
// "sqlmap" would otherwise never match a scanner that only identifies itself
// in its User-Agent.
func appendRuleConditions(lines []string, target string, pattern string) []string {
	if target == "%{HTTP_USER_AGENT}" {
		return append(lines, fmt.Sprintf("  RewriteCond %s \"%s\" [NC]", target, pattern))
	}
	return append(lines,
		fmt.Sprintf("  RewriteCond %s \"%s\" [NC,OR]", target, pattern),
		fmt.Sprintf("  RewriteCond %%{HTTP_USER_AGENT} \"%s\" [NC]", pattern),
	)
}

func wafApacheAction(policy *WAFPolicy, action string) string {
	if strings.EqualFold(strings.TrimSpace(policy.Mode), "monitor") {
		return "[E=OAT_WAF_MONITOR:1,L]"
	}
	if strings.EqualFold(strings.TrimSpace(action), "LOG") {
		// Do not stop rewrite processing: a log-only rule must never prevent a
		// later blocking rule from matching the same request.
		return "[E=OAT_WAF_LOG:1]"
	}
	return "[F,L]"
}

func normalizeWafSpacePattern(p string) string {
	if strings.Contains(p, "%20") {
		return p
	}
	p = strings.ReplaceAll(p, `\s+`, "__WAF_ONE_OR_MORE__")
	p = strings.ReplaceAll(p, `\s*`, "__WAF_ZERO_OR_MORE__")
	p = strings.ReplaceAll(p, `\s`, "__WAF_ONE_SPACE__")

	var sb strings.Builder
	runes := []rune(p)
	for i := 0; i < len(runes); i++ {
		if runes[i] == ' ' && (i == 0 || runes[i-1] != '\\') {
			for i+1 < len(runes) && runes[i+1] == ' ' {
				i++
			}
			sb.WriteString("__WAF_ONE_OR_MORE__")
		} else {
			sb.WriteRune(runes[i])
		}
	}
	p = sb.String()

	p = strings.ReplaceAll(p, "__WAF_ZERO_OR_MORE__", `(?:\s|%20|\+)*`)
	p = strings.ReplaceAll(p, "__WAF_ONE_OR_MORE__", `(?:\s|%20|\+)+`)
	p = strings.ReplaceAll(p, "__WAF_ONE_SPACE__", `(?:\s|%20|\+)`)
	return p
}

func wafRulePattern(rule WAFRule) (string, string, bool) {
	pattern := strings.TrimSpace(rule.Pattern)
	if pattern != "" {
		if strings.ContainsAny(pattern, "\r\n\x00\"") || endsWithUnescapedBackslash(pattern) {
			return "", "", false
		}
		return "%{THE_REQUEST}", normalizeWafSpacePattern(pattern), true
	}

	switch strings.ToLower(strings.TrimSpace(rule.Category)) {
	case "sql injection":
		return "%{THE_REQUEST}", `(?i)(\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|\bexec\b|--|/\*|\bor(?:\s|%20|\+)+\d+=\d+)`, true
	case "xss", "xss filter", "cross-site scripting":
		return "%{THE_REQUEST}", `(?i)(<script|javascript:|onerror=|onload=|<img[^>]+src=|<svg|alert\(|document\.cookie)`, true
	case "path traversal", "lfi":
		return "%{THE_REQUEST}", `(?i)(\.\./|\.\.\\|%2e%2e%2f|%252e)`, true
	case "rce", "command injection", "remote code execution":
		return "%{THE_REQUEST}", `(\$\(|` + "`" + `|;.*sh|cmd\.exe|/bin/|powershell|eval\(|exec\()`, true
	case "rfi", "remote file inclusion":
		return "%{THE_REQUEST}", `(?i)(https?://[^/]+/.*\.(php|sh|py|rb|pl))`, true
	case "bot protection", "bad bot", "scanner":
		return "%{HTTP_USER_AGENT}", `(nikto|nmap|masscan|sqlmap|nessus|openvas|acunetix|burpsuite|w3af|skipfish|dirbuster|scrapy|zgrab|python-requests/|go-http-client|curl/|wget/|libwww-perl)`, true
	default:
		return "", "", false
	}
}

func endsWithUnescapedBackslash(value string) bool {
	count := 0
	for i := len(value) - 1; i >= 0 && value[i] == '\\'; i-- {
		count++
	}
	return count%2 == 1
}

func sanitizeApacheComment(value string) string {
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

// renderNFTables builds the kernel-side blocklist and rate limit. Returning an
// empty string means the agent should remove the OAT-owned table.
func renderNFTables(policy *WAFPolicy) (string, []string) {
	warnings := []string{}
	if !policy.EngineEnabled {
		return "", warnings
	}

	blockLines := []string{}
	for _, entry := range policy.IPBlocklist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		family, address, ok := nftAddress(entry)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("blocklist entry %q is not a valid IP or CIDR", entry))
			continue
		}
		blockLines = append(blockLines, fmt.Sprintf("    %s saddr %s drop", family, address))
	}

	rateLines := []string{}
	if policy.RateLimitRequests > 0 && policy.RateLimitWindowSeconds > 0 {
		perSecond := (policy.RateLimitRequests + policy.RateLimitWindowSeconds - 1) / policy.RateLimitWindowSeconds
		if perSecond < 1 {
			perSecond = 1
		}
		rateLines = append(rateLines, fmt.Sprintf(
			"    meta l4proto tcp th dport { 80, 443 } ct state new limit rate over %d/second drop",
			perSecond,
		))
	}

	if len(blockLines) == 0 && len(rateLines) == 0 {
		return "", warnings
	}

	lines := []string{
		"table inet oat_waf {}",
		"delete table inet oat_waf",
		"table inet oat_waf {",
		"    chain input {",
		"        type filter hook input priority -50; policy accept;",
		"",
	}
	for _, bl := range blockLines {
		lines = append(lines, "        "+strings.TrimSpace(bl))
	}
	for _, rl := range rateLines {
		lines = append(lines, "        "+strings.TrimSpace(rl))
	}
	lines = append(lines, "    }", "}")
	return strings.Join(lines, "\n"), warnings
}

func nftAddress(entry string) (string, string, bool) {
	if strings.Contains(entry, "/") {
		ip, network, err := net.ParseCIDR(entry)
		if err != nil {
			return "", "", false
		}
		if ip.To4() != nil {
			return "ip", network.String(), true
		}
		return "ip6", network.String(), true
	}

	ip := net.ParseIP(entry)
	if ip == nil {
		return "", "", false
	}
	if ip.To4() != nil {
		return "ip", ip.String(), true
	}
	return "ip6", ip.String(), true
}
