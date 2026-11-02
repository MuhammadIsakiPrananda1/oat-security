//go:build linux

package main

import (
	"strings"
)

// applyFirewallPolicy enforces the desired perimeter ACL as the nftables table
// `inet oat_ngfw` on the local kernel. It shares the WAF's command helpers
// (findHostTool, runWAFCommand, runWAFCommandWithInput, …) because both need
// the same guarded, atomic nft invocation pattern.
func applyFirewallPolicy(cfg *Config, policy *FirewallPolicy) FirewallApplyResult {
	if policy == nil {
		return FirewallApplyResult{
			Status:  fwStatusFailed,
			Message: "the server returned an empty firewall policy",
		}
	}

	nftPath := findHostTool("nft")
	if nftPath == "" {
		return FirewallApplyResult{
			Status:  fwStatusUnsupported,
			Message: "nftables (nft) is not installed on this host; install nftables to enforce the perimeter ACL",
			Target:  "linux",
		}
	}

	script, applied, warnings := renderNFTablesFirewall(policy)

	if script == "" {
		// No ACL entries are desired. Remove the OAT-owned table; a missing
		// table is already the desired state and not an error.
		output, err := runWAFCommand(nftPath, "delete", "table", "inet", "oat_ngfw")
		if err != nil && !nftTableMissing(output, err) {
			// Non-fatal notice: table might not exist yet
			warnings = append(warnings, "table cleanup notice: "+compactOutput(output, err))
		}
		return FirewallApplyResult{
			Status:  fwStatusApplied,
			Message: fwApplyMessage(warnings, "Firewall active (0 ACL rules)."),
			Target:  "nftables",
		}
	}

	// nft -f applies the whole script atomically: the previous kernel rules stay
	// in place until the new ruleset validates and loads.
	if output, err := runWAFCommandWithInput(script, nftPath, "-f", "-"); err != nil {
		return FirewallApplyResult{
			Status:  fwStatusFailed,
			Message: "nftables apply failed: " + compactOutput(output, err),
			Target:  "nftables",
		}
	}

	return FirewallApplyResult{
		Status:       fwStatusApplied,
		Message:      fwApplyMessage(warnings, "Perimeter ACL active in kernel (table inet oat_ngfw)."),
		Target:       "nftables",
		RulesApplied: applied,
	}
}

// fwApplyMessage joins the render warnings (skipped rules, bad addresses) into
// the ack message; a clean run reports the fallback text.
func fwApplyMessage(warnings []string, fallback string) string {
	if len(warnings) == 0 {
		return fallback
	}
	return strings.Join(dedupeStrings(warnings), " | ")
}
