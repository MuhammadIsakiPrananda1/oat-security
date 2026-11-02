package main

import (
	"encoding/json"
	"fmt"
	"log"
)

const (
	fwStatusApplied     = "APPLIED"
	fwStatusFailed      = "FAILED"
	fwStatusUnsupported = "UNSUPPORTED"
)

// FirewallRule mirrors one enabled entry of the dashboard perimeter ACL.
type FirewallRule struct {
	ID          string `json:"id"`
	Priority    int    `json:"priority"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Port        string `json:"port"`
	Protocol    string `json:"protocol"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// FirewallPolicy is the full desired kernel state for this organization.
type FirewallPolicy struct {
	Revision        int64          `json:"revision"`
	PolicyUpdatedAt string         `json:"policyUpdatedAt,omitempty"`
	Rules           []FirewallRule `json:"rules"`
}

type FirewallApplyResult struct {
	Status       string
	Message      string
	Target       string
	RulesApplied int
}

type fwStatusPayload struct {
	Revision     int64  `json:"revision"`
	Status       string `json:"status"`
	Message      string `json:"message,omitempty"`
	Target       string `json:"target,omitempty"`
	RulesApplied int    `json:"rulesApplied"`
	AppliedAt    string `json:"appliedAt,omitempty"`
}

func (c *Client) FetchFirewallPolicy() (*FirewallPolicy, error) {
	responseBody, err := c.post("/api/agents/firewall/policy", map[string]string{}, true)
	if err != nil {
		return nil, err
	}
	var policy FirewallPolicy
	if err := json.Unmarshal(responseBody, &policy); err != nil {
		return nil, fmt.Errorf("decode firewall policy: %w", err)
	}
	return &policy, nil
}

func (c *Client) ReportFirewallStatus(policy *FirewallPolicy, result FirewallApplyResult) error {
	appliedAt := ""
	if result.Status == fwStatusApplied {
		appliedAt = nowISO()
	}
	_, err := c.post("/api/agents/firewall/status", fwStatusPayload{
		Revision:     policy.Revision,
		Status:       result.Status,
		Message:      result.Message,
		Target:       result.Target,
		RulesApplied: result.RulesApplied,
		AppliedAt:    appliedAt,
	}, true)
	return err
}

// runFirewallOnce mirrors runWAFOnce for the perimeter NGFW: pull the desired
// ACL revision, enforce it as an nftables table, and ack the result. Results
// are cached in the state store, so an unchanged revision costs one signed
// request per tick instead of a kernel mutation.
func runFirewallOnce(client *Client, cfg *Config, state *StateStore, debug bool) {
	if !cfg.FWIsEnabled() {
		// Report the operator's explicit opt-out instead of leaving the
		// deployment view stuck on "waiting" forever. Do not cache this
		// result: re-enabling the NGFW must re-report on the next start.
		policy, err := client.FetchFirewallPolicy()
		if err != nil {
			if debug {
				log.Printf("[fw] policy pull failed while NGFW is disabled: %v", err)
			}
			return
		}
		if policy.Revision <= 0 {
			return
		}
		result := FirewallApplyResult{
			Status:  fwStatusUnsupported,
			Message: "NGFW enforcement is disabled in the agent configuration (fwEnabled=false)",
			Target:  "disabled",
		}
		if err := client.ReportFirewallStatus(policy, result); err != nil {
			log.Printf("[fw] could not report disabled status for revision %d: %v", policy.Revision, err)
		}
		return
	}

	policy, err := client.FetchFirewallPolicy()
	if err != nil {
		if debug {
			log.Printf("[fw] policy pull failed: %v", err)
		}
		return
	}
	if policy.Revision <= 0 {
		return
	}

	appliedRevision, appliedStatus, _ := state.FWResult()
	if appliedRevision == policy.Revision && (appliedStatus == fwStatusApplied || appliedStatus == fwStatusUnsupported) {
		return
	}

	result := applyFirewallPolicy(cfg, policy)
	if err := client.ReportFirewallStatus(policy, result); err != nil {
		log.Printf("[fw] could not report status for revision %d: %v", policy.Revision, err)
		return
	}

	state.SetFWResult(policy.Revision, result.Status, nowISO())
	if result.Status == fwStatusApplied {
		log.Printf("[fw] revision %d applied on %s (%d rule(s))", policy.Revision, result.Target, result.RulesApplied)
		if result.Message != "" {
			log.Printf("[fw] %s", result.Message)
		}
	} else {
		log.Printf("[fw] revision %d %s: %s", policy.Revision, result.Status, result.Message)
	}
}
