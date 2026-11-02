package main

import (
	"encoding/json"
	"fmt"
	"log"
)

const (
	wafStatusApplied     = "APPLIED"
	wafStatusFailed      = "FAILED"
	wafStatusUnsupported = "UNSUPPORTED"
)

type WAFRule struct {
	ID          string `json:"id"`
	RuleID      string `json:"ruleId"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

type WAFPolicy struct {
	Revision               int64     `json:"revision"`
	EngineEnabled          bool      `json:"engineEnabled"`
	Mode                   string    `json:"mode"`
	RateLimitRequests      int       `json:"rateLimitRequests"`
	RateLimitWindowSeconds int       `json:"rateLimitWindowSeconds"`
	IPAllowlist            []string  `json:"ipAllowlist"`
	IPBlocklist            []string  `json:"ipBlocklist"`
	GeoBlockCountries      []string  `json:"geoBlockCountries"`
	BotProtectionEnabled   bool      `json:"botProtectionEnabled"`
	PolicyUpdatedAt        string    `json:"policyUpdatedAt"`
	Rules                  []WAFRule `json:"rules"`
}

type WAFApplyResult struct {
	Status       string
	Message      string
	Target       string
	RulesApplied int
}

type wafStatusPayload struct {
	Revision      int64  `json:"revision"`
	Status        string `json:"status"`
	Message       string `json:"message,omitempty"`
	Target        string `json:"target,omitempty"`
	RulesApplied  int    `json:"rulesApplied"`
	EngineEnabled bool   `json:"engineEnabled"`
	Mode          string `json:"mode,omitempty"`
	AppliedAt     string `json:"appliedAt,omitempty"`
}

func (c *Client) FetchWAFPolicy() (*WAFPolicy, error) {
	responseBody, err := c.post("/api/agents/waf/policy", map[string]string{}, true)
	if err != nil {
		return nil, err
	}
	var policy WAFPolicy
	if err := json.Unmarshal(responseBody, &policy); err != nil {
		return nil, fmt.Errorf("decode WAF policy: %w", err)
	}
	return &policy, nil
}

func (c *Client) ReportWAFStatus(policy *WAFPolicy, result WAFApplyResult) error {
	appliedAt := ""
	if result.Status == wafStatusApplied {
		appliedAt = nowISO()
	}
	_, err := c.post("/api/agents/waf/status", wafStatusPayload{
		Revision:      policy.Revision,
		Status:        result.Status,
		Message:       result.Message,
		Target:        result.Target,
		RulesApplied:  result.RulesApplied,
		EngineEnabled: policy.EngineEnabled,
		Mode:          policy.Mode,
		AppliedAt:     appliedAt,
	}, true)
	return err
}

func runWAFOnce(client *Client, cfg *Config, state *StateStore, debug bool) {
	if !cfg.WAFIsEnabled() {
		// Report the operator's explicit opt-out instead of leaving the
		// dashboard stuck on "waiting" forever. Do not cache this result:
		// re-enabling WAF must apply the current revision on the next start.
		policy, err := client.FetchWAFPolicy()
		if err != nil {
			if debug {
				log.Printf("[waf] policy pull failed while WAF is disabled: %v", err)
			}
			return
		}
		if policy.Revision <= 0 {
			return
		}
		result := WAFApplyResult{
			Status:  wafStatusUnsupported,
			Message: "WAF enforcement is disabled in the agent configuration (wafEnabled=false)",
			Target:  "disabled",
		}
		if err := client.ReportWAFStatus(policy, result); err != nil {
			log.Printf("[waf] could not report disabled status for revision %d: %v", policy.Revision, err)
		}
		return
	}

	policy, err := client.FetchWAFPolicy()
	if err != nil {
		if debug {
			log.Printf("[waf] policy pull failed: %v", err)
		}
		return
	}
	if policy.Revision <= 0 {
		return
	}

	appliedRevision, appliedStatus, _ := state.WAFResult()
	if appliedRevision == policy.Revision && (appliedStatus == wafStatusApplied || appliedStatus == wafStatusUnsupported) {
		return
	}

	result := applyWAFPolicy(cfg, policy)
	if err := client.ReportWAFStatus(policy, result); err != nil {
		log.Printf("[waf] could not report status for revision %d: %v", policy.Revision, err)
		return
	}

	state.SetWAFResult(policy.Revision, result.Status, nowISO())
	if result.Status == wafStatusApplied {
		log.Printf("[waf] revision %d applied on %s (%d rule(s))", policy.Revision, result.Target, result.RulesApplied)
		if result.Message != "" {
			log.Printf("[waf] %s", result.Message)
		}
	} else {
		log.Printf("[waf] revision %d %s: %s", policy.Revision, result.Status, result.Message)
	}
}
