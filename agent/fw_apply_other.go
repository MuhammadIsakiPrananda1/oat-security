//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

func applyFirewallPolicy(cfg *Config, policy *FirewallPolicy) FirewallApplyResult {
	return FirewallApplyResult{
		Status:  fwStatusUnsupported,
		Message: fmt.Sprintf("NGFW enforcement is only supported on Linux hosts with nftables; this agent is %s/%s", runtime.GOOS, runtime.GOARCH),
		Target:  runtime.GOOS,
	}
}
