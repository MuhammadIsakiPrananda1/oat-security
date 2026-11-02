//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

func applyWAFPolicy(cfg *Config, policy *WAFPolicy) WAFApplyResult {
	return WAFApplyResult{
		Status:  wafStatusUnsupported,
		Message: fmt.Sprintf("WAF enforcement is only supported on Linux hosts running Apache 2; this agent is %s/%s", runtime.GOOS, runtime.GOARCH),
		Target:  runtime.GOOS,
	}
}
