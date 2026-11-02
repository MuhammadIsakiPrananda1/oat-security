//go:build windows

package main

import "runtime"

func CollectMetrics() Metrics {
	return Metrics{
		Hostname: hostname(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		IP:       hostIP(),
		CPUCores: runtime.NumCPU(),
	}
}
