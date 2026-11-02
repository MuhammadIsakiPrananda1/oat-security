//go:build !linux && !windows

package main

import "runtime"

func CollectMetrics() Metrics {
	return Metrics{
		Hostname: hostname(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		IP:       hostIP(),
	}
}
