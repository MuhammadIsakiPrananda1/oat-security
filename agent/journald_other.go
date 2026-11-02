//go:build !linux

package main

import "context"

func startJournald(_ context.Context, _ *Config, _ *Queue) {
	// journalctl is only available on Linux.
}
