//go:build !windows

package main

import "context"

func startWindowsEventLogs(_ context.Context, _ *Config, _ *StateStore, _ *Queue) {
	// Windows event log collection is only available on Windows.
}
