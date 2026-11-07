//go:build linux

package main

import (
	"bufio"
	"context"
	"log"
	"os/exec"
	"path/filepath"
	"time"
)

func startJournald(ctx context.Context, cfg *Config, queue *Queue) {
	if !cfg.Journald {
		return
	}
	go func() {
		stateDir := cfg.StateDir
		if stateDir == "" {
			stateDir = defaultStateDir()
		}
		cursorPath := filepath.Join(stateDir, "journald.cursor")
		command := exec.CommandContext(ctx, "journalctl", "-f", "-o", "json", "--no-pager", "--no-tail", "--cursor-file="+cursorPath)
		stdout, err := command.StdoutPipe()
		if err != nil {
			log.Printf("[agent] journald: %v", err)
			return
		}
		if err := command.Start(); err != nil {
			log.Printf("[agent] journald unavailable: %v", err)
			return
		}
		log.Printf("[agent] journald collector started")

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			for {
				if _, logCount := queue.Len(); logCount < 3000 || ctx.Err() != nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			logs, events := parseJournaldLine(cfg, scanner.Text())
			for _, entry := range logs {
				queue.AddLog(entry)
			}
			for _, event := range events {
				queue.AddEvent(event)
			}
		}
		if err := command.Wait(); err != nil && ctx.Err() == nil {
			log.Printf("[agent] journald collector stopped: %v", err)
		}
	}()
}
