package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxFIMFileSize = 10 * 1024 * 1024
	maxFIMFiles    = 20000
	maxFIMChanges  = 250
)

func startFIM(ctx context.Context, cfg *Config, state *StateStore, queue *Queue) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
		runFIM(cfg, state, queue)
		ticker := time.NewTicker(time.Duration(cfg.FIMSeconds) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runFIM(cfg, state, queue)
			}
		}
	}()
}

func runFIM(cfg *Config, state *StateStore, queue *Queue) {
	snapshot := collectFIMSnapshot(cfg.FIMPaths)
	if len(snapshot) == 0 && !state.HasFIMBaseline() {
		return
	}

	if !state.HasFIMBaseline() {
		state.SetFIMSnapshot(snapshot, true)
		_ = state.Save()
		queue.AddLog(LogEntry{
			Timestamp: nowISO(),
			Level:     "INFO",
			Source:    "agent",
			EventType: "fim_baseline",
			Message:   fmt.Sprintf("File integrity baseline created for %d files", len(snapshot)),
			Host:      cfg.Hostname,
			IP:        hostIP(),
			Collector: "fim",
			Metadata: map[string]any{
				"files": len(snapshot),
			},
		})
		log.Printf("[agent] FIM baseline created (%d files)", len(snapshot))
		return
	}

	previous := state.FIMSnapshot()
	changes := 0

	for path, newHash := range snapshot {
		oldHash, existed := previous[path]
		if existed && oldHash == newHash {
			continue
		}
		if changes >= maxFIMChanges {
			break
		}
		change := "modified"
		level := "WARN"
		severity := "Medium"
		if !existed {
			change = "added"
			severity = "Medium"
		}
		if isSensitivePath(path) {
			severity = "High"
		}
		changes++
		enqueueFIMChange(cfg, queue, path, change, oldHash, newHash, level, severity)
	}

	for path := range previous {
		if _, stillExists := snapshot[path]; stillExists {
			continue
		}
		if changes >= maxFIMChanges {
			break
		}
		changes++
		enqueueFIMChange(cfg, queue, path, "deleted", previous[path], "", "WARN", "High")
	}

	state.SetFIMSnapshot(snapshot, true)
	_ = state.Save()

	if changes > 0 {
		log.Printf("[agent] FIM detected %d change(s)", changes)
	}
}

func enqueueFIMChange(cfg *Config, queue *Queue, path, change, oldHash, newHash, level, severity string) {
	if change == "deleted" {
		level = "ERROR"
	}
	message := fmt.Sprintf("File integrity %s: %s", change, path)
	queue.AddLog(LogEntry{
		Timestamp: nowISO(),
		Level:     level,
		Source:    "agent",
		EventType: "fim_" + change,
		Message:   message,
		Host:      cfg.Hostname,
		IP:        hostIP(),
		Collector: "fim",
		Metadata: map[string]any{
			"path":    path,
			"change":  change,
			"oldHash": oldHash,
			"newHash": newHash,
		},
	})
	queue.AddEvent(Event{
		Timestamp:     nowISO(),
		EventType:     "file_integrity_" + change,
		Severity:      severity,
		SourceIP:      hostIP(),
		DestinationIP: hostIP(),
		Protocol:      "LOCAL",
		Application:   "fim",
		Action:        "LOG",
		ThreatName:    "File Integrity Change: " + filepath.Base(path),
		Metadata: map[string]any{
			"path":    path,
			"change":  change,
			"oldHash": oldHash,
			"newHash": newHash,
		},
		Collector: "fim",
	})
}

func collectFIMSnapshot(paths []string) map[string]string {
	snapshot := make(map[string]string, 256)
	count := 0

	for _, root := range expandGlobs(paths) {
		root = filepath.Clean(root)
		info, err := os.Lstat(root)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !info.IsDir() {
			if info.Size() > maxFIMFileSize {
				continue
			}
			if hash, ok := hashFile(root); ok {
				snapshot[root] = hash
			}
			continue
		}

		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if entry.IsDir() {
				if shouldSkipFIMDir(path) {
					return filepath.SkipDir
				}
				return nil
			}
			if count >= maxFIMFiles {
				return filepath.SkipAll
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			fileInfo, err := entry.Info()
			if err != nil || fileInfo.Size() > maxFIMFileSize {
				return nil
			}
			if hash, ok := hashFile(path); ok {
				snapshot[path] = hash
				count++
			}
			return nil
		})
	}
	return snapshot
}

func hashFile(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, maxFIMFileSize+1)); err != nil {
		return "", false
	}
	return hex.EncodeToString(hasher.Sum(nil)), true
}

func shouldSkipFIMDir(path string) bool {
	cleaned := filepath.ToSlash(path)
	skip := []string{
		"/proc", "/sys", "/dev", "/run", "/var/lib/oat-agent",
		"/var/lib/docker", "/var/lib/containers", "/snap",
	}
	for _, prefix := range skip {
		if cleaned == prefix || strings.HasPrefix(cleaned, prefix+"/") {
			return true
		}
	}
	return false
}

func isSensitivePath(path string) bool {
	cleaned := filepath.ToSlash(path)
	prefixes := []string{
		"/etc/", "/boot/", "/root/", "/home/", "/usr/bin/", "/usr/sbin/",
		"C:/Windows/System32/", "C:/Program Files/",
	}
	lower := strings.ToLower(cleaned)
	for _, prefix := range prefixes {
		if strings.Contains(lower, strings.ToLower(prefix)) {
			return true
		}
	}
	return strings.Contains(lower, "/.ssh/")
}
