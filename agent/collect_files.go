package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxLineBytes = 256 * 1024

type fileTailer struct {
	cfg   *Config
	state *StateStore
	queue *Queue
}

func startFileTailers(ctx context.Context, cfg *Config, state *StateStore, queue *Queue) {
	tailer := &fileTailer{cfg: cfg, state: state, queue: queue}
	go tailer.loop(ctx)
}

func (t *fileTailer) loop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.scan(ctx)
		}
	}
}

func (t *fileTailer) scan(ctx context.Context) {
	paths := expandGlobs(t.cfg.LogPaths)
	for _, path := range paths {
		if ctx.Err() != nil {
			return
		}
		t.tailFile(path)
	}
}

func expandGlobs(patterns []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if len(matches) == 0 {
			if _, err := os.Stat(pattern); err == nil {
				matches = []string{pattern}
			}
		}
		for _, match := range matches {
			cleaned := filepath.Clean(match)
			if seen[cleaned] {
				continue
			}
			seen[cleaned] = true
			result = append(result, cleaned)
		}
	}
	return result
}

func (t *fileTailer) tailFile(path string) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}
	size := info.Size()

	offset, known := t.state.GetOffset(path)
	if !known {
		offset = 0
	}
	if size < offset {
		// Truncated or rotated in place.
		offset = 0
	}
	if size == offset {
		return
	}

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return
	}

	reader := bufio.NewReaderSize(file, 64*1024)
	consumed := int64(0)
	lineLength := 0
	lineBuffer := make([]byte, 0, 4096)

	for {
		fragment, readErr := reader.ReadSlice('\n')
		if len(fragment) > 0 {
			lineLength += len(fragment)
			if len(lineBuffer) < maxLineBytes {
				remaining := maxLineBytes - len(lineBuffer)
				if len(fragment) <= remaining {
					lineBuffer = append(lineBuffer, fragment...)
				} else {
					lineBuffer = append(lineBuffer, fragment[:remaining]...)
				}
			}
		}

		if readErr == bufio.ErrBufferFull {
			continue
		}

		if readErr == nil {
			consumed += int64(lineLength)
			line := strings.TrimRight(string(lineBuffer), "\r\n")
			lineBuffer = lineBuffer[:0]
			lineLength = 0
			if line != "" {
				logs, events := parseLine(t.cfg, path, line)
				for _, entry := range logs {
					t.queue.AddLog(entry)
				}
				for _, event := range events {
					t.queue.AddEvent(event)
				}
			}
			if _, logCount := t.queue.Len(); logCount >= 3000 {
				break
			}
			continue
		}

		if readErr == io.EOF {
			// Leave a partial line unconsumed; it will be completed (or
			// rotated away) on a later poll.
			break
		}

		log.Printf("[agent] read %s: %v", path, readErr)
		break
	}

	if consumed > 0 {
		t.state.SetOffset(path, offset+consumed)
	}
}
