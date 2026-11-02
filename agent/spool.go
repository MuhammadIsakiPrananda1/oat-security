package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const maxSpoolFiles = 100

type Spool struct {
	dir string
}

func newSpool(dir string) (*Spool, error) {
	spoolDir := filepath.Join(dir, "spool")
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return nil, err
	}
	return &Spool{dir: spoolDir}, nil
}

func (s *Spool) Save(batch Batch) error {
	if len(batch.Events) == 0 && len(batch.Logs) == 0 {
		return nil
	}
	data, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	random := make([]byte, 4)
	_, _ = rand.Read(random)
	name := fmt.Sprintf("batch-%d-%s.json", time.Now().UnixNano(), hex.EncodeToString(random))
	temp := filepath.Join(s.dir, name+".tmp")
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, filepath.Join(s.dir, name)); err != nil {
		return err
	}
	s.enforceLimit()
	return nil
}

func (s *Spool) files() []string {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		files = append(files, filepath.Join(s.dir, entry.Name()))
	}
	sort.Strings(files)
	return files
}

func (s *Spool) LoadOldest(limit int) (Batch, []string) {
	combined := Batch{}
	files := s.files()
	if limit <= 0 || limit > len(files) {
		limit = len(files)
	}
	loaded := make([]string, 0, limit)
	for _, file := range files[:limit] {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var batch Batch
		if err := json.Unmarshal(data, &batch); err != nil {
			_ = os.Remove(file)
			continue
		}
		combined.Events = append(combined.Events, batch.Events...)
		combined.Logs = append(combined.Logs, batch.Logs...)
		loaded = append(loaded, file)
	}
	return combined, loaded
}

func (s *Spool) Remove(paths []string) {
	for _, file := range paths {
		_ = os.Remove(file)
	}
}

func (s *Spool) Count() int {
	return len(s.files())
}

func (s *Spool) enforceLimit() {
	files := s.files()
	if len(files) <= maxSpoolFiles {
		return
	}
	for _, file := range files[:len(files)-maxSpoolFiles] {
		_ = os.Remove(file)
	}
}
