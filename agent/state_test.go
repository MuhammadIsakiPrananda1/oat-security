package main

import "testing"

func TestClearWAFResultPreservesTelemetryState(t *testing.T) {
	dir := t.TempDir()
	store, err := loadState(dir)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}

	store.SetOffset("/var/log/apache2/access.log", 42)
	store.SetFIMSnapshot(map[string]string{"/etc/passwd": "abc123"}, true)
	store.SetWAFResult(5, wafStatusApplied, "2026-10-20T00:00:00Z")

	store.ClearWAFResult()
	revision, status, appliedAt := store.WAFResult()
	if revision != 0 || status != "" || appliedAt != "" {
		t.Fatalf("cached WAF result was not cleared: revision=%d status=%q appliedAt=%q", revision, status, appliedAt)
	}
	if offset, ok := store.GetOffset("/var/log/apache2/access.log"); !ok || offset != 42 {
		t.Fatalf("log offset was lost: offset=%d ok=%v", offset, ok)
	}
	if !store.HasFIMBaseline() {
		t.Fatal("FIM baseline flag was lost")
	}
	if got := store.FIMSnapshot()["/etc/passwd"]; got != "abc123" {
		t.Fatalf("FIM snapshot was lost: %q", got)
	}

	if err := store.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	reloaded, err := loadState(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	revision, status, appliedAt = reloaded.WAFResult()
	if revision != 0 || status != "" || appliedAt != "" {
		t.Fatalf("cleared WAF result was not persisted: revision=%d status=%q appliedAt=%q", revision, status, appliedAt)
	}
	if offset, ok := reloaded.GetOffset("/var/log/apache2/access.log"); !ok || offset != 42 {
		t.Fatalf("persisted log offset was lost: offset=%d ok=%v", offset, ok)
	}
}
