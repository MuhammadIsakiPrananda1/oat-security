package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type stateData struct {
	FileOffsets     map[string]int64  `json:"fileOffsets"`
	FIM             map[string]string `json:"fim"`
	FIMBaseline     bool              `json:"fimBaseline"`
	Winlog          map[string]int64  `json:"winlog"`
	Malware         map[string]int64  `json:"malware,omitempty"`
	MalwareFiles    map[string]int64  `json:"malwareFiles,omitempty"`
	MalwareBaseline bool              `json:"malwareBaseline,omitempty"`
	LastHeartbeat   string            `json:"lastHeartbeat,omitempty"`
	WAFRevision     int64             `json:"wafRevision,omitempty"`
	WAFStatus       string            `json:"wafStatus,omitempty"`
	WAFAppliedAt    string            `json:"wafAppliedAt,omitempty"`
	FWRevision      int64             `json:"fwRevision,omitempty"`
	FWStatus        string            `json:"fwStatus,omitempty"`
	FWAppliedAt     string            `json:"fwAppliedAt,omitempty"`
}

type StateStore struct {
	mu   sync.Mutex
	path string
	data stateData
}

func loadState(stateDir string) (*StateStore, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	store := &StateStore{
		path: filepath.Join(stateDir, "state.json"),
		data: stateData{
			FileOffsets:  map[string]int64{},
			FIM:          map[string]string{},
			Winlog:       map[string]int64{},
			Malware:      map[string]int64{},
			MalwareFiles: map[string]int64{},
		},
	}

	data, err := os.ReadFile(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, &store.data); err != nil {
		// A corrupt state file must not stop the agent. Starting fresh is safe:
		// log offsets re-baseline and FIM creates a new baseline.
		return store, nil
	}
	if store.data.FileOffsets == nil {
		store.data.FileOffsets = map[string]int64{}
	}
	if store.data.FIM == nil {
		store.data.FIM = map[string]string{}
	}
	if store.data.Winlog == nil {
		store.data.Winlog = map[string]int64{}
	}
	if store.data.Malware == nil {
		store.data.Malware = map[string]int64{}
	}
	if store.data.MalwareFiles == nil {
		store.data.MalwareFiles = map[string]int64{}
	}
	return store, nil
}

func (s *StateStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	temp := s.path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, s.path)
}

func (s *StateStore) GetOffset(path string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.data.FileOffsets[path]
	return value, ok
}

func (s *StateStore) SetOffset(path string, offset int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.FileOffsets[path] = offset
}

func (s *StateStore) FIMSnapshot() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyMap := make(map[string]string, len(s.data.FIM))
	for key, value := range s.data.FIM {
		copyMap[key] = value
	}
	return copyMap
}

func (s *StateStore) SetFIMSnapshot(snapshot map[string]string, baseline bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.FIM = snapshot
	s.data.FIMBaseline = baseline
}

func (s *StateStore) HasFIMBaseline() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.FIMBaseline
}

func (s *StateStore) WinlogLast(channel string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Winlog[channel]
}

func (s *StateStore) SetWinlogLast(channel string, recordID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Winlog[channel] = recordID
}

// ----------------------------------------------------------------------
// Upload watcher state
// ----------------------------------------------------------------------

// MalwareSnapshot returns the last modified time observed for each web file.
func (s *StateStore) MalwareSnapshot() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyMap := make(map[string]int64, len(s.data.MalwareFiles))
	for key, value := range s.data.MalwareFiles {
		copyMap[key] = value
	}
	return copyMap
}

func (s *StateStore) SetMalwareSnapshot(snapshot map[string]int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.MalwareFiles = snapshot
}

func (s *StateStore) HasMalwareBaseline() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.MalwareBaseline
}

func (s *StateStore) SetMalwareBaseline() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.MalwareBaseline = true
}

// MarkMalwareScanned remembers a file/hash pair so the same bytes are never
// analyzed twice, even if the file is renamed.
func (s *StateStore) MarkMalwareScanned(key string, when int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Malware == nil {
		s.data.Malware = map[string]int64{}
	}
	s.data.Malware[key] = when
}

func (s *StateStore) MalwareScanned(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data.Malware[key]
	return ok
}

func (s *StateStore) PruneMalwareScanned(before int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, when := range s.data.Malware {
		if when < before {
			delete(s.data.Malware, key)
		}
	}
}

func (s *StateStore) SetLastHeartbeat(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.LastHeartbeat = value
}

func (s *StateStore) LastHeartbeat() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.LastHeartbeat
}

func (s *StateStore) WAFResult() (int64, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.WAFRevision, s.data.WAFStatus, s.data.WAFAppliedAt
}

func (s *StateStore) SetWAFResult(revision int64, status, appliedAt string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.WAFRevision = revision
	s.data.WAFStatus = status
	s.data.WAFAppliedAt = appliedAt
}

// ClearWAFResult forgets the cached WAF revision without touching log offsets,
// FIM baselines, or the offline spool. Enrollment calls this so a reinstall
// always re-evaluates the current server revision instead of skipping it.
func (s *StateStore) ClearWAFResult() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.WAFRevision = 0
	s.data.WAFStatus = ""
	s.data.WAFAppliedAt = ""
}

func (s *StateStore) FWResult() (int64, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.FWRevision, s.data.FWStatus, s.data.FWAppliedAt
}

func (s *StateStore) SetFWResult(revision int64, status, appliedAt string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.FWRevision = revision
	s.data.FWStatus = status
	s.data.FWAppliedAt = appliedAt
}

// ClearFirewallResult is the NGFW counterpart of ClearWAFResult. Enrollment
// calls both so a reinstall never trusts a cached revision from an earlier
// identity.
func (s *StateStore) ClearFirewallResult() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.FWRevision = 0
	s.data.FWStatus = ""
	s.data.FWAppliedAt = ""
}
