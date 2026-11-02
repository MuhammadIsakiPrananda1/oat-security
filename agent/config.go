package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Config struct {
	Server            string            `json:"server"`
	AgentID           string            `json:"agentId"`
	OrganizationID    string            `json:"organizationId"`
	ApplicationID     string            `json:"applicationId,omitempty"`
	ApplicationName   string            `json:"applicationName,omitempty"`
	ApplicationDomain string            `json:"applicationDomain,omitempty"`
	PrivateKey        string            `json:"privateKey"`
	Name              string            `json:"name"`
	Hostname          string            `json:"hostname"`
	Labels            map[string]string `json:"labels,omitempty"`
	LogPaths          []string          `json:"logPaths,omitempty"`
	FIMPaths          []string          `json:"fimPaths,omitempty"`
	MalwareWatch      *bool             `json:"malwareWatch,omitempty"`
	MalwareSeconds    int               `json:"malwareSeconds"`
	MalwarePaths      []string          `json:"malwarePaths,omitempty"`
	Journald          bool              `json:"journald"`
	WindowsEventLogs  []string          `json:"windowsEventLogs,omitempty"`
	HeartbeatSeconds  int               `json:"heartbeatSeconds"`
	FlushSeconds      int               `json:"flushSeconds"`
	FIMSeconds        int               `json:"fimSeconds"`
	SCASeconds        int               `json:"scaSeconds"`
	StateDir          string            `json:"stateDir,omitempty"`
	Insecure          bool              `json:"insecure,omitempty"`
	CAFile            string            `json:"caFile,omitempty"`
	Debug             bool              `json:"debug,omitempty"`
	WAFEnabled        *bool             `json:"wafEnabled,omitempty"`
	WAFSeconds        int               `json:"wafSeconds,omitempty"`
	WAFApacheConfig   string            `json:"wafApacheConfig,omitempty"`
	FWEnabled         *bool             `json:"fwEnabled,omitempty"`
	FWSeconds         int               `json:"fwSeconds,omitempty"`
	EnrolledAt        string            `json:"enrolledAt,omitempty"`
}

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "OATAgent", "config.json")
	}
	return "/etc/oat-agent/config.json"
}

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "OATAgent", "state")
	}
	return "/var/lib/oat-agent"
}

func defaultLogPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{}
	}
	return []string{
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/nginx/access.log",
		"/var/log/nginx/error.log",
		"/var/log/nginx/*access.log",
		"/var/log/apache2/access.log",
		"/var/log/apache2/error.log",
		"/var/log/apache2/*access.log",
		"/var/log/httpd/access_log",
		"/var/log/httpd/error_log",
		"/www/wwwlogs/*.log",             // aaPanel website logs
		"/usr/local/apache/logs/*_log",    // cPanel access logs
		"/var/lib/docker/containers/*/*.log", // Docker container JSON logs
	}
}

func defaultFIMPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Windows\System32\drivers\etc\hosts`,
			`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
		}
	}
	return []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/sudoers",
		"/etc/ssh/sshd_config",
		"/etc/crontab",
		"/etc/systemd/system",
		"/root/.ssh",
		"/home/*/.ssh/authorized_keys",
	}
}

func defaultWindowsEventLogs() []string {
	if runtime.GOOS == "windows" {
		return []string{"Security", "System", "Application"}
	}
	return []string{}
}

func normalizeServer(value string) string {
	server := strings.TrimSpace(value)
	server = strings.TrimRight(server, "/")
	if server != "" && !strings.Contains(server, "://") {
		server = "https://" + server
	}
	return server
}

func applyConfigDefaults(cfg *Config) {
	cfg.Server = normalizeServer(cfg.Server)
	if cfg.Hostname == "" {
		hostname, err := os.Hostname()
		if err == nil {
			cfg.Hostname = hostname
		} else {
			cfg.Hostname = "unknown-host"
		}
	}
	if cfg.Name == "" {
		cfg.Name = cfg.Hostname
	}
	if cfg.HeartbeatSeconds <= 0 {
		cfg.HeartbeatSeconds = 1
	}
	if cfg.FlushSeconds <= 0 {
		cfg.FlushSeconds = 1
	}
	if cfg.FIMSeconds <= 0 {
		cfg.FIMSeconds = 300
	}
	if cfg.MalwareSeconds <= 0 {
		cfg.MalwareSeconds = 5
	}
	if cfg.SCASeconds <= 0 {
		cfg.SCASeconds = 21600
	}
	if cfg.WAFSeconds <= 0 {
		cfg.WAFSeconds = 15
	}
	if cfg.FWSeconds <= 0 {
		cfg.FWSeconds = 15
	}
	if cfg.WAFApacheConfig == "" && runtime.GOOS == "linux" {
		cfg.WAFApacheConfig = "/etc/apache2/conf-available/oat-waf.conf"
	}
	if cfg.StateDir == "" {
		cfg.StateDir = defaultStateDir()
	}
	if len(cfg.LogPaths) == 0 {
		cfg.LogPaths = defaultLogPaths()
	}
	if len(cfg.FIMPaths) == 0 {
		cfg.FIMPaths = defaultFIMPaths()
	}
	if len(cfg.WindowsEventLogs) == 0 {
		cfg.WindowsEventLogs = defaultWindowsEventLogs()
	}
	if cfg.Labels == nil {
		cfg.Labels = map[string]string{}
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	applyConfigDefaults(&cfg)
	return &cfg, nil
}

// WAFIsEnabled defaults to true so every enrolled agent reports its WAF
// capability. Non-Linux agents report UNSUPPORTED instead of pretending to
// enforce rules. Operators can opt out with --no-waf.
func (c *Config) WAFIsEnabled() bool {
	if c.WAFEnabled != nil {
		return *c.WAFEnabled
	}
	return true
}

// FWIsEnabled is the NGFW counterpart of WAFIsEnabled: the perimeter ACL is
// enforced by default wherever nftables exists, and --no-fw opts out.
func (c *Config) FWIsEnabled() bool {
	if c.FWEnabled != nil {
		return *c.FWEnabled
	}
	return true
}

// MalwareIsEnabled controls the upload watcher. It watches every web root on
// the host and sends each new file to the analysis engine, so it is enabled by
// default and can be turned off with --no-malware-watch.
func (c *Config) MalwareIsEnabled() bool {
	if c.MalwareWatch != nil {
		return *c.MalwareWatch
	}
	return true
}

func boolPointer(value bool) *bool {
	return &value
}

func saveConfig(path string, cfg *Config) error {
	applyConfigDefaults(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func currentAgentInfo(cfg *Config) AgentInfo {
	return AgentInfo{
		Hostname:   cfg.Hostname,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Version:    version,
		IP:         hostIP(),
		WAFEnabled: cfg.WAFIsEnabled(),
		// Report the websites running on this host so the console can offer a
		// "monitored website" picker when the server hosts more than one.
		DetectedSites: detectLocalSites(),
	}
}
