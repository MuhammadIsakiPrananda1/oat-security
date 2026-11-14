package main

type Event struct {
	Timestamp      string         `json:"timestamp"`
	EventType      string         `json:"eventType"`
	Severity       string         `json:"severity"`
	SourceIP       string         `json:"sourceIp,omitempty"`
	DestinationIP  string         `json:"destinationIp,omitempty"`
	Protocol       string         `json:"protocol,omitempty"`
	Application    string         `json:"application,omitempty"`
	Action         string         `json:"action,omitempty"`
	URI            string         `json:"uri,omitempty"`
	Method         string         `json:"method,omitempty"`
	Port           int            `json:"port,omitempty"`
	StatusCode     int            `json:"statusCode,omitempty"`
	ThreatName     string         `json:"threatName,omitempty"`
	PayloadSnippet string         `json:"payloadSnippet,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Collector      string         `json:"collector,omitempty"`
}

type LogEntry struct {
	Timestamp     string         `json:"timestamp"`
	Level         string         `json:"level"`
	Source        string         `json:"source,omitempty"`
	EventType     string         `json:"eventType"`
	Message       string         `json:"message"`
	Host          string         `json:"host,omitempty"`
	IP            string         `json:"ip,omitempty"`
	CorrelationID string         `json:"correlationId,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	RawLog        string         `json:"rawLog,omitempty"`
	Collector     string         `json:"collector,omitempty"`
}

type AgentInfo struct {
	Hostname      string         `json:"hostname"`
	OS            string         `json:"os"`
	Arch          string         `json:"arch"`
	Version       string         `json:"version"`
	IP            string         `json:"ip,omitempty"`
	WAFEnabled    bool           `json:"wafEnabled"`
	DetectedSites []DetectedSite `json:"detectedSites,omitempty"`
}

type Metrics struct {
	Hostname      string  `json:"hostname"`
	OS            string  `json:"os"`
	Arch          string  `json:"arch"`
	IP            string  `json:"ip,omitempty"`
	CPUPercent    float64 `json:"cpuPercent"`
	CPUCores      int     `json:"cpuCores,omitempty"`
	MemoryPercent float64 `json:"memoryPercent"`
	MemoryUsedMB  float64 `json:"memoryUsedMb,omitempty"`
	MemoryTotalMB float64 `json:"memoryTotalMb,omitempty"`
	DiskPercent   float64 `json:"diskPercent"`
	DiskUsedGB    float64 `json:"diskUsedGb,omitempty"`
	DiskTotalGB   float64 `json:"diskTotalGb,omitempty"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
	UptimeSeconds float64 `json:"uptimeSeconds"`
	ProcessCount  int     `json:"processCount"`
	Kernel        string  `json:"kernel,omitempty"`
}

type Batch struct {
	Agent   AgentInfo  `json:"agent"`
	Events  []Event    `json:"events,omitempty"`
	Logs    []LogEntry `json:"logs,omitempty"`
	Metrics *Metrics   `json:"metrics,omitempty"`
}

type EnrollResponse struct {
	AgentID              string                   `json:"agentId"`
	OrganizationID       string                   `json:"organizationId"`
	OrganizationName     string                   `json:"organizationName"`
	OrganizationCreated  bool                     `json:"organizationCreated"`
	ApplicationID        string                   `json:"applicationId"`
	ApplicationName      string                   `json:"applicationName"`
	ApplicationDomain    string                   `json:"applicationDomain"`
	DetectedApplications []map[string]interface{} `json:"detectedApplications,omitempty"`
	ServerTime           string                   `json:"serverTime"`
	HeartbeatSeconds     int                      `json:"heartbeatSeconds"`
	FlushSeconds         int                      `json:"flushSeconds"`
	Message              string                   `json:"message"`
}

// HeartbeatResponse is what the console answers with on every heartbeat.
// The operator can pick the monitored website at any time, so the agent
// adopts the current binding here.
type HeartbeatResponse struct {
	OK          bool   `json:"ok"`
	ServerTime  string `json:"serverTime"`
	Application *struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Domain string `json:"domain"`
	} `json:"application"`
	// Containment orders issued from the console after a file was already
	// analyzed (quarantine now, delete now). They are acknowledged through
	// /api/agents/malware/result so the server stops returning them.
	MalwareActions []MalwareAction `json:"malwareActions"`
	Config         map[string]any  `json:"config"`
}

// MalwareAction is a pending containment order for one analyzed file.
type MalwareAction struct {
	ScanID          string `json:"id"`
	Action          string `json:"action"`
	FilePath        string `json:"file_path"`
	FileName        string `json:"file_name"`
	SHA256          string `json:"sha256"`
	QuarantinedPath string `json:"quarantined_path,omitempty"`
}
