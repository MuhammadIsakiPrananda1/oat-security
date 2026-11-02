package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var version = "1.0.0"

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enroll":
		runEnroll(os.Args[2:])
	case "run":
		runAgentCommand(os.Args[2:])
	case "test":
		runTest(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("oat-agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`OAT Endpoint Agent

Usage:
  oat-agent enroll --server URL --token TOKEN [--name NAME] [--config PATH]
  oat-agent run [--config PATH] [--once] [--debug] [--no-waf] [--no-fw]
  oat-agent test [--config PATH] [--message TEXT]
  oat-agent status [--config PATH]
  oat-agent version

WAF & NGFW:
  On Linux, the agent also pulls the organization WAF policy from the signed
  server channel and applies it to Apache (mod_rewrite) and nftables. This is a
  constrained policy channel, not a remote shell. Use --no-waf to opt out.
  The perimeter NGFW ACL is enforced the same way as an nftables table
  (inet oat_ngfw). Use --no-fw to opt out.

Security:
  The enrollment token is single-use and expires. The agent generates an
  Ed25519 keypair locally; the private key never leaves this host. Every
  heartbeat and telemetry request is signed and replay-protected.

  Use HTTPS. Plain HTTP is only accepted for localhost unless --insecure is
  passed explicitly (lab use only).
`)
}

func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to the agent config file")
	server := fs.String("server", "", "OAT server base URL, e.g. https://security.example.com")
	token := fs.String("token", "", "one-time enrollment token")
	tokenFile := fs.String("token-file", "", "read the enrollment token from a file")
	name := fs.String("name", "", "display name for this agent")
	insecure := fs.Bool("insecure", false, "allow HTTP / skip TLS verification (lab only)")
	caFile := fs.String("ca", "", "custom CA bundle (PEM) for a private PKI")
	labelsFlag := fs.String("labels", "", "comma-separated labels, e.g. env:prod,role:web")
	logPathsFlag := fs.String("log-paths", "", "comma-separated log paths or globs")
	fimPathsFlag := fs.String("fim-paths", "", "comma-separated FIM paths or globs")
	noJournald := fs.Bool("no-journald", false, "disable the journald collector")
	winlogFlag := fs.String("winlog", "", "comma-separated Windows event log channels")
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for agent state and the offline spool")
	noWAF := fs.Bool("no-waf", false, "disable local WAF policy enforcement")
	wafApacheConfig := fs.String("waf-apache-config", "", "Apache conf path managed by the agent")
	noFW := fs.Bool("no-fw", false, "disable local NGFW ACL enforcement")
	noMalware := fs.Bool("no-malware-watch", false, "disable real-time upload scanning of web roots")
	malwarePaths := fs.String("malware-paths", "", "comma-separated list of web root directories to watch for uploads")
	malwareSeconds := fs.Int("malware-seconds", 0, "upload watcher polling interval in seconds (default 5)")
	_ = fs.Parse(args)

	if *server == "" {
		fatal("--server is required")
	}
	enrollmentToken := strings.TrimSpace(*token)
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fatal("read token file: %v", err)
		}
		enrollmentToken = strings.TrimSpace(string(data))
	}
	if enrollmentToken == "" {
		// No token: the server provisions the organization from this first
		// agent install, so the console shows the protected website right away.
		fmt.Printf("No enrollment token supplied — requesting bootstrap enrollment.\n")
	}

	serverURL := normalizeServer(*server)
	if err := validateServerURL(serverURL, *insecure); err != nil {
		fatal("%v", err)
	}

	hostnameValue := hostname()
	if *name == "" {
		*name = hostnameValue
	}

	cfg := &Config{
		Server:           serverURL,
		Name:             *name,
		Hostname:         hostnameValue,
		Labels:           parseLabels(*labelsFlag),
		LogPaths:         splitList(*logPathsFlag),
		FIMPaths:         splitList(*fimPathsFlag),
		Journald:         !*noJournald,
		WindowsEventLogs: splitList(*winlogFlag),
		Insecure:         *insecure,
		CAFile:           *caFile,
		StateDir:         *stateDir,
		WAFApacheConfig:  *wafApacheConfig,
		MalwarePaths:     splitList(*malwarePaths),
		MalwareSeconds:   *malwareSeconds,
	}
	if *noWAF {
		cfg.WAFEnabled = boolPointer(false)
	}
	if *noFW {
		cfg.FWEnabled = boolPointer(false)
	}
	if *noMalware {
		cfg.MalwareWatch = boolPointer(false)
	}
	applyConfigDefaults(cfg)

	response, err := enrollAgent(cfg, enrollmentToken, *name)
	if err != nil {
		fatal("enrollment failed: %v", err)
	}
	if err := saveConfig(*configPath, cfg); err != nil {
		fatal("save config: %v", err)
	}

	// Re-enrollment may reuse an existing state directory. Discard the cached
	// WAF and NGFW results so this agent applies and reports the current
	// revision instead of trusting a result from an earlier install.
	if store, err := loadState(cfg.StateDir); err == nil {
		store.ClearWAFResult()
		store.ClearFirewallResult()
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not reset cached enforcement state: %v\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "warning: could not load agent state to reset cached enforcement results: %v\n", err)
	}

	fmt.Printf("Enrollment successful.\n")
	fmt.Printf("  Agent ID:       %s\n", response.AgentID)
	fmt.Printf("  Organization:   %s\n", response.OrganizationID)
	if response.OrganizationCreated {
		fmt.Printf("  New organization: %s (created from this agent install)\n", response.OrganizationName)
	}
	if response.ApplicationDomain != "" {
		fmt.Printf("  Website:        %s (%s)\n", response.ApplicationName, response.ApplicationDomain)
	}
	if len(response.DetectedApplications) > 0 {
		fmt.Printf("  Auto-detected websites registered in dashboard:\n")
		for _, app := range response.DetectedApplications {
			domain, _ := app["domain"].(string)
			name, _ := app["name"].(string)
			if domain == "" {
				domain = name
			}
			fmt.Printf("    • %s\n", domain)
		}
		fmt.Printf("  You can assign this agent to a different website from Dashboard → Agents.\n")
	}
	fmt.Printf("  Config:         %s\n", *configPath)
	fmt.Printf("  State:          %s\n", cfg.StateDir)
	fmt.Printf("\nStart the service with: oat-agent run --config %s\n", *configPath)
}

func runAgentCommand(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to the agent config file")
	once := fs.Bool("once", false, "send one heartbeat/flush cycle and exit")
	debug := fs.Bool("debug", false, "verbose logging")
	noWAF := fs.Bool("no-waf", false, "disable local WAF policy enforcement")
	noFW := fs.Bool("no-fw", false, "disable local NGFW ACL enforcement")
	noMalware := fs.Bool("no-malware-watch", false, "disable real-time upload scanning of web roots")
	malwarePaths := fs.String("malware-paths", "", "comma-separated list of web root directories to watch for uploads")
	malwareSeconds := fs.Int("malware-seconds", 0, "upload watcher polling interval in seconds (default 5)")
	wafApacheConfig := fs.String("waf-apache-config", "", "Apache conf path managed by the agent")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal("%v", err)
	}
	if cfg.AgentID == "" || cfg.PrivateKey == "" {
		fatal("agent is not enrolled; run the enroll command first")
	}
	if *debug {
		cfg.Debug = true
	}
	if *noWAF {
		cfg.WAFEnabled = boolPointer(false)
	}
	if *noFW {
		cfg.FWEnabled = boolPointer(false)
	}
	if *noMalware {
		cfg.MalwareWatch = boolPointer(false)
	}
	if strings.TrimSpace(*malwarePaths) != "" {
		var paths []string
		for _, part := range strings.Split(*malwarePaths, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				paths = append(paths, trimmed)
			}
		}
		cfg.MalwarePaths = paths
	}
	if *malwareSeconds > 0 {
		cfg.MalwareSeconds = *malwareSeconds
	}
	if *wafApacheConfig != "" {
		cfg.WAFApacheConfig = *wafApacheConfig
	}
	if err := validateServerURL(cfg.Server, cfg.Insecure); err != nil {
		fatal("%v", err)
	}

	client, err := newClient(cfg)
	if err != nil {
		fatal("%v", err)
	}
	state, err := loadState(cfg.StateDir)
	if err != nil {
		fatal("load state: %v", err)
	}
	spool, err := newSpool(cfg.StateDir)
	if err != nil {
		fatal("init spool: %v", err)
	}
	queue := newQueue(2000, 8000)
	// urgentFlush receives a signal whenever a high-priority event is queued
	// (SSH failed, BLOCK/DENY/DROP actions) so we flush immediately instead of
	// waiting for the next periodic tick — this eliminates up to 5s of latency.
	urgentFlush := make(chan struct{}, 8)
	queue.SetUrgentFlush(urgentFlush)

	metrics := CollectMetrics()
	// The console decides which website this agent monitors. The heartbeat
	// answer carries the current binding, so persist it when it changes.
	savedApplicationID := cfg.ApplicationID
	heartbeat := func(metrics Metrics) {
		response, err := client.Heartbeat(metrics)
		if err != nil {
			log.Printf("[agent] heartbeat failed: %v", err)
			return
		}
		state.SetLastHeartbeat(nowISO())
		if cfg.ApplicationID != savedApplicationID {
			savedApplicationID = cfg.ApplicationID
			if cfg.ApplicationDomain != "" {
				log.Printf("[agent] monitoring website set to %s", cfg.ApplicationDomain)
			} else {
				log.Printf("[agent] website selection cleared by the console")
			}
			if err := saveConfig(*configPath, cfg); err != nil {
				log.Printf("[agent] could not persist the website binding: %v", err)
			}
		}
		// Console-initiated containment orders ride along with the heartbeat.
		if response != nil && len(response.MalwareActions) > 0 {
			executeMalwareActions(client, cfg, state, response.MalwareActions)
		}
	}
	heartbeat(metrics)

	if *once {
		runWAFOnce(client, cfg, state, *debug)
		runFirewallOnce(client, cfg, state, *debug)
		flush(client, cfg, queue, spool, *debug)
		_ = state.Save()
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runWAFOnce(client, cfg, state, *debug)
	runFirewallOnce(client, cfg, state, *debug)

	startFileTailers(ctx, cfg, state, queue)
	startJournald(ctx, cfg, queue)
	startWindowsEventLogs(ctx, cfg, state, queue)
	startFIM(ctx, cfg, state, queue)
	startSCA(ctx, cfg, queue)
	startMalwareWatcher(ctx, cfg, state)

	flushTicker := time.NewTicker(time.Duration(cfg.FlushSeconds) * time.Second)
	heartbeatTicker := time.NewTicker(time.Duration(cfg.HeartbeatSeconds) * time.Second)
	stateTicker := time.NewTicker(5 * time.Second)
	var wafTicker *time.Ticker
	var wafTickerC <-chan time.Time
	if cfg.WAFIsEnabled() {
		wafTicker = time.NewTicker(time.Duration(cfg.WAFSeconds) * time.Second)
		wafTickerC = wafTicker.C
	}
	var fwTicker *time.Ticker
	var fwTickerC <-chan time.Time
	if cfg.FWIsEnabled() {
		fwTicker = time.NewTicker(time.Duration(cfg.FWSeconds) * time.Second)
		fwTickerC = fwTicker.C
	}
	defer flushTicker.Stop()
	defer heartbeatTicker.Stop()
	defer stateTicker.Stop()
	if wafTicker != nil {
		defer wafTicker.Stop()
	}
	if fwTicker != nil {
		defer fwTicker.Stop()
	}

	log.Printf("[agent] running as %s (%s), server %s", cfg.Name, cfg.AgentID, cfg.Server)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[agent] shutting down, flushing buffered telemetry")
			flush(client, cfg, queue, spool, cfg.Debug)
			_ = state.Save()
			return
		case <-urgentFlush:
			// Drain any additional signals queued in the same burst so we don't
			// spam the server with one-event batches during a brute-force storm.
			for len(urgentFlush) > 0 {
				<-urgentFlush
			}
			flush(client, cfg, queue, spool, cfg.Debug)
			// Reset the periodic ticker so we don't double-flush immediately.
			flushTicker.Reset(time.Duration(cfg.FlushSeconds) * time.Second)
		case <-flushTicker.C:
			flush(client, cfg, queue, spool, cfg.Debug)
		case <-heartbeatTicker.C:
			metrics := CollectMetrics()
			heartbeat(metrics)
		case <-wafTickerC:
			runWAFOnce(client, cfg, state, *debug)
		case <-fwTickerC:
			runFirewallOnce(client, cfg, state, *debug)
		case <-stateTicker.C:
			_ = state.Save()
		}
	}
}

func flush(client *Client, cfg *Config, queue *Queue, spool *Spool, debug bool) {
	events, logs := queue.Take()
	spooled, spoolPaths := spool.LoadOldest(5)
	events = append(spooled.Events, events...)
	logs = append(spooled.Logs, logs...)

	if len(events) == 0 && len(logs) == 0 {
		spool.Remove(spoolPaths)
		return
	}

	totalEvents := len(events)
	totalLogs := len(logs)

	for len(events) > 0 || len(logs) > 0 {
		eventCount := minInt(250, len(events))
		logCount := minInt(500, len(logs))
		batch := Batch{
			Agent:  currentAgentInfo(cfg),
			Events: events[:eventCount],
			Logs:   logs[:logCount],
		}
		if err := client.SendBatch(&batch); err != nil {
			remaining := Batch{Agent: currentAgentInfo(cfg), Events: events, Logs: logs}
			if spoolErr := spool.Save(remaining); spoolErr != nil {
				log.Printf("[agent] CRITICAL: failed to spool %d events/%d logs: %v", len(events), len(logs), spoolErr)
			}
			spool.Remove(spoolPaths)
			log.Printf("[agent] send failed (%v); buffered %d events and %d logs", err, len(events), len(logs))
			return
		}
		events = events[eventCount:]
		logs = logs[logCount:]
	}

	spool.Remove(spoolPaths)
	if debug {
		log.Printf("[agent] sent %d events and %d logs", totalEvents, totalLogs)
	}
}

func runTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to the agent config file")
	message := fs.String("message", "Connectivity test from OAT endpoint agent", "test log message")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal("%v", err)
	}
	client, err := newClient(cfg)
	if err != nil {
		fatal("%v", err)
	}
	queue := newQueue(10, 10)
	queue.AddLog(LogEntry{
		Timestamp: nowISO(),
		Level:     "INFO",
		Source:    "agent",
		EventType: "agent_test",
		Message:   *message,
		Host:      cfg.Hostname,
		IP:        hostIP(),
		Collector: "agent",
	})
	queue.AddEvent(Event{
		Timestamp:     nowISO(),
		EventType:     "agent_test",
		Severity:      "Low",
		SourceIP:      hostIP(),
		DestinationIP: hostIP(),
		Protocol:      "LOCAL",
		Application:   "OAT Endpoint Agent",
		Action:        "LOG",
		ThreatName:    "Endpoint Agent Connectivity Test",
		Metadata:      map[string]any{"test": true},
		Collector:     "agent",
	})

	events, logs := queue.Take()
	batch := Batch{
		Agent:  currentAgentInfo(cfg),
		Events: events,
		Logs:   logs,
	}
	if err := client.SendBatch(&batch); err != nil {
		fatal("test send failed: %v", err)
	}
	fmt.Println("Test telemetry sent. Check Live Traffic and Centralized Logs in the dashboard.")
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to the agent config file")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal("%v", err)
	}
	state, err := loadState(cfg.StateDir)
	if err != nil {
		fatal("%v", err)
	}
	spool, err := newSpool(cfg.StateDir)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("Agent:          %s (%s)\n", cfg.Name, cfg.AgentID)
	fmt.Printf("Organization:   %s\n", cfg.OrganizationID)
	fmt.Printf("Website:        %s (%s)\n", cfg.ApplicationName, cfg.ApplicationDomain)
	fmt.Printf("Server:         %s\n", cfg.Server)
	fmt.Printf("Hostname:       %s\n", cfg.Hostname)
	fmt.Printf("Version:        %s\n", version)
	fmt.Printf("State dir:      %s\n", cfg.StateDir)
	fmt.Printf("Last heartbeat: %s\n", state.LastHeartbeat())
	revision, wafStatus, wafAppliedAt := state.WAFResult()
	if revision > 0 {
		fmt.Printf("WAF:            revision %d %s (%s)\n", revision, wafStatus, wafAppliedAt)
	} else {
		fmt.Printf("WAF:            not checked in yet\n")
	}
	fmt.Printf("Spool batches:  %d\n", spool.Count())
	fmt.Printf("Config:         %s\n", *configPath)
}

func validateServerURL(server string, insecure bool) error {
	parsed, err := url.Parse(server)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid server URL %q", server)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" {
		return fmt.Errorf("server URL must use https://")
	}
	host := parsed.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if !isLocal && !insecure {
		return fmt.Errorf("refusing plain HTTP to %s: use HTTPS, or pass --insecure explicitly for a lab", host)
	}
	return nil
}

func parseLabels(value string) map[string]string {
	labels := map[string]string{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pieces := strings.SplitN(part, ":", 2)
		if len(pieces) != 2 {
			continue
		}
		key := strings.TrimSpace(pieces[0])
		labelValue := strings.TrimSpace(pieces[1])
		if key != "" {
			labels[key] = labelValue
		}
	}
	return labels
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "oat-agent: "+format+"\n", args...)
	os.Exit(1)
}
