package main

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	syslogTimeRe  = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+`)
	webTimeRe     = regexp.MustCompile(`\[([^\]]+)\]`)
	webLineRe     = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+)`)
	sshFailedRe   = regexp.MustCompile(`Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([^\s]+) port (\d+)`)
	sshInvalidRe  = regexp.MustCompile(`Invalid user (\S+) from ([^\s]+)`)
	sshAcceptedRe = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from ([^\s]+) port (\d+)`)
	sudoRe        = regexp.MustCompile(`sudo:\s+(\S+)\s+:.*COMMAND=(.*)`)
	ufwRe         = regexp.MustCompile(`\[UFW (BLOCK|ALLOW)\].*?SRC=([0-9a-fA-F:.]+).*?DST=([0-9a-fA-F:.]+).*?PROTO=(\S+)`)
	ngfwRe        = regexp.MustCompile(`OAT_NGFW_(DROP|LOG|ALLOW).*?SRC=([0-9a-fA-F:.]+).*?DST=([0-9a-fA-F:.]+).*?PROTO=(\S+)`)
	genericSrcRe  = regexp.MustCompile(`SRC=([0-9a-fA-F:.]+)`)
	genericDstRe  = regexp.MustCompile(`DST=([0-9a-fA-F:.]+)`)
	genericDptRe  = regexp.MustCompile(`DPT=(\d+)`)
	fail2banBanRe = regexp.MustCompile(`(?i)\[(\S+)\]\s+Ban\s+([0-9a-fA-F:.]+)`)
	fail2banUnbanRe = regexp.MustCompile(`(?i)\[(\S+)\]\s+Unban\s+([0-9a-fA-F:.]+)`)
	sqlAttackRe   = regexp.MustCompile(`(?i)(union(\s|%20|\+)+(all(\s|%20|\+)+)?select|select.+from|or(\s|%20|\+)+1=1|sleep\(|benchmark\(|information_schema|xp_cmdshell)`)
	xssAttackRe   = regexp.MustCompile(`(?i)(<script|%3cscript|javascript:|onerror(\s|%20)*=|onload(\s|%20)*=)`)
	traversalRe   = regexp.MustCompile(`(?i)(\.\./|%2e%2e%2f|/etc/passwd|/proc/self/environ|boot\.ini)`)
	reconRe       = regexp.MustCompile(`(?i)(wp-login\.php|xmlrpc\.php|/\.env|/\.git/config|phpmyadmin|/server-status)`)
)

func collectorFromPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasPrefix(base, "journald:"):
		return "journald"
	case strings.Contains(base, "auth") || base == "secure":
		return "auth"
	case strings.Contains(base, "nginx") || strings.Contains(base, "apache") || strings.Contains(base, "httpd") || strings.Contains(base, "access") || strings.Contains(base, "error"):
		return "web"
	case strings.Contains(base, "ufw") || strings.Contains(base, "firewall") || strings.Contains(base, "fail2ban"):
		return "firewall"
	case strings.Contains(base, "syslog") || base == "messages":
		return "system"
	default:
		return "file"
	}
}

func cleanIP(value string) string {
	candidate := strings.Trim(value, "[](),;")
	candidate = strings.TrimPrefix(candidate, "::ffff:")
	if index := strings.Index(candidate, "%"); index >= 0 {
		candidate = candidate[:index]
	}
	if net.ParseIP(candidate) != nil {
		return candidate
	}
	return ""
}

func truncate(value string, max int) string {
	if value == "" || max <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func parseLogTimestamp(path, line string, now time.Time) time.Time {
	collector := collectorFromPath(path)
	if collector == "auth" || collector == "system" {
		if match := syslogTimeRe.FindStringSubmatch(line); match != nil {
			if parsed, err := time.ParseInLocation("Jan _2 15:04:05", match[1], now.Location()); err == nil {
				parsed = parsed.AddDate(now.Year(), 0, 0)
				if parsed.After(now.Add(24 * time.Hour)) {
					parsed = parsed.AddDate(-1, 0, 0)
				}
				return parsed
			}
		}
	}
	if collector == "web" {
		if match := webTimeRe.FindStringSubmatch(line); match != nil {
			if parsed, err := time.Parse("02/Jan/2006:15:04:05 -0700", match[1]); err == nil {
				return parsed
			}
			if parsed, err := time.Parse("02/Jan/2006:15:04:05", match[1]); err == nil {
				return parsed
			}
		}
	}
	return now
}

func baseLog(cfg *Config, path, line, level, collector string, timestamp time.Time) LogEntry {
	host := cfg.Hostname
	ip := hostIP()
	if strings.HasPrefix(collector, "journald") {
		host = hostname()
	}
	return LogEntry{
		Timestamp: timestamp.UTC().Format(time.RFC3339Nano),
		Level:     level,
		Source:    "agent",
		EventType: collector,
		Message:   truncate(line, 4000),
		Host:      host,
		IP:        ip,
		RawLog:    truncate(line, 16000),
		Collector: collector,
		Metadata: map[string]any{
			"logPath": path,
		},
	}
}

func parseLine(cfg *Config, path, line string) ([]LogEntry, []Event) {
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	collector := collectorFromPath(path)
	timestamp := parseLogTimestamp(path, line, time.Now())
	events, level := detectEvents(cfg, path, line, timestamp)
	entry := baseLog(cfg, path, line, level, collector, timestamp)
	return []LogEntry{entry}, events
}

func detectEvents(cfg *Config, path, line string, timestamp time.Time) ([]Event, string) {
	level := "INFO"
	collector := collectorFromPath(path)
	destination := hostIP()
	if destination == "" {
		destination = "0.0.0.0"
	}
	ts := timestamp.UTC().Format(time.RFC3339Nano)
	lower := strings.ToLower(line)
	events := make([]Event, 0, 1)

	if match := sshFailedRe.FindStringSubmatch(line); match != nil {
		level = "WARN"
		events = append(events, Event{
			Timestamp:     ts,
			EventType:     "ssh_failed_login",
			Severity:      "Medium",
			SourceIP:      cleanIP(match[2]),
			DestinationIP: destination,
			Protocol:      "TCP",
			Application:   "sshd",
			Action:        "LOG",
			Port:          22,
			ThreatName:    "SSH Failed Login",
			Metadata: map[string]any{
				"user":       match[1],
				"sourcePort": match[3],
				"logPath":    path,
			},
			Collector: "auth",
		})
	}

	if match := sshInvalidRe.FindStringSubmatch(line); match != nil {
		level = "WARN"
		events = append(events, Event{
			Timestamp:     ts,
			EventType:     "ssh_invalid_user",
			Severity:      "Medium",
			SourceIP:      cleanIP(match[2]),
			DestinationIP: destination,
			Protocol:      "TCP",
			Application:   "sshd",
			Action:        "LOG",
			Port:          22,
			ThreatName:    "SSH Invalid User Attempt",
			Metadata: map[string]any{
				"user":    match[1],
				"logPath": path,
			},
			Collector: "auth",
		})
	}

	if match := sshAcceptedRe.FindStringSubmatch(line); match != nil {
		events = append(events, Event{
			Timestamp:     ts,
			EventType:     "ssh_login_success",
			Severity:      "Low",
			SourceIP:      cleanIP(match[2]),
			DestinationIP: destination,
			Protocol:      "TCP",
			Application:   "sshd",
			Action:        "ALLOW",
			Port:          22,
			ThreatName:    "SSH Login Accepted",
			Metadata: map[string]any{
				"user":       match[1],
				"sourcePort": match[3],
				"logPath":    path,
			},
			Collector: "auth",
		})
	}

	if match := sudoRe.FindStringSubmatch(line); match != nil {
		events = append(events, Event{
			Timestamp:     ts,
			EventType:     "sudo_command",
			Severity:      "Low",
			SourceIP:      hostIP(),
			DestinationIP: destination,
			Protocol:      "LOCAL",
			Application:   "sudo",
			Action:        "LOG",
			ThreatName:    "Privileged Command Executed",
			Metadata: map[string]any{
				"user":    match[1],
				"command": truncate(match[2], 1000),
				"logPath": path,
			},
			Collector: "auth",
		})
	}

	if match := webLineRe.FindStringSubmatch(line); match != nil {
		method := match[3]
		uri := match[4]
		statusCode, _ := strconv.Atoi(match[5])
		switch {
		case statusCode >= 500:
			level = "ERROR"
		case statusCode >= 400:
			level = "WARN"
		}

		attackName := ""
		severity := ""
		if sqlAttackRe.MatchString(uri) {
			attackName = "Web Attack (SQL Injection)"
			severity = "Critical"
		} else if xssAttackRe.MatchString(uri) {
			attackName = "Web Attack (Cross-Site Scripting)"
			severity = "High"
		} else if traversalRe.MatchString(uri) {
			attackName = "Web Attack (Path Traversal)"
			severity = "High"
		} else if reconRe.MatchString(uri) {
			attackName = "Web Reconnaissance"
			severity = "Medium"
		}
		if attackName != "" {
			level = "ERROR"
			if severity == "Critical" {
				level = "CRITICAL"
			}
			webAction := "LOG"
			if statusCode == 403 || statusCode == 401 || statusCode == 429 || severity == "Critical" || severity == "High" {
				webAction = "BLOCK"
			}
			events = append(events, Event{
				Timestamp:      ts,
				EventType:      "web_attack",
				Severity:       severity,
				SourceIP:       cleanIP(match[1]),
				DestinationIP:  destination,
				Protocol:       "TCP",
				Application:    "web",
				Action:         webAction,
				URI:            truncate(uri, 2000),
				Method:         method,
				StatusCode:     statusCode,
				ThreatName:     attackName,
				PayloadSnippet: truncate(uri, 1000),
				Metadata: map[string]any{
					"status":  statusCode,
					"logPath": path,
				},
				Collector: "web",
			})
		}
	}

	if match := ufwRe.FindStringSubmatch(line); match != nil {
		action := "ALLOW"
		if strings.EqualFold(match[1], "BLOCK") {
			action = "BLOCK"
			level = "WARN"
		}
		port := 0
		if portMatch := genericDptRe.FindStringSubmatch(line); portMatch != nil {
			port, _ = strconv.Atoi(portMatch[1])
		}
		events = append(events, Event{
			Timestamp:     ts,
			EventType:     "firewall_" + strings.ToLower(match[1]),
			Severity:      "Medium",
			SourceIP:      cleanIP(match[2]),
			DestinationIP: cleanIP(match[3]),
			Protocol:      strings.ToUpper(match[4]),
			Application:   "firewall",
			Action:        action,
			Port:          port,
			ThreatName:    "Firewall " + strings.ToUpper(match[1]),
			Metadata: map[string]any{
				"logPath": path,
			},
			Collector: "firewall",
		})
	} else if collector == "firewall" && (strings.Contains(lower, "drop") || strings.Contains(lower, "block") || strings.Contains(lower, "deny")) {
		src := ""
		dst := ""
		if match := genericSrcRe.FindStringSubmatch(line); match != nil {
			src = cleanIP(match[1])
		}
		if match := genericDstRe.FindStringSubmatch(line); match != nil {
			dst = cleanIP(match[1])
		}
		port := 0
		if match := genericDptRe.FindStringSubmatch(line); match != nil {
			port, _ = strconv.Atoi(match[1])
		}
		if src != "" {
			level = "WARN"
			events = append(events, Event{
				Timestamp:     ts,
				EventType:     "firewall_block",
				Severity:      "Medium",
				SourceIP:      src,
				DestinationIP: dst,
				Protocol:      "TCP",
				Application:   "firewall",
				Action:        "BLOCK",
				Port:          port,
				ThreatName:    "Firewall Blocked Connection",
				Metadata:      map[string]any{"logPath": path},
				Collector:     "firewall",
			})
		}
	}

	// Kernel-side NGFW verdicts. The nftables rules the agent installs log with
	// the OAT_NGFW_ prefix, so every denied/monitored flow closes the loop:
	// console ACL → kernel tables → this parser → dashboard tiles.
	if match := ngfwRe.FindStringSubmatch(line); match != nil {
		kind := strings.ToUpper(match[1])
		action := "BLOCK"
		eventType := "firewall_drop"
		threatName := "NGFW Dropped Connection"
		severity := "Medium"
		switch kind {
		case "LOG":
			action = "LOG"
			eventType = "firewall_log"
			threatName = "NGFW Monitored Connection"
			severity = "Low"
		case "ALLOW":
			action = "ALLOW"
			eventType = "firewall_allow"
			threatName = "NGFW Allowed Connection"
			severity = "Low"
		default:
			level = "WARN"
		}
		port := 0
		if portMatch := genericDptRe.FindStringSubmatch(line); portMatch != nil {
			port, _ = strconv.Atoi(portMatch[1])
		}
		events = append(events, Event{
			Timestamp:     ts,
			EventType:     eventType,
			Severity:      severity,
			SourceIP:      cleanIP(match[2]),
			DestinationIP: cleanIP(match[3]),
			Protocol:      strings.ToUpper(match[4]),
			Application:   "firewall",
			Action:        action,
			Port:          port,
			ThreatName:    threatName,
			Metadata: map[string]any{
				"logPath": path,
			},
			Collector: "firewall",
		})
	}

	if collector == "auth" && strings.Contains(lower, "authentication failure") && len(events) == 0 {
		level = "WARN"
		events = append(events, Event{
			Timestamp:     ts,
			EventType:     "authentication_failure",
			Severity:      "Medium",
			SourceIP:      destination,
			DestinationIP: destination,
			Protocol:      "LOCAL",
			Application:   "pam",
			Action:        "LOG",
			ThreatName:    "Authentication Failure",
			Metadata:      map[string]any{"logPath": path},
			Collector:     "auth",
		})
	}

	if match := fail2banBanRe.FindStringSubmatch(line); match != nil {
		level = "WARN"
		events = append(events, Event{
			Timestamp:     ts,
			EventType:     "fail2ban_ban",
			Severity:      "High",
			SourceIP:      cleanIP(match[2]),
			DestinationIP: destination,
			Protocol:      "TCP",
			Application:   "fail2ban",
			Action:        "BLOCK",
			ThreatName:    "Fail2ban Host Banned (" + match[1] + ")",
			Metadata: map[string]any{
				"jail":    match[1],
				"logPath": path,
			},
			Collector: "firewall",
		})
	} else if match := fail2banUnbanRe.FindStringSubmatch(line); match != nil {
		events = append(events, Event{
			Timestamp:     ts,
			EventType:     "fail2ban_unban",
			Severity:      "Low",
			SourceIP:      cleanIP(match[2]),
			DestinationIP: destination,
			Protocol:      "TCP",
			Application:   "fail2ban",
			Action:        "ALLOW",
			ThreatName:    "Fail2ban Host Unbanned (" + match[1] + ")",
			Metadata: map[string]any{
				"jail":    match[1],
				"logPath": path,
			},
			Collector: "firewall",
		})
	}

	if strings.Contains(lower, "segfault") {
		level = "ERROR"
	}
	if level == "INFO" && collector != "web" {
		if strings.Contains(lower, " error ") || strings.HasPrefix(lower, "error") ||
			strings.Contains(lower, " failed ") || strings.HasPrefix(lower, "failed") ||
			strings.Contains(lower, " denied ") || strings.HasPrefix(lower, "denied") {
			level = "WARN"
		}
	}

	return events, level
}

// Low-value journald chatter. Security-relevant lines (sshd auth, sudo, unit
// failures, kernel warnings) are kept; DHCP renewals and session bookkeeping
// are dropped so they cannot dominate the dashboard log feed.
func isJournaldNoise(identifier, message string) bool {
	if identifier == "oat-agent" {
		return true
	}
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "dhcprequest"),
		strings.Contains(lower, "dhcpack"),
		strings.Contains(lower, "dhcpoffer"),
		strings.Contains(lower, "dhcprelease"),
		strings.Contains(lower, "session-") && strings.Contains(lower, ".scope"),
		strings.HasPrefix(lower, "new session "),
		strings.HasPrefix(lower, "removed session "),
		strings.HasPrefix(lower, "session ") && strings.Contains(lower, " logged out"),
		strings.Contains(lower, "pam_env(sshd:session): deprecated"),
		strings.Contains(lower, "pam_unix(sshd:session): session opened"),
		strings.Contains(lower, "pam_unix(sshd:session): session closed"):
		return true
	}
	return false
}

func parseJournaldLine(cfg *Config, raw string) ([]LogEntry, []Event) {
	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, nil
	}
	message := jsonString(data["MESSAGE"])
	if strings.TrimSpace(message) == "" {
		return nil, nil
	}

	timestamp := time.Now()
	if value := jsonString(data["__REALTIME_TIMESTAMP"]); value != "" {
		if micros, err := strconv.ParseInt(value, 10, 64); err == nil {
			timestamp = time.Unix(0, micros*1000)
		}
	}

	priority := jsonString(data["PRIORITY"])
	level := "INFO"
	switch priority {
	case "0", "1", "2":
		level = "CRITICAL"
	case "3":
		level = "ERROR"
	case "4":
		level = "WARN"
	case "7":
		level = "DEBUG"
	}

	identifier := jsonString(data["SYSLOG_IDENTIFIER"])
	if identifier == "" {
		identifier = "journald"
	}
	host := jsonString(data["_HOSTNAME"])
	if host == "" {
		host = cfg.Hostname
	}

	path := "journald:" + identifier
	events, detectedLevel := detectEvents(cfg, path, message, timestamp)
	if level == "INFO" && detectedLevel != "INFO" {
		level = detectedLevel
	}

	if isJournaldNoise(identifier, message) {
		if len(events) == 0 {
			return nil, nil
		}
		return nil, events
	}

	entry := LogEntry{
		Timestamp: timestamp.UTC().Format(time.RFC3339Nano),
		Level:     level,
		Source:    "agent",
		EventType: "journald",
		Message:   truncate(message, 4000),
		Host:      host,
		IP:        hostIP(),
		RawLog:    truncate(raw, 16000),
		Collector: "journald",
		Metadata: map[string]any{
			"unit":       identifier,
			"pid":        jsonString(data["_PID"]),
			"priority":   priority,
			"journaldId": jsonString(data["_SYSTEMD_UNIT"]),
		},
	}
	return []LogEntry{entry}, events
}

func jsonString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	case []any:
		if len(typed) == 0 {
			return ""
		}
		return jsonString(typed[0])
	default:
		if typed == nil {
			return ""
		}
		return fmt.Sprintf("%v", typed)
	}
}
