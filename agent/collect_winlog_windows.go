//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type winEvent struct {
	RecordID         any    `json:"RecordId"`
	TimeCreated      any    `json:"TimeCreated"`
	ID               any    `json:"Id"`
	LevelDisplayName string `json:"LevelDisplayName"`
	ProviderName     string `json:"ProviderName"`
	Message          string `json:"Message"`
	LogName          string `json:"LogName"`
}

var (
	validChannelRe = regexp.MustCompile(`^[A-Za-z0-9 _/-]+$`)
	winSourceIPRe  = regexp.MustCompile(`(?i)Source Network Address:\s*([0-9a-fA-F:.]+)`)
	winDateRe      = regexp.MustCompile(`/Date\((\d+)\)/`)
)

func startWindowsEventLogs(ctx context.Context, cfg *Config, state *StateStore, queue *Queue) {
	for _, channel := range cfg.WindowsEventLogs {
		channel = strings.TrimSpace(channel)
		if channel == "" || !validChannelRe.MatchString(channel) {
			continue
		}
		go func(logName string) {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			var lastError string
			for {
				if err := pollWindowsChannel(logName, state, queue); err != nil {
					message := err.Error()
					if message != lastError {
						log.Printf("[agent] Windows event log %s: %v", logName, err)
						lastError = message
					}
				} else {
					lastError = ""
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}(channel)
	}
}

func baselineWindowsChannel(channel string, state *StateStore, queue *Queue) {
	if state.WinlogLast(channel) > 0 {
		return
	}
	script := fmt.Sprintf(
		"try { $e = Get-WinEvent -LogName '%s' -MaxEvents 1 -ErrorAction Stop; $e.RecordId } catch { '' }",
		channel,
	)
	output, err := runPowerShell(script)
	if err != nil {
		return
	}
	recordID, _ := strconv.ParseInt(strings.TrimSpace(output), 10, 64)
	if recordID > 0 {
		state.SetWinlogLast(channel, recordID)
		_ = state.Save()
	}
	queue.AddLog(LogEntry{
		Timestamp: nowISO(),
		Level:     "INFO",
		Source:    "agent",
		EventType: "windows_eventlog_baseline",
		Message:   fmt.Sprintf("Windows event log collector initialized for %s at record %d", channel, recordID),
		Host:      hostname(),
		IP:        hostIP(),
		Collector: "windows_eventlog",
		Metadata: map[string]any{
			"channel":  channel,
			"recordId": recordID,
		},
	})
}

func pollWindowsChannel(channel string, state *StateStore, queue *Queue) error {
	last := state.WinlogLast(channel)
	xpath := fmt.Sprintf("*[System[EventRecordID > %d]]", last)
	script := fmt.Sprintf(
		"$ProgressPreference='SilentlyContinue'; try { Get-WinEvent -LogName '%s' -FilterXPath '%s' -MaxEvents 100 -Oldest -ErrorAction Stop | Select-Object RecordId,TimeCreated,Id,LevelDisplayName,ProviderName,Message,LogName | ConvertTo-Json -Compress } catch { '' }",
		channel,
		xpath,
	)
	output, err := runPowerShell(script)
	if err != nil {
		return err
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	events, err := decodeWindowsEvents(output)
	if err != nil {
		return err
	}

	maxRecordID := last
	for _, event := range events {
		recordID := toInt64(event.RecordID)
		if recordID <= last {
			continue
		}
		if recordID > maxRecordID {
			maxRecordID = recordID
		}
		enqueueWindowsEvent(channel, event, queue)
	}
	if maxRecordID > last {
		state.SetWinlogLast(channel, maxRecordID)
		_ = state.Save()
	}
	return nil
}

func decodeWindowsEvents(output string) ([]winEvent, error) {
	var list []winEvent
	if err := json.Unmarshal([]byte(output), &list); err == nil {
		return list, nil
	}
	var single winEvent
	if err := json.Unmarshal([]byte(output), &single); err != nil {
		return nil, err
	}
	return []winEvent{single}, nil
}

func enqueueWindowsEvent(channel string, event winEvent, queue *Queue) {
	eventID := int(toInt64(event.ID))
	recordID := toInt64(event.RecordID)
	level := windowsLevel(event.LevelDisplayName)
	timestamp := windowsTimestamp(event.TimeCreated)
	message := truncate(strings.TrimSpace(event.Message), 4000)
	if message == "" {
		message = fmt.Sprintf("Windows event %d from %s", eventID, event.ProviderName)
	}

	queue.AddLog(LogEntry{
		Timestamp: timestamp,
		Level:     level,
		Source:    "agent",
		EventType: "windows_event",
		Message:   fmt.Sprintf("[%s] Event %d: %s", channel, eventID, message),
		Host:      hostname(),
		IP:        hostIP(),
		RawLog:    truncate(message, 16000),
		Collector: "windows_eventlog",
		Metadata: map[string]any{
			"channel":   channel,
			"recordId":  recordID,
			"eventId":   eventID,
			"provider":  event.ProviderName,
			"levelName": event.LevelDisplayName,
		},
	})

	severity := ""
	eventType := ""
	threatName := ""
	action := "LOG"
	switch eventID {
	case 4625:
		severity, eventType, threatName = "High", "windows_failed_logon", "Windows Failed Logon"
	case 4624:
		severity, eventType, threatName, action = "Low", "windows_logon_success", "Windows Logon Accepted", "ALLOW"
	case 4672:
		severity, eventType, threatName = "Medium", "windows_special_privileges", "Windows Special Privileges Assigned"
	case 4720:
		severity, eventType, threatName = "Medium", "windows_user_created", "Windows User Account Created"
	case 4726:
		severity, eventType, threatName = "Medium", "windows_user_deleted", "Windows User Account Deleted"
	case 4732:
		severity, eventType, threatName = "Medium", "windows_group_member_added", "Windows Security Group Member Added"
	case 4740:
		severity, eventType, threatName = "Medium", "windows_account_locked", "Windows Account Locked Out"
	case 4719:
		severity, eventType, threatName = "Medium", "windows_audit_policy_changed", "Windows Audit Policy Changed"
	case 4698:
		severity, eventType, threatName = "Medium", "windows_scheduled_task_created", "Windows Scheduled Task Created"
	case 7045:
		severity, eventType, threatName = "Medium", "windows_service_installed", "Windows Service Installed"
	case 1102:
		severity, eventType, threatName = "Critical", "windows_audit_log_cleared", "Windows Audit Log Cleared"
	}
	if severity == "" {
		return
	}

	sourceIP := hostIP()
	if match := winSourceIPRe.FindStringSubmatch(message); match != nil {
		if cleaned := cleanIP(match[1]); cleaned != "" {
			sourceIP = cleaned
		}
	}

	queue.AddEvent(Event{
		Timestamp:     timestamp,
		EventType:     eventType,
		Severity:      severity,
		SourceIP:      sourceIP,
		DestinationIP: hostIP(),
		Protocol:      "LOCAL",
		Application:   "windows-security",
		Action:        action,
		ThreatName:    threatName,
		Metadata: map[string]any{
			"channel":   channel,
			"recordId":  recordID,
			"eventId":   eventID,
			"provider":  event.ProviderName,
			"levelName": event.LevelDisplayName,
		},
		Collector: "windows_eventlog",
	})
}

func windowsLevel(value string) string {
	switch strings.ToLower(value) {
	case "critical":
		return "CRITICAL"
	case "error":
		return "ERROR"
	case "warning":
		return "WARN"
	case "verbose":
		return "DEBUG"
	default:
		return "INFO"
	}
}

func windowsTimestamp(value any) string {
	text := fmt.Sprintf("%v", value)
	if match := winDateRe.FindStringSubmatch(text); match != nil {
		if millis, err := strconv.ParseInt(match[1], 10, 64); err == nil {
			return time.UnixMilli(millis).UTC().Format(time.RFC3339Nano)
		}
	}
	if parsed, err := time.Parse(time.RFC3339, text); err == nil {
		return parsed.UTC().Format(time.RFC3339Nano)
	}
	return nowISO()
}

func toInt64(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case string:
		parsed, _ := strconv.ParseInt(typed, 10, 64)
		return parsed
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	default:
		return 0
	}
}

func runPowerShell(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	return string(output), err
}
