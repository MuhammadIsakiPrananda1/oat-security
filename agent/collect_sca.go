package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

func startSCA(ctx context.Context, cfg *Config, queue *Queue) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}
		runSCA(cfg, queue)
		ticker := time.NewTicker(time.Duration(cfg.SCASeconds) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runSCA(cfg, queue)
			}
		}
	}()
}

func runSCA(cfg *Config, queue *Queue) {
	if runtime.GOOS == "linux" {
		runLinuxSCA(cfg, queue)
		return
	}
	addSCAResult(queue, cfg, "platform", "Security configuration assessment", "INFO",
		fmt.Sprintf("SCA checks are not implemented for %s yet", runtime.GOOS), "")
}

func runLinuxSCA(cfg *Config, queue *Queue) {
	directives := readSSHDirectives()
	permitRoot := directives["permitrootlogin"]
	if permitRoot == "" {
		permitRoot = "prohibit-password"
	}
	if permitRoot == "yes" {
		addSCAResult(queue, cfg, "ssh-root-login", "SSH root login disabled", "FAIL",
			"PermitRootLogin is set to yes", "Set PermitRootLogin no in /etc/ssh/sshd_config")
	} else {
		addSCAResult(queue, cfg, "ssh-root-login", "SSH root login disabled", "PASS",
			fmt.Sprintf("PermitRootLogin=%s", permitRoot), "")
	}

	passwordAuth := directives["passwordauthentication"]
	if passwordAuth == "" {
		passwordAuth = "yes"
	}
	if passwordAuth == "yes" {
		addSCAResult(queue, cfg, "ssh-password-auth", "SSH password authentication disabled", "FAIL",
			"PasswordAuthentication is set to yes", "Prefer public-key authentication and set PasswordAuthentication no")
	} else {
		addSCAResult(queue, cfg, "ssh-password-auth", "SSH password authentication disabled", "PASS",
			fmt.Sprintf("PasswordAuthentication=%s", passwordAuth), "")
	}

	emptyPasswords := directives["permitemptypasswords"]
	if emptyPasswords == "yes" {
		addSCAResult(queue, cfg, "ssh-empty-passwords", "SSH empty passwords disabled", "CRITICAL",
			"PermitEmptyPasswords is set to yes", "Set PermitEmptyPasswords no and rotate affected credentials")
	} else {
		addSCAResult(queue, cfg, "ssh-empty-passwords", "SSH empty passwords disabled", "PASS",
			"PermitEmptyPasswords is not enabled", "")
	}

	if firewallActive() {
		addSCAResult(queue, cfg, "host-firewall", "Host firewall active", "PASS",
			"ufw, firewalld, or nftables is active", "")
	} else {
		addSCAResult(queue, cfg, "host-firewall", "Host firewall active", "FAIL",
			"No active ufw, firewalld, or nftables ruleset detected", "Enable ufw/firewalld and allow only required ports")
	}

	if aslrEnabled() {
		addSCAResult(queue, cfg, "aslr", "Address space layout randomization", "PASS",
			"kernel.randomize_va_space=2", "")
	} else {
		addSCAResult(queue, cfg, "aslr", "Address space layout randomization", "FAIL",
			"ASLR is not fully enabled", "Set kernel.randomize_va_space=2")
	}

	if info, err := os.Stat("/etc/shadow"); err == nil {
		if info.Mode().Perm()&0o007 != 0 {
			addSCAResult(queue, cfg, "shadow-permissions", "Credential file permissions", "CRITICAL",
				fmt.Sprintf("/etc/shadow mode is %o (world-accessible)", info.Mode().Perm()),
				"Run chmod 640 /etc/shadow and chown root:shadow /etc/shadow")
		} else {
			addSCAResult(queue, cfg, "shadow-permissions", "Credential file permissions", "PASS",
				fmt.Sprintf("/etc/shadow mode is %o", info.Mode().Perm()), "")
		}
	}

	if _, err := exec.LookPath("auditctl"); err != nil {
		addSCAResult(queue, cfg, "auditd", "Audit daemon installed", "FAIL",
			"auditd/auditctl is not installed", "Install auditd and enable the audit service")
	} else if commandSucceeds("pgrep", "-x", "auditd") {
		addSCAResult(queue, cfg, "auditd", "Audit daemon installed", "PASS",
			"auditd is running", "")
	} else {
		addSCAResult(queue, cfg, "auditd", "Audit daemon installed", "FAIL",
			"auditd is installed but not running", "Start and enable the auditd service")
	}
}

func readSSHDirectives() map[string]string {
	files := []string{"/etc/ssh/sshd_config"}
	if matches, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		sort.Strings(matches)
		files = append(files, matches...)
	}
	directives := map[string]string{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			directives[strings.ToLower(fields[0])] = strings.ToLower(fields[1])
		}
	}
	return directives
}

func firewallActive() bool {
	if output, err := runCommand("ufw", "status"); err == nil {
		if strings.Contains(strings.ToLower(output), "status: active") {
			return true
		}
	}
	if output, err := runCommand("firewall-cmd", "--state"); err == nil {
		if strings.Contains(strings.ToLower(output), "running") {
			return true
		}
	}
	if output, err := runCommand("nft", "list", "ruleset"); err == nil {
		if strings.TrimSpace(output) != "" {
			return true
		}
	}
	return false
}

func aslrEnabled() bool {
	data, err := os.ReadFile("/proc/sys/kernel/randomize_va_space")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "2"
}

func runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(output), err
}

func commandSucceeds(name string, args ...string) bool {
	_, err := runCommand(name, args...)
	return err == nil
}

func addSCAResult(queue *Queue, cfg *Config, id, title, status, detail, remediation string) {
	level := "INFO"
	if status == "FAIL" {
		level = "WARN"
	}
	if status == "CRITICAL" {
		level = "CRITICAL"
	}
	message := fmt.Sprintf("[SCA %s] %s: %s", status, title, detail)
	queue.AddLog(LogEntry{
		Timestamp: nowISO(),
		Level:     level,
		Source:    "agent",
		EventType: "sca",
		Message:   message,
		Host:      cfg.Hostname,
		IP:        hostIP(),
		Collector: "sca",
		Metadata: map[string]any{
			"check":       id,
			"status":      status,
			"detail":      detail,
			"remediation": remediation,
		},
	})
	if status == "CRITICAL" {
		queue.AddEvent(Event{
			Timestamp:     nowISO(),
			EventType:     "sca_critical",
			Severity:      "High",
			SourceIP:      hostIP(),
			DestinationIP: hostIP(),
			Protocol:      "LOCAL",
			Application:   "sca",
			Action:        "LOG",
			ThreatName:    "Security Configuration Failure: " + title,
			Metadata: map[string]any{
				"check":       id,
				"detail":      detail,
				"remediation": remediation,
			},
			Collector: "sca",
		})
	}
}
