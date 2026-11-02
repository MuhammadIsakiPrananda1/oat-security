//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const wafCommandTimeout = 20 * time.Second

func applyWAFPolicy(cfg *Config, policy *WAFPolicy) WAFApplyResult {
	if policy == nil {
		return WAFApplyResult{
			Status:  wafStatusFailed,
			Message: "the server returned an empty WAF policy",
		}
	}

	apacheConfig := strings.TrimSpace(cfg.WAFApacheConfig)
	if apacheConfig == "" {
		apacheConfig = "/etc/apache2/conf-available/oat-waf.conf"
	}
	configDir := filepath.Dir(apacheConfig)
	apacheCtl := findApacheControl()
	hasApache := false

	if info, err := os.Stat(configDir); err == nil && info.IsDir() && apacheCtl != "" {
		hasApache = true
	}

	var warnings []string
	target := ""

	if hasApache {
		configText, renderWarnings := renderApacheWAF(policy)
		warnings = append(warnings, renderWarnings...)

		previous, previousErr := os.ReadFile(apacheConfig)
		previousMode := os.FileMode(0o644)
		if info, err := os.Stat(apacheConfig); err == nil {
			previousMode = info.Mode().Perm()
		}

		if err := writeManagedFile(apacheConfig, []byte(configText), 0o644); err != nil {
			return WAFApplyResult{
				Status:  wafStatusFailed,
				Message: fmt.Sprintf("could not write %s: %v", apacheConfig, err),
				Target:  "Apache 2",
			}
		}

		// Debian keeps available configs separate from enabled configs.
		confReady := filepath.Base(configDir) != "conf-available"
		if filepath.Base(configDir) == "conf-available" {
			if path := findHostTool("a2enconf"); path != "" {
				confName := strings.TrimSuffix(filepath.Base(apacheConfig), ".conf")
				output, enableErr := runWAFCommand(path, confName)
				if enableErr == nil || alreadyEnabledOutput(output) {
					confReady = true
				}
			} else {
				enabledPath := filepath.Join(filepath.Dir(configDir), "conf-enabled", filepath.Base(apacheConfig))
				if _, err := os.Lstat(enabledPath); err == nil {
					confReady = true
				}
			}
		} else {
			confReady = true
		}

		if confReady {
			if path := findHostTool("a2enmod"); path != "" {
				_, _ = runWAFCommand(path, "rewrite")
			}
			if _, err := runWAFCommand(apacheCtl, "configtest"); err == nil {
				if _, reloadErr := reloadApache(apacheCtl); reloadErr == nil {
					target = "Apache 2"
				} else {
					restoreManagedFile(apacheConfig, previous, previousErr == nil, previousMode)
				}
			} else {
				restoreManagedFile(apacheConfig, previous, previousErr == nil, previousMode)
			}
		}
	}

	nftPath := findHostTool("nft")
	if nftPath != "" {
		script, nftRenderWarnings := renderNFTables(policy)
		warnings = append(warnings, nftRenderWarnings...)

		if script == "" {
			output, err := runWAFCommand(nftPath, "delete", "table", "inet", "oat_waf")
			if err != nil && !nftTableMissing(output, err) {
				warnings = append(warnings, "nftables table cleanup notice: "+compactOutput(output, err))
			} else {
				if target != "" {
					target += " + nftables"
				} else {
					target = "nftables"
				}
			}
		} else if output, err := runWAFCommandWithInput(script, nftPath, "-f", "-"); err != nil {
			if target == "" {
				return WAFApplyResult{
					Status:  wafStatusFailed,
					Message: "nftables apply failed: " + compactOutput(output, err),
					Target:  "nftables",
				}
			}
			warnings = append(warnings, "nftables sync notice: "+compactOutput(output, err))
		} else {
			if target != "" {
				target += " + nftables"
			} else {
				target = "nftables"
			}
		}
	} else if target == "" {
		return WAFApplyResult{
			Status:  wafStatusUnsupported,
			Message: "Neither Apache 2 nor nftables was found on this host. Install Apache 2 or nftables to enforce WAF policies.",
			Target:  "linux",
		}
	}

	if len(policy.GeoBlockCountries) > 0 {
		warnings = append(warnings, "geo blocking stays at the dashboard ingest layer; endpoint WAF has no GeoIP database")
	}

	message := ""
	if len(warnings) > 0 {
		message = strings.Join(dedupeStrings(warnings), " | ")
	}
	if message == "" {
		message = fmt.Sprintf("WAF policy applied successfully via %s.", target)
	}

	return WAFApplyResult{
		Status:       wafStatusApplied,
		Message:      message,
		Target:       target,
		RulesApplied: len(policy.Rules),
	}
}

func findApacheControl() string {
	for _, name := range []string{"apache2ctl", "apachectl"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	for _, candidate := range []string{"/usr/sbin/apache2ctl", "/usr/sbin/apachectl"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func reloadApache(apacheCtl string) (string, error) {
	if path := findHostTool("systemctl"); path != "" {
		if output, reloadErr := runWAFCommand(path, "reload", "apache2"); reloadErr == nil {
			return output, nil
		}
	}
	if path := findHostTool("service"); path != "" {
		if output, reloadErr := runWAFCommand(path, "apache2", "reload"); reloadErr == nil {
			return output, nil
		}
	}
	return runWAFCommand(apacheCtl, "graceful")
}

func writeManagedFile(path string, content []byte, mode os.FileMode) error {
	temp := fmt.Sprintf("%s.tmp-%d", path, os.Getpid())
	if err := os.WriteFile(temp, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(temp, mode); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func restoreManagedFile(path string, previous []byte, hadPrevious bool, mode os.FileMode) {
	if !hadPrevious {
		previous = []byte("# OAT Security WAF: no active policy (last apply was rolled back).\n")
	}
	if err := writeManagedFile(path, previous, mode); err != nil {
		_ = os.WriteFile(path, previous, mode)
	}
}

func runWAFCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wafCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func runWAFCommandWithInput(input, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wafCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// findHostTool looks in PATH first and then in the standard sbin/bin
// locations. systemd services do not always inherit /usr/sbin on PATH.
func findHostTool(name string) string {
	if found, err := exec.LookPath(name); err == nil {
		return found
	}
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func alreadyEnabledOutput(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "already enabled") || strings.Contains(lower, "already exists")
}

func nftTableMissing(output string, err error) bool {
	text := strings.ToLower(output)
	if err != nil {
		text += " " + strings.ToLower(err.Error())
	}
	return strings.Contains(text, "no such file or directory") || strings.Contains(text, "does not exist")
}

func compactOutput(output string, err error) string {
	text := strings.TrimSpace(output)
	if text == "" && err != nil {
		text = err.Error()
	}
	text = strings.ReplaceAll(text, "\r", "")
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) > 1200 {
		text = text[:1200] + "…"
	}
	if text == "" {
		return "unknown error"
	}
	return text
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
