//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// DetectedSite represents a website found running on this host.
type DetectedSite struct {
	Domain     string `json:"domain"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	ServerType string `json:"serverType"`
	Root       string `json:"root,omitempty"`
}

// detectLocalSites on Windows checks common web ports for active listeners.
func detectLocalSites() []DetectedSite {
	commonPorts := []struct {
		port  int
		proto string
	}{
		{80, "HTTP"}, {443, "HTTPS"}, {8080, "HTTP"},
		{8443, "HTTPS"}, {3000, "HTTP"}, {8000, "HTTP"},
	}

	seen := map[string]bool{}
	var sites []DetectedSite
	myHostname := hostname()

	for _, p := range commonPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), 300*1000*1000)
		if err != nil {
			continue
		}
		conn.Close()
		domain := strings.ToLower(myHostname)
		key := fmt.Sprintf("%s:%d", domain, p.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		sites = append(sites, DetectedSite{
			Domain:     domain,
			Port:       p.port,
			Protocol:   p.proto,
			ServerType: "unknown",
		})
	}
	return sites
}

// detectWebRoots returns the conventional Windows document roots that exist on
// this host. The upload watcher only inspects files inside these directories.
func detectWebRoots() []string {
	seen := map[string]bool{}
	var roots []string

	add := func(candidate string) {
		candidate = strings.TrimSpace(strings.Trim(candidate, `"'`))
		if candidate == "" {
			return
		}
		candidate = filepath.Clean(candidate)
		if seen[candidate] {
			return
		}
		info, err := os.Stat(candidate)
		if err != nil || !info.IsDir() {
			return
		}
		seen[candidate] = true
		roots = append(roots, candidate)
	}

	// ASP.NET / IIS
	add(`C:\inetpub\wwwroot`)
	// XAMPP, Laragon, WampServer
	add(`C:\xampp\htdocs`)
	add(`C:\laragon\www`)
	add(`C:\wamp64\www`)
	add(`C:\wamp\www`)
	// Apache on Windows
	add(`C:\Apache24\htdocs`)

	if drive := os.Getenv("SystemDrive"); drive != "" {
		add(filepath.Join(drive+`\`, "inetpub", "wwwroot"))
	}

	return roots
}
