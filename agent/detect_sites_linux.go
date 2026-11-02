//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DetectedSite represents a website found running on this host.
type DetectedSite struct {
	Domain     string `json:"domain"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	ServerType string `json:"serverType"`
	Root       string `json:"root,omitempty"`
}

// detectLocalSites scans the host for running web servers and returns a
// deduplicated list of websites. It checks:
//  1. Nginx server_name directives from sites-enabled
//  2. Apache ServerName / ServerAlias directives from sites-enabled
//  3. Active TCP listeners on common web ports (80, 443, 8080, 8443, 3000, …)
//
// Results are conservative: only domains that look like real hostnames are
// returned (no wildcards, no bare IPs unless no domain found).
func detectLocalSites() []DetectedSite {
	seen := map[string]bool{}
	var sites []DetectedSite

	add := func(domain string, port int, proto, server, root string) {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" || domain == "localhost" || domain == "_" || domain == "*" {
			return
		}
		// Skip wildcard and plain IP
		if strings.HasPrefix(domain, "*.") {
			return
		}
		if net.ParseIP(domain) != nil {
			return
		}
		key := fmt.Sprintf("%s:%d", domain, port)
		if seen[key] {
			return
		}
		seen[key] = true
		sites = append(sites, DetectedSite{
			Domain:     domain,
			Port:       port,
			Protocol:   proto,
			ServerType: server,
			Root:       strings.TrimSpace(root),
		})
	}

	// ── 1. Nginx, OpenResty, aaPanel, cPanel EA-Nginx ───────────────────────
	nginxDirs := []string{
		"/etc/nginx/sites-enabled",
		"/etc/nginx/conf.d",
		"/etc/nginx/vhost",                       // aaPanel
		"/www/server/panel/vhost/nginx",          // aaPanel Nginx vhosts
		"/etc/nginx/conf.d/users",                // cPanel EA-Nginx
		"/usr/local/nginx/conf/sites-enabled",
		"/usr/local/nginx/conf/vhost",
	}
	serverNameRe := regexp.MustCompile(`(?i)^\s*server_name\s+(.+?);`)
	listenRe := regexp.MustCompile(`(?i)^\s*listen\s+(\S+)`)
	rootRe := regexp.MustCompile(`(?i)^\s*root\s+([^;]+);`)

	for _, dir := range nginxDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			var serverNames []string
			port := 80
			proto := "HTTP"
			root := ""
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := scanner.Text()
				if m := serverNameRe.FindStringSubmatch(line); m != nil {
					for _, name := range strings.Fields(m[1]) {
						serverNames = append(serverNames, name)
					}
				}
				if m := rootRe.FindStringSubmatch(line); m != nil {
					root = strings.TrimSpace(m[1])
				}
				if m := listenRe.FindStringSubmatch(line); m != nil {
					raw := m[1]
					if strings.Contains(raw, "ssl") || strings.HasSuffix(raw, "443") {
						port = 443
						proto = "HTTPS"
					} else {
						parts := strings.Split(raw, ":")
						if p, err := strconv.Atoi(parts[len(parts)-1]); err == nil && p > 0 {
							port = p
						}
					}
				}
			}
			for _, name := range serverNames {
				add(name, port, proto, "nginx", root)
			}
		}
	}

	// ── 2. Apache, cPanel, aaPanel, LiteSpeed ─────────────────────────────────
	apacheDirs := []string{
		"/etc/apache2/sites-enabled",
		"/etc/httpd/conf.d",
		"/etc/httpd/vhosts.d",
		"/etc/apache2/conf.d",
		"/etc/apache2/conf.d/userdata",           // cPanel
		"/etc/apache2/conf/httpd.conf",
		"/www/server/panel/vhost/apache",         // aaPanel Apache vhosts
		"/usr/local/lsws/conf/vhosts",            // OpenLiteSpeed / LiteSpeed
	}
	serverNameApacheRe := regexp.MustCompile(`(?i)^\s*(?:ServerName|ServerAlias)\s+(\S+)`)
	virtualHostRe := regexp.MustCompile(`(?i)<VirtualHost[^>]*:(\d+)`)
	documentRootRe := regexp.MustCompile(`(?i)^\s*DocumentRoot\s+(.+)$`)

	for _, dir := range apacheDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			port := 80
			proto := "HTTP"
			var names []string
			docRoot := ""
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := scanner.Text()
				if m := virtualHostRe.FindStringSubmatch(line); m != nil {
					if p, err := strconv.Atoi(m[1]); err == nil {
						port = p
						if port == 443 {
							proto = "HTTPS"
						}
					}
				}
				if m := serverNameApacheRe.FindStringSubmatch(line); m != nil {
					names = append(names, m[1])
				}
				if m := documentRootRe.FindStringSubmatch(line); m != nil {
					docRoot = strings.Trim(strings.TrimSpace(m[1]), `"'`)
				}
			}
			for _, name := range names {
				add(name, port, proto, "apache", docRoot)
			}
		}
	}

	// ── 3. Docker / Podman Container Detection ────────────────────────────────
	for _, engine := range []string{"docker", "podman"} {
		path := findHostTool(engine)
		if path == "" {
			continue
		}
		// Format: container_id|names|image|ports
		out, err := runWAFCommand(path, "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}")
		if err != nil || strings.TrimSpace(out) == "" {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) < 4 {
				continue
			}
			cName := parts[1]
			ports := parts[3]

			// Extract forwarded host ports, e.g. "0.0.0.0:8080->80/tcp", ":::443->443/tcp"
			portRe := regexp.MustCompile(`(?::|0\.0\.0\.0:)(\d+)->(\d+)`)
			matches := portRe.FindAllStringSubmatch(ports, -1)
			for _, m := range matches {
				if len(m) >= 2 {
					if hostPort, err := strconv.Atoi(m[1]); err == nil && hostPort > 0 {
						proto := "HTTP"
						if hostPort == 443 || hostPort == 8443 {
							proto = "HTTPS"
						}
						domain := fmt.Sprintf("%s.local", cName)
						add(domain, hostPort, proto, engine, "")
					}
				}
			}
		}
	}

	// ── 4. Active port listeners (fallback for any container/reverse proxy/custom stack) ────
	commonPorts := []struct {
		port  int
		proto string
	}{
		{80, "HTTP"}, {443, "HTTPS"}, {8080, "HTTP"},
		{8443, "HTTPS"}, {8888, "HTTP"}, {3000, "HTTP"},
		{5000, "HTTP"}, {8000, "HTTP"}, {9000, "HTTP"},
	}
	myHostname := hostname()
	for _, p := range commonPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), 150*time.Millisecond)
		if err != nil {
			continue
		}
		conn.Close()
		add(myHostname, p.port, p.proto, "web-service", "")
	}

	return sites
}

// detectWebRoots returns the directories that actually serve websites on this
// host: the root/document root of every configured virtual host plus the
// conventional document roots that exist. The upload watcher only inspects
// files inside these directories.
func detectWebRoots() []string {
	seen := map[string]bool{}
	var roots []string

	add := func(candidate string) {
		candidate = strings.TrimSpace(strings.Trim(candidate, `"'`))
		if candidate == "" || !filepath.IsAbs(candidate) {
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

	for _, site := range detectLocalSites() {
		add(site.Root)
	}

	// Conventional document roots across standard Linux, cPanel, aaPanel, Docker volumes.
	for _, candidate := range []string{
		"/var/www", "/var/www/html", "/srv/www", "/srv/www/htdocs",
		"/usr/share/nginx/html", "/var/lib/nginx/html",
		"/opt/lampp/htdocs", "/var/www/html/public",
		"/www/wwwroot",                           // aaPanel sites root
		"/usr/local/apache/htdocs",
		"/var/lib/docker/volumes",
	} {
		add(candidate)
	}
	if matches, err := filepath.Glob("/home/*/public_html"); err == nil {
		for _, match := range matches {
			add(match)
		}
	}
	// aaPanel & custom multi-tenant site paths
	if matches, err := filepath.Glob("/www/wwwroot/*"); err == nil {
		for _, match := range matches {
			add(match)
		}
	}

	return roots
}
