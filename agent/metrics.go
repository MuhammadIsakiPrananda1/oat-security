package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func hostIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var results []string
	var fallback string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		nameLower := strings.ToLower(iface.Name)
		// Exclude podman, docker, and virtual container bridges/veth interfaces
		if strings.Contains(nameLower, "docker") || strings.Contains(nameLower, "podman") ||
			strings.HasPrefix(nameLower, "br-") || strings.HasPrefix(nameLower, "veth") ||
			strings.HasPrefix(nameLower, "cni") || strings.HasPrefix(nameLower, "flannel") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				results = append(results, fmt.Sprintf("%s: %s", iface.Name, ipv4.String()))
				if fallback == "" {
					fallback = ipv4.String()
				}
			}
		}
	}
	if len(results) > 0 {
		return strings.Join(results, ", ")
	}
	return fallback
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "unknown-host"
	}
	return name
}
