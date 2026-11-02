//go:build linux

package main

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var (
	metricsMu     sync.Mutex
	lastCPUTotal  float64
	lastCPUIdle   float64
	haveCPUSample bool
)

func readProcStat() (total, idle float64, ok bool) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for index, field := range fields[1:] {
		value, err := strconv.ParseFloat(field, 64)
		if err != nil {
			continue
		}
		total += value
		if index == 3 || index == 4 { // idle + iowait
			idle += value
		}
	}
	return total, idle, total > 0
}

func cpuPercent() float64 {
	total, idle, ok := readProcStat()
	if !ok {
		return 0
	}
	metricsMu.Lock()
	defer metricsMu.Unlock()
	if !haveCPUSample {
		lastCPUTotal, lastCPUIdle, haveCPUSample = total, idle, true
		return 0
	}
	deltaTotal := total - lastCPUTotal
	deltaIdle := idle - lastCPUIdle
	lastCPUTotal, lastCPUIdle = total, idle
	if deltaTotal <= 0 {
		return 0
	}
	percent := (deltaTotal - deltaIdle) / deltaTotal * 100
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

func memoryStats() (percent, usedMB, totalMB float64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}
	defer file.Close()
	var totalKB, availableKB float64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseFloat(fields[1], 64)
		switch fields[0] {
		case "MemTotal:":
			totalKB = value
		case "MemAvailable:":
			availableKB = value
		}
	}
	if totalKB <= 0 {
		return 0, 0, 0
	}
	usedKB := totalKB - availableKB
	percent = clampPercent(usedKB / totalKB * 100)
	usedMB = usedKB / 1024
	totalMB = totalKB / 1024
	return percent, usedMB, totalMB
}

func diskStats() (percent, usedGB, totalGB float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil || stat.Blocks == 0 {
		return 0, 0, 0
	}
	used := stat.Blocks - stat.Bfree
	percent = clampPercent(float64(used) / float64(stat.Blocks) * 100)
	totalBytes := float64(stat.Blocks) * float64(stat.Bsize)
	usedBytes := float64(used) * float64(stat.Bsize)
	usedGB = usedBytes / (1024 * 1024 * 1024)
	totalGB = totalBytes / (1024 * 1024 * 1024)
	return percent, usedGB, totalGB
}

func loadAverages() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	one, _ := strconv.ParseFloat(fields[0], 64)
	five, _ := strconv.ParseFloat(fields[1], 64)
	fifteen, _ := strconv.ParseFloat(fields[2], 64)
	return one, five, fifteen
}

func uptimeSeconds() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return value
}

func processCount() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "" {
			continue
		}
		if name[0] >= '0' && name[0] <= '9' {
			count++
		}
	}
	return count
}

func kernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func CollectMetrics() Metrics {
	load1, load5, load15 := loadAverages()
	memPct, memUsedMB, memTotalMB := memoryStats()
	diskPct, diskUsedGB, diskTotalGB := diskStats()
	return Metrics{
		Hostname:      hostname(),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		IP:            hostIP(),
		CPUPercent:    cpuPercent(),
		CPUCores:      runtime.NumCPU(),
		MemoryPercent: memPct,
		MemoryUsedMB:  memUsedMB,
		MemoryTotalMB: memTotalMB,
		DiskPercent:   diskPct,
		DiskUsedGB:    diskUsedGB,
		DiskTotalGB:   diskTotalGB,
		Load1:         load1,
		Load5:         load5,
		Load15:        load15,
		UptimeSeconds: uptimeSeconds(),
		ProcessCount:  processCount(),
		Kernel:        kernelVersion(),
	}
}

func clampPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
