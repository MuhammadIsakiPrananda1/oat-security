#!/usr/bin/env pwsh
# =============================================================
# OAT Endpoint Agent — Build Script (PowerShell / Windows)
# =============================================================
# Builds all platform binaries and outputs them to .\dist\
#
# Usage:
#   .\build.ps1                     # build all platforms
#   .\build.ps1 -Version 1.2.3      # override version
#   .\build.ps1 -LinuxOnly          # Linux targets only
#   .\build.ps1 -WindowsOnly        # Windows targets only
# =============================================================
param(
  [string]$Version = "",
  [switch]$LinuxOnly,
  [switch]$WindowsOnly
)

$ErrorActionPreference = "Stop"

$Dist   = ".\dist"
$Binary = "oat-agent"

# Auto-detect version from main.go
if (-not $Version) {
  $line = Get-Content main.go | Where-Object { $_ -match 'var version' } | Select-Object -First 1
  if ($line -match '"(.+)"') { $Version = $Matches[1] }
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  OAT Endpoint Agent — Build v$Version" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $Dist)) { New-Item -ItemType Directory -Path $Dist | Out-Null }

$ldflags = "-s -w -X main.version=$Version"

function Build-Target {
  param($OS, $Arch, $Out)
  Write-Host -NoNewline "  Building ${OS}/${Arch} → ${Out} ... "
  $env:CGO_ENABLED = "0"
  $env:GOOS        = $OS
  $env:GOARCH      = $Arch
  go build -ldflags $ldflags -o "$Dist\$Out" .
  $size = (Get-Item "$Dist\$Out").Length / 1MB
  Write-Host ("✓ ({0:N1} MB)" -f $size) -ForegroundColor Green
}

# ── Linux targets ─────────────────────────────────────────────
if (-not $WindowsOnly) {
  Write-Host "── Linux ──────────────────────────────────────────────" -ForegroundColor Yellow
  Build-Target linux amd64 "${Binary}-linux-amd64"
  Build-Target linux arm64 "${Binary}-linux-arm64"
}

# ── Windows targets ───────────────────────────────────────────
if (-not $LinuxOnly) {
  Write-Host "── Windows ────────────────────────────────────────────" -ForegroundColor Yellow
  Build-Target windows amd64 "${Binary}-windows-amd64.exe"
  Build-Target windows arm64 "${Binary}-windows-arm64.exe"
}

# Reset env
Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
$env:CGO_ENABLED = "1"

# ── SHA256 checksums ──────────────────────────────────────────
Write-Host ""
Write-Host "── Generating checksums ────────────────────────────────" -ForegroundColor Yellow
$checksums = Get-ChildItem "$Dist\${Binary}-*" | ForEach-Object {
  $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
  "$hash  $($_.Name)"
}
$checksums | Tee-Object "$Dist\SHA256SUMS"

Write-Host ""
Write-Host "✅  Build complete → $Dist\" -ForegroundColor Green
Get-ChildItem $Dist | Select-Object Name, @{N='Size (MB)';E={[math]::Round($_.Length/1MB,2)}} | Format-Table -AutoSize
