# OAT Endpoint Agent installer for Windows.
#
# Run in an elevated PowerShell:
#   irm https://security.example.com/api/agents/install.ps1 | iex
#   (set OAT_SERVER and OAT_TOKEN environment variables first)
#
# Or:
#   .\install.ps1 -Server https://security.example.com -Token oat_enr_...
#
# The token is single-use and expires. The agent generates its keypair locally;
# the private key never leaves the endpoint.

[CmdletBinding()]
param(
    [string]$Server = $env:OAT_SERVER,
    [string]$Token = $env:OAT_TOKEN,
    [string]$Name = $env:COMPUTERNAME,
    [string]$CAFile = $env:OAT_CA,
    [switch]$Insecure,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "This installer must run in an elevated PowerShell (Run as Administrator)."
}

$TaskName = "OAT Security Agent"
$InstallDir = Join-Path $env:ProgramFiles "OATAgent"
$ConfigPath = Join-Path $env:ProgramData "OATAgent\config.json"
$StateDir = Join-Path $env:ProgramData "OATAgent\state"
$ExePath = Join-Path $InstallDir "oat-agent.exe"
$RunScript = Join-Path $InstallDir "run-agent.cmd"
$LogPath = Join-Path $env:ProgramData "OATAgent\agent.log"

if ($Uninstall) {
    Write-Host "Stopping and removing OAT agent ..."
    schtasks.exe /End /TN $TaskName 2>$null | Out-Null
    schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null
    if (Test-Path $ExePath) { Remove-Item $ExePath -Force }
    if (Test-Path $RunScript) { Remove-Item $RunScript -Force }
    Write-Host "OAT agent removed. Config and state remain in $env:ProgramData\OATAgent."
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Token)) {
    Fail "Server and Token are required. Set OAT_SERVER / OAT_TOKEN or pass -Server / -Token."
}

$Server = $Server.TrimEnd("/")
try { $uri = [Uri]$Server } catch { Fail "Invalid server URL: $Server" }
if ($uri.Scheme -eq "http") {
    $isLocal = $uri.Host -in @("localhost", "127.0.0.1", "::1")
    if (-not $isLocal -and -not $Insecure) {
        Fail "Refusing plain HTTP to $($uri.Host). Use HTTPS, or pass -Insecure for a lab."
    }
} elseif ($uri.Scheme -ne "https") {
    Fail "Server URL must start with https://."
}

if (-not [string]::IsNullOrWhiteSpace($CAFile) -and -not (Test-Path $CAFile)) {
    Fail "CA certificate not found: $CAFile"
}

$arch = if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
} else {
    Fail "32-bit Windows is not supported. Use a 64-bit endpoint."
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tempExe = Join-Path $env:TEMP ("oat-agent-" + [Guid]::NewGuid().ToString("N") + ".exe")
$tokenFile = Join-Path $env:TEMP ("oat-enroll-" + [Guid]::NewGuid().ToString("N") + ".tmp")

try {
    $downloadUrl = "$Server/api/agents/download?os=windows&arch=$arch"
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    Write-Host "Downloading OAT agent for windows/$arch from $Server ..."

    if ($null -ne $curl) {
        $curlArgs = @("-fsSL", "--retry", "3", "--connect-timeout", "15")
        if (-not [string]::IsNullOrWhiteSpace($CAFile)) { $curlArgs += @("--cacert", $CAFile) }
        if ($Insecure) { $curlArgs += "-k" }
        $curlArgs += @($downloadUrl, "-o", $tempExe)
        & $curl.Source @curlArgs
        if ($LASTEXITCODE -ne 0) { Fail "Agent download failed (curl exit code $LASTEXITCODE)." }
    } else {
        if (-not [string]::IsNullOrWhiteSpace($CAFile)) {
            Write-Warning "curl.exe was not found; the CA file is used for enrollment but not for this download."
        }
        if ($Insecure) {
            $previousCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            try {
                Invoke-WebRequest -Uri $downloadUrl -OutFile $tempExe -UseBasicParsing
            } finally {
                [Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
            }
        } else {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $tempExe -UseBasicParsing
        }
    }

    if (-not (Test-Path $tempExe) -or (Get-Item $tempExe).Length -lt 100000) {
        Fail "Downloaded agent binary looks invalid. Is the server built with 'npm run agent:build'?"
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path $ConfigPath) -Force | Out-Null
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

    if (Test-Path $ExePath) { Stop-Process -Name "oat-agent" -Force -ErrorAction SilentlyContinue }
    Move-Item -Path $tempExe -Destination $ExePath -Force

    Set-Content -Path $tokenFile -Value $Token -NoNewline -Encoding ASCII

    Write-Host "Enrolling this endpoint ..."
    $enrollArgs = @(
        "enroll",
        "--server", $Server,
        "--token-file", $tokenFile,
        "--name", $Name,
        "--config", $ConfigPath,
        "--state-dir", $StateDir
    )
    if ($Insecure) { $enrollArgs += "--insecure" }
    if (-not [string]::IsNullOrWhiteSpace($CAFile)) { $enrollArgs += @("--ca", $CAFile) }
    & $ExePath @enrollArgs
    if ($LASTEXITCODE -ne 0) { Fail "Agent enrollment failed (exit code $LASTEXITCODE)." }
} finally {
    if (Test-Path $tempExe) { Remove-Item $tempExe -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tokenFile) { Remove-Item $tokenFile -Force -ErrorAction SilentlyContinue }
}

$runContent = @"
@echo off
"$ExePath" run --config "$ConfigPath" >> "$LogPath" 2>&1
"@
Set-Content -Path $RunScript -Value $runContent -Encoding ASCII

$action = New-ScheduledTaskAction -Execute $RunScript
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "OAT agent installed and started." -ForegroundColor Green
Write-Host "  Task:   Get-ScheduledTask -TaskName '$TaskName'"
Write-Host "  Logs:   Get-Content '$LogPath' -Wait"
Write-Host "  Config: $ConfigPath"
Write-Host ""
Write-Host "The agent should appear as ONLINE in Dashboard -> Endpoint Agents within 30 seconds."
