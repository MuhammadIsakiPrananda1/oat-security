## ============================================================
## OAT Endpoint Agent — Build & Release Makefile
## ============================================================
##
## Usage:
##   make build            → build for current OS (Windows: oat-agent.exe)
##   make linux            → cross-compile Linux amd64 + arm64 binaries
##   make windows          → cross-compile Windows amd64 + arm64 binaries
##   make all              → build all four targets → agent/dist/
##   make clean            → remove build artifacts (but not dist/ binaries)
##   make test             → run unit tests
##   make version V=x.y.z  → update version string and rebuild all
##
## Requirements:
##   - Go 1.22+ installed and in PATH
##   - For cross-compilation on Windows: CGO_ENABLED=0 is set automatically
## ============================================================

VERSION ?= $(shell powershell -NoProfile -Command "(Get-Content main.go) -match 'var version' | ForEach-Object { ($$_ -split '\"')[1] }")
BINARY  := oat-agent
DIST    := dist
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build linux windows all clean test version help

## Default: build for current platform
build:
	@echo Building $(BINARY) $(VERSION) for current platform...
	go build $(LDFLAGS) -o $(BINARY).exe .
	@echo Done: $(BINARY).exe

## Build Linux binaries (cross-compile)
linux:
	@if not exist $(DIST) mkdir $(DIST)
	@echo Building Linux amd64...
	set CGO_ENABLED=0 && set GOOS=linux && set GOARCH=amd64 && go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux-amd64 .
	@echo Building Linux arm64...
	set CGO_ENABLED=0 && set GOOS=linux && set GOARCH=arm64 && go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux-arm64 .
	@echo Linux binaries built in $(DIST)/

## Build Windows binaries (cross-compile)
windows:
	@if not exist $(DIST) mkdir $(DIST)
	@echo Building Windows amd64...
	set CGO_ENABLED=0 && set GOOS=windows && set GOARCH=amd64 && go build $(LDFLAGS) -o $(DIST)/$(BINARY)-windows-amd64.exe .
	@echo Building Windows arm64...
	set CGO_ENABLED=0 && set GOOS=windows && set GOARCH=arm64 && go build $(LDFLAGS) -o $(DIST)/$(BINARY)-windows-arm64.exe .
	@echo Windows binaries built in $(DIST)/

## Build all four platform targets
all: linux windows
	@echo All targets built in $(DIST)/
	cd $(DIST) && powershell -NoProfile -Command "Get-FileHash * | Select-Object Hash,Path | Format-Table -AutoSize" > SHA256SUMS 2>&1 || true
	@echo SHA256SUMS updated.

## Remove local build artifacts
clean:
	@if exist $(BINARY).exe del /f $(BINARY).exe
	@if exist oat-agent-test.exe del /f oat-agent-test.exe
	@echo Cleaned.

## Run unit tests
test:
	go test ./... -v -count=1

## Update version in main.go and rebuild
version:
	@if "$(V)"=="" (echo Usage: make version V=x.y.z && exit 1)
	powershell -NoProfile -Command "(Get-Content main.go) -replace 'var version = \".*\"', 'var version = \"$(V)\"' | Set-Content main.go"
	@echo Version updated to $(V)
	$(MAKE) all V=$(V)

## Show help
help:
	@echo.
	@echo   make build            Build for current platform
	@echo   make linux            Cross-compile for Linux amd64 + arm64
	@echo   make windows          Cross-compile for Windows amd64 + arm64
	@echo   make all              Build all four targets into dist/
	@echo   make clean            Remove local build artifacts
	@echo   make test             Run unit tests
	@echo   make version V=x.y.z  Bump version and rebuild all
	@echo.
