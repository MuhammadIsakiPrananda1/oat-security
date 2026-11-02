#!/usr/bin/env bash
# =============================================================
# OAT Endpoint Agent — Build Script
# =============================================================
# Builds all platform binaries and outputs them to ./dist/
#
# Usage:
#   bash build.sh                   # build all platforms
#   bash build.sh --version 1.2.3   # override version
#   bash build.sh --linux-only      # build Linux targets only
#   bash build.sh --windows-only    # build Windows targets only
# =============================================================
set -euo pipefail

DIST="./dist"
BINARY="oat-agent"
VERSION=""
LINUX_ONLY=0
WINDOWS_ONLY=0

# ── Parse args ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --linux-only) LINUX_ONLY=1; shift ;;
    --windows-only) WINDOWS_ONLY=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Auto-detect version from main.go if not set ───────────────
if [[ -z "$VERSION" ]]; then
  VERSION=$(grep 'var version' main.go | sed 's/.*"\(.*\)"/\1/')
fi

echo "╔══════════════════════════════════════════════════════╗"
echo "║  OAT Endpoint Agent — Build v${VERSION}"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

mkdir -p "$DIST"

# Strip symbols for smallest binary: -s -w
LDFLAGS="-ldflags=-s -w -X main.version=${VERSION}"

build_target() {
  local OS=$1 ARCH=$2 OUT=$3
  echo -n "  Building ${OS}/${ARCH} → ${OUT} ... "
  CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build $LDFLAGS -o "${DIST}/${OUT}" .
  local SIZE
  SIZE=$(du -sh "${DIST}/${OUT}" | cut -f1)
  echo "✓ (${SIZE})"
}

# ── Linux targets ─────────────────────────────────────────────
if [[ "$WINDOWS_ONLY" -eq 0 ]]; then
  echo "── Linux ──────────────────────────────────────────────"
  build_target linux amd64 "${BINARY}-linux-amd64"
  build_target linux arm64 "${BINARY}-linux-arm64"
fi

# ── Windows targets ───────────────────────────────────────────
if [[ "$LINUX_ONLY" -eq 0 ]]; then
  echo "── Windows ────────────────────────────────────────────"
  build_target windows amd64 "${BINARY}-windows-amd64.exe"
  build_target windows arm64 "${BINARY}-windows-arm64.exe"
fi

# ── SHA256 checksums ──────────────────────────────────────────
echo ""
echo "── Generating checksums ────────────────────────────────"
(cd "$DIST" && sha256sum ${BINARY}-* 2>/dev/null || shasum -a 256 ${BINARY}-*) | tee "${DIST}/SHA256SUMS"

echo ""
echo "✅  Build complete → ${DIST}/"
ls -lh "$DIST"
