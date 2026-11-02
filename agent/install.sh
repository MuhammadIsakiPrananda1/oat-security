#!/usr/bin/env bash
# OAT Endpoint Agent installer for Linux.
#
# Usage:
#   sudo bash install.sh --server https://security.example.com --token oat_enr_...
#   curl -fsSL https://security.example.com/api/agents/install.sh | sudo bash -s -- \
#     --server https://security.example.com --token oat_enr_...
#
# On a fresh platform the token can be omitted: the first agent install
# provisions the organization and registers the website it protects.
#
# The token is single-use and expires. The agent generates its keypair locally;
# the private key never leaves the endpoint.
set -euo pipefail

SERVER="${OAT_SERVER:-}"
TOKEN="${OAT_TOKEN:-}"
NAME="${OAT_NAME:-$(hostname -f 2>/dev/null || hostname)}"
CONFIG_PATH="/etc/oat-agent/config.json"
INSECURE="0"
UNINSTALL="0"
CA_FILE=""

usage() {
  cat <<'EOF'
OAT Endpoint Agent installer (Linux)

Options:
  --server URL        OAT server base URL (required)
  --token TOKEN       one-time enrollment token (optional on a fresh platform:
                      the first agent install provisions the organization)
  --name NAME         display name for this endpoint (default: hostname)
  --config PATH       config path (default: /etc/oat-agent/config.json)
  --ca PATH           trust a private CA certificate (PEM)
  --insecure          allow HTTP / skip TLS verification (lab only)
  --uninstall         stop and remove the agent
  -h, --help          show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --name) NAME="${2:-}"; shift 2 ;;
    --config) CONFIG_PATH="${2:-}"; shift 2 ;;
    --ca) CA_FILE="${2:-}"; shift 2 ;;
    --insecure) INSECURE="1"; shift ;;
    --uninstall) UNINSTALL="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This installer must run as root (use sudo)." >&2
  exit 1
fi

BIN="/usr/local/bin/oat-agent"
UNIT="/etc/systemd/system/oat-agent.service"

if [[ "$UNINSTALL" == "1" ]]; then
  systemctl stop oat-agent 2>/dev/null || true
  systemctl disable oat-agent 2>/dev/null || true
  rm -f "$UNIT" "$BIN"
  systemctl daemon-reload 2>/dev/null || true
  echo "OAT agent removed. Config and state remain in /etc/oat-agent and /var/lib/oat-agent."
  exit 0
fi

if [[ -z "$SERVER" ]]; then
  echo "--server is required." >&2
  usage
  exit 1
fi

SERVER="${SERVER%/}"
case "$SERVER" in
  https://*) ;;
  http://localhost*|http://127.0.0.1*|http://\[::1\]*) ;;
  http://*)
    if [[ "$INSECURE" != "1" ]]; then
      echo "Refusing plain HTTP to a remote host. Use HTTPS, or pass --insecure for a lab." >&2
      exit 1
    fi
    ;;
  *)
    echo "Server URL must start with https:// (or http://localhost for a lab)." >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported CPU architecture: $(uname -m). Supported: x86_64, aarch64." >&2
    exit 1
    ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to download the agent." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required (systemctl not found)." >&2
  exit 1
fi

if [[ -n "$CA_FILE" && ! -r "$CA_FILE" ]]; then
  echo "CA certificate is not readable: $CA_FILE" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

CURL_ARGS=(-fsSL --retry 3 --connect-timeout 15)
if [[ -n "$CA_FILE" ]]; then
  CURL_ARGS+=(--cacert "$CA_FILE")
fi
if [[ "$INSECURE" == "1" ]]; then
  CURL_ARGS+=(-k)
fi

echo "Downloading OAT agent for linux/$ARCH from $SERVER ..."
curl "${CURL_ARGS[@]}" \
  "$SERVER/api/agents/download?os=linux&arch=$ARCH" \
  -o "$TMP_DIR/oat-agent"

if [[ ! -s "$TMP_DIR/oat-agent" ]] || [[ "$(wc -c < "$TMP_DIR/oat-agent")" -lt 100000 ]]; then
  echo "Downloaded agent binary looks invalid. Is the server reachable and built with 'npm run agent:build'?" >&2
  exit 1
fi

# Automatically install and enable necessary system dependencies so the agent can enforce
# firewall ACL rules (nftables/iptables), fail2ban host protection, and web inspection directly from this website console.
echo "Ensuring required firewall, fail2ban & network dependencies are installed..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o Acquire::Check-Valid-Until=false update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq nftables iptables fail2ban curl >/dev/null 2>&1 || true
  systemctl enable nftables fail2ban >/dev/null 2>&1 || true
  systemctl start nftables fail2ban >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q nftables iptables fail2ban curl >/dev/null 2>&1 || true
  systemctl enable nftables fail2ban >/dev/null 2>&1 || true
  systemctl start nftables fail2ban >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
  yum install -y -q nftables iptables fail2ban curl >/dev/null 2>&1 || true
  systemctl enable nftables fail2ban >/dev/null 2>&1 || true
  systemctl start nftables fail2ban >/dev/null 2>&1 || true
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm nftables iptables fail2ban curl >/dev/null 2>&1 || true
  systemctl enable nftables fail2ban >/dev/null 2>&1 || true
  systemctl start nftables fail2ban >/dev/null 2>&1 || true
fi

install -d -m 0750 /etc/oat-agent /var/lib/oat-agent
install -m 0755 "$TMP_DIR/oat-agent" "$BIN"

umask 077

echo "Enrolling this endpoint ..."
if [[ -n "$TOKEN" ]]; then
  printf '%s' "$TOKEN" > "$TMP_DIR/enroll.token"
  ENROLL_ARGS=(enroll --server "$SERVER" --token-file "$TMP_DIR/enroll.token" --name "$NAME" --config "$CONFIG_PATH")
else
  # No token: the server provisions the organization from this first install.
  ENROLL_ARGS=(enroll --server "$SERVER" --name "$NAME" --config "$CONFIG_PATH")
fi
if [[ -n "$CA_FILE" ]]; then
  ENROLL_ARGS+=(--ca "$CA_FILE")
fi
if [[ "$INSECURE" == "1" ]]; then
  ENROLL_ARGS+=(--insecure)
fi
if ! "$BIN" "${ENROLL_ARGS[@]}"; then
  if [[ -z "$TOKEN" ]]; then
    echo "" >&2
    echo "Bootstrap enrollment was refused: this platform is already provisioned." >&2
    echo "Create a one-time enrollment token in the console (Endpoint Agents -> Deploy a new endpoint agent)" >&2
    echo "and re-run this installer with:  --token oat_enr_..." >&2
  fi
  exit 1
fi
rm -f "$TMP_DIR/enroll.token"

cat > "$UNIT" <<EOF
[Unit]
Description=OAT Security Endpoint Agent
Documentation=https://github.com/oat-security
After=network-online.target apache2.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN run --config $CONFIG_PATH
Restart=always
RestartSec=5
User=root
Group=root
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=false
ProtectHome=false
ProtectKernelTunables=false
ProtectControlGroups=false
RestrictSUIDSGID=false
MemoryDenyWriteExecute=false
ReadWritePaths=-/var/lib/oat-agent -/etc/oat-agent -/etc/apache2/conf-available -/etc/apache2/conf-enabled -/etc/apache2/mods-enabled -/etc/nginx -/run
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable oat-agent >/dev/null 2>&1
systemctl restart oat-agent

echo ""
echo "OAT agent installed and started."
echo "  Service: systemctl status oat-agent"
echo "  Logs:    journalctl -u oat-agent -f"
echo "  Config:  $CONFIG_PATH"
echo ""
echo "The agent should appear as ONLINE in Dashboard -> Endpoint Agents within 30 seconds."
