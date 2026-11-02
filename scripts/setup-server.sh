#!/bin/bash
# ============================================================
# Setup Server OAT Security — Jalankan sekali di server
# ============================================================
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "======================================================"
echo "   OAT Security — Server Setup Script"
echo "   Domain: aotsecurity.neverlandstudio.ai.id"
echo "======================================================"
echo -e "${NC}"

# ─── 1. Cek root ──────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ Script ini harus dijalankan sebagai root!${NC}"
  exit 1
fi

# ─── 2. Install Caddy ─────────────────────────────────────
echo -e "${CYAN}[1/6] Install Caddy...${NC}"
if ! command -v caddy &> /dev/null; then
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y caddy
  echo -e "${GREEN}  ✅ Caddy berhasil diinstall${NC}"
else
  echo -e "${GREEN}  ✅ Caddy sudah terinstall$(caddy version)${NC}"
fi

# ─── 3. Install Docker (jika belum ada) ───────────────────
echo -e "${CYAN}[2/6] Cek Docker...${NC}"
if ! command -v docker &> /dev/null; then
  curl -fsSL https://get.docker.com | sh
  echo -e "${GREEN}  ✅ Docker berhasil diinstall${NC}"
else
  echo -e "${GREEN}  ✅ Docker sudah ada: $(docker --version)${NC}"
fi

# ─── 4. Buat direktori aplikasi ───────────────────────────
echo -e "${CYAN}[3/6] Setup direktori /opt/oat-security...${NC}"
mkdir -p /opt/oat-security
mkdir -p /var/log/caddy

# Copy file yang dibutuhkan
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cp "$PROJECT_DIR/docker-compose.prod.yml" /opt/oat-security/docker-compose.prod.yml
cp "$PROJECT_DIR/.env.production"         /opt/oat-security/.env
echo -e "${GREEN}  ✅ File berhasil di-copy ke /opt/oat-security/${NC}"

# ─── 5. Setup Caddyfile ───────────────────────────────────
echo -e "${CYAN}[4/6] Setup Caddy...${NC}"
cp "$PROJECT_DIR/Caddyfile" /etc/caddy/Caddyfile
systemctl enable caddy
systemctl restart caddy
sleep 2
if systemctl is-active --quiet caddy; then
  echo -e "${GREEN}  ✅ Caddy aktif dan berjalan${NC}"
else
  echo -e "${RED}  ❌ Caddy gagal start. Cek: journalctl -xe -u caddy${NC}"
fi

# ─── 6. Generate SSH Key untuk GitHub Actions ─────────────
echo -e "${CYAN}[5/6] Generate SSH key untuk GitHub Actions...${NC}"
SSH_KEY_PATH="$HOME/.ssh/github_actions_oat"
if [ ! -f "$SSH_KEY_PATH" ]; then
  ssh-keygen -t ed25519 -C "github-actions-oat-security" -f "$SSH_KEY_PATH" -N ""
fi
# Tambahkan public key ke authorized_keys
cat "${SSH_KEY_PATH}.pub" >> "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
echo -e "${GREEN}  ✅ SSH key siap${NC}"

# ─── 7. Tampilkan info GitHub Secrets ─────────────────────
echo -e "${CYAN}[6/6] Informasi untuk GitHub Secrets...${NC}"
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo -e "${YELLOW}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║         TAMBAHKAN INI KE GITHUB SECRETS               ║${NC}"
echo -e "${YELLOW}║  https://github.com/MuhammadIsakiPrananda1/           ║${NC}"
echo -e "${YELLOW}║  oat-security/settings/secrets/actions                ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}SSH_HOST${NC}         = $SERVER_IP"
echo -e "${GREEN}SSH_USER${NC}         = root"
echo ""
echo -e "${GREEN}SSH_PRIVATE_KEY${NC}  = (isi dengan teks di bawah ini, copy semua termasuk header):"
echo -e "${YELLOW}──────────────────────────────────────────────${NC}"
cat "$SSH_KEY_PATH"
echo -e "${YELLOW}──────────────────────────────────────────────${NC}"
echo ""
echo -e "${GREEN}GHCR_TOKEN${NC}       = Buat Personal Access Token di:"
echo "                   https://github.com/settings/tokens"
echo "                   Centang scope: read:packages, write:packages"
echo ""
echo -e "${CYAN}======================================================"
echo "  Setup selesai! Langkah berikutnya:"
echo ""
echo "  1. Tambahkan 4 secrets ke GitHub (lihat di atas)"
echo "  2. Arahkan DNS domain ke IP: $SERVER_IP"
echo "  3. Push kode ke GitHub:"
echo "     git add . && git commit -m 'feat: CI/CD' && git push origin main"
echo "======================================================"
echo -e "${NC}"

