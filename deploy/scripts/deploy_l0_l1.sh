#!/usr/bin/env bash
# 一键部署 L0（public）+ L1（lab）到服务器
# 用法：先配置 SSH 别名（~/.ssh/config 里 Host myserver），然后：
#   bash deploy_l0_l1.sh [myserver]
set -euo pipefail

SRV="${1:-myserver}"   # ssh 别名，可用环境变量覆盖
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==> 构建 L0 (Astro)..."
(cd "$ROOT/packages/public" && npm ci --silent && npm run build)

echo "==> 创建远端目录..."
ssh "$SRV" "sudo mkdir -p /var/www/public /var/www/lab && sudo chown \$USER:www-data /var/www/public /var/www/lab"

echo "==> 同步 L0 dist -> /var/www/public..."
rsync -az --delete "$ROOT/packages/public/dist/" "$SRV:/var/www/public/"

echo "==> 同步 L1 lab -> /var/www/lab..."
rsync -az --delete "$ROOT/packages/lab/" "$SRV:/var/www/lab/"

echo "==> 重载 nginx (可选, 若配置有变)..."
ssh "$SRV" "sudo nginx -t && sudo systemctl reload nginx" || true

echo "✅ 部署完成: https://leyanwc.xyz  https://lab.leyanwc.xyz"