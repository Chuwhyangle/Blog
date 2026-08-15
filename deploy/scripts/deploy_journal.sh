#!/usr/bin/env bash
# 部署 L2（journal）到服务器：后端 + 前端
# 用法：bash deploy_journal.sh [myserver]
set -euo pipefail

SRV="${1:-myserver}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==> 构建前端..."
(cd "$ROOT/packages/journal/web" && npm ci --silent && npm run build)

echo "==> 同步前端 -> /var/www/journal..."
ssh "$SRV" "sudo mkdir -p /var/www/journal && sudo chown \$USER:www-data /var/www/journal"
rsync -az --delete "$ROOT/packages/journal/web/dist/" "$SRV:/var/www/journal/"

echo "==> 同步后端代码（排除 .venv）..."
rsync -az --delete \
  --exclude '.venv' --exclude '__pycache__' \
  "$ROOT/packages/journal/api/" "$SRV:/srv/blog/packages/journal/api/"

echo "==> 重启服务..."
ssh "$SRV" "sudo systemctl restart journal-api && sudo systemctl status journal-api --no-pager | head -5"

echo "✅ 部署完成: https://journal.leyanwc.xyz"
echo "   检查: curl https://journal.leyanwc.xyz/api/health"