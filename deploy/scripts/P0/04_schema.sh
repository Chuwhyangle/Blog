#!/usr/bin/env bash
# P0 · Step 4：导入 journal schema（8 张表）
# 用法：sudo bash 04_schema.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_FILE="${SCRIPT_DIR}/../../sql/schema.sql"

echo "导入 $SQL_FILE ..."
mysql -ujournal_ddl -p < "$SQL_FILE"

echo "--- 验证表清单 ---"
mysql -ujournal_ddl -p -e "SHOW TABLES FROM journal;"