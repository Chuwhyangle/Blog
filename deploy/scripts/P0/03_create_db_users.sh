#!/usr/bin/env bash
# P0 · Step 3：建库 + 独立用户（多项目隔离，③ §2）
#   journal_ddl : 只做迁移（改表结构），平时不用
#   journal_app  : 运行时用户，仅 DML，连 DROP 都执行不了
# 用法：sudo bash 03_create_db_users.sh  （会提示输入 root 密码）
set -euo pipefail

# 两个强随机口令（openssl 生成，打印一次，复制到 deploy/env/.env 后删除终端记录）
APP_PW=$(openssl rand -base64 24)
DDL_PW=$(openssl rand -base64 24)

echo "==== 即将生成 ===="
echo "journal_app 口令: $APP_PW"
echo "journal_ddl 口令: $DDL_PW"
echo "请复制到 deploy/env/.env.journal（模板见 deploy/env/.env.example）"
echo

mysql -uroot -p <<SQL
CREATE DATABASE IF NOT EXISTS journal
  CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;

-- 运行时用户：仅本机、仅 DML
CREATE USER IF NOT EXISTS 'journal_app'@'127.0.0.1' IDENTIFIED BY '$APP_PW';
GRANT SELECT, INSERT, UPDATE, DELETE ON journal.* TO 'journal_app'@'127.0.0.1';

-- 迁移用户：只改表结构时手动用
CREATE USER IF NOT EXISTS 'journal_ddl'@'127.0.0.1' IDENTIFIED BY '$DDL_PW';
GRANT ALL PRIVILEGES ON journal.* TO 'journal_ddl'@'127.0.0.1';

FLUSH PRIVILEGES;
SQL

echo "--- 验证 ---"
mysql -uroot -p -e "SHOW GRANTS FOR 'journal_app'@'127.0.0.1';"