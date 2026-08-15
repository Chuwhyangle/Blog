#!/usr/bin/env bash
# P0 · Step 2：探测 MySQL 版本 → 输出对应调优建议（②/⑪ Q6a）
# 共用实例：此脚本只是探测+打印，不自动改配置（避免影响其他项目）。
# 用法：sudo bash 02_mysql_probe.sh
set -euo pipefail

echo "==== MySQL 版本 ===="
mysql -uroot -p -e "SELECT VERSION();" 2>/dev/null

echo
echo "==== 当前关键变量 ===="
mysql -uroot -p -e "
SELECT @@innodb_buffer_pool_size/1024/1024 AS buffer_pool_MB,
       @@innodb_log_file_size/1024/1024  AS log_file_MB,
       @@performance_schema              AS perf_schema,
       @@max_connections                 AS max_conn,
       @@skip_name_resolve                AS skip_name_resolve;" 2>/dev/null

echo
echo "==== 现有 MySQL 账号（检查 TCP 用户 host）===="
mysql -uroot -p -e "SELECT user, host FROM mysql.user;" 2>/dev/null

echo
echo "==== 调优指引 ===="
echo "按 ⑪ Q6a："
echo "- 8.0.30+  → 用 innodb_redo_log_capacity（在线可改，无需重启），忽略 log_file_size"
echo "- 8.0.0–29 → innodb_log_file_size 需重启"
echo "- 5.7      → 需重启 + 手工处理旧 redo；utf8mb4_0900_ai_ci 不存在，用 utf8mb4_unicode_ci"
echo
echo "改 config 前先确认：其他项目可否容忍一次 MySQL 重启（低峰期）。"
echo "skip_name_resolve 是全局开关：若开，需先给走 TCP 的 @'localhost' 老账号补 @'127.0.0.1'。"