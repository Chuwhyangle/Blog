#!/usr/bin/env bash
# P0 · Step 1：swap + swappiness（2C4G 必备，防 OOM killer 静默杀 MySQL）
# 用法：sudo bash 01_swap.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 sudo 运行"; exit 1
fi

# 已有 swap 则跳过
if swapon --show | grep -q '^/swapfile'; then
  echo "swap 已存在，跳过"
  swapon --show
  exit 0
fi

SIZE=2G
if ! fallocate -l "$SIZE" /swapfile 2>/dev/null; then
  echo "fallocate 失败（文件系统可能不支持），改用 dd"
  dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress
fi
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab

# swappiness=10：尽量不用，只做保险
sysctl -w vm.swappiness=10
grep -q 'vm.swappiness' /etc/sysctl.conf || echo 'vm.swappiness=10' >> /etc/sysctl.conf

echo "--- 结果 ---"
free -h | grep -i swap
cat /proc/sys/vm/swappiness