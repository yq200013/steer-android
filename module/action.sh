#!/system/bin/sh
# KernelSU 模块「操作」按钮：原生控制台里直接看诊断（不经过 WebView）
MODDIR=${0%/*}
B=/data/adb/steer/steer
[ -x "$B" ] || B="$MODDIR/bin/steer"
[ -x "$B" ] || { echo "找不到 steer 二进制（模块可能未正确安装）"; exit 1; }

echo "=== Steer 诊断 ==="
"$B" diag 2>&1
