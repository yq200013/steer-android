#!/system/bin/sh
# 卸载：可逆、精确、不用 rm -rf 打整棵 /sys
BASE=/data/adb/steer
MODDIR=${0%/*}

# 1) 置停止标记，让 watchdog 自己退出（不依赖 pkill 匹配）
touch "$BASE/stop" 2>/dev/null
touch "$MODDIR/remove" 2>/dev/null

# 2) 停守护（精确匹配我们自己的路径，绝不 killall）
pkill -f "$BASE/steer daemon" 2>/dev/null
sleep 1
# watchdog 可能仍在跑：两种写法都杀一遍（$0 可能是相对路径）
pkill -f "/data/adb/modules/steer/service.sh" 2>/dev/null
[ -n "$MODDIR" ] && pkill -f "$MODDIR/service.sh" 2>/dev/null

# 3) 若我们曾"接管"过平台的挂载点，把它原样还回去（守护若已死也能还原）
B=/data/adb/steer/steer
[ -x "$B" ] && "$B" restore  2>/dev/null
[ -x "$B" ] && "$B" tcclean  2>/dev/null   # TC 过滤器不会随进程消失，必须显式摘

# 4) 清 eBPF pin：只删我们创建的那几个文件，再删空目录
for m in policy cfg pending by_port stats; do
  [ -e "/sys/fs/bpf/steer/$m" ] && rm -f "/sys/fs/bpf/steer/$m" 2>/dev/null
done
[ -d /sys/fs/bpf/steer ] && rmdir /sys/fs/bpf/steer 2>/dev/null

echo "steer 已停止，eBPF 已解绑（进程退出后由内核自动 detach）。"
echo "配置与日志保留在 $BASE（含 cfg / policy / *.log）。"
echo "如需彻底清除，请手动执行: rm -rf $BASE"
