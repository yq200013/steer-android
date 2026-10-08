#!/system/bin/sh
# 开机自启 + watchdog。设计原则：宁可不用，也不能把机器搞坏。
MODDIR=${0%/*}
BASE=/data/adb/steer
LOG_MAX=1048576

mkdir -p "$BASE" 2>/dev/null
chmod 700 "$BASE" 2>/dev/null
rm -f "$BASE/stop" 2>/dev/null          # 清掉上次卸载留下的停止标记

# 临时文件 + rename：直接 cp 覆盖正在运行的二进制会 ETXTBSY
cp -f "$MODDIR/bin/steer"       "$BASE/steer.new"       2>/dev/null && mv -f "$BASE/steer.new" "$BASE/steer"
cp -f "$MODDIR/bpf/steer.bpf.o" "$BASE/steer.bpf.o.new" 2>/dev/null && mv -f "$BASE/steer.bpf.o.new" "$BASE/steer.bpf.o"
cp -f "$MODDIR/bpf/steer.stamp"  "$BASE/steer.stamp.new"  2>/dev/null && mv -f "$BASE/steer.stamp.new"  "$BASE/steer.stamp"
[ -x "$BASE/steer" ] || { echo "steer 二进制缺失" >> "$BASE/steer.log"; exit 1; }
chmod 0755 "$BASE/steer"

log()  { echo "$(date '+%m-%d %H:%M:%S') $*" >> "$BASE/steer.log" 2>/dev/null; }
rot()  { [ -f "$1" ] && [ "$(wc -c < "$1" 2>/dev/null || echo 0)" -gt $LOG_MAX ] && mv -f "$1" "$1.1" 2>/dev/null; return 0; }

start_once() {
  rot "$BASE/daemon.log"
  nohup "$BASE/steer" daemon >> "$BASE/daemon.log" 2>&1 &
}

# 等 SOCKS5 起来（最多 180s）。端口从 cfg 读，不硬编码
SP=$(sed -n 's/^socks_port=//p' "$BASE/cfg" 2>/dev/null | head -1)
[ -n "$SP" ] || SP=1180
i=0
while [ $i -lt 90 ]; do
  ss -tlnH 2>/dev/null | grep -qE ":$SP\\b" && break
  i=$((i + 1)); sleep 2
done
[ $i -ge 90 ] && log "等 SOCKS5(:$SP) 超时，仍继续启动（就绪前一律直连）"

start_once
log "service.sh: daemon launched"

# watchdog：模块被禁用/卸载就自杀；掉线才重拉；连续失败 5 次放弃（防无限重启）
(
  fails=0
  while true; do
    sleep 20

    if [ -f "$BASE/stop" ] || [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then
      log "watchdog: 模块被禁用/卸载，停止并退出"
      pkill -f "$BASE/steer daemon" 2>/dev/null
      exit 0
    fi

    rot "$BASE/daemon.log"

    if pgrep -f "$BASE/steer daemon" >/dev/null 2>&1; then
      fails=0
      continue
    fi

    fails=$((fails + 1))
    if [ $fails -ge 5 ]; then
      log "watchdog: 连续 $fails 次启动失败，停止重试（请查 $BASE/steer.log）"
      exit 0
    fi
    log "watchdog: 守护掉线，第 $fails 次重拉"
    start_once
    sleep 5
    pgrep -f "$BASE/steer daemon" >/dev/null 2>&1 && fails=0
  done
) &
