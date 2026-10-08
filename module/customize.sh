#!/system/bin/sh
# KernelSU 安装脚本
SKIPMOUNT=true
PROPFILE=false
POSTFSDATA=false
LATESTARTSERVICE=true

ui_print() { echo "$1"; }

[ "$ARCH" = "arm64" ] || abort "仅支持 arm64（当前 $ARCH）"

for f in bin/steer bpf/steer.bpf.o; do
  [ -f "$MODPATH/$f" ] || abort "缺少 $f"
  set_perm "$MODPATH/$f" 0 0 0755
done
set_perm "$MODPATH/service.sh"   0 0 0755
set_perm "$MODPATH/action.sh"    0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755

mkdir -p /data/adb/steer
chmod 700 /data/adb/steer

# 立刻把可执行文件与 BPF 对象放到位。
# 注意：**不能直接 cp 覆盖正在运行的二进制**——Linux 会返回 ETXTBSY，旧代码就留在原地了。
# 所以走"临时文件 + rename"（rename 可以替换正在运行的文件）。
install_file() {
  # $1 源  $2 目标  $3 权限
  if ! cp -f "$1" "$2.new"; then
    ui_print "!! 复制 $1 失败"
    return 1
  fi
  chmod "$3" "$2.new" 2>/dev/null
  if ! mv -f "$2.new" "$2"; then
    ui_print "!! 落地 $2 失败"
    rm -f "$2.new"
    return 1
  fi
  return 0
}
install_file "$MODPATH/bin/steer"       /data/adb/steer/steer       0755
install_file "$MODPATH/bpf/steer.bpf.o" /data/adb/steer/steer.bpf.o 0644
install_file "$MODPATH/bpf/steer.stamp"  /data/adb/steer/steer.stamp  0644

# 安装完立刻校验版本，避免"模块显示新版、实际跑旧版"
if [ -x /data/adb/steer/steer ]; then
  ui_print "- 已就位: $(/data/adb/steer/steer version 2>/dev/null || echo '(无法执行)')"
fi

if [ ! -f /data/adb/steer/cfg ]; then
  cat > /data/adb/steer/cfg <<'EOF'
socks_host=127.0.0.1
socks_port=1180
socks_user=
socks_pass=
relay_port=25200
default_mode=direct
flags=1
enabled=1
takeover=1
udp=1
relay_udp_port=25201
redirect_flags=0
EOF
  chmod 600 /data/adb/steer/cfg
fi

ui_print "- 已安装。重启后在 KernelSU 管理器里打开本模块的 WebUI 面板。"
ui_print "- 面板里选应用 -> 即时生效；默认策略保持 direct 即“只代理选中的应用”。"
ui_print "- 注意：webroot 的权限由 KernelSU 自动设置，请勿手动改。"
