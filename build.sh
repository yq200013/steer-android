#!/bin/sh
# 构建 Steer（BPF + 用户态 + KernelSU 模块 zip）
#
# 顺序很重要：
#   1) 编译 BPF 对象 -> 2) 定版本 -> 3) 用 .o 的 hash 生成构建戳
#   -> 4) 用 (版本 + 戳) 编译用户态 -> 5) 自洽检查 -> 6) 权限 -> 打包
set -e
ROOT=$(cd "$(dirname "$0")" && pwd)
SRC=$ROOT/src
MOD=$ROOT/module
OUT=$ROOT/build
DIST=$ROOT/dist

INC="-I/usr/include/aarch64-linux-gnu"
[ -d /usr/include/x86_64-linux-gnu ] && INC="-I/usr/include/x86_64-linux-gnu"

rm -rf "$OUT" "$DIST"
mkdir -p "$OUT" "$MOD/bin" "$MOD/bpf" "$DIST"

echo "== 1/6 编译 eBPF 对象 =="
clang -target bpf -D__TARGET_ARCH_arm64 $INC -O2 -g -Wall \
      -c "$SRC/steer.bpf.c" -o "$OUT/steer.bpf.o"
ls -l "$OUT/steer.bpf.o"
cp "$OUT/steer.bpf.o" "$MOD/bpf/steer.bpf.o"

echo "== 2/6 版本（来自 module.prop）=="
PROP=$MOD/module.prop
if grep -q $'\r' "$PROP"; then echo "!! module.prop 含 CR，必须为 LF"; exit 1; fi
ID=$(sed -n 's/^id=//p' "$PROP")
case "$ID" in ''|*[!A-Za-z0-9._-]*) echo "!! id 非法: [$ID]"; exit 1;; esac
case "$ID" in [A-Za-z]*) ;; *) echo "!! id 必须以字母开头"; exit 1;; esac
grep -qE '^versionCode=[0-9]+$' "$PROP" || { echo "!! versionCode 必须是整数"; exit 1; }
for k in name version author description; do
  grep -qE "^$k=.+" "$PROP" || { echo "!! module.prop 缺少 $k"; exit 1; }
done
MVER=$(sed -n 's/^version=//p' "$PROP")
MVC=$(sed -n 's/^versionCode=//p' "$PROP")
echo "   id=$ID  version=$MVER  versionCode=$MVC"

echo "== 3/6 构建戳（防"二进制与 .o 不是同一次构建"）=="
BPF_HASH=$(sha256sum "$MOD/bpf/steer.bpf.o" | cut -d' ' -f1)
STAMP="${MVER}+${BPF_HASH%${BPF_HASH#????????????????}}"
echo "$STAMP" > "$MOD/bpf/steer.stamp"
echo "   stamp = $STAMP"

echo "== 4/6 编译用户态（注入 版本 + 构建戳，静态链接）=="
gcc -O2 -Wall -static -pthread $INC \
    -DSTEER_VERSION="\"steer $MVER (build $MVC)\"" \
    -DSTEER_STAMP="\"$STAMP\"" \
    -o "$OUT/steer" "$SRC/steer.c" -lbpf -lelf -lz -lzstd
file "$OUT/steer"
cp "$OUT/steer" "$MOD/bin/steer"

echo "== 5/6 自洽检查（BPF <-> 用户态）=="
python3 "$ROOT/tools/check_consistency.py"

echo "== 6/6 规范化权限 =="
chmod 0755 "$MOD"
chmod 0755 "$MOD/bin" "$MOD/bpf" "$MOD/webroot"
chmod 0755 "$MOD/customize.sh" "$MOD/service.sh" "$MOD/action.sh" "$MOD/uninstall.sh" "$MOD/bin/steer"
chmod 0644 "$MOD/module.prop" "$MOD/bpf/steer.bpf.o" "$MOD/bpf/steer.stamp" "$MOD/skip_mount"
find "$MOD/webroot" -type d -exec chmod 0755 {} \;
find "$MOD/webroot" -type f -exec chmod 0644 {} \;

echo "== 打包 =="
ZIP=$DIST/steer-$MVER.zip
rm -f "$ZIP"
cd "$MOD"
zip -qr "$ZIP" module.prop customize.sh service.sh action.sh uninstall.sh skip_mount bin bpf webroot
echo
unzip -Z -l "$ZIP"
echo
echo "产物: $ZIP"

