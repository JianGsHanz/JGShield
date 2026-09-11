#!/usr/bin/env bash
# 同口径 A/B：对任意 ylyk 包做"安装 → 首启 → 复启 N 次"的冷启动测量，
# 并记录 oat 目录 / 数据目录里的落地 dex，用于对比 梆梆(SecShell) vs JGShield。
#
# 用法: ab_bangcle.sh <apk> <mode_label> [N]
set -u
export PATH="/d/Android/AndoridSDK/platform-tools:$PATH"
PKG=com.zhuomogroup.ylyk
APK="$1"; LABEL="$2"; N="${3:-5}"
OUT="/tmp/ab_${LABEL}"; mkdir -p "$OUT"

say() { echo "[$(date +%H:%M:%S)] $*"; }

act() { adb shell cmd package resolve-activity --brief "$PKG" 2>/dev/null | tr -d '\r' | tail -1; }

measure() { # $1 = tag  -> 取 AM 系统侧 Displayed total
  adb logcat -c 2>/dev/null
  adb shell am start -n "$A" >/dev/null 2>&1
  sleep 9
  adb logcat -d -v time > "$OUT/$1.log" 2>/dev/null
  V=$(grep -oE "Displayed ${PKG}/[^ ]*: \+[0-9]+ms \(total \+[0-9sm]+\)" "$OUT/$1.log" | tail -1)
  echo "${V:-<无 Displayed 行>}"
}

say "安装 $APK"
adb install -r "$APK" 2>&1 | tail -2

CP=$(adb shell "dumpsys package $PKG | grep -m1 codePath" 2>/dev/null | tr -d '\r' | sed 's/.*codePath=//')
say "codePath=$CP"
echo -n "  base.apk 字节 = "; adb shell "ls -l $CP/base.apk" 2>/dev/null | tr -d '\r' | awk '{print $5}'
adb shell "dumpsys package $PKG | grep versionName" 2>/dev/null | tr -d '\r' | head -1

A=$(act); say "launcher=$A"

echo; say "=== 安装后、首启前的 oat 目录 ==="
adb shell "su -c 'ls -l $CP/oat/arm64/ 2>/dev/null'" 2>/dev/null | tr -d '\r'

# 先热身一次（消除安装期 dexopt 抖动），再测首启
say "热身 1 次"
adb shell am force-stop $PKG; A="$A" measure warmup >/dev/null 2>&1
sleep 3

say "=== 冷启动 x$N ==="
for i in $(seq 1 "$N"); do
  adb shell am force-stop $PKG; sleep 1
  T=$(measure "run$i")
  SHA=$(adb shell "su -c 'sha1sum $CP/base.apk'" 2>/dev/null | tr -d '\r' | awk '{print substr($1,1,12)}')
  echo "  run$i: $T   [apk sha1=${SHA:-?}]"
done

echo; say "=== 运行后 oat 目录 ==="
adb shell "su -c 'ls -l $CP/oat/arm64/ 2>/dev/null'" 2>/dev/null | tr -d '\r'

echo; say "=== 数据目录里落地的 dex/odex/oat/vdex ==="
adb shell "su -c 'find /data/data/$PKG -name \"*.dex\" -o -name \"*.odex\" -o -name \"*.vdex\" -o -name \"*.oat\" -o -name \"*.jar\" 2>/dev/null | head -20'" 2>/dev/null | tr -d '\r'

echo; say "=== 数据目录顶层（看壳的私有目录名）==="
adb shell "su -c 'ls -la /data/data/$PKG/ 2>/dev/null'" 2>/dev/null | tr -d '\r' | head -25

echo; say "=== files/ 与 cache/ 下 >256KB 的文件 ==="
adb shell "su -c 'find /data/data/$PKG/files /data/data/$PKG/cache -type f -size +256k 2>/dev/null | head -20'" 2>/dev/null | tr -d '\r'

say "DONE label=$LABEL out=$OUT"
