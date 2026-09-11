#!/usr/bin/env bash
# 通用冷启动 A/B：安装 → 热身 → N 轮冷启动（Displayed） → meminfo → oat 目录
# 用法: ab_pkg.sh <apk> <label> [N]
set -u
export PATH="/d/Android/AndoridSDK/platform-tools:$PATH"
PKG=com.zhuomogroup.ylyk
APK="$1"; LABEL="$2"; N="${3:-6}"
OUT="/tmp/ab_${LABEL}"; mkdir -p "$OUT"
RE='Displayed com\.zhuomogroup\.ylyk/[^ ]*: \+[0-9sm]+( \(total \+[0-9sm]+\))?'
say(){ echo "[$(date +%H:%M:%S)] $*"; }

say "安装 $LABEL"
adb install -r "$APK" 2>&1 | tail -1
CP=$(adb shell "dumpsys package $PKG | grep -m1 codePath" 2>/dev/null | tr -d '\r' | sed 's/.*codePath=//')
echo -n "  base.apk="; adb shell "ls -l $CP/base.apk" 2>/dev/null | tr -d '\r' | awk '{print $5}'
A=$(adb shell cmd package resolve-activity --brief $PKG 2>/dev/null | tr -d '\r' | tail -1)
say "launcher=$A"
say "安装后 oat/arm64:"; adb shell "su -c 'ls -l $CP/oat/arm64/ 2>/dev/null'" 2>/dev/null | tr -d '\r' | sed 's/^/    /'

boot(){ # $1 tag
  adb shell am force-stop $PKG; sleep 1
  adb logcat -c 2>/dev/null
  adb shell am start -n "$A" >/dev/null 2>&1
  sleep 9
  adb logcat -d -v time > "$OUT/$1.log" 2>/dev/null
  grep -oE "$RE" "$OUT/$1.log" | head -1
}

say "热身"; boot warmup; sleep 2
say "=== 冷启动 x$N ==="
for i in $(seq 1 $N); do echo "  run$i: $(boot run$i)"; done

say "=== dumpsys meminfo ==="
adb shell "dumpsys meminfo $PKG" 2>/dev/null | tr -d '\r' | sed -n '/MEMINFO in pid/,/TOTAL/p' | head -26
say "=== 运行后 oat/arm64 ==="; adb shell "su -c 'ls -l $CP/oat/arm64/ 2>/dev/null'" 2>/dev/null | tr -d '\r' | sed 's/^/    /'
say "DONE $LABEL -> $OUT"
