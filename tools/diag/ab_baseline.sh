#!/bin/bash
# A/B 对照：把「改前基线包」装回去，用与 coldfix2 完全相同的 AM 系统侧计时口径测 N 轮。
# 用法: bash _wk_diag/ab_baseline.sh <APK> <期望字节数> <标签> <轮数> <输出目录>
export PATH="/d/Android/AndoridSDK/platform-tools:$PATH"
APK="$1"; WANT="$2"; TAG="$3"; N="${4:-10}"; OUT="$5"
mkdir -p "$OUT"
A=com.zhuomogroup.ylyk/.module.login.splash.SplashActivity

echo "==== 安装 $TAG ===="
adb install -r "$APK" 2>&1 | tail -2
CP=$(adb shell "dumpsys package com.zhuomogroup.ylyk | grep -m1 codePath" 2>/dev/null | tr -d '\r' | sed 's/.*codePath=//')
GOT=$(adb shell "ls -l $CP/base.apk" 2>/dev/null | tr -d '\r' | awk '{print $5}')
echo "装机核验: base.apk=$GOT (期望 $WANT)"
[ "$GOT" != "$WANT" ] && { echo "!! 验包失败，数据不可用"; exit 1; }
adb shell "dumpsys package com.zhuomogroup.ylyk | grep versionName" 2>/dev/null | tr -d '\r' | head -1

echo "==== 热身 1 次 ===="
adb shell am force-stop com.zhuomogroup.ylyk; adb shell am start -W -n "$A" >/dev/null 2>&1
sleep 6

adb logcat -G 64M >/dev/null 2>&1
for i in $(seq 1 "$N"); do
  adb shell am force-stop com.zhuomogroup.ylyk; sleep 1
  adb logcat -c >/dev/null 2>&1
  adb shell am start -n "$A" >/dev/null 2>&1
  sleep 8
  adb logcat -d -v time > "$OUT/raw$i.log" 2>/dev/null
  T=$(grep -oE "total \+[0-9sm]+\)" "$OUT/raw$i.log" 2>/dev/null | tail -1 | tr -d ')')
  S=$(grep -c "bootShell: inject shell dex len=" "$OUT/raw$i.log" 2>/dev/null)
  echo "[$i/$N] $T   shellAttach=$S"
done
echo "==== $TAG 完成 ===="
