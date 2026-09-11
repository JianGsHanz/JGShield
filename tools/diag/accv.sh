#!/bin/bash
# VMP 对照包冷启动验收（2026-09-10 18:12）
# 基于 _acc.sh，补上「每轮验包」（0907 事故铁律：装错包必须当轮作废）。
#   验包三重：① base.apk 字节数 == 期望  ② versionName  ③ 本轮有壳日志
# 另加 VMP 专项：VMP 失败可能是"静默算错"不崩 -> 额外统计虚拟化方法被调用痕迹。
PKG=com.zhuomogroup.ylyk
ACT=$PKG/.module.login.splash.SplashActivity
N=${1:-15}
OUT=${2:-/tmp/accv}
EXPECT_SIZE=${3:-71694737}          # h_fix16_vmp.apk 字节数
EXPECT_LABEL=${4:-h_fix16_vmp}
rm -rf $OUT; mkdir -p $OUT
pass=0; shell_fail=0; native=0; jdwp=0; noboot=0; noshell=0; wrongpkg=0

# adb shell 不展开通配符 -> 用 dumpsys 的 codePath 定位 base.apk
apk_size() {
    local cp
    cp=$(timeout 25 adb shell "dumpsys package $PKG | grep -m1 codePath" 2>/dev/null \
         | tr -d '\r' | sed 's/.*codePath=//')
    [ -z "$cp" ] && { echo ""; return; }
    timeout 25 adb shell "ls -l $cp/base.apk" 2>/dev/null | tr -d '\r' | awk '{print $5}'
}

# 每轮开跑前先验一次包身份（装错后续全废）
CK=$(apk_size)
VN=$(timeout 25 adb shell "dumpsys package $PKG | grep versionName" | tr -d '\r' | sed 's/.*versionName=//' | head -1)
echo "==== 装机核验: base.apk=$CK (期望 $EXPECT_SIZE)  versionName=$VN  样本=$EXPECT_LABEL ===="
if [ "$CK" != "$EXPECT_SIZE" ]; then
    echo "!!!! 装机包大小不匹配，拒绝开跑（先 adb install -r 正确样本）"
    exit 2
fi

for i in $(seq 1 $N); do
    timeout 20 adb shell am force-stop $PKG >/dev/null 2>&1
    for w in $(seq 1 20); do
        P=$(timeout 15 adb shell pidof $PKG 2>/dev/null | tr -d '\r')
        [ -z "$P" ] && break
        sleep 0.5
    done
    timeout 15 adb logcat -c >/dev/null 2>&1
    timeout 20 adb shell am start -n $ACT >/dev/null 2>&1
    sleep 24
    timeout 25 adb logcat -d > $OUT/raw$i.log 2>/dev/null
    # 锚点不写死 shell tag（P7 起 tag 随机化，如 GX-BT / t48Ahk），
    # 只认 "xxx: bootShell" 这一 bootShell 事件本身。
    P=$(grep -oE "^[0-9-]+ [0-9:.]+ +[0-9]+ +[0-9]+ [A-Z] [A-Za-z0-9_.-]+ +: bootShell" $OUT/raw$i.log \
        | head -1 | awk '{print $3}')
    if [ -n "$P" ]; then
        grep " $P " $OUT/raw$i.log > $OUT/run$i.log
    else
        # 锚点缺失（logcat 环形缓冲冲掉 bootShell 行）时：
        # 按包名/进程号兜底，避免把「已启动成功」误判成 NOSHELL。
        P=$(timeout 15 adb shell pidof $PKG 2>/dev/null | tr -d '\r' | awk '{print $1}')
        if [ -n "$P" ] && grep -q " $P " $OUT/raw$i.log; then
            grep " $P " $OUT/raw$i.log > $OUT/run$i.log
            echo "  [warn] run$i: bootShell 行缺失，已用 pid=$P 兜底切分" >> $OUT/harness_warn.txt
        else
            : > $OUT/run$i.log
        fi
    fi
    SFL=$(grep -c "GX bootstrap failed" $OUT/run$i.log)
    FL=$(grep -c "Fatal signal" $OUT/run$i.log)
    JD=$(grep -cE "ADB-JDWP|adbconnection|DdmHandleHello" $OUT/run$i.log)
    DISP=$(grep -ciE "Displayed com.zhuomogroup.ylyk" $OUT/raw$i.log)
    SHELL=$(grep -c "bootShell: inject shell" $OUT/run$i.log)
    ATT=$(grep -c "load: attach OK" $OUT/run$i.log)
    # VMP 专项：VMP 虚拟化方法执行路径的日志（解释器/shim 若打印）
    VMPLOG=$(grep -ciE "vmp" $OUT/run$i.log)
    # 每轮验包：本轮 base.apk 大小（防中途换包）
    RS=$(apk_size)
    if [ "$SHELL" = "0" ]; then
        if [ "$RS" != "$EXPECT_SIZE" ]; then
            wrongpkg=$((wrongpkg+1)); st=WRONGPKG
        else
            noshell=$((noshell+1)); st=NOSHELL
        fi
    elif [ "$FL" != "0" ] && [ "$JD" != "0" ]; then
        jdwp=$((jdwp+1)); st=JDWP
    elif [ "$SFL" != "0" ]; then
        shell_fail=$((shell_fail+1)); st=SHELL_FAIL
    elif [ "$FL" != "0" ]; then
        native=$((native+1)); st=NATIVE
    elif [ "$ATT" != "0" ] && [ "$DISP" -ge 1 ]; then
        pass=$((pass+1)); st=OK
    else
        noboot=$((noboot+1)); st=NOBOOT
    fi
    printf "[%2d/%d] %-10s shellAttach=%s booted=%s vmpLog=%s pid=[%s]\n" \
        $i $N $st "$ATT" "$DISP" "$VMPLOG" "${P:-none}"
done

echo "==================== 汇总（$EXPECT_LABEL）===================="
echo "PASS=$pass  SHELL_FAIL=$shell_fail  NATIVE=$native  JDWP=$jdwp  NOBOOT=$noboot  NOSHELL=$noshell  WRONGPKG=$wrongpkg  (总 $N)"
printf "PASS=%s SHELL_FAIL=%s NATIVE=%s JDWP=%s NOBOOT=%s NOSHELL=%s WRONGPKG=%s N=%s\n" \
    $pass $shell_fail $native $jdwp $noboot $noshell $wrongpkg $N > $OUT/summary.txt
[ "$noshell" != "0" ] && echo "!! NOSHELL=$noshell 壳没执行，数据不可用"
[ "$wrongpkg" != "0" ] && echo "!! WRONGPKG=$wrongpkg 中途换包，数据不可用"
echo "--- 非 OK 的 run 及致命行 ---"
for i in $(seq 1 $N); do
    f=$OUT/run$i.log
    [ -f "$f" ] || continue
    if grep -q "GX bootstrap failed" $f; then
        echo "[run$i SHELL_FAIL] $(grep -m1 -oE 'GX bootstrap failed: [^ ]+.*' $f | head -c 160)"
    fi
    if grep -q "Fatal signal" $f; then
        echo "[run$i NATIVE] $(grep -m1 'Fatal signal' $f | sed 's/^[0-9-]* [0-9:.]* //' | head -c 200)"
    fi
done
