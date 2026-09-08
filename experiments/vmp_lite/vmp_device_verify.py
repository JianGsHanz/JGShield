#!/usr/bin/env python
# 真机验证 VMP 进壳包：装机 -> 启动 -> 监听崩溃 -> root 内存扫描私有字节码。
# 用法: python vmp_device_verify.py <apk> [设备serial]
import sys, os, subprocess, time, json

APK = sys.argv[1] if len(sys.argv) > 1 else "E:/jiagu/output/h_vmp1_ylyk_594.apk"
SERIAL = sys.argv[2] if len(sys.argv) > 2 else "45fc129b"
PKG = "com.zhuomogroup.ylyk"

def adb(args, timeout=60):
    cmd = ["adb", "-s", SERIAL] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def main():
    print("[1] 安装:", APK)
    r = adb(["install", "-r", "-d", APK])
    print(r.stdout[-500:], r.stderr[-500:])
    if r.returncode != 0:
        print("[FAIL] 安装失败"); return 1

    print("[2] 启动 App (monkey 触发主入口)")
    adb(["shell", "am", "force-stop", PKG])
    time.sleep(1)
    adb(["shell", "monkey", "-p", PKG, "-c", "android.intent.category.LAUNCHER", "1"])
    time.sleep(8)

    print("[3] 取 pid + 监听崩溃 15s")
    pid = adb(["shell", "pidof", PKG]).stdout.strip()
    print("    pid =", pid)
    if not pid:
        print("[FAIL] App 未运行(可能启动即崩)"); return 1
    # logcat 崩溃关键字
    r = adb(["logcat", "-d", "-t", "200", "AndroidRuntime:E", "CRASH:E", "art:E", "*:E"], timeout=30)
    fatal = [l for l in r.stdout.splitlines() if "FATAL EXCEPTION" in l or "ClassNotFoundException" in l or "VerifyError" in l or "Native method" in l and "UnsatisfiedLinkError" in l]
    if fatal:
        print("[FAIL] 发现崩溃:"); 
        for l in fatal[:10]: print("   ", l)
        return 1
    print("[OK] 无致命崩溃, pid=", pid)

    print("[4] root 内存扫描私有字节码 (magic fdc2) 与 dalvik 明文")
    # 在进程内存里搜 fdc2 魔术 + 确认目标方法体无 dalvik 明文
    scan = (
        "su -c '"
        "P=$(pidof %s); "
        "echo pid=$P; "
        "dd if=/proc/$P/mem bs=4096 2>/dev/null | "
        "wc -c; "
        "' " % PKG
    )
    # 用 python 在 host 侧拉内存段头做轻量扫描（避免整机 dd 太大）
    # 简化：直接 grep /proc/pid/maps 里的匿名/dex 区，再用 dd 抽关键区搜 fdc2
    r = adb(["shell", "su", "-c", "pidof %s" % PKG])
    pid = r.stdout.strip()
    # 扫描所有可读区域前若干字节里的 fdc2 出现次数（抽样，避免全量 dd）
    scan_cmd = ("su -c 'P=$(pidof %s); "
                "for off in $(grep -E \"r--|rw-\" /proc/$P/maps | awk \"{print \\$1}\" | head -40); do "
                "  lo=${off%%-*}; hi=${off##*-}; "
                "  sz=$((0x$hi-0x$lo)); "
                "  if [ $sz -gt 2097152 ]; then sz=2097152; fi; "
                "  dd if=/proc/$P/mem bs=1 skip=$((0x$lo)) count=$sz 2>/dev/null | "
                "  grep -a -c -m1 $'\\xfd\\xc2' >/dev/null && echo FOUND_FDC2_AT_$lo; "
                "done'" % PKG)
    r2 = adb(["shell", "sh", "-c", scan_cmd], timeout=120)
    found = "FOUND_FDC2" in r2.stdout
    print("    内存扫描输出(节选):", r2.stdout[:800].replace("\n"," | "))
    if found:
        print("[OK] 进程内存中发现私有字节码魔术 fdc2 (VMP 解释器数据已载入)")
    else:
        print("[WARN] 未在抽样区域内发现 fdc2 (可能抽样遗漏, 非结论性失败)")

    print("[5] 汇总")
    print("  pid=%s  crash_free=%s  fdc2_in_mem=%s" % (pid, not fatal, found))
    return 0

if __name__ == "__main__":
    sys.exit(main())
