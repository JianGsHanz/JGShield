# -*- coding: utf-8 -*-
"""
device_check.py —— 在真实设备/模拟器上验证加固 APK 运行期无闪退。

步骤：
  adb install -r  ->  am start 启动 Launcher Activity
  -> sleep 等待  ->  检查是否成为前台(resumed) Activity
  -> 抓取 logcat 检测 FATAL EXCEPTION / AndroidRuntime 崩溃
  -> 卸载（保持环境干净）
返回 PASS / FAIL。
"""
import os
import sys
import time
import argparse
import subprocess

import config
from config import _decode_bytes

# 使检测端的 shell TAG 与本次加固产物一致（build/stamp.json）
config.apply_stamp_from_file()
import stamp as _stamp

ADB = config.ADB

def adb(target, *args, check=True):
    cmd = [ADB, "-s", target] + list(args)
    # 外部工具按系统代码页(GBK)输出，读字节后用 _decode_bytes 容错解码，避免中文乱码
    r = subprocess.run(cmd, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError("adb %s failed rc=%d" % (args[0], r.returncode))
    r.stdout = _decode_bytes(r.stdout or b"")
    r.stderr = _decode_bytes(r.stderr or b"")
    return r

def get_pkg_launch(apk):
    r = subprocess.run([config.AAPT, "dump", "badging", apk],
                       capture_output=True)
    p = type("R", (), {})()
    p.stdout = _decode_bytes(r.stdout or b"")
    pkg = launch = None
    for line in (p.stdout or "").splitlines():
        if line.startswith("package:"):
            # package: name='com.x' ...
            import re
            m = re.search(r"name='([^']+)'", line)
            if m:
                pkg = m.group(1)
        elif line.startswith("launchable-activity:") or line.startswith("launchable activity"):
            # 兼容新版(连字符)与旧版(空格) aapt 输出
            import re
            m = re.search(r"name='([^']+)'", line)
            if m:
                launch = m.group(1)
    return pkg, launch

def wake_device(target):
    """唤醒设备并保持屏幕常亮，避免锁屏导致前台检测误判。"""
    for ke in ("224", "82"):  # KEYCODE_WAKEUP, MENU
        adb(target, "shell", "input", "keyevent", ke, check=False)
    adb(target, "shell", "svc", "power", "stayon", "true", check=False)
    adb(target, "shell", "settings", "put", "system",
        "screen_off_timeout", "600000", check=False)
    adb(target, "shell", "wm", "dismiss-keyguard", check=False)
    time.sleep(1)

def check(apk, target, keep=False):
    apk = os.path.abspath(apk)
    pkg, launch = get_pkg_launch(apk)
    if not pkg or not launch:
        return False, "无法解析包名/启动 Activity (pkg=%s launch=%s)" % (pkg, launch)
    print("  包名:", pkg, " 启动:", launch)

    # 0) 唤醒设备，避免锁屏导致 resumed 误判
    wake_device(target)

    # 1) 安装
    adb(target, "install", "-r", "-t", apk)
    # 2) 清 logcat
    adb(target, "logcat", "-c")
    # 3) 启动
    r = adb(target, "shell", "am", "start", "-n", "%s/%s" % (pkg, launch))
    if "Error" in (r.stdout or "") or "Starting" not in (r.stdout or ""):
        # 尝试用 pkg/.MainActivity
        r2 = adb(target, "shell", "am", "start", pkg)
        if "Error" in (r2.stdout or "") and "Starting" not in (r2.stdout or ""):
            return False, "am start 失败: " + (r.stdout or r.stderr or "")
    time.sleep(5)
    # 4) 是否前台 resumed
    d = adb(target, "shell", "dumpsys", "activity", "activities")
    resumed = ("mResumedActivity" in d.stdout and pkg in d.stdout) or \
              ("mFocusedActivity" in d.stdout and pkg in d.stdout)
    # 5) 崩溃检测
    lc = adb(target, "logcat", "-d")
    logs = lc.stdout or ""
    crash = ("FATAL EXCEPTION" in logs) or ("AndroidRuntime: Crash" in logs) or \
            ("Process: %s" % pkg in logs and "has died" in logs)
    # 收集与本包相关日志
    pkg_logs = "\n".join([l for l in logs.splitlines() if pkg in l][:40])

    # 收集壳自身日志（按本次随机化 TAG，确认加固链路跑通）
    _st = _stamp.load()
    _tag = (_st["tag_app"] if _st else "GX")
    shell_logs = "\n".join([l for l in logs.splitlines()
                             if _tag in l or "method restore" in l
                             or "integrity" in l or "native guard" in l
                             or "fileless" in l or "realApp" in l][:40])

    ok = resumed and not crash
    detail = "resumed=%s crash=%s" % (resumed, crash)
    if pkg_logs.strip():
        detail += "\n    [相关日志]\n    " + "\n    ".join(pkg_logs.splitlines()[:20])
    if shell_logs.strip():
        detail += "\n    [壳日志 TAG=%s]\n    " % _tag + "\n    ".join(shell_logs.splitlines()[:30])
    if not keep:
        try:
            adb(target, "uninstall", pkg)
        except Exception:
            pass
    return ok, detail

def main():
    ap = argparse.ArgumentParser(description="设备/模拟器运行期验证")
    ap.add_argument("apk")
    ap.add_argument("--target", default="emulator-5554")
    ap.add_argument("--keep", action="store_true", help="不卸载")
    args = ap.parse_args()
    try:
        ok, detail = check(args.apk, args.target, args.keep)
    except Exception as e:
        print("FAIL:", e)
        sys.exit(1)
    print("[%s] %s" % ("PASS" if ok else "FAIL", detail))
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
