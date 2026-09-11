# -*- coding: utf-8 -*-
"""冷启动分段计时分析：从 logcat dump 里还原壳引导各阶段耗时。
用法: python boot_timeline.py <logcat文件> [pid]
不带 pid 时自动取日志里出现 bootShell 的那个 pid。
"""
import re, sys, io
from collections import OrderedDict

MARKERS = OrderedDict([
    ("Start proc",              r"Start proc (\d+):"),
    ("markOwnDex",              r"markOwnDex: own shell dex"),
    ("inject shell dex",        r"bootShell: inject shell dex len="),
    ("native guard loaded",     r"native guard loaded"),
    ("response mode",           r"response mode -> native"),
    ("batch-restore 完成",       r"P3.4 load batch-restore dex_idx=\d+"),
    ("method restore mode",     r"method restore effective mode="),
    ("dex-region-writable",     r"dex-region-writable: done"),
    ("header 自检跳过(SHA-1)",   r"dex header already consistent"),
    ("integrity 校验完",         r"integrity dex_idx=\d+"),
    ("anti-dump scramble",      r"anti-dump v3: dex de-structured"),
    ("scramble 汇总",            r"anti-dump v3: processed \d+ dex"),
    ("fileless inject OK",      r"load: fileless inject OK"),
    ("injectDexElements OK",    r"load: injectDexElements OK"),
    ("origApp",                 r"load: origApp="),
    ("swap OK",                 r"load: swap OK"),
    ("realApp.onCreate OK",     r"load: realApp.onCreate\(\) OK"),
    ("onCreate OK(GX-BT)",      r"onCreate: realApp.onCreate\(\) OK"),
    ("Displayed",               r"Displayed .*SplashActivity: \+(\d+)ms"),
])


def tms(line):
    m = re.match(r"(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d\d\d)", line)
    if not m:
        return None
    return (((int(m.group(3)) * 60 + int(m.group(4))) * 60 + int(m.group(5))) * 1000
            + int(m.group(6)))


def main():
    path = sys.argv[1]
    want = sys.argv[2] if len(sys.argv) > 2 else None
    lines = io.open(path, encoding="utf-8", errors="replace").read().splitlines()

    if want is None:
        for l in lines:
            if "bootShell: inject shell dex len=" in l:
                m = re.search(r"\(\s*(\d+)\)", l)
                if m:
                    want = m.group(1)
                    break
    if want is None:
        print("找不到 shell 进程 pid")
        return
    print("=== 壳进程 pid=%s 冷启动分段 ===" % want)

    rows = []
    seen = set()
    # 2026-09-11 修 bug：logcat 的 pid 字段是【右对齐】的，4 位 pid 会写成 "( 4141)"
    # 而 5 位写成 "(21825)"。原先按 "(pid)" 精确子串匹配 ⇒ 4/3 位 pid 一律匹不上
    # （表现为 "无匹配标记"）。改用正则容忍括号内空白。
    pat_pid = re.compile(r"\(\s*%s\s*\)" % want)
    for l in lines:
        if not pat_pid.search(l):
            continue
        for name, pat in MARKERS.items():
            if name in seen and name not in ("anti-dump scramble",):
                continue
            if re.search(pat, l):
                t = tms(l)
                if t is None:
                    continue
                extra = ""
                if name == "anti-dump scramble":
                    mm = re.search(r"len=(\d+)", l)
                    extra = " len=%s" % mm.group(1) if mm else ""
                if name not in ("anti-dump scramble",):
                    seen.add(name)
                rows.append((t, name + extra))
                break

    rows.sort(key=lambda x: x[0])
    if not rows:
        print("无匹配标记")
        return
    t0 = rows[0][0]
    prev = None
    total = 0
    for t, name in rows:
        d = "" if prev is None else "  +%dms" % (t - prev)
        prev = t
        total = t - t0
        print("%6dms  %s%s" % (t - t0, name, d))
    print("---- 从 Start proc 到最后一个标记: %dms ----" % total)


main()
