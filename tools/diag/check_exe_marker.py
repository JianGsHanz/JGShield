#!/usr/bin/env python3
# 判别加固产物是否由"新 exe"(含 anti-dump v3 own-dex 跳过修复 + jg_noptrace 旁路)编出。
# 用法: python check_exe_marker.py <加固后的.apk> [更多.apk ...]
# 判定: 壳 .so 含 jg_noptrace / markOwnDex ... will be skipped / anti-dump v3:  -> 新 exe
#       全无 -> 旧 exe (崩溃包的来历)
import zipfile, sys

MARKERS = [b"jg_noptrace",
           b"markOwnDex",
           b"will be skipped",
           b"anti-dump v3:"]

def check(apk):
    try:
        z = zipfile.ZipFile(apk)
    except Exception as e:
        print(f"[FAIL] {apk}: 打开失败 {e}")
        return
    sos = [n for n in z.namelist()
           if n.startswith("lib/arm64-v8a/") and n.endswith(".so")]
    found = set()
    shell = None
    for s in sos:
        d = z.read(s)
        for m in MARKERS:
            if m in d:
                found.add(m)
                shell = s
    if found:
        print(f"[NEW-EXE] {apk}")
        print(f"   壳 .so = {shell}")
        print(f"   命中标记: {[x.decode() for x in found]}")
    else:
        print(f"[OLD-EXE ] {apk}  <- 壳 .so 无新标记，是旧 exe 产物（会崩的那个出处）")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python check_exe_marker.py <apk> [apk...]")
        sys.exit(1)
    for a in sys.argv[1:]:
        check(a)
