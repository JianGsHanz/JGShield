"""开发期一次性脚本：用 androguard 编译 4 个白名单方法的私有字节码，
恢复其 canonical（未 XOR key 的）形式，输出可写入 vmp_protect.py 的常量。
运行时不再需要 androguard —— 只需用 per-build key 重新 XOR 包裹即可。"""
import os, zipfile, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE))
sys.path.insert(0, ROOT)
import vmp_protect as V
from vmp_from_dex import compile_method

APK = os.environ.get("VMP_APK", "D:/APK/ylyk_5.9.4/app-Ptest-5.9.4-2026-08-04.apk")
z = zipfile.ZipFile(APK)
names = sorted(n for n in z.namelist() if n.endswith(".dex") and b"zhuomogroup" in z.read(n))
orig = [z.read(n) for n in names]

tg = V.discover_targets(names, orig)
print("发现目标数:", len(tg))
# 用与历史一致的 per-method key 编译（仅用于恢复 canonical code）
KEYS = [0x5d, 0x53, 0xc0, 0x58]

out = {}
for i, t in enumerate(tg):
    blob, _m, preg = compile_method(t["cls"], t["name"], t["desc"], xor_key=KEYS[i], method=t["method"])
    key = blob[2]
    xored = blob[3:]
    canonical = bytes(b ^ key for b in xored)
    out[(t["cls"], t["name"], t["desc"])] = (canonical.hex(), preg, len(canonical))
    print("  %s.%s%s  param_reg=%d  canonical_len=%d  canonical_hex=%s"
          % (t["cls"], t["name"], t["desc"], preg, len(canonical), canonical.hex()))

# 输出可粘贴的常量
print("\n===== PRECOMPILED_VMP 常量（粘贴到 vmp_protect.py）=====")
lines = ["PRECOMPILED_VMP = {"]
for (cls, name, desc), (chex, preg, clen) in out.items():
    lines.append("    (%r, %r, %r): {\"code\": bytes.fromhex(%r), \"param_reg\": %d},"
                 % (cls, name, desc, chex, preg))
lines.append("}")
print("\n".join(lines))
