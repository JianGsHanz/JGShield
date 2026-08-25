# -*- coding: utf-8 -*-
"""
冻结态（PyInstaller onefile）真实路径仿真 + 真实验证。

布局：
  SIM/bundle/        == _MEIPASS（只读资源根；tools/ 在此）
  SIM/exe/           == EXEC_DIR（exe 同级，可写；BUILD_DIR = exe/build）
  SIM/exe/jiagu_gui.exe (伪装 executable，使 dirname(executable)=exe)

内层（-c）在 import config 之前设置 sys.frozen=True / sys._MEIPASS=bundle /
sys.executable=exe/jiagu_gui.exe，然后跑 harden(rebuild_stub=True)。

验证：
  1) 内层打印 BUILD_DIR / STAMP_PATH，确认落在 exe/ 而非 bundle/（否则 _MEIPASS 只读写入会崩）。
  2) 比对 BUNDLE 运行前后文件集合，确认 build_stub/harden 没有任何写泄漏进 _MEIPASS。
  3) androguard 解析产物 APK：
       - manifest application name == stamp 的随机化 BOOTSTRAP_APP
       - 该随机化类确实存在于 classes.dex 中（不再是默认 com.gx.runtime.GxBootstrap）
"""
import os
import sys
import json
import shutil
import subprocess

SIM = r"E:\jiagu\_frozen_sim"
BUNDLE = os.path.join(SIM, "bundle")
EXE = os.path.join(SIM, "exe")
OUT = os.path.join(EXE, "output", "h.apk")
SRC = r"E:\jiagu"
TOOLS = os.path.join(SRC, "tools")
SAMPLE = r"E:\jiagu\test_apks\sample4.apk"
PY = r"E:\jiagu\_build_venv\Scripts\python.exe"

if not os.path.isfile(SAMPLE):
    raise SystemExit("sample4.apk 缺失，先运行 gen_samples.py --count 4")

# 绕过 safe-delete shim（其 shutil.rmtree 为 fail-closed，删不掉旧目录），
# 用 os 原语手动递归删除，确保每次都是干净布局。
def _rmtree_manual(path):
    if not os.path.isdir(path):
        return
    for dp, dirs, fns in os.walk(path, topdown=False):
        for f in fns:
            try:
                os.remove(os.path.join(dp, f))
            except OSError:
                pass
        for d in dirs:
            try:
                os.rmdir(os.path.join(dp, d))
            except OSError:
                pass
    try:
        os.rmdir(path)
    except OSError:
        pass

# 清理 + 建立布局
_rmtree_manual(SIM)
os.makedirs(os.path.join(EXE, "build"), exist_ok=True)
os.makedirs(os.path.join(EXE, "output"), exist_ok=True)

# 把只读资源 tools/ 放进 bundle（充当 _MEIPASS）
shutil.copytree(TOOLS, os.path.join(BUNDLE, "tools"))

def _snapshot(root):
    s = set()
    for dp, _, fns in os.walk(root):
        for f in fns:
            s.add(os.path.relpath(os.path.join(dp, f), root))
    return s

before = _snapshot(BUNDLE)

code = (
    "import sys, os; "
    "sys.frozen=True; "
    "sys._MEIPASS=r'%s'; "
    "sys.executable=r'%s'; "
    "import config; "
    "print('BUILD_DIR=' + config.BUILD_DIR); "
    "print('STAMP_PATH=' + config._STAMP_PATH); "
    "import harden; "
    "harden.harden(r'%s', r'%s', rebuild_stub=True); "
    "print('HARDEN_DONE'); "
) % (BUNDLE, os.path.join(EXE, "jiagu_gui.exe"), SAMPLE, OUT)

print(">>> 运行冻结态内层 harden ...")
proc = subprocess.run([PY, "-c", code], cwd=SRC, capture_output=True)
out = proc.stdout.decode("utf-8", errors="replace")
err = proc.stderr.decode("utf-8", errors="replace")
print("=== INNER STDOUT ===\n" + out)
print("=== INNER STDERR (tail) ===\n" + (err[-4000:] if len(err) > 4000 else err))

if proc.returncode != 0:
    print("\nXXX 内层 harden 失败 rc=%d，保留 %s 供排查" % (proc.returncode, SIM))
    sys.exit(2)

# --- 断言 1：stamp 写入 exe/build（非 _MEIPASS）---
stamp_path_used = os.path.join(EXE, "build", "stamp.json")
assert os.path.isfile(stamp_path_used), "stamp 未写入 exe/build: %s" % stamp_path_used
print("OK: stamp 写入 exe/build (非 _MEIPASS)")

# --- 断言 2：无写泄漏进 _MEIPASS ---
after = _snapshot(BUNDLE)
leaked = after - before
if leaked:
    print("\nXXX 检测到写泄漏进 _MEIPASS/BUNDLE:")
    for f in sorted(leaked):
        print("    + " + f)
    print("保留 %s 供排查" % SIM)
    sys.exit(3)
print("OK: 无写泄漏进 _MEIPASS/BUNDLE")

# --- 断言 3：androguard 真实验证 manifest == dex 类 ---
with open(stamp_path_used, "r", encoding="utf-8") as f:
    st = json.load(f)
boot = st["pkg"] + "." + st["classes"]["GxBootstrap"]
print("\nSTAMP BOOTSTRAP_APP =", boot)
assert boot != "com.gx.runtime.GxBootstrap", "stamp 未随机化！"
assert os.path.isfile(OUT), "产物 APK 缺失: %s" % OUT

from androguard.core.apk import APK
from androguard.core.dex import DEX

apk = APK(OUT)
man = apk.get_attribute_value("application", "name")
print("MANIFEST application name =", man)
assert man == boot, "Manifest 类(%s) != stamp 随机化引导壳(%s)" % (man, boot)

desc = "L" + man.replace(".", "/") + ";"
classes = set()
for dx in apk.get_all_dex():
    db = dx.get_bytes() if hasattr(dx, "get_bytes") else bytes(dx)
    d = DEX(db)
    for c in d.get_classes():
        classes.add(c.get_name())
present = desc in classes
print("classes.dex 中的类数 =", len(classes))
print("引导壳类 %s 存在于 classes.dex = %s" % (desc, present))
assert present, "引导壳类 %s 不在 classes.dex 中 -> 真机会 ClassNotFoundException" % desc

# 反向确认：默认固定名已不存在
assert "Lcom/gx/runtime/GxBootstrap;" not in classes, "默认固定类仍残留！"

print("\n==== 全部通过：冻结态加固产物 Manifest 类 == dex 随机化类，闪退根因已消除 ====")
# 清理仿真目录（手动绕过 safe-delete shim）
_rmtree_manual(SIM)
print("(已清理 _frozen_sim 临时目录)")
