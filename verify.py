# -*- coding: utf-8 -*-
"""
verify.py —— 加固产物静态回测（每步回归用）

检查项：
  A. 载荷回测：解密 jg 条目中的 JGS1 载荷还原原始 DEX，与输入逐一比对（无误差）
  B. Manifest：Application 已换成壳类；orig_app meta 存在且指向原 Application
  C. 可打包性：aapt dump badging 能解析（包名/启动 Activity 正常）
  D. 签名有效：apksigner verify 通过（v1/v2/v3）
"""
import os
import re
import sys
import shutil
import argparse
import traceback

import config
from harden import list_original_dexes, read_dexes, run, env_with_android
import verify_payload

def step_a_payload(hardened, orig_dexes):
    ok, detail = verify_payload.check_payload(hardened, orig_dexes)
    return ok, detail

def step_b_manifest(hardened, work, expected_orig_app):
    decoded = os.path.join(work, "verify_decoded")
    config.rmtree_safe(decoded)
    run([config.JAVA, "-jar", config.APKTOOL, "d", hardened, "-o", decoded, "-f"],
        env=env_with_android())
    mp = os.path.join(decoded, "AndroidManifest.xml")
    xml = open(mp, encoding="utf-8").read()
    errs = []
    if config.SHELL_APP not in xml:
        errs.append("Manifest 中未出现壳 Application")
    if config.META_ORIG not in xml:
        errs.append("Manifest 中未出现 orig_app meta")
    # 校验 meta 值正确
    m = re.search(r'android:name="%s" android:value="([^"]*)"' % re.escape(config.META_ORIG), xml)
    if m:
        got = m.group(1)
        if got != (expected_orig_app or ""):
            errs.append("orig_app meta 值不符: got=%r want=%r" % (got, expected_orig_app or ""))
    else:
        errs.append("无法解析 orig_app meta 值")
    return (len(errs) == 0, "; ".join(errs) if errs else "ok")

def step_c_badging(hardened):
    p = run([config.AAPT, "dump", "badging", hardened], check=False)
    if p.returncode != 0:
        return False, "aapt dump badging 失败"
    out = p.stdout
    if "package:" not in out:
        return False, "badging 无 package 信息"
    return True, "ok"

def step_d_signature(hardened):
    p = run([config.JAVA, "-jar", config.APKSIGNER, "verify", hardened], check=False)
    if p.returncode != 0:
        return False, "apksigner verify 失败:\n" + (p.stderr or p.stdout)
    return True, "ok"

def verify(hardened, original, keep=False):
    hardened = os.path.abspath(hardened)
    original = os.path.abspath(original)
    print("=" * 60)
    print("回测加固产物:", hardened)
    print("对照原始 APK:", original)
    print("=" * 60)

    orig_dexes = read_dexes(original, list_original_dexes(original))
    print("原始 DEX 数量:", len(orig_dexes))

    work = os.path.join(config.WORK_DIR, "verify_" +
                        os.path.splitext(os.path.basename(hardened))[0])
    config.rmtree_safe(work)
    os.makedirs(work, exist_ok=True)

    results = {}
    results["A_payload"], results["A_detail"] = step_a_payload(hardened, orig_dexes)
    # 期望的原 Application 名（从 original manifest 解析）
    expected_orig = _orig_app_of(original, work)
    results["B_manifest"], results["B_detail"] = step_b_manifest(hardened, work, expected_orig)
    results["C_badging"], results["C_detail"] = step_c_badging(hardened)
    results["D_signature"], results["D_detail"] = step_d_signature(hardened)

    ok = all([results["A_payload"], results["B_manifest"], results["C_badging"], results["D_signature"]])
    print("-" * 60)
    print("A 载荷还原一致 :", "PASS" if results["A_payload"] else "FAIL", "-", results["A_detail"])
    print("B Manifest    :", "PASS" if results["B_manifest"] else "FAIL", "-", results["B_detail"])
    print("C 可打包性    :", "PASS" if results["C_badging"] else "FAIL", "-", results["C_detail"])
    print("D 签名有效    :", "PASS" if results["D_signature"] else "FAIL", "-", results["D_detail"])
    print("-" * 60)
    print("总体:", "ALL PASS" if ok else "HAS FAILURE")
    if not keep:
        config.rmtree_safe(work)
    return ok, results

def _orig_app_of(original, work):
    decoded = os.path.join(work, "orig_decoded")
    config.rmtree_safe(decoded)
    run([config.JAVA, "-jar", config.APKTOOL, "d", original, "-o", decoded, "-f"],
        env=env_with_android())
    xml = open(os.path.join(decoded, "AndroidManifest.xml"), encoding="utf-8").read()
    m = re.search(r"<application\b[^>]*android:name=\"([^\"]+)\"", xml, re.S)
    if not m:
        return ""
    name = m.group(1)
    if name.startswith("."):
        pm = re.search(r'package="([^"]+)"', xml)
        if pm:
            name = pm.group(1) + name
    return name

def main():
    ap = argparse.ArgumentParser(description="JGShield 加固产物回测")
    ap.add_argument("hardened", help="加固后的 APK")
    ap.add_argument("original", help="原始 APK（用于比对）")
    ap.add_argument("--keep", action="store_true", help="保留工作目录")
    args = ap.parse_args()
    try:
        ok, _ = verify(args.hardened, args.original, args.keep)
    except Exception:
        traceback.print_exc()
        ok = False
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
