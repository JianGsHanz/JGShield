# -*- coding: utf-8 -*-
"""
batch_harden.py —— 一键加固整个目录下的 APK（默认 test_apks）

对每个 APK：加固 -> 静态回测 -> 汇总报告。
"""
import os
import sys
import time
import glob
import argparse
import traceback

import config
import harden
import verify

def run_batch(input_dir=None, output_dir=None, keep=False,
               ks=None, ks_alias=None, ks_pass=None, ks_keypass=None,
               skip_verify=False):
    """可被 GUI 直接调用的批量加固入口。返回 (ok_count, total, results)。"""
    inp = os.path.abspath(input_dir or config.SAMPLES_DIR)
    out = os.path.abspath(output_dir or config.OUTPUT_DIR)
    os.makedirs(out, exist_ok=True)

    apks = sorted(glob.glob(os.path.join(inp, "*.apk")))
    apks = [a for a in apks if not os.path.basename(a).startswith("hardened_")]
    if not apks:
        print("未找到待加固 APK：", inp)
        return 0, 0, []

    print("=" * 64)
    print("一键加固：扫描到 %d 个 APK" % len(apks))
    print("输入目录:", inp)
    print("输出目录:", out)
    if ks:
        print("签名密钥库:", ks, "(alias=%s)" % (ks_alias or config.KEY_ALIAS))
    else:
        print("签名密钥库: 内置默认")
    if skip_verify:
        print("跳过静态回测（--skip-verify）")
    print("=" * 64)

    results = []
    batch_t0 = time.time()
    for apk in apks:
        name = os.path.basename(apk)
        print("\n>>>> 处理", name)
        status = "OK"
        out_apk = None
        detail = ""
        elapsed = 0.0
        t0 = time.time()
        try:
            out_apk = harden.harden(apk, keep=keep,
                                    ks=ks, ks_alias=ks_alias,
                                    ks_pass=ks_pass, ks_keypass=ks_keypass,
                                    output_apk=os.path.join(out, "hardened_" + name))
            if not skip_verify:
                ok, res = verify.verify(out_apk, apk, keep=keep)
                if not ok:
                    status = "VERIFY_FAIL"
                    detail = "静态回测未全部通过"
        except Exception as e:
            status = "HARDEN_FAIL"
            detail = "%s: %s" % (type(e).__name__, e)
            traceback.print_exc()
        elapsed = time.time() - t0
        results.append((name, status, out_apk, detail, elapsed))

    batch_elapsed = time.time() - batch_t0
    print("\n" + "=" * 64)
    print("汇总报告")
    print("=" * 64)
    print("%-30s %-6s %8s" % ("APP", "状态", "耗时"))
    print("-" * 64)
    ok_count = 0
    total_time = 0.0
    for name, status, out_apk, detail, elapsed in results:
        mark = "OK" if status == "OK" else "FAIL"
        if status == "OK":
            ok_count += 1
        print("%-30s %-6s %7.1fs" % (name[:30], mark, elapsed))
        total_time += elapsed
    print("-" * 64)
    print("%-30s %-6s %7.1fs" % ("合计", "", total_time))
    print("%-30s %-6s %7.1fs" % ("壁钟时间", "", batch_elapsed))
    print("成功 %d / 共 %d" % (ok_count, len(results)))
    print("=" * 64)
    return ok_count, len(results), results


def main():
    ap = argparse.ArgumentParser(description="一键批量加固目录下 APK")
    ap.add_argument("--input-dir", default=config.SAMPLES_DIR)
    ap.add_argument("--output-dir", default=config.OUTPUT_DIR)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--ks", help="签名密钥库(jks/keystore/p12)，默认用内置")
    ap.add_argument("--ksAlias", help="密钥别名")
    ap.add_argument("--ksPass", help="密钥库密码")
    ap.add_argument("--ksKeyPass", help="密钥密码(默认同密钥库密码)")
    ap.add_argument("--skip-verify", action="store_true", help="跳过静态回测（大幅提速）")
    ap.add_argument("--ollvm-ndk", metavar="DIR",
                    help="OLLVM NDK 的 bin 目录（clang 混淆版）；指定后壳 native 启用 OLLVM 混淆")
    ap.add_argument("--ollvm-passes", metavar="PASS...",
                    help="OLLVM pass 列表，空格/逗号分隔（如 sub,sobf）；需与 --ollvm-ndk 同时指定")
    args = ap.parse_args()
    # OLLVM opt-in：注入环境变量，供 build_stub 在 harden 时读取（每次 harden 重解析）
    if args.ollvm_ndk:
        os.environ["JGSHIELD_OLLVM_NDK_BIN"] = args.ollvm_ndk
    if args.ollvm_passes:
        os.environ["JGSHIELD_OLLVM_PASSES"] = args.ollvm_passes
    ok_count, total, _ = run_batch(args.input_dir, args.output_dir, args.keep,
                                   args.ks, args.ksAlias, args.ksPass, args.ksKeyPass,
                                   skip_verify=args.skip_verify)
    sys.exit(0 if total > 0 and ok_count == total else 1)

if __name__ == "__main__":
    main()
