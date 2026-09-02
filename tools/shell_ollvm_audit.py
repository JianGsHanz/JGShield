#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JGShield 壳 so OLLVM 应用判定（可复现取证脚本）

用法:
  python shell_ollvm_audit.py <apk> [arm64_壳so成员名, 默认自动探测]

判据（三条互相独立，全部命中才判"已上 OLLVM"）:
  1) .comment 含裸 "clang version 14.0.6"（无 "Android (" 前缀）
     —— 只有从 llvm.org 14.0.6 源码自编的 OLLVM clang 编出来的 .o 才贡献该串；
        NDK 自带 clang 串带 "Android (8490178, based on r...)" 前缀，且每个 NDK 链接的
        .so 都因 crtbegin_so.o / crtend_so.o 而带该串（与是否过 OLLVM 无关，不能当证据）。
        本工具只看"裸串"是否存在。
  2) .text 段相对无 OLLVM 基线（~25KB）膨胀 >=3 倍
     —— 仅控制流混淆(-fla/-bcf)能造成 4~7 倍膨胀；-sub/-sobf 仅 ~2 倍。
  3) 反汇编后分支指令数相对基线（~20）膨胀 >=10 倍
     —— 控制流混淆的直接指纹。

常见误判提醒:
  - 看到 "Android (...)" 前缀串 ≠ "NDK 原版编译、没混淆"；要找的是裸串。
  - FRIDA_SIGS / jg_guard.c 明文 ≠ "没混淆"；-sobf 不剥 .comment 源路径，且可能漏加密该字面量。
    已知上 OLLVM 的包里同样含这些明文。
  - 函数名(.symtab/.dynsym)全名 ≠ "没混淆"；OLLVM 不改符号名。
  - 本构建的 -fla 用直连条件分支(b.eq/b.ne 链)做调度器，不用跳表/间接 br；
    按"间接 br 跳表"判扁平化的检测器会误报 0/35（假阴性）。
"""
import zipfile, re, subprocess, sys, os, glob, tempfile

RE_LINE = re.compile(r'^\s*[0-9a-f]+:\s+(?:(?:[0-9a-f]{2})\s+)+\s*([A-Za-z][\w.]*)\s*(.*)$')

def find_objdump():
    # 钉到 r25.1（与壳 so 的 NDK r25b 构建同源，输出格式已验证）；
    # 新版(27.x)的 llvm-objdump 反汇编格式不同，会使分支解析失效。
    pref = r"D:/Android/AndoridSDK/ndk/25.1.8937393/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-objdump.exe"
    if os.path.exists(pref):
        return pref
    pats = glob.glob(r"D:/Android/AndoridSDK/ndk/*/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-objdump.exe")
    return pats[0] if pats else "llvm-objdump"

def detect_shell_member(z):
    known = ('tp','ijk','vloud','aiengine','liteav','sqlcipher','mmkv','Bugly','downloadproxy',
             'tx','security','SerialPort','xcrash','jcore','ndkbitmap')
    cands = [i for i in z.infolist() if i.filename.startswith('lib/arm64') and i.filename.endswith('.so')
             and not any(k in i.filename for k in known) and i.file_size > 100_000]
    return cands[0].filename if cands else None

def audit(apk, member=None):
    z = zipfile.ZipFile(apk)
    if member is None:
        member = detect_shell_member(z)
        if not member:
            print("!! 未找到壳 so（自动探测失败），请手动指成员名"); return
    data = z.read(member)
    ob = find_objdump()
    tf = tempfile.NamedTemporaryFile(suffix='.so', delete=False)
    tf.write(data); tf.close()
    try:
        # 1) .text 大小
        h_out = subprocess.run([ob, "-h", tf.name], capture_output=True, timeout=120).stdout.decode('latin1','replace')
        text_size = 0
        for ln in h_out.splitlines():
            if '.text' in ln:
                m = re.search(r'\.text\s+([0-9a-fA-F]+)', ln)
                if m: text_size = int(m.group(1), 16)
        # 2) .comment 裸串
        c_out = subprocess.run([ob, "-s", "-j", ".comment", tf.name], capture_output=True, timeout=120).stdout.decode('latin1','replace')
        # 只抽取 -s 输出的 ASCII 列（去掉十六进制列，否则会截断 "clang version 14.0.6"）
        ascii_parts = []
        for ln in c_out.splitlines():
            am = re.match(r'^\s*[0-9a-f]{4}\s', ln)
            if not am: continue
            rest = ln[am.end():]
            parts = re.split(r'  +', rest, maxsplit=1)
            if len(parts) == 2: ascii_parts.append(parts[1])
        comment = ''.join(ascii_parts)
        # NDK 自带 clang 串: "Android (8490178, based on ...) clang version 14.0.6" —— 每个 NDK .so 必有
        has_ndk = 'Android (8490178' in comment
        # OLLVM 自编 clang 串: 裸 "clang version 14.0.6"。OLLVM 包里该串出现 2 次
        # （一次嵌在 NDK 前缀串内，一次裸串）；纯 NDK 包只出现 1 次。
        bare = comment.count('clang version 14.0.6') >= 2
        # 3) 反汇编分支
        d_out = subprocess.run([ob, "-d", "--section=.text", tf.name], capture_output=True, timeout=300).stdout.decode('latin1','replace')
        branches = 0
        for ln in d_out.splitlines():
            m = RE_LINE.match(ln)
            if not m: continue
            op = m.group(1)
            if op == 'br' or (op.startswith('b') and op != 'blr'): branches += 1
    finally:
        os.unlink(tf.name)
    verdict = "OLLVM 已应用" if (bare and text_size >= 25_588*3 and branches >= 20*10) else "未检出 OLLVM"
    print("APK  : %s" % os.path.basename(apk))
    print("壳 so: %s (%d B)" % (member, len(data)))
    print("  .text            = %d B (0x%x)" % (text_size, text_size))
    print("  .comment 裸 clang14.0.6(OLLVM特征) = %s" % ("有" if bare else "无"))
    print("  .comment NDK前缀串(必有,不计数)      = %s" % ("有" if has_ndk else "无"))
    print("  反汇编分支数       = %d" % branches)
    print("  >>> 判定: %s" % verdict)
    print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    audit(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
