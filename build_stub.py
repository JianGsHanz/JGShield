# -*- coding: utf-8 -*-
"""
build_stub.py - 按 stamp 随机化并（重）构建壳产物。

产出：
  - build/dex/stub.dex        随机化后的壳 DEX（包名/类名/meta/TAG/payload/magic/Obf-native 全部随机）
  - tools/libjgguard/<abi>/libjgguard.so   重编 4 ABI native（JNI 符号随类名随机、魔数随机、Obf 密钥随机）
  - build/stamp.json          本次随机化参数（harden/verify/device_check 的唯一事实来源）

设计要点：
  - 壳源码位于 src/java/com/gx/runtime/{GxApp,GxGuard}.java（同包）。
  - Obf 字符串解密密钥原本以 K_SEED 形式明文躺在 DEX（GxApp.java 的 deriveKey()），
    逆向者读 jadx 即可还原 -> 本次把 Obf.d() 改为调用 nativeDecode，密钥仅存于 .so。
  - 注意自举：System.loadLibrary 在 attachBaseContext 才调用，故 lib 名不能走 Obf（否则死锁）；
    MAGIC 在类加载期用 Obf.d()，但魔数非机密 -> MAGIC 改用普通随机字面量，且所有其余 Obf.d()
    调用均在 ensureLoaded 之后，可安全下沉 native。
  - 包名/类名随机化牵动 JNI 符号 -> native 必须同步重编（JNI 符号段随类名随机）。
"""
import json
import glob
import os
import re
import shutil
import subprocess

import config
import stamp

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_RUNTIME = os.path.join(HERE, "src", "java", "com", "gx", "runtime")
NATIVE_SRC = os.path.join(HERE, "src", "native")
TMP_JAVA = os.path.join(HERE, "build", "src_tmp")
TMP_NATIVE = os.path.join(HERE, "build", "native_tmp")
TMP_CLASSES = os.path.join(HERE, "build", "classes_tmp")
D8 = os.path.join(config.TOOLS, "d8.jar")
ANDROID_JAR = config.ANDROID_JAR

NDK = "D:/Android/AndoridSDK/ndk/25.1.8937393"
CLANG_DIR = os.path.join(NDK, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin")
ABIS = {
    "arm64-v8a": "aarch64-linux-android21-clang.cmd",
    "armeabi-v7a": "armv7a-linux-androideabi21-clang.cmd",
    "x86_64": "x86_64-linux-android21-clang.cmd",
    "x86": "i686-linux-android21-clang.cmd",
}
# 编入单一 .so 的源文件（test_method_restore.c 为独立自测，不编入）
NATIVE_COMPILE = [
    "jg_guard.c", "jg_method_restore.c", "jg_integrity.c",
    "jg_inline_hook.c", "jg_method_restore_hook.c", "jg_hook_bridge.S",
]

# Obf 旧密钥（与 GxApp.java 原 deriveKey() 一致），用于把源码中旧密文串解码为明文以便重编码
_OLD_KSEED = [0x13572A6C, 0x4E1B3679, 0x0D516874, 0x2B3F4452]


def _old_key():
    k = bytearray(16)
    for i in range(4):
        v = _OLD_KSEED[i]
        k[i * 4] = (v >> 24) & 0xFF
        k[i * 4 + 1] = (v >> 16) & 0xFF
        k[i * 4 + 2] = (v >> 8) & 0xFF
        k[i * 4 + 3] = v & 0xFF
    return bytes(k)


def _old_decode(cints):
    k = _old_key()
    return "".join(chr(cints[i] ^ k[i % 16]) for i in range(len(cints)))


# ── Java 源码变换 ──────────────────────────────────────────────────────────────

OBF_NATIVE_TEMPLATE = """class Obf {
    private static volatile boolean _obfLoaded = false;
    static String d(byte[] c) {
        // 自举：类加载期（<clinit>）就可能调用 d() 解密字符串常量，早于 attachBaseContext
        // 里的 ensureLoaded()；若此处不自行加载，nativeDecode 会因库未加载抛 UnsatisfiedLinkError
        // 导致 App 启动即崩。loadLibrary 幂等，重复调用安全。
        if (!_obfLoaded) {
            try { System.loadLibrary("%s"); } catch (Throwable ignored) {}
            _obfLoaded = true;
        }
        return nativeDecode(c);
    }
    private static native String nativeDecode(byte[] c);
}
"""


def _transform_java(txt, st):
    classes = st["classes"]
    pkg = st["pkg"]

    # 1) 包名
    txt = txt.replace("package com.gx.runtime;", "package %s;" % pkg)
    # 2) meta 键（字符串字面量）
    txt = txt.replace('"gx.orig_app"', '"%s"' % st["meta_orig"])
    txt = txt.replace('"gx.ssl_pins"', '"%s"' % st["meta_ssl"])
    txt = txt.replace('"gx.strengthen"', '"%s"' % st["meta_strengthen"])
    # 2.5) payload 条目名（壳读取端必须 == harden 写入端，否则读不到载荷崩溃）
    txt = re.sub(r'PAYLOAD_ENTRY\s*=\s*"[^"]*"',
                 'PAYLOAD_ENTRY = "%s"' % st["payload_entry"], txt)
    # 2.6) 异常/日志消息里的 GX 子串（非独立 TAG 字面量，step 3 的精确匹配碰不到）
    txt = txt.replace('"GX init failed: "',
                      '"%s init failed: "' % st["tag_app"])
    txt = txt.replace('"GX: pin mismatch for "',
                      '"%s: pin mismatch for "' % st["tag_app"])
    # 3) TAG（各类独立随机）
    txt = txt.replace('"GX"', '"%s"' % st["tag_app"])
    txt = txt.replace('"GX-Native"', '"%s"' % st["tag_native"])
    txt = txt.replace('"GX-AT"', '"%s"' % st["tag_at"])
    txt = txt.replace('"GX-AD"', '"%s"' % st["tag_ad"])
    txt = txt.replace('"GX-SSL"', '"%s"' % st["tag_ssl"])
    txt = txt.replace('"GX-VPN"', '"%s"' % st["tag_vpn"])
    # 4) MAGIC 改普通随机字面量（魔数非机密，避免类加载期触发 native Obf 自举）
    txt = re.sub(r'MAGIC\s*=\s*Obf\.d\(new byte\[\]\{[^}]*\}\);',
                 'MAGIC = "%s";' % st["magic"], txt)
    # 5) lib 名改普通随机字面量（loadLibrary 早于库加载，不能走 Obf）
    txt = re.sub(r'System\.loadLibrary\(Obf\.d\(new byte\[\]\{[^}]*\}\)\);',
                 'System.loadLibrary("%s");' % st["lib_name"], txt)
    # 6) Obf 类改为 native 实现（密钥下沉 .so）；%s 填入随机 lib 名用于自举加载
    txt = re.sub(r'class Obf\s*\{.*?\}\s*$', OBF_NATIVE_TEMPLATE % st["lib_name"],
                 txt, flags=re.S)
    # 7) 其余 Obf.d(...) 密文串用新密钥重编码（顺带让密文字节数组每构建不同）
    new_key = st["obf_key"]

    def _reenc(m):
        arr = m.group(1)
        ints = [int(x.strip().replace("(byte)", ""), 0)
                for x in arr.split(",") if x.strip()]
        plain = _old_decode(ints)
        out = [(ord(plain[i]) ^ new_key[i % 16]) & 0xFF
               for i in range(len(plain))]
        return "Obf.d(new byte[]{%s})" % ", ".join("(byte)0x%02X" % v for v in out)

    txt = re.sub(r'Obf\.d\(new byte\[\]\{([^}]*)\}\)', _reenc, txt)
    # 8) P8 Bootstrap 反射调用 GxApp.boot 的类名字符串随机化 —— 必须在「类名替换」(step 9)
    # 之前执行，否则 step 9 已把 GxApp→随机名，导致 "com.gx.runtime.GxApp" 模式消失而失效。
    txt = txt.replace('"com.gx.runtime.GxApp"',
                      '"%s.%s"' % (st["pkg"], st["classes"]["GxApp"]))
    # 9) 类名最后改（覆盖所有引用，含刚生成的模板与调用）。注意：本步骤的 old 是
    # 原始类名（如 GxApp），不会误伤 step 8 已生成的 "pkg.随机名" 字符串。
    for old, new in classes.items():
        txt = re.sub(r'\b' + re.escape(old) + r'\b', new, txt)
    # 10) P8 引导壳占位替换（仅 GxBootstrap.java 含这些占位，GxApp 不受影响）
    txt = txt.replace("__LIB_NAME__", st["lib_name"])
    txt = txt.replace("__SHELL_DEX_ENTRY__", st["shell_dex_entry"])
    txt = txt.replace("__PAYLOAD_ENTRY__", st["payload_entry"])
    return txt


def _build_java(st):
    shutil.rmtree(TMP_JAVA, ignore_errors=True)
    shutil.rmtree(TMP_CLASSES, ignore_errors=True)
    dest_pkg = st["pkg"].replace(".", "/")
    dest_dir = os.path.join(TMP_JAVA, dest_pkg)
    os.makedirs(dest_dir)

    def _compile_to_dex(java_files, out_dex):
        cf = []
        for fn in java_files:
            with open(os.path.join(SRC_RUNTIME, fn), encoding="utf-8") as f:
                txt = f.read()
            txt = _transform_java(txt, st)
            cls_key = fn[:-5]  # "GxApp"/"GxGuard"/"GxBootstrap"
            new_cls = st["classes"][cls_key]
            new_path = os.path.join(dest_dir, new_cls + ".java")
            with open(new_path, "w", encoding="utf-8") as f:
                f.write(txt)
            cf.append(new_path)
        classes_dir = os.path.join(TMP_CLASSES, cls_key)
        shutil.rmtree(classes_dir, ignore_errors=True)
        os.makedirs(classes_dir)
        subprocess.check_call([
            config.JAVAC, "--release", "8", "-encoding", "UTF-8",
            "-cp", ANDROID_JAR, "-d", classes_dir,
        ] + cf)
        class_files = []
        for _r, _d, _fs in os.walk(classes_dir):
            for _f in _fs:
                if _f.endswith(".class"):
                    class_files.append(os.path.join(_r, _f))
        dex_out = os.path.join(HERE, "build", "dex_out_" + cls_key)
        shutil.rmtree(dex_out, ignore_errors=True)
        os.makedirs(dex_out)
        subprocess.check_call([
            config.JAVA, "-cp", D8, "com.android.tools.r8.D8",
            "--lib", ANDROID_JAR, "--min-api", "21",
            "--output", dex_out,
        ] + class_files)
        produced = glob.glob(os.path.join(dex_out, "classes*.dex"))
        if not produced:
            raise RuntimeError("d8 未产出任何 dex for %s" % cls_key)
        if len(produced) > 1:
            raise RuntimeError("壳超出单 dex 限制: %s" % produced)
        shutil.copy(sorted(produced)[0], out_dex)
        return out_dex

    # ① 壳主 DEX（GxApp + GxGuard → stub.dex，加密前明文，harden 会加密它）
    _compile_to_dex(("GxApp.java", "GxGuard.java"), config.STUB_DEX)
    print("[*] stub.dex 构建完成（随机包名 %s）: %s" % (st["pkg"], config.STUB_DEX))
    # ② P8 引导壳（GxBootstrap → bootstrap.dex，明文，作 APK 入口 classes.dex）
    _compile_to_dex(("GxBootstrap.java",), config.BOOTSTRAP_DEX)
    print("[*] bootstrap.dex 构建完成: %s" % config.BOOTSTRAP_DEX)


# ── native 源码变换 ────────────────────────────────────────────────────────────

def _obf_native_c(st):
    pkg_us = st["pkg_underscore"]
    new_obf = st["classes"]["Obf"]
    key = ", ".join("0x%02X" % b for b in st["obf_key"])
    return (
        "\n/* Obf 字符串解密：密钥仅存于 native（DEX 中不再出现），"
        "逆向须分析 .so 才能还原。 */\n"
        "static const uint8_t OBF_KEY[16] = { %s };\n"
        "JNIEXPORT jstring JNICALL Java_%s_%s_nativeDecode("
        "JNIEnv *env, jclass clazz, jbyteArray cipher) {\n"
        "    jsize len = (*env)->GetArrayLength(env, cipher);\n"
        "    jbyte *c = (*env)->GetByteArrayElements(env, cipher, NULL);\n"
        "    if (!c) return (*env)->NewStringUTF(env, \"\");\n"
        "    jchar *out = (jchar*)malloc((len + 1) * sizeof(jchar));\n"
        "    for (jsize i = 0; i < len; i++) {\n"
        "        jint ci = c[i];\n"
        "        jint k = OBF_KEY[i %% 16];\n"
        "        jint x = ci ^ k;\n"
        "        out[i] = (jchar)(x & 0xFFFF);\n"
        "    }\n"
        "    jstring s = (*env)->NewString(env, out, len);\n"
        "    (*env)->ReleaseByteArrayElements(env, cipher, c, JNI_ABORT);\n"
        "    free(out);\n"
        "    return s;\n"
        "}\n" % (key, pkg_us, new_obf)
    )


def _sed_native(s, st):
    pkg_us = st["pkg_underscore"]
    classes = st["classes"]
    # JNI 符号类名段随机化（仅 GxGuard/GxKeys/GxDecryptor/Obf 有 JNI）
    for old, new in (("GxGuard", classes["GxGuard"]),
                     ("GxKeys", classes["GxKeys"]),
                     ("GxDecryptor", classes["GxDecryptor"]),
                     ("Obf", classes["Obf"])):
        s = re.sub(r'Java_com_gx_runtime_' + re.escape(old) + r'_',
                   'Java_%s_%s_' % (pkg_us, new), s)
    # 任何残留的包名路径（如 FindClass 字面量，当前无，但保险）
    s = s.replace("com_gx_runtime", pkg_us)
    # 魔数随机化（native 侧 payload 校验）
    s = s.replace('"JGS1"', '"%s"' % st["magic"])
    # lib 名随机化（native 自保护 / maps 扫描需匹配真实随机名，否则既留指纹又扫不到自己）
    s = s.replace('"libjgguard.so"', '"lib%s.so"' % st["lib_name"])
    # native 侧 log tag 随机化（JG-* 是 logcat/二进制里的指纹；
    # 注意保留 JG| / JG|m 等 HKDF 域名分隔符——它们必须与 harden.py 一致，不能改）
    for old, key in (("JG-Native", "tag_native_log"),
                     ("JG-Integrity", "tag_integrity_log"),
                     ("JG-MethodRestore", "tag_mr_log"),
                     ("JG-InlineHook", "tag_ih_log"),
                     ("JG-MethodRestoreHook", "tag_mrh_log")):
        if key in st:
            s = s.replace('"%s"' % old, '"%s"' % st[key])
    return s


def _build_native(st):
    shutil.rmtree(TMP_NATIVE, ignore_errors=True)
    shutil.copytree(NATIVE_SRC, TMP_NATIVE)
    for fn in NATIVE_COMPILE:
        p = os.path.join(TMP_NATIVE, fn)
        with open(p, encoding="utf-8", errors="ignore") as f:
            s = f.read()
        s = _sed_native(s, st)
        with open(p, "w", encoding="utf-8") as f:
            f.write(s)
    # 在 jg_guard.c 末尾追加 Obf nativeDecode
    guard_path = os.path.join(TMP_NATIVE, "jg_guard.c")
    with open(guard_path, encoding="utf-8") as f:
        g = f.read()
    g += _obf_native_c(st)
    with open(guard_path, "w", encoding="utf-8") as f:
        f.write(g)

    # 内联 hook 子系统（jg_inline_hook.c / jg_method_restore_hook.c / jg_hook_bridge.S）
    # 是 AArch64 专属、仅 opt-in 的实验特性（P3.3，默认关闭）。其中 jg_hook_bridge.S
    # 为纯 AArch64 汇编，编入 32 位 ABI 会直接报错。故仅在 arm64-v8a 编入 hook 文件，
    # 其余 ABI 只编核心三文件（jg_guard/jg_method_restore/jg_integrity）+ 追加的 Obf nativeDecode。
    _hook_files = {"jg_inline_hook.c", "jg_method_restore_hook.c", "jg_hook_bridge.S"}

    built = 0
    for abi, clang_name in ABIS.items():
        clang = os.path.join(CLANG_DIR, clang_name)
        out_dir = os.path.join(config.LIBJGGUARD_DIR, abi)
        os.makedirs(out_dir, exist_ok=True)
        # 清理旧随机名的 .so，避免散落多个库
        for old in glob.glob(os.path.join(out_dir, "lib*.so")):
            os.remove(old)
        out = os.path.join(out_dir, "lib%s.so" % st["lib_name"])
        srcs = [os.path.join(TMP_NATIVE, f) for f in NATIVE_COMPILE
                if abi == "arm64-v8a" or f not in _hook_files]
        subprocess.check_call(
            [clang, "--shared", "-fPIC", "-O2", "-o", out] + srcs +
            ["-llog", "-lz"])
        built += 1
        print("[*] native 构建完成 (%s): %s" % (abi, out))
    if not built:
        raise RuntimeError("未构建任何 ABI 的 native 库")


def main():
    st = stamp.generate()
    stamp.write(stamp.STAMP_PATH, st)
    _build_java(st)
    _build_native(st)
    print("[*] stamp 已写入: %s" % stamp.STAMP_PATH)
    return st


if __name__ == "__main__":
    main()
