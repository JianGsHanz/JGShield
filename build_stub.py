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
import posixpath
import re
import shutil
import subprocess
import sys
import platform

import config
import stamp
import whitebox_kdf

# Windows 下 --windowed exe 调起 console 子进程（javac/java/clang 均为 console
# 子系统）会为其单独分配一个控制台窗口 → 加固时黑窗频闪。加此 flag 抑制。
# 非 Windows 该常量降级为 0，无副作用。
_SUBPROC_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_RUNTIME = os.path.join(HERE, "src", "java", "com", "gx", "runtime")
NATIVE_SRC = os.path.join(HERE, "src", "native")
# 临时目录必须可写：冻结态 HERE==_MEIPASS 只读，故统一落在 config.BUILD_DIR
# （exe 同级 build/，可写且持久）。非冻结态 BUILD_DIR==本工程 build/，行为不变。
TMP_JAVA = os.path.join(config.BUILD_DIR, "src_tmp")
TMP_NATIVE = os.path.join(config.BUILD_DIR, "native_tmp")
TMP_CLASSES = os.path.join(config.BUILD_DIR, "classes_tmp")
D8 = os.path.join(config.TOOLS, "d8.jar")
ANDROID_JAR = config.ANDROID_JAR

# NDK 路径：优先读环境变量（跨平台/可移植），硬编码 Windows 路径仅作 fallback
def _resolve_ndk():
    for env_key in ("ANDROID_NDK_HOME", "ANDROID_NDK"):
        env = os.environ.get(env_key)
        if env and os.path.isdir(env):
            return env
    return "D:/Android/AndoridSDK/ndk/25.1.8937393"

NDK = _resolve_ndk()

# OLLVM 混淆 NDK（可选，opt-in）：
# 设为“带 OLLVM 的 clang 所在 bin 目录”（如 D:/Android/AndoridSDK/ndk/27.2.../.../bin），
# 原生壳编译即改用该 clang 并附加 -fla/-sub/-bcf/-sobf 混淆 pass。
# 未设置时退回普通 NDK（25.1），行为完全不变。用途：对抗熟悉 mocika-shield 的逆向者，
# 把壳 native（解密/反调/反篡改逻辑）做控制流扁平化 + 指令替换 + 字符串加密，抬高逆向成本。
def _resolve_ollvm():
    env = os.environ.get("JGSHIELD_OLLVM_NDK_BIN")
    if not env:
        return None
    # 兼容 Git-Bash 的 /d/... 形式（原生 Python 的 os.path 不认这种 POSIX 风格），
    # 统一转成 Windows 盘符路径 D:/...，避免「目录存在却 isdir 判定为 None」而退回普通 NDK。
    if env.startswith("/") and len(env) >= 3 and env[2] == "/":
        env = env[1].upper() + ":" + env[2:]
    if os.path.isdir(env):
        return env
    return None

# OLLVM pass 组合：指令替换(-sub) + 字符串加密(-sobf)。
# 实测该 OLLVM 构建(clang18)对真实壳 native 代码只有 -sub/-sobf 可用：
#   - -fla(控制流扁平化) 与 -bcf(虚假控制流) 均会令 clang 段错误(0xC0000005)，
#     崩溃点在 @jg_aes256gcm_decrypt 的 "Canonicalize natural loops"；-fla 仅 -O0 不崩但
#     生成未优化膨胀代码，不可用于生产。属 OLLVM 在该 clang 版本上的已知不稳定。
#   - 如需 -fla/-bcf，可经 JGSHIELD_OLLVM_PASSES 自行开启（在此 NDK 上大概率崩溃），或换用
#     基于更老 clang(如 14/15)的 OLLVM 构建。
# 仅启用 OLLVM 时生效。
def _resolve_ollvm_passes():
    # 默认直接返回 flag 形式（与下方解析分支一致），否则会被当成 clang 的输入文件名而编译失败
    default = ["-mllvm", "-sub", "-mllvm", "-sobf"]
    raw = os.environ.get("JGSHIELD_OLLVM_PASSES")
    if not raw:
        return default
    # 同时支持空格与逗号分隔（"sub sobf" / "sub,sobf"），避免逗号写法被当成单个无效 pass 名而静默失效
    names = [x for x in raw.replace(",", " ").split() if x]
    flags = []
    for n in names:
        flags += ["-mllvm", "-%s" % n]
    return flags

# 模块级默认（main() 每次调用会重新解析，使 GUI 重复加固 / 环境变量变更即时生效）
OLLVM_NDK_BIN = _resolve_ollvm()
OLLVM_PASS_NAMES = _resolve_ollvm_passes()

# ── 远端 OLLVM（路线 B：SSH 中转）──────────────────────────────────────────────
# 背景：Windows 当前 OLLVM NDK(clang18) 只能跑 -sub/-sobf；-fla/-bcf 在壳 native 上
# 触发 clang ICE（Canonicalize natural loops）。用户在 Ubuntu 原生编出 OLLVM14 clang
# （四件套全可用），并把该 clang 注入 NDK r25c 的 bin（覆盖 NDK 自带 clang，使 NDK 的
# aarch64-linux-android21-clang 等包装脚本改用 OLLVM clang）。Windows 侧 JGShield 通过
# SSH 把随机化后的 native 源传到 VM，远端用 NDK 包装脚本编 4 ABI .so，再 scp 回本地。
# 启用条件：JGSHIELD_OLLVM_REMOTE=1 且 _HOST / _NDK_BIN 均设置。
def _resolve_ollvm_remote():
    return bool(os.environ.get("JGSHIELD_OLLVM_REMOTE"))

def _resolve_ollvm_remote_host():
    return os.environ.get("JGSHIELD_OLLVM_REMOTE_HOST", "").strip()

def _resolve_ollvm_remote_port():
    return os.environ.get("JGSHIELD_OLLVM_REMOTE_PORT", "22").strip()

def _resolve_ollvm_remote_ndk_bin():
    # 远端“已注入 OLLVM 的 NDK bin”绝对路径（Linux，无 .cmd）
    return os.environ.get("JGSHIELD_OLLVM_REMOTE_NDK_BIN", "").strip()

def _resolve_ollvm_remote_sysroot():
    """远端 NDK 的 sysroot。

    必须显式传 --sysroot：NDK 自带的 clang 有个私有补丁（按 binary 位置 bin/../sysroot
    自动定位），我们自编的 stock LLVM 没有该补丁，不给就会找不到 <android/log.h>、
    链接时找不到 -llog/-lz。默认按 <远端 NDK bin>/../sysroot 推导，可用环境变量覆盖。
    """
    return os.environ.get("JGSHIELD_OLLVM_REMOTE_SYSROOT", "").strip()


def _resolve_ollvm_remote_passes():
    # OLLVM14 四件套全可用，默认开满；可用 JGSHIELD_OLLVM_REMOTE_PASSES 覆盖
    raw = os.environ.get("JGSHIELD_OLLVM_REMOTE_PASSES") or "sub,sobf,fla,bcf"
    names = [x for x in raw.replace(",", " ").split() if x]
    flags = []
    for n in names:
        flags += ["-mllvm", "-%s" % n]
    return flags

def _remote_bins():
    # 优先系统 PATH 的 ssh/scp（Git for Windows 自带）；否则退 .exe
    ssh = shutil.which("ssh") or "ssh.exe"
    scp = shutil.which("scp") or "scp.exe"
    return ssh, scp

def _run_remote(cmd):
    # Windows 下 ssh/scp 走 Git-Bash 的 MSYS 运行时，会自动把形似 Windows 路径的参数
    # 转换（如 E:/jiagu/... → /e/jiagu/...）。本地源路径本是 Windows 路径、远端目标
    # ~/xxx 不应被转 → 统一禁掉 MSYS 路径转换，让 scp/ssh 收到字面量（与 adb 处理一致）。
    env = None
    if sys.platform.startswith("win"):
        env = dict(os.environ)
        env["MSYS_NO_PATHCONV"] = "1"
    print("[remote] %s" % " ".join(cmd))
    subprocess.check_call(cmd, creationflags=_SUBPROC_FLAGS, env=env)

# 远端 Linux 下 NDK clang 无 .cmd 扩展名
_REMOTE_CLANG = {
    "arm64-v8a": "aarch64-linux-android21-clang",
    "armeabi-v7a": "armv7a-linux-androideabi21-clang",
    "x86_64": "x86_64-linux-android21-clang",
    "x86": "i686-linux-android21-clang",
}

# NDK 预编译工具链子目录随宿主平台而变：
#   Windows -> windows-x86_64 ; macOS(Intel) -> darwin-x86_64 ;
#   macOS(Apple Silicon) -> darwin-arm64 ; Linux -> linux-x86_64
def _ndk_prebuilt_subdir():
    if sys.platform.startswith("win"):
        return "windows-x86_64"
    if sys.platform == "darwin":
        return "darwin-arm64" if platform.machine().startswith("arm") else "darwin-x86_64"
    return "linux-x86_64"

CLANG_DIR = os.path.join(NDK, "toolchains", "llvm", "prebuilt", _ndk_prebuilt_subdir(), "bin")

# Windows 上 NDK clang 是 .cmd 批处理包装；macOS/Linux 无扩展名
_CLANG_EXT = ".cmd" if sys.platform.startswith("win") else ""
ABIS = {
    "arm64-v8a": "aarch64-linux-android21-clang" + _CLANG_EXT,
    "armeabi-v7a": "armv7a-linux-androideabi21-clang" + _CLANG_EXT,
    "x86_64": "x86_64-linux-android21-clang" + _CLANG_EXT,
    "x86": "i686-linux-android21-clang" + _CLANG_EXT,
}
# 编入单一 .so 的源文件（test_method_restore.c 为独立自测，不编入）
NATIVE_COMPILE = [
    "jg_guard.c", "jg_method_restore.c", "jg_integrity.c",
    "jg_inline_hook.c", "jg_method_restore_hook.c", "jg_hook_bridge.S",
    "jg_anti_frida.c",
]

# 内联 hook 子系统仅 AArch64 编入（jg_hook_bridge.S 为纯 AArch64 汇编）
_HOOK_FILES = {"jg_inline_hook.c", "jg_method_restore_hook.c", "jg_hook_bridge.S"}

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
    # P0-C 内存级 anti-dump 开关 meta 键随机化（防 grep 固定 "gx.antidump"）
    txt = txt.replace('"gx.antidump"', '"%s"' % st["meta_antidump"])
    # A·强反 Frida 开关 meta 键随机化（防 grep 固定 "gx.antifrida"）
    txt = txt.replace('"gx.antifrida"', '"%s"' % st["meta_antifrida"])
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
    # 11) P0-B 轻量：密钥派生 label 前缀随机化（消除固定 "JG|" 分隔符）。
    # 必须与 harden.py 的 config.KEY_PREFIX 及 native 侧完全同名（均来自同一 stamp），
    # 否则写端加密密钥 ≠ 读端解密密钥 → GCM 认证失败。仅命中含 "JG|" 的代码字面量，
    # 不影响注释。
    kp = st["key_prefix"]
    txt = txt.replace('"JG|shell0"', '"%s%s0"' % (kp, "shell"))
    txt = txt.replace('"JG|" + info', '"%s" + info' % kp)
    return txt


def _build_java(st):
    shutil.rmtree(TMP_JAVA, ignore_errors=True)
    shutil.rmtree(TMP_CLASSES, ignore_errors=True)
    dest_pkg = st["pkg"].replace(".", "/")
    dest_dir = os.path.join(TMP_JAVA, dest_pkg)
    os.makedirs(dest_dir, exist_ok=True)

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
        # 兼容安全删除 shim 拦截 rmtree 的情形：用 os 原语兜底清空，避免残留旧随机名
        # .class 文件被 d8 误编入（会导致壳 DEX 含过期类）。exist_ok 保证幂等重入。
        if os.path.isdir(classes_dir):
            for _r, _d, _fs in os.walk(classes_dir, topdown=False):
                for _f in _fs:
                    try:
                        os.remove(os.path.join(_r, _f))
                    except OSError:
                        pass
                for _d2 in _d:
                    try:
                        os.rmdir(os.path.join(_r, _d2))
                    except OSError:
                        pass
        os.makedirs(classes_dir, exist_ok=True)
        subprocess.check_call([
            config.JAVAC, "--release", "8", "-encoding", "UTF-8",
            "-cp", ANDROID_JAR, "-d", classes_dir,
        ] + cf, creationflags=_SUBPROC_FLAGS)
        class_files = []
        for _r, _d, _fs in os.walk(classes_dir):
            for _f in _fs:
                if _f.endswith(".class"):
                    class_files.append(os.path.join(_r, _f))
        dex_out = os.path.join(config.BUILD_DIR, "dex_out_" + cls_key)
        shutil.rmtree(dex_out, ignore_errors=True)
        os.makedirs(dex_out, exist_ok=True)
        subprocess.check_call([
            config.JAVA, "-cp", D8, "com.android.tools.r8.D8",
            "--lib", ANDROID_JAR, "--min-api", "21",
            "--output", dex_out,
        ] + class_files, creationflags=_SUBPROC_FLAGS)
        produced = glob.glob(os.path.join(dex_out, "classes*.dex"))
        if not produced:
            raise RuntimeError("d8 未产出任何 dex for %s" % cls_key)
        if len(produced) > 1:
            raise RuntimeError("壳超出单 dex 限制: %s" % produced)
        os.makedirs(os.path.dirname(out_dex), exist_ok=True)
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
    # JNI 符号类名段随机化（GxGuard/GxKeys/GxDecryptor/Obf 有 JNI；
    # P0-A 起 GxBootstrap 也新增 native 壳密钥派生，必须同步改写其 JNI 符号）
    for old, new in (("GxGuard", classes["GxGuard"]),
                     ("GxKeys", classes["GxKeys"]),
                     ("GxDecryptor", classes["GxDecryptor"]),
                     ("GxBootstrap", classes["GxBootstrap"]),
                     ("Obf", classes["Obf"])):
        s = re.sub(r'Java_com_gx_runtime_' + re.escape(old) + r'_',
                   'Java_%s_%s_' % (pkg_us, new), s)
    # 任何残留的包名路径（如 FindClass 字面量，当前无，但保险）
    s = s.replace("com_gx_runtime", pkg_us)
    # 魔数随机化（native 侧 payload 校验）
    s = s.replace('"JGS1"', '"%s"' % st["magic"])
    # lib 名随机化（native 自保护 / maps 扫描需匹配真实随机名，否则既留指纹又扫不到自己）
    s = s.replace('"libjgguard.so"', '"lib%s.so"' % st["lib_name"])
    # P0-B 轻量：per-method 密钥 label 前缀随机化（消除固定 "JG|m" 分隔符）。
    # 必须与 harden.py 的 config.KEY_PREFIX 及 Java 侧完全同名（均来自同一 stamp），
    # 否则写端加密密钥 ≠ 读端解密密钥 → GCM 认证失败。
    kp = st["key_prefix"]
    s = s.replace('"JG|m%u"', '"' + kp + 'm%u"')
    s = s.replace('"JG|m%u.%u"', '"' + kp + 'm%u.%u"')
    # P0-A 壳 DEX 密钥前缀随机化：nativeDeriveShellKey 的 info 字符串字面量
    # "JG|shell0" 必须先替换为随机前缀，否则解密端死用 "JG|" 与写端随机前缀不等
    # → GCM BAD_DECRYPT（与 Java 侧 build_stub 的 "JG|shell0" 替换保持一致）。
    s = s.replace('"JG|shell0"', '"%s%s0"' % (kp, "shell"))
    # native 侧 log tag 随机化（JG-* 是 logcat/二进制里的指纹；
    # 注：原固定 "JG|"/"JG|m" HKDF 分隔符已随机化为 st["key_prefix"]，不再是明文 "JG|"）
    for old, key in (("JG-Native", "tag_native_log"),
                     ("JG-Integrity", "tag_integrity_log"),
                     ("JG-MethodRestore", "tag_mr_log"),
                     ("JG-InlineHook", "tag_ih_log"),
                     ("JG-MethodRestoreHook", "tag_mrh_log")):
        if key in st:
            s = s.replace('"%s"' % old, '"%s"' % st[key])
    return s


def _regen_vectors(st):
    """P0-B 轻量：重算原生自测向量以匹配随机 key_prefix。

    method_restore_vectors.h 非 NATIVE_COMPILE（仅 test_method_restore.c 引用），
    不走 _sed_native，故在此单独重写 V_LABEL0 / V_HMAC_KEY。
    V_HMAC_KEY = HMAC-SHA256(V_SEED, prefix+"m0")，与原生自测
    jg_hmac_sha256(V_SEED, prefix+"m0") 比对；GCM 向量（V_GCM1_KEY 等）自包含，
    与 label 无关，保持不变。"""
    from Crypto.Hash import HMAC, SHA256
    hdr = os.path.join(TMP_NATIVE, "method_restore_vectors.h")
    if not os.path.isfile(hdr):
        return
    with open(hdr, encoding="utf-8") as f:
        s = f.read()
    kp = st["key_prefix"]
    new_label = (kp + "m0").encode("utf-8")
    # V_SEED 固定（见头文件 L6-10）
    vseed = bytes([0xdb, 0x3a, 0xb1, 0xf9, 0x96, 0xc2, 0x91, 0x1f, 0xb4, 0x56, 0xc9, 0xad,
                   0xd0, 0xae, 0x09, 0x94, 0x8a, 0x85, 0x34, 0xca, 0x0b, 0x28, 0x8e, 0xed,
                   0xc9, 0x41, 0xae, 0xf1, 0x1d, 0x59, 0x7b, 0x2d])
    mac = HMAC.new(vseed, digestmod=SHA256)
    mac.update(new_label)
    hk = mac.digest()
    arr = ",\n  ".join("0x%02x" % b for b in hk)
    s = re.sub(r'#define V_LABEL0 "JG\|m0"',
               '#define V_LABEL0 "%s"' % (kp + "m0"), s)
    s = re.sub(r'static const unsigned char V_HMAC_KEY\[32\] = \{[^}]*\};',
               'static const unsigned char V_HMAC_KEY[32] = {\n  %s\n};' % arr, s)
    with open(hdr, "w", encoding="utf-8") as f:
        f.write(s)


def _bake_whitebox_kdf(st):
    """P0-B 真白盒：把 WB_STATE 烘焙进 TMP_NATIVE/whitebox_kdf.h（仅 wb_kdf 开启时）。

    WB_STATE = SHA256 处理完 wb_secret 的 64B 填充块后的中间态(8×uint32)，
    由 whitebox_kdf.wb_state_c_array 计算，与 Python 写端（harden/verify 的
    whitebox_kdf.wb_derive）逐字节一致 → 写读对称。clean 构建不调用本函数，
    native 走干净 HMAC，whitebox_kdf.h 保持模板默认零值（且不被 include）。"""
    wb_secret = bytes(st["wb_secret"])
    state = whitebox_kdf.wb_state_c_array(wb_secret)
    hdr_path = os.path.join(TMP_NATIVE, "whitebox_kdf.h")
    with open(hdr_path, encoding="utf-8") as f:
        s = f.read()
    s = s.replace("#define WB_STATE {0,0,0,0,0,0,0,0}",
                  "#define WB_STATE {%s}" % state)
    with open(hdr_path, "w", encoding="utf-8") as f:
        f.write(s)
    print("[*] 白盒 KDF 已烘焙 WB_STATE 进 whitebox_kdf.h")


def _build_native(st):
    shutil.rmtree(TMP_NATIVE, ignore_errors=True)
    shutil.copytree(NATIVE_SRC, TMP_NATIVE)
    _regen_vectors(st)
    if st.get("wb_kdf"):
        _bake_whitebox_kdf(st)
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

    # 远端 OLLVM（路线 B）：本地完成源码随机化后，传给 Ubuntu VM 编译
    if _resolve_ollvm_remote():
        return _build_native_remote(st)

    # 内联 hook 子系统（jg_inline_hook.c / jg_method_restore_hook.c / jg_hook_bridge.S）
    # 是 AArch64 专属、仅 opt-in 的实验特性（P3.3，默认关闭）。其中 jg_hook_bridge.S
    # 为纯 AArch64 汇编，编入 32 位 ABI 会直接报错。故仅在 arm64-v8a 编入 hook 文件，
    # 其余 ABI 只编核心三文件（jg_guard/jg_method_restore/jg_integrity）+ 追加的 Obf nativeDecode。
    _hook_files = {"jg_inline_hook.c", "jg_method_restore_hook.c", "jg_hook_bridge.S"}

    built = 0
    for abi, clang_name in ABIS.items():
        # OLLVM opt-in：启用时改用混淆 NDK 的 clang 并附加可配混淆 pass；否则普通 NDK。
        # 注：该 OLLVM 构建不支持 -seed（实测 "Unknown command line argument '-seed'"），
        # 故每构建的混淆结构差异来自壳 native 源码内已按构建随机化的常量（OBF_KEY / 随机 TAG /
        # lib_name 等，由 stamp 注入）——这些随机值进入被混淆函数的 IR，使各构建产物天然不同。
        if OLLVM_NDK_BIN:
            clang = os.path.join(OLLVM_NDK_BIN, clang_name)
            # 该 OLLVM NDK 为 clang18，隐含函数声明默认按错误论处；原壳源码 jg_inline_hook.c
            # 用到 process_vm_writev（NDK25/clang14 仅告警）在此变硬错。加 -Wno-error 仅降级该告警，
            # 不改壳源码语义，使 OLLVM 路径可编译（行为等价于旧 NDK）。
            obf_flags = OLLVM_PASS_NAMES + [
                "-Wno-error=implicit-function-declaration",
                # -unwindlib=none 必须显式给：upstream clang 对 Android 目标默认
                # rtlib=compiler-rt（ToolChain::GetDefaultRuntimeLibType）→ 链接时无条件
                # 追加 -l:libunwind.a，而 NDK r23+ sysroot 没有它（Ubuntu VM 实锤）。
                # 壳 .so 是纯 C 无异常，不依赖 libunwind；-unwindlib 自 clang8 起都支持。
                "-unwindlib=none",
            ]
            obf_tag = " [OLLVM]"
        else:
            clang = os.path.join(CLANG_DIR, clang_name)
            obf_flags = []
            obf_tag = ""
        out_dir = os.path.join(config.LIBJGGUARD_DIR, abi)
        os.makedirs(out_dir, exist_ok=True)
        # 清理旧随机名的 .so，避免散落多个库
        for old in glob.glob(os.path.join(out_dir, "lib*.so")):
            os.remove(old)
        out = os.path.join(out_dir, "lib%s.so" % st["lib_name"])
        srcs = [os.path.join(TMP_NATIVE, f) for f in NATIVE_COMPILE
                if abi == "arm64-v8a" or f not in _hook_files]
        subprocess.check_call(
            [clang, "--shared", "-fPIC", "-O2", "-fno-ident"] + obf_flags + ["-o", out] + srcs +
            (["-DWB_KDF"] if st.get("wb_kdf") else []) +
            ["-Wl,-s", "-llog", "-lz"], creationflags=_SUBPROC_FLAGS)
        built += 1
        print("[*] native 构建完成%s (%s): %s" % (obf_tag, abi, out))
    if not built:
        raise RuntimeError("未构建任何 ABI 的 native 库")


def _build_native_remote(st):
    """路线 B：本地已完成源码随机化，scp 到 Ubuntu VM，ssh 调远端注入 OLLVM 的 NDK clang
    编出 4 ABI 的 lib<lib_name>.so，再 scp 回 tools/libjgguard/<abi>/。保留每次随机化。"""
    host = _resolve_ollvm_remote_host()
    if not host:
        raise RuntimeError("远端 OLLVM 模式已启用，但未设置 JGSHIELD_OLLVM_REMOTE_HOST")
    port = _resolve_ollvm_remote_port()
    ndk_bin = _resolve_ollvm_remote_ndk_bin()
    if not ndk_bin:
        raise RuntimeError("远端 OLLVM 模式已启用，但未设置 JGSHIELD_OLLVM_REMOTE_NDK_BIN"
                           "（远端已注入 OLLVM 的 NDK bin 目录）")
    # 远端是 Linux：路径一律按 posix 处理。用户在 Windows GUI 里可能粘贴含反斜杠的
    # 路径，且 os.path.join 在 Windows 上会拼出 '\'，拼进远端 shell 命令必然失败
    # （踩过的坑：预检 ls -l .../bin\aarch64-linux-android21-clang 直接 exit 2）。
    ndk_bin = ndk_bin.replace("\\", "/").rstrip("/")
    ssh, scp = _remote_bins()
    obf_flags = _resolve_ollvm_remote_passes() + ["-Wno-error=implicit-function-declaration"]
    # sysroot：默认按 <远端 NDK bin>/../sysroot 推导（NDK 标准布局），可用环境变量覆盖
    sysroot = _resolve_ollvm_remote_sysroot()
    if not sysroot:
        sysroot = posixpath.dirname(ndk_bin) + "/sysroot"

    token = "jgshield_%d" % os.getpid()
    remote_base = "~/jgshield_remote/%s" % token
    # scp -r <本地目录> host:<remote_base> 是把「目录本身」拷进 remote_base，
    # 落位名 = 本地目录的 basename（native_tmp），而不是我们假想的 TMP_NATIVE。
    # 远端路径必须按 basename 拼，否则 cd 失败 → && 短路 → 静默 exit 1，
    # 编译器一行报错都看不到（踩过的坑，只能靠端到端跑才暴露）。
    remote_native = remote_base + "/" + os.path.basename(TMP_NATIVE.rstrip("/\\"))

    # 0) 建远端目录（父目录必须先存在，否则首次运行 scp -r 会失败）
    _run_remote([ssh, "-p", port, host, "mkdir -p %s" % remote_base])
    # 0.1) 预检：远端 clang 是否存在（早失败，别等 4 次编译才报错）
    _probe = posixpath.join(ndk_bin, _REMOTE_CLANG["arm64-v8a"])
    _run_remote([ssh, "-p", port, host, "ls -l %s && ls -d %s" % (_probe, sysroot)])

    # 1) 传随机化后的源码到远端
    _run_remote([scp, "-P", port, "-r", TMP_NATIVE, "%s:%s" % (host, remote_base)])

    # 2) 逐 ABI 远端编译 + 回传
    built = 0
    for abi in _REMOTE_CLANG:
        clang = posixpath.join(ndk_bin, _REMOTE_CLANG[abi])
        srcs = [f for f in NATIVE_COMPILE
                if abi == "arm64-v8a" or f not in _HOOK_FILES]
        out_name = "lib%s.so" % st["lib_name"]
        wb = "-DWB_KDF" if st.get("wb_kdf") else ""
        # -unwindlib=none 必须显式给：upstream clang 对 Android 目标无条件追加
        # -l:libunwind.a（clang/lib/Driver/ToolChains/CommonArgs.cpp 的 AddUnwindLibrary），
        # 而 NDK r23+ 的 sysroot 已移除 libunwind → 不关掉就链接失败。
        # NDK 自带的 clang 有私有补丁规避，我们自编的 stock LLVM 没有。
        cmd = ("cd %s && %s --sysroot=%s -unwindlib=none --shared -fPIC -O2 %s %s -o %s %s -llog -lz"
               % (remote_native, clang, sysroot, " ".join(obf_flags), wb,
                  out_name, " ".join(srcs)))
        _run_remote([ssh, "-p", port, host, cmd])

        out_dir = os.path.join(config.LIBJGGUARD_DIR, abi)
        os.makedirs(out_dir, exist_ok=True)
        for old in glob.glob(os.path.join(out_dir, "lib*.so")):
            os.remove(old)
        _run_remote([scp, "-P", port, "%s:%s/%s" % (host, remote_native, out_name),
                     os.path.join(out_dir, out_name)])
        built += 1
        print("[*] native 构建完成 [REMOTE OLLVM] (%s): %s" % (abi, out_name))

    # 3) 清理远端临时目录
    _run_remote([ssh, "-p", port, host, "rm -rf %s" % remote_base])
    if not built:
        raise RuntimeError("未构建任何 ABI 的 native 库")


def main(wb_kdf=False):
    # 重新解析 OLLVM 配置（模块级已解析一次；此处再解析以支持 GUI 重复加固 / 环境变量变更即时生效）
    global OLLVM_NDK_BIN, OLLVM_PASS_NAMES
    OLLVM_NDK_BIN = _resolve_ollvm()
    OLLVM_PASS_NAMES = _resolve_ollvm_passes()
    # 确保可写构建目录存在（冻结态 exe/build 是首次运行，目录尚不存在）
    os.makedirs(config.BUILD_DIR, exist_ok=True)
    st = stamp.generate(wb_kdf=wb_kdf)
    stamp.write(stamp.STAMP_PATH, st)
    _build_java(st)
    _build_native(st)
    print("[*] stamp 已写入: %s" % stamp.STAMP_PATH)
    return st


if __name__ == "__main__":
    main()
