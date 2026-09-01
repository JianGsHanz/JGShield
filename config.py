# -*- coding: utf-8 -*-
"""
JGShield 加固工具集 - 共享配置
所有路径统一使用正斜杠（Windows 版 CPython 可正常识别）。

冻结为 exe/app 时，bundled 资源（tools/、stub.dex）从 sys._MEIPASS 解析；
输出/工作目录放在可执行文件同级目录。非冻结时从本文件所在目录解析。

跨平台：Windows / macOS / Linux 的工具文件名与 JDK/SDK 路径不同，由本文件统一适配。
"""
import os
import sys
import json
import locale

# -------------------------------------------------------------------------- #
# 平台检测：Windows / macOS / Linux 的工具文件名与路径不同
# -------------------------------------------------------------------------- #
IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def _exe(name):
    """按平台返回可执行文件名：Windows 加 .exe，macOS/Linux 无扩展名。"""
    return name + ".exe" if IS_WINDOWS else name


# -------------------------------------------------------------------------- #
# 路径解析：区分 frozen（PyInstaller）与 script 运行
# -------------------------------------------------------------------------- #
def _is_frozen():
    return getattr(sys, "frozen", False)


if _is_frozen():
    # PyInstaller onefile: 解压临时目录
    _BUNDLE = sys._MEIPASS
    EXEC_DIR = os.path.dirname(sys.executable)
else:
    _BUNDLE = os.path.dirname(os.path.abspath(__file__))
    EXEC_DIR = _BUNDLE

ROOT = EXEC_DIR  # 向后兼容
TOOLS = os.path.join(_BUNDLE, "tools")

# 构建期「可写」目录： executable 同级 build/。
# 冻结态下 _BUNDLE(sys._MEIPASS) 是只读临时解压目录，任何 build 产物（stamp.json /
# stub.dex / bootstrap.dex / libjgguard .so / 临时源码）都必须落在这里，否则抛
# PermissionError；且 stamp 读写端必须都指向它，否则 Manifest 类名与 dex 类名不一致
# 导致 ClassNotFoundException 闪退。非冻结态 EXEC_DIR==_BUNDLE，行为不变。
BUILD_DIR = os.path.join(EXEC_DIR, "build")

# -------------------------------------------------------------------------- #
# Java 运行时（apktool / uber-apk-signer / apksigner 均依赖 java）
# -------------------------------------------------------------------------- #
_JAVA_CANDIDATES = [
    # Windows
    "C:/Program Files/Java/jdk-11.0.21/bin/java.exe",
    "C:/Program Files/Java/jdk-17/bin/java.exe",
    "C:/Program Files/Java/jdk-21/bin/java.exe",
    "C:/Program Files/Java/jdk-22/bin/java.exe",
    # macOS (Homebrew / 系统 JDK / JAVA_HOME)
    "/opt/homebrew/opt/openjdk/bin/java",
    "/usr/local/opt/openjdk/bin/java",
    "/Library/Java/JavaVirtualMachines/jdk-11.jdk/Contents/Home/bin/java",
    "/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home/bin/java",
    "/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin/java",
    # Linux
    "/usr/lib/jvm/default-java/bin/java",
    "/usr/lib/jvm/java-11-openjdk/bin/java",
    "/usr/bin/java",
]
JAVA = None
for _j in _JAVA_CANDIDATES:
    if os.path.isfile(_j):
        JAVA = _j
        break
if not JAVA:
    JAVA = "java"  # 回退到 PATH

# -------------------------------------------------------------------------- #
# 外壳 DEX（由 GxApp.java 编译而来，含 12 个壳类）；P8 起被加密为载荷段
# -------------------------------------------------------------------------- #
STUB_DEX = os.path.join(BUILD_DIR, "dex", "stub.dex")
# P8 引导壳 DEX（GxBootstrap.java 编译，极简，作 APK 的 classes.dex 明文入口）
BOOTSTRAP_DEX = os.path.join(BUILD_DIR, "dex", "bootstrap.dex")
# P8 随机化默认值（apply_stamp_from_file 覆盖）
SHELL_DEX_ENTRY = "gxsh"     # 加密壳 DEX 的随机 zip 条目名
BOOTSTRAP_APP = "com.gx.runtime.GxBootstrap"

# -------------------------------------------------------------------------- #
# native 反篡改库（由各 ABI 的 libjgguard.so 组成，加固时注入 APK 的 lib/<abi>/）
# 源码 src/native/jg_guard.c，由 build_native.bat/.sh 用 NDK 编译到此目录
# -------------------------------------------------------------------------- #
LIBJGGUARD_DIR = os.path.join(BUILD_DIR, "libjgguard")

# -------------------------------------------------------------------------- #
# 第三方工具（全部 bundled 在 tools/ 下，exe 自包含）
# jar 类跨平台通用；原生二进制按平台选文件名
# -------------------------------------------------------------------------- #
APKTOOL = os.path.join(TOOLS, "apktool.jar")
AAPT = os.path.join(TOOLS, _exe("aapt"))
UBER = os.path.join(TOOLS, "uber-apk-signer.jar")
APKSIGNER = os.path.join(TOOLS, "apksigner.jar")

# keytool（用于从用户指定的 keystore 提取证书 DER 以派生种子）
if JAVA and (JAVA == "java" or os.path.basename(JAVA) == "java"):
    KEYTOOL = "keytool"
else:
    _java_dir = os.path.dirname(JAVA)
    KEYTOOL = os.path.join(_java_dir, _exe("keytool"))
    if not os.path.isfile(KEYTOOL):
        KEYTOOL = "keytool"

# javac（gen_samples.py 编译测试样本用；与 JAVA 同目录，按平台加 .exe）
if JAVA and (JAVA == "java" or os.path.basename(JAVA) == "java"):
    JAVAC = "javac"
else:
    _java_dir = os.path.dirname(JAVA)
    JAVAC = os.path.join(_java_dir, _exe("javac"))
    if not os.path.isfile(JAVAC):
        JAVAC = "javac"

# adb（bundled 或从 SDK / PATH 查找）
ADB = os.path.join(TOOLS, _exe("adb"))
if not os.path.isfile(ADB):
    _adb_name = _exe("adb")
    for _base in [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
                  os.path.expanduser("~/Library/Android/sdk"),
                  os.path.expanduser("~/Android/Sdk"),
                  "C:/Android/Sdk", "D:/Android/AndoridSDK"]:
        if not _base:
            continue
        _a = os.path.join(_base, "platform-tools", _adb_name)
        if os.path.isfile(_a):
            ADB = _a
            break
    else:
        ADB = "adb"  # 回退到 PATH

# DX / ANDROID_JAR（仅 gen_samples 用，best-effort）
DX = os.path.join(TOOLS, "dx.jar")
if not os.path.isfile(DX):
    for _base in [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
                  "D:/Android/Android Decompile/AndroidKiller_v1.3.1/bin/dex2jar/lib",
                  os.path.expanduser("~/Library/Android/sdk"),
                  os.path.expanduser("~/Android/Sdk"), "C:/Android/Sdk"]:
        if not _base:
            continue
        _dx = os.path.join(_base, "dx-27.0.3.jar")
        if os.path.isfile(_dx):
            DX = _dx
            break
ANDROID_JAR = os.path.join(TOOLS, "android.jar")
if not os.path.isfile(ANDROID_JAR):
    for _base in [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
                  "D:/Android/AndoridSDK/platforms",
                  os.path.expanduser("~/Library/Android/sdk/platforms"),
                  os.path.expanduser("~/Android/Sdk/platforms"), "C:/Android/Sdk/platforms"]:
        if not _base:
            continue
        for _lv in ("android-34", "android-33", "android-32", "android-31"):
            _aj = os.path.join(_base, _lv, "android.jar")
            if os.path.isfile(_aj):
                ANDROID_JAR = _aj
                break
        else:
            continue
        break
SIGN_FRAMEWORK = EXEC_DIR

# -------------------------------------------------------------------------- #
# 签名密钥（加固后的 APK 用其签名；壳在运行期通过 PackageManager 读取同一证书派生密钥）
# -------------------------------------------------------------------------- #
KEYSTORE = os.path.join(TOOLS, "common.jks")
KEY_ALIAS = "common"
KEY_PASS = "123123"
CERT_DER = os.path.join(TOOLS, "common.cer")

# -------------------------------------------------------------------------- #
# 加固壳相关常量（必须与 GxApp.java 保持一致）
# -------------------------------------------------------------------------- #
MAGIC = b"JGS1"
META_ORIG = "gx.orig_app"
META_SSL_PINS = "gx.ssl_pins"
# P-CAPTURE 统一响应姿态：加固期注入，壳运行期读取覆盖默认 "log"
# 取值 "log"（默认，fail-safe，仅记日志）或 "exit"（命中即退出进程）。
META_STRENGTHEN = "gx.strengthen"
# P0-C 内存级 anti-dump 开关 meta 名（默认 "gx.antidump"，apply_stamp 覆盖为随机值）。
# 仅 --antidump 开启时 harden 把该 meta 值写为 "1"，壳运行期读取启用内存扫描。
META_ANTIDUMP = "gx.antidump"
# A·强反 Frida 开关 meta 名（默认 "gx.antifrida"，apply_stamp 覆盖为随机值）。
# 仅 --antifrida 开启时 harden 把该 meta 值写为 "1"，壳运行期读取启用 Frida 检测。
META_ANTIFRIDA = "gx.antifrida"
# P0-B 轻量：密钥派生 label 前缀（默认 "JG|"，apply_stamp 覆盖为随机值）。
# harden.py 加密端与壳解密端必须共用此变量，保证写读逐字节一致。
KEY_PREFIX = b"JG|"
# P0-B 真白盒：是否启用白盒融合派生（默认 False，opt-in，仅 --wb-kdf 开启）。
# 开启时 WB_SECRET 参与派生，native 侧经 WB_KDF 烘焙的 WB_STATE 融合，
# 与 harden/verify 的 whitebox_kdf.wb_derive 逐字节一致。
WB_KDF = False
WB_SECRET = b""
SHELL_APP = "com.gx.runtime.GxApp"
# 载荷 ZIP 条目名（默认 z9，随机化由 stamp 覆盖）
PAYLOAD_ENTRY = "z9"
# 注入到 APK 的 native 库文件名（不含 lib 前缀/ .so 后缀；默认 jgguard，随机化由 stamp 覆盖）
LIB_NAME = "jgguard"

# -------------------------------------------------------------------------- #
# 按构建随机化（抹壳特征）：从 build/stamp.json 覆盖上述常量。
# build_stub.py 每次加固先生成 stamp 并重建 stub.dex / .so，harden/verify/device_check
# 在本进程内调用 apply_stamp_from_file() 使写端与壳读端完全一致。
# -------------------------------------------------------------------------- #
_STAMP_PATH = os.path.join(BUILD_DIR, "stamp.json")


def apply_stamp(st):
    global MAGIC, META_ORIG, META_SSL_PINS, META_STRENGTHEN, SHELL_APP, PAYLOAD_ENTRY, LIB_NAME
    global SHELL_DEX_ENTRY, BOOTSTRAP_APP, KEY_PREFIX, WB_KDF, WB_SECRET, META_ANTIDUMP, META_ANTIFRIDA
    # 兼容旧 stamp.json：后加的键一律 .get() 兜底——exe 同级 build/ 里可能残留旧版
    # stamp.json（如 8/25 旧构建缺 meta_antidump/key_prefix/wb_*），硬下标会让 exe
    # 启动 import 阶段即 KeyError（踩过：KeyError 'meta_antidump'）。核心键
    # （magic/meta_orig/meta_ssl/meta_strengthen/pkg）P1 时代就有，仍用硬下标。
    MAGIC = st["magic"].encode("utf-8") if isinstance(st["magic"], str) else st["magic"]
    META_ORIG = st["meta_orig"]
    META_SSL_PINS = st["meta_ssl"]
    META_STRENGTHEN = st["meta_strengthen"]
    META_ANTIDUMP = st.get("meta_antidump", META_ANTIDUMP)
    META_ANTIFRIDA = st.get("meta_antifrida", META_ANTIFRIDA)
    _classes = st.get("classes", {})
    SHELL_APP = st["pkg"] + "." + _classes.get("GxApp", "GxApp")
    BOOTSTRAP_APP = st["pkg"] + "." + _classes.get("GxBootstrap", "GxBootstrap")
    PAYLOAD_ENTRY = st.get("payload_entry", PAYLOAD_ENTRY)
    LIB_NAME = st.get("lib_name", LIB_NAME)
    SHELL_DEX_ENTRY = st.get("shell_dex_entry", SHELL_DEX_ENTRY)
    KEY_PREFIX = st.get("key_prefix", KEY_PREFIX.decode("utf-8")).encode("utf-8")
    WB_KDF = bool(st.get("wb_kdf", False))
    WB_SECRET = bytes(st["wb_secret"]) if st.get("wb_secret") else b""


def apply_stamp_from_file(path=_STAMP_PATH):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            apply_stamp(json.load(f))

# -------------------------------------------------------------------------- #
# 工作/输出目录（放在 exe 同级，便于用户找到产物）
# -------------------------------------------------------------------------- #
WORK_DIR = os.path.join(EXEC_DIR, "work")
OUTPUT_DIR = os.path.join(EXEC_DIR, "output")
SAMPLES_DIR = os.path.join(EXEC_DIR, "test_apks")
GEN_DIR = os.path.join(EXEC_DIR, "gen_samples")


def _decode_bytes(b):
    """将外部工具（aapt/adb/java 等）输出字节解码为 str。

    这些原生/JVM 工具在中文 Windows 上常按系统代码页(cp936/GBK)输出，
    而本程序的管道统一用 UTF-8，若直接 utf-8 解码会乱码。这里依次尝试
    utf-8 -> gbk/cp936 -> 系统首选编码 -> utf-8(替换)，确保中文正确还原、绝不乱码。
    """
    encodings = ["utf-8", "gbk", "cp936"]
    sys_enc = locale.getpreferredencoding(False)
    if sys_enc and sys_enc.lower() not in ("utf-8", "utf8"):
        encodings.append(sys_enc)
    for enc in encodings:
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", errors="replace")


def rmtree_safe(path):
    """沙箱可能禁止目录删除（无回收站），尽力而为，失败不影响主流程。"""
    import shutil
    if not os.path.exists(path):
        return
    try:
        shutil.rmtree(path)
    except OSError:
        try:
            for root, dirs, files in os.walk(path, topdown=False):
                for f in files:
                    try:
                        os.remove(os.path.join(root, f))
                    except OSError:
                        pass
                for d in dirs:
                    try:
                        os.rmdir(os.path.join(root, d))
                    except OSError:
                        pass
        except OSError:
            pass
