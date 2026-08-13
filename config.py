# -*- coding: utf-8 -*-
"""
JGShield 加固工具集 - 共享配置
所有路径统一使用正斜杠（Windows 版 CPython 可正常识别）。

冻结为 exe 时，bundled 资源（tools/、stub.dex）从 sys._MEIPASS 解析；
输出/工作目录放在 exe 同级目录。非冻结时从本文件所在目录解析。
"""
import os
import sys
import locale


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

# -------------------------------------------------------------------------- #
# Java 运行时（apktool / uber-apk-signer / apksigner 均依赖 java）
# -------------------------------------------------------------------------- #
_JAVA_CANDIDATES = [
    "C:/Program Files/Java/jdk-11.0.21/bin/java.exe",
    "C:/Program Files/Java/jdk-17/bin/java.exe",
    "C:/Program Files/Java/jdk-21/bin/java.exe",
    "C:/Program Files/Java/jdk-22/bin/java.exe",
]
JAVA = None
for _j in _JAVA_CANDIDATES:
    if os.path.isfile(_j):
        JAVA = _j
        break
if not JAVA:
    JAVA = "java"  # 回退到 PATH

# -------------------------------------------------------------------------- #
# 外壳 DEX（由 ShieldApplication.java 编译而来，含 5 个壳类）
# -------------------------------------------------------------------------- #
STUB_DEX = os.path.join(_BUNDLE, "build", "dex", "stub.dex")

# -------------------------------------------------------------------------- #
# 第三方工具（全部 bundled 在 tools/ 下，exe 自包含）
# -------------------------------------------------------------------------- #
APKTOOL = os.path.join(TOOLS, "apktool.jar")
AAPT = os.path.join(TOOLS, "aapt.exe")
UBER = os.path.join(TOOLS, "uber-apk-signer.jar")
APKSIGNER = os.path.join(TOOLS, "apksigner.jar")

# keytool（用于从用户指定的 keystore 提取证书 DER 以派生种子）
if JAVA and os.path.basename(JAVA).lower().startswith("java"):
    _java_dir = os.path.dirname(JAVA)
    _kt = os.path.join(_java_dir, "keytool.exe")
    KEYTOOL = _kt if os.path.isfile(_kt) else "keytool"
else:
    KEYTOOL = "keytool"

# adb（bundled 或从 SDK / PATH 查找）
ADB = os.path.join(TOOLS, "adb.exe")
if not os.path.isfile(ADB):
    for _a in ["D:/Android/AndoridSDK/platform-tools/adb.exe",
               "C:/Android/Sdk/platform-tools/adb.exe"]:
        if os.path.isfile(_a):
            ADB = _a
            break
    else:
        ADB = "adb"  # 回退到 PATH

# DX / ANDROID_JAR（仅 gen_samples 用，best-effort）
DX = os.path.join(TOOLS, "dx.jar")
if not os.path.isfile(DX):
    _dx_alt = "D:/Android/Android Decompile/AndroidKiller_v1.3.1/bin/dex2jar/lib/dx-27.0.3.jar"
    DX = _dx_alt if os.path.isfile(_dx_alt) else DX
ANDROID_JAR = os.path.join(TOOLS, "android.jar")
if not os.path.isfile(ANDROID_JAR):
    _aj_alt = "D:/Android/AndoridSDK/platforms/android-33/android.jar"
    ANDROID_JAR = _aj_alt if os.path.isfile(_aj_alt) else ANDROID_JAR
SIGN_FRAMEWORK = EXEC_DIR

# -------------------------------------------------------------------------- #
# 签名密钥（加固后的 APK 用其签名；壳在运行期通过 PackageManager 读取同一证书派生密钥）
# -------------------------------------------------------------------------- #
KEYSTORE = os.path.join(TOOLS, "common.jks")
KEY_ALIAS = "common"
KEY_PASS = "123123"
CERT_DER = os.path.join(TOOLS, "common.cer")

# -------------------------------------------------------------------------- #
# 加固壳相关常量（必须与 ShieldApplication.java 保持一致）
# -------------------------------------------------------------------------- #
MAGIC = b"JGS1"
META_ORIG = "com.jiagu.orig_app"
SHELL_APP = "com.jiagu.shield.ShieldApplication"

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
