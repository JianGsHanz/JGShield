"""DEX 字符串加密（抗 AI 静态逆向）。

策略
----
在 harden 链路里、App 原始 DEX 被加密进载荷 *之前*，把每个 `const-string` 指令改写为：
    const-string vX, "<base64(XOR(原串))>"
    invoke-static {vX}, Lcom/jiagu/obf/ObfStr;->d(Ljava/lang/String;)Ljava/lang/String;
    move-result-object vX
解密器 `ObfStr.d` 以独立 obf.dex 随载荷加载（与 App DEX 同一 classloader），运行时把密文还原。

为什么这样做（而非改壳或 OLLVM）：
- 只加密 App 自身的字符串常量（URL / key / 日志 / 错误文案 / 反射用类名等），直接打掉
  "JADX + LLM 读 DEX" 的语义来源，对被动 LLM 杠杆最大。
- 不碰类名/方法名（不触发 manifest / 反射 / JNI 崩坏）。
- 解密器在独立 obf.dex，密钥不落 App DEX；obf.dex 本身随载荷 AES-GCM 加密，at-rest 也受保护。
- 纯离线：smali 改写用 apktool（仓库已有），解密器纯 java（无 android 依赖，可 JVM 单测）。

解密器 obf.dex 重建（源码 src/java/com/jiagu/obf/ObfStr.java，纯 java.lang）：
    # d8 编成 zip 后取 classes.dex 重命名
    java -cp tools/d8.jar com.android.tools.r8.D8 --min-api 21 \
         --lib tools/android.jar --output tools/obf.zip \
         src/java/com/jiagu/obf/ObfStr.java
    unzip -p tools/obf.zip classes.dex > tools/obf.dex
KEY 必须与 ObfStr.java 的 KEY 字段、本文件 OBF_KEY 三者完全一致（当前 b"JGShieldDEXobf01"）。

约束 / 边界（诚实）
----------------
- 这是"混淆"不是"加密"：DEX 解密加载后明文常驻，攻击者跑起来即可抽；价值在抬高静态 AI 成本。
- 跳过含反斜杠 `\\` 的字符串（smali 转义安全，避免把 `\\"` 等误改坏），这类占比极低。
- 解密器类名**每次加固随机化**（B3'）：`gen_dec_class()` 生成随机包名+类名，从模板实时 javac+d8 编译 obf.dex，
  消除固定静态锚点 `Lcom/jiagu/obf/ObfStr;`（逆向者 grep `ObfStr;->d` 即可定位所有解密点）。随机编译失败才回退固定名。
- 密钥固定 16 字节（与 ObfStr.java 必须一致）。
"""
import os
import re
import base64
import zipfile
import shutil
import subprocess

import random

import config

OBF_KEY = b"JGShieldDEXobf01"
DEC_CLASS = "Lcom/jiagu/obf/ObfStr;"   # 固定回退名（随机编译失败时用，与 tools/obf.dex 一致）
DEC_METHOD = DEC_CLASS + "->d(Ljava/lang/String;)Ljava/lang/String;"
OBF_DEX = os.path.join(config.TOOLS, "obf.dex")
OBF_SRC_TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "src", "java", "com", "jiagu", "obf", "ObfStr.java")
D8_JAR = os.path.join(config.TOOLS, "d8.jar")


def _javac_path():
    """从 config.JAVA(java.exe) 派生同目录 javac.exe。"""
    j = config.JAVA
    if j and os.path.basename(j).lower().startswith("java"):
        return os.path.join(os.path.dirname(j), "javac.exe")
    return "javac"  # PATH 回退


JAVAC = _javac_path()

# const-string vN, "LIT"   /   const-string/jumbo vN, "LIT"
_CS_RE = re.compile(
    r'^(?P<ind>\s*)const-string(/jumbo)?\s+(?P<reg>v[0-9a-fA-F]+),\s*"(?P<lit>.*)"\s*$'
)

_SUBPROC_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run_java(args):
    subprocess.check_call([config.JAVA, "-jar"] + args,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          creationflags=_SUBPROC_FLAGS)


def encrypt_string(s):
    ct = bytes(c ^ OBF_KEY[i % len(OBF_KEY)] for i, c in enumerate(s.encode("utf-8")))
    return base64.b64encode(ct).decode("ascii")


def obf_dec_method(dec_class):
    """解密器静态方法引用，随 dec_class 变化（B3' 随机化）。"""
    return dec_class + "->d(Ljava/lang/String;)Ljava/lang/String;"


def gen_dec_class():
    """生成随机解密器类描述符，如 `La7F3k/pQ2xZ;`（包名+类名均随机，无 com/jiagu/obf 前缀）。

    每次加固唯一化，消除固定静态锚点 `Lcom/jiagu/obf/ObfStr;`（逆向者 grep `ObfStr;->d`
    即可定位所有解密点）。契合 JGShield「靠随机化对抗熟悉 mociika-shield 者」的核心思路。
    """
    alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    alnum = alpha + "0123456789"
    pkg = random.choice(alpha) + "".join(random.choice(alnum) for _ in range(random.randint(4, 9)))
    cls = random.choice(alpha) + "".join(random.choice(alnum) for _ in range(random.randint(4, 9)))
    return "L%s/%s;" % (pkg, cls)


def compile_obf_dex(dec_class, workdir):
    """从模板生成随机类名的解密器，javac --release 8 -> d8 --min-api 21 -> classes.dex。

    返回 obf.dex 字节。失败时抛异常（调用方回退到固定名 tools/obf.dex）。
    算法与 ObfStr.java / encrypt_string 必须一致（KEY=b"JGShieldDEXobf01"）。
    """
    if not os.path.isfile(OBF_SRC_TEMPLATE):
        raise RuntimeError("缺少解密器模板 %s" % OBF_SRC_TEMPLATE)
    desc = dec_class.strip("L").rstrip(";")          # a7F3k/pQ2xZ
    pkg, cls = desc.split("/")
    srcdir = os.path.join(workdir, "_obfsrc")
    pkgdir = os.path.join(srcdir, pkg)
    os.makedirs(pkgdir, exist_ok=True)
    jpath = os.path.join(pkgdir, cls + ".java")
    tmpl = open(OBF_SRC_TEMPLATE, "r", encoding="utf-8").read()
    tmpl = tmpl.replace("package com.jiagu.obf;", "package %s;" % pkg)
    tmpl = tmpl.replace("public class ObfStr", "public class %s" % cls)
    with open(jpath, "w", encoding="utf-8") as f:
        f.write(tmpl)

    outdir = os.path.join(workdir, "_obfcls")
    shutil.rmtree(outdir, ignore_errors=True)
    os.makedirs(outdir, exist_ok=True)
    try:
        subprocess.check_call([JAVAC, "-encoding", "UTF-8", "--release", "8", "-d", outdir, jpath],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             creationflags=_SUBPROC_FLAGS)
    except subprocess.CalledProcessError as e:
        raise RuntimeError("javac 失败: " + (e.stderr or b"").decode("utf-8", "replace"))
    classfile = os.path.join(outdir, pkg, cls + ".class")

    zippath = os.path.join(workdir, "_obf_tmp.zip")
    if os.path.isfile(zippath):
        os.remove(zippath)
    try:
        subprocess.check_call([config.JAVA, "-cp", D8_JAR, "com.android.tools.r8.D8",
                              "--min-api", "21", "--lib", config.ANDROID_JAR,
                              "--output", zippath, classfile],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             creationflags=_SUBPROC_FLAGS)
    except subprocess.CalledProcessError as e:
        raise RuntimeError("d8 失败: " + (e.stderr or b"").decode("utf-8", "replace"))
    with zipfile.ZipFile(zippath) as z:
        return z.read("classes.dex")


def _transform_smali(path, dec_class):
    changed = 0
    dec_method = obf_dec_method(dec_class)
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = _CS_RE.match(line.rstrip("\n"))
            if m and m.group("lit") != "" and "\\" not in m.group("lit"):
                reg = m.group("reg")
                b64 = encrypt_string(m.group("lit"))
                ind = m.group("ind")
                out.append('%sconst-string %s, "%s"\n' % (ind, reg, b64))
                out.append("%sinvoke-static {%s}, %s\n" % (ind, reg, dec_method))
                out.append("%smove-result-object %s\n" % (ind, reg))
                changed += 1
            else:
                out.append(line)
    if changed:
        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(out))
    return changed


def obfuscate_apk(input_apk, workdir, dec_class):
    """对整个 APK 做 DEX 字符串加密，返回 (dex 字节列表[按 classes.dex, classes2.dex... 排序], 改写条数)。

    实现：apktool 解码整包（含 res/，aapt2 才能正确回编 manifest）→ 改写所有 smali 的
    const-string → 加密+调用解密器(dec_class 决定解密器类，B3' 随机化) → apktool 回编整包
    → 只抽取回编后的 classes*.dex。最终加固产物的资源仍来自原始 APK（harden 走 zip 直打包），
    这里仅借用回编后的 DEX，因此资源被 apktool 重编译不影响交付物。
    """
    os.makedirs(workdir, exist_ok=True)
    dec = os.path.join(workdir, "dec")
    reb = os.path.join(workdir, "reb.apk")
    shutil.rmtree(dec, ignore_errors=True)
    _run_java([config.APKTOOL, "d", input_apk, "-o", dec, "-f"])

    total = 0
    for root, _, files in os.walk(dec):
        for fn in files:
            if fn.endswith(".smali"):
                total += _transform_smali(os.path.join(root, fn), dec_class)

    _run_java([config.APKTOOL, "b", dec, "-o", reb])

    out = []
    with zipfile.ZipFile(reb) as z:
        for n in z.namelist():
            m = re.match(r"classes(\d*)\.dex$", n)
            if m:
                num = m.group(1)
                out.append(((0, 0) if num == "" else (1, int(num)), z.read(n)))
    out.sort(key=lambda kv: kv[0])
    return [b for _, b in out], total


def load_obf_dex():
    if not os.path.isfile(OBF_DEX):
        raise RuntimeError("缺少解密器 %s（请先 d8 编译 ObfStr -> obf.dex）" % OBF_DEX)
    with open(OBF_DEX, "rb") as f:
        return f.read()
