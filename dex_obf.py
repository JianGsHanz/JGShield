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
- 解密器类名固定 `Lcom/jiagu/obf/ObfStr;`（v1 为稳妥未随机化；随机化列入后续）。
- 密钥固定 16 字节（与 ObfStr.java 必须一致）。
"""
import os
import re
import base64
import zipfile
import shutil
import subprocess

import config

OBF_KEY = b"JGShieldDEXobf01"
DEC_CLASS = "Lcom/jiagu/obf/ObfStr;"
DEC_METHOD = DEC_CLASS + "->d(Ljava/lang/String;)Ljava/lang/String;"
OBF_DEX = os.path.join(config.TOOLS, "obf.dex")

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


def _transform_smali(path):
    changed = 0
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = _CS_RE.match(line.rstrip("\n"))
            if m and m.group("lit") != "" and "\\" not in m.group("lit"):
                reg = m.group("reg")
                b64 = encrypt_string(m.group("lit"))
                ind = m.group("ind")
                out.append('%sconst-string %s, "%s"\n' % (ind, reg, b64))
                out.append("%sinvoke-static {%s}, %s\n" % (ind, reg, DEC_METHOD))
                out.append("%smove-result-object %s\n" % (ind, reg))
                changed += 1
            else:
                out.append(line)
    if changed:
        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(out))
    return changed


def obfuscate_apk(input_apk, workdir):
    """对整个 APK 做 DEX 字符串加密，返回 (dex 字节列表[按 classes.dex, classes2.dex... 排序], 改写条数)。

    实现：apktool 解码整包（含 res/，aapt2 才能正确回编 manifest）→ 改写所有 smali 的
    const-string → 加密+调用解密器 → apktool 回编整包 → 只抽取回编后的 classes*.dex。
    最终加固产物的资源仍来自原始 APK（harden 走 zip 直打包），这里仅借用回编后的 DEX，
    因此资源被 apktool 重编译不影响交付物。
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
                total += _transform_smali(os.path.join(root, fn))

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
