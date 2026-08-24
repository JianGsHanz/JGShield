# -*- coding: utf-8 -*-
"""
JGShield 壳指纹随机化（按构建唯一化）。

每次 harden 生成一份 stamp（随机包名 / 类名 / meta 键 / TAG / payload 条目 / 魔数 /
lib 名 / Obf 密钥），写入 build/stamp.json，作为 build_stub / harden / verify /
device_check 的唯一事实来源，确保「写端(manifest/payload)」与「壳读端(stub.dex/.so)」
完全一致。

这是「抹壳特征」的核心：MT 管理器 / ApkScan 之类工具依赖固定的
包名 com.gx.runtime、meta 键 gx.*、TAG GX、payload 条目 z9/jg、魔数 JGS1、
native 库名 libjgguard.so 来识别加固壳；全部随机化后，静态扫描无法用固定特征命中。
"""
import json
import os
import random
import string

HERE = os.path.dirname(os.path.abspath(__file__))
STAMP_PATH = os.path.join(HERE, "build", "stamp.json")

_ALNUM = string.ascii_letters + string.digits
# 魔数可用字符（可打印 ASCII，避开引号/反斜杠，避免 C/Java 字符串转义问题）
_MAGIC_CHARS = "!#$&()*+,-.0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"

# 需要随机化改名的全部壳类（含 4 个带 JNI 方法的类：GxGuard/GxKeys/GxDecryptor/Obf）
_SHELL_CLASSES = [
    "GxApp", "GxGuard", "GxKeys", "GxDecryptor", "GxAssets", "GxAntiDebug",
    "GxTamper", "GxAntiDump", "GxLoader", "GxPinning", "GxProxy", "Obf",
]


def _seg(n=4):
    """合法 Java 包名段：字母开头。"""
    return random.choice(string.ascii_lowercase) + \
        "".join(random.choice(_ALNUM) for _ in range(n - 1))


def _cls(n=6):
    """合法 Java 类名：大写字母开头。"""
    return random.choice(string.ascii_uppercase) + \
        "".join(random.choice(_ALNUM) for _ in range(n - 1))


def _uniq(used, gen):
    while True:
        v = gen()
        if v not in used and v not in ("com", "android", "java"):
            used.add(v)
            return v


def generate():
    """生成一份随机化 stamp。"""
    used = set()

    pkg = _uniq(used, lambda: _seg(4) + "." + _seg(4))
    classes = {c: _uniq(used, lambda: _cls(6)) for c in _SHELL_CLASSES}

    meta_orig = _uniq(used, lambda: "a" + _seg(4) + "." + "b" + _seg(4))
    meta_ssl = _uniq(used, lambda: "c" + _seg(4) + "." + "d" + _seg(4))
    meta_strengthen = _uniq(used, lambda: "e" + _seg(4) + "." + "f" + _seg(4))

    def _tag():
        return "".join(random.choice(string.ascii_letters + string.digits)
                       for _ in range(random.randint(3, 6)))

    tags = {t: _uniq(used, _tag)
            for t in ("app", "native", "at", "ad", "ssl", "vpn",
                      "native_log", "integrity_log", "mr_log",
                      "ih_log", "mrh_log")}

    payload_entry = _uniq(
        used,
        lambda: "".join(random.choice(string.ascii_lowercase + string.digits)
                         for _ in range(random.randint(2, 4))))

    magic = "".join(random.choice(_MAGIC_CHARS) for _ in range(4))

    lib_name = _uniq(
        used,
        lambda: "".join(random.choice(string.ascii_lowercase + string.digits)
                        for _ in range(random.randint(4, 6))))

    # Obf XOR 密钥：每构建随机，且仅存于 native（DEX 中不再出现）
    obf_key = [random.randint(0, 255) for _ in range(16)]

    return {
        "pkg": pkg,
        "pkg_underscore": pkg.replace(".", "_"),
        "classes": classes,
        "meta_orig": meta_orig,
        "meta_ssl": meta_ssl,
        "meta_strengthen": meta_strengthen,
        "tag_app": tags["app"], "tag_native": tags["native"], "tag_at": tags["at"],
        "tag_ad": tags["ad"], "tag_ssl": tags["ssl"], "tag_vpn": tags["vpn"],
        "tag_native_log": tags["native_log"], "tag_integrity_log": tags["integrity_log"],
        "tag_mr_log": tags["mr_log"], "tag_ih_log": tags["ih_log"],
        "tag_mrh_log": tags["mrh_log"],
        "payload_entry": payload_entry,
        "magic": magic,
        "lib_name": lib_name,
        "obf_key": obf_key,
    }


def write(path, st):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(st, f, indent=2)


def load(path=STAMP_PATH):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
