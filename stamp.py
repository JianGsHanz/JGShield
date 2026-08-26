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

import config

# STAMP 是「写端 / 读端」的唯一事实来源。
# 关键：冻结态（PyInstaller onefile）下 _MEIPASS 是只读临时解压目录，build_stub 写入的
# stamp 若落在此处，config.apply_stamp_from_file() 从 EXEC_DIR/build 读取会读不到 →
# apply_stamp 不生效 → Manifest 写入默认固定类 com.gx.runtime.GxBootstrap，但 dex 内类已
# 随机化 → 真机 ClassNotFoundException 闪退。故必须直接复用 config.BUILD_DIR（exe 同级、
# 可写且持久），与 config._STAMP_PATH 完全同一对象，杜绝路径分裂。
STAMP_PATH = os.path.join(config.BUILD_DIR, "stamp.json")

_ALNUM = string.ascii_letters + string.digits
# 魔数可用字符（可打印 ASCII，避开引号/反斜杠，避免 C/Java 字符串转义问题）
_MAGIC_CHARS = "!#$&()*+,-.0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"

# 需要随机化改名的全部壳类（含 4 个带 JNI 方法的类：GxGuard/GxKeys/GxDecryptor/Obf）
# P8：新增 GxBootstrap（引导壳，也纳入随机化以抹特征）
_SHELL_CLASSES = [
    "GxApp", "GxGuard", "GxKeys", "GxDecryptor", "GxAssets", "GxAntiDebug",
    "GxTamper", "GxAntiDump", "GxLoader", "GxPinning", "GxProxy", "Obf",
    "GxBootstrap",
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


def generate(wb_kdf=False):
    """生成一份随机化 stamp。

    wb_kdf: 是否启用 P0-B 真白盒融合派生（默认 False，opt-in，仅 --wb-kdf 开启）。
    开启时 wb_secret 仍随机生成并烘焙进 .so 的 WB_STATE；关闭时 wb_secret 仍生成
    但 native 走干净 HMAC、WB_STATE 无意义。"""
    used = set()

    pkg = _uniq(used, lambda: _seg(4) + "." + _seg(4))
    classes = {c: _uniq(used, lambda: _cls(6)) for c in _SHELL_CLASSES}

    meta_orig = _uniq(used, lambda: "a" + _seg(4) + "." + "b" + _seg(4))
    meta_ssl = _uniq(used, lambda: "c" + _seg(4) + "." + "d" + _seg(4))
    meta_strengthen = _uniq(used, lambda: "e" + _seg(4) + "." + "f" + _seg(4))
    # P0-C 内存级 anti-dump 开关 meta：默认不注入（关闭）；--antidump 时 harden 注入值 "1"。
    meta_antidump = _uniq(used, lambda: "g" + _seg(4) + "." + "h" + _seg(4))
    # A·强反 Frida 开关 meta：默认不注入（关闭）；--antifrida 时 harden 注入值 "1"。
    meta_antifrida = _uniq(used, lambda: "i" + _seg(4) + "." + "j" + _seg(4))

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

    # P8 加密壳 DEX 的随机 zip 条目名（Bootstrap 从此条目读加密壳 DEX）
    shell_dex_entry = _uniq(
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

    # P0-B 轻量：密钥派生 label 前缀，每构建随机，消除固定 "JG|" 明文分隔符。
    # 必须同时注入 Java/C 源码（build_stub）并写入 method_restore_vectors.h，
    # 且 harden.py 加密端从同一 stamp 读取 config.KEY_PREFIX —— 写读逐字节一致。
    # 仅用字母/数字，避免 C/Java 字符串字面量转义问题。
    key_prefix = "".join(random.choice(string.ascii_letters + string.digits)
                         for _ in range(random.randint(2, 4)))

    # P0-B 真白盒：白盒融合密钥（每 stub 随机）。非密钥本身，而是用于把干净
    # HMAC(seed, msg) 再经一次以 wb_secret 预处理态为起点的 SHA256，使 .so 内
    # 不再出现连续的 seed 字面量、也不再有可被一行 HMAC() 直接复用的干净派生。
    # 诚实边界：seed 仍可由 APK 证书+salt 重建 → 白盒只提成本不补秘密；默认关，
    # 仅 --wb-kdf 开启。wb_secret 仅以「融合后的 WB_STATE」形式出现在 .so/烘焙期，
    # 不暴露连续字面量。
    wb_kdf = bool(wb_kdf)
    wb_secret = [random.randint(0, 255) for _ in range(32)]

    return {
        "pkg": pkg,
        "pkg_underscore": pkg.replace(".", "_"),
        "classes": classes,
        "meta_orig": meta_orig,
        "meta_ssl": meta_ssl,
        "meta_strengthen": meta_strengthen,
        "meta_antidump": meta_antidump,
        "meta_antifrida": meta_antifrida,
        "tag_app": tags["app"], "tag_native": tags["native"], "tag_at": tags["at"],
        "tag_ad": tags["ad"], "tag_ssl": tags["ssl"], "tag_vpn": tags["vpn"],
        "tag_native_log": tags["native_log"], "tag_integrity_log": tags["integrity_log"],
        "tag_mr_log": tags["mr_log"], "tag_ih_log": tags["ih_log"],
        "tag_mrh_log": tags["mrh_log"],
        "payload_entry": payload_entry,
        "shell_dex_entry": shell_dex_entry,
        "magic": magic,
        "lib_name": lib_name,
        "obf_key": obf_key,
        "key_prefix": key_prefix,
        "wb_kdf": wb_kdf,
        "wb_secret": wb_secret,
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
