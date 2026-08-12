# -*- coding: utf-8 -*-
"""
载荷校验：读取加固 APK 中自定义顶层 ZIP 条目 "jg"（JGS1 魔数），
用相同种子解密并还原原始 DEX，与输入逐一比对。
被 harden.py（内嵌回测）与 verify.py（静态回测）复用。
"""
import os
import re
import struct
import zipfile
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

import config

def load_seed():
    """回退用：从内置证书派生种子（仅当未提供用户 keystore 时）。"""
    with open(config.CERT_DER, "rb") as f:
        cert = f.read()
    return SHA256.new(cert).digest()

# --------------------------------------------------------------------------
# 从已签名 APK 自身的 META-INF 签名块提取证书，派生种子。
# 与设备端 DeriveKeys.certDer 取得同一证书，验证无需用户提供 keystore。
# --------------------------------------------------------------------------
def _der_read(data, off):
    tag = data[off]; off += 1
    length = data[off]; off += 1
    if length & 0x80:
        nbytes = length & 0x7f
        length = int.from_bytes(data[off:off + nbytes], "big")
        off += nbytes
    return tag, length, off, off + length

def _cert_from_pkcs7(data):
    # ContentInfo ::= SEQUENCE { OID, [0] EXPLICIT SignedData }
    t, _, vs, n = _der_read(data, 0)
    if t != 0x30:
        raise RuntimeError("非 PKCS7 ContentInfo")
    _, _, v1, n1 = _der_read(data, vs)
    t2, _, v2, _ = _der_read(data, n1)            # [0] EXPLICIT SignedData
    t3, _, v3, _ = _der_read(data, v2)            # SignedData SEQUENCE
    if t3 != 0x30:
        raise RuntimeError("非 SignedData")
    p = v3
    _, _, _, p = _der_read(data, p)               # version INTEGER
    _, _, _, p = _der_read(data, p)               # digestAlgorithms SET
    _, _, _, p = _der_read(data, p)               # encapContentInfo SEQUENCE
    t4, _, v4, _ = _der_read(data, p)             # [0] certificates
    if t4 != 0xA0:
        raise RuntimeError("签名块中未找到 certificates")
    ct, _, cv, cn = _der_read(data, v4)           # 第一个 Certificate（v4 指向其 SEQUENCE 标签）
    if ct != 0x30:
        raise RuntimeError("certificates 首元素非 Certificate")
    # 返回从 Certificate 标签开始到结束的完整 DER（含 tag+length 头），
    # 否则会少算 4 字节导致与 keytool 导出的证书 SHA256 不一致。
    return data[v4:cn]

def seed_from_apk(apk_path):
    with zipfile.ZipFile(apk_path) as z:
        names = [n for n in z.namelist()
                 if n.startswith("META-INF/")
                 and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))]
        if not names:
            raise RuntimeError("APK 中未找到签名证书 (META-INF/*.RSA)")
        der = z.read(names[0])
    cert = _cert_from_pkcs7(der)
    return SHA256.new(cert).digest()

def derive_key(seed, idx):
    mac = HMAC.new(seed, digestmod=SHA256)
    mac.update(b"JG|dex" + str(idx).encode("utf-8"))
    return mac.digest()

def _read_int(b, off):
    return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8) \
        | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24)

def parse_payload(apk_path, seed=None):
    """返回 (count, [decrypted_dex_bytes, ...]) 或抛异常。
    种子默认从加固产物自身的签名证书派生（与设备端一致），
    无需用户提供 keystore。"""
    with zipfile.ZipFile(apk_path) as z:
        names = z.namelist()
        if "classes.dex" not in names:
            raise RuntimeError("APK 中无 classes.dex")
        if "jg" not in names:
            raise RuntimeError("APK 中无 jg 载荷条目")
        tail = z.read("jg")
    if len(tail) < 8:
        raise RuntimeError("jg 载荷过短")
    if tail[0:4] != config.MAGIC:
        raise RuntimeError("魔数不匹配: %r" % tail[0:4])
    p = 4
    count = _read_int(tail, p)
    p += 4
    if seed is None:
        seed = seed_from_apk(apk_path)
    dexs = []
    for i in range(count):
        ln = _read_int(tail, p)
        p += 4
        blob = tail[p:p + ln]
        p += ln
        iv = blob[0:12]
        rest = blob[12:]
        key = derive_key(seed, i)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        comp = cipher.decrypt_and_verify(rest[:-16], rest[-16:])
        dex = zlib.decompress(comp)
        dexs.append(dex)
    return count, dexs

def check_payload(apk_path, orig_dexes, seed=None):
    """解密还原并与原始 DEX 列表比对。返回 (ok, detail)。
    种子默认从加固产物自身的签名证书派生（与设备端一致）。"""
    try:
        if seed is None:
            seed = seed_from_apk(apk_path)
        count, dexs = parse_payload(apk_path)
        if count != len(orig_dexes):
            return False, "dex 数量不符: 载荷=%d 原始=%d" % (count, len(orig_dexes))
        for i, (got, exp) in enumerate(zip(dexs, orig_dexes)):
            if got != exp:
                return False, "第 %d 个 dex 解密后与原始不一致 (len %d vs %d)" % (
                    i, len(got), len(exp))
        return True, "ok"
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)
