# -*- coding: utf-8 -*-
"""
载荷校验：读取加固 APK 中自定义顶层 ZIP 条目 "z9"（JGS1 魔数），
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

def load_cert_hash():
    """回退用：内置证书的 cert_hash = SHA256(证书DER)（仅当未提供用户 keystore 时）。"""
    with open(config.CERT_DER, "rb") as f:
        cert = f.read()
    return SHA256.new(cert).digest()

load_seed = load_cert_hash  # 兼容旧调用名

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

def extract_salt(apk_path):
    """从 jg 载荷末尾取 32B build_salt（HKDF-Extract 加盐派生的盐）。
    所有区段解析器读完 dex+asset+method 后自然停住、从不触及这 32B，
    故盐安全地位于载荷最末。"""
    with zipfile.ZipFile(apk_path) as z:
        if "z9" not in z.namelist():
            raise RuntimeError("APK 中无 jg 载荷条目")
        tail = z.read("z9")
    if len(tail) < 32:
        raise RuntimeError("jg 载荷过短，无法提取 salt trailer")
    return tail[-32:]

def seed_from_apk(apk_path):
    """与设备端 DeriveKeys.seed(ctx,salt) 一致：
      cert_hash = SHA256(签名证书DER)      # 从加固产物自身 META-INF 证书取
      salt      = jg 载荷末 32B
      seed      = HMAC-SHA256(key=salt, msg=cert_hash)   # HKDF-Extract
    无需用户提供 keystore（证书从产物自身读取，与真机运行时相同）。"""
    with zipfile.ZipFile(apk_path) as z:
        names = [n for n in z.namelist()
                 if n.startswith("META-INF/")
                 and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))]
        if not names:
            raise RuntimeError("APK 中未找到签名证书 (META-INF/*.RSA)")
        der = z.read(names[0])
    cert = _cert_from_pkcs7(der)
    cert_hash = SHA256.new(cert).digest()
    salt = extract_salt(apk_path)
    mac = HMAC.new(salt, digestmod=SHA256)
    mac.update(cert_hash)
    return mac.digest()

def derive_key(seed, idx, label=b"dex"):
    mac = HMAC.new(seed, digestmod=SHA256)
    mac.update(b"JG|" + label + str(idx).encode("utf-8"))
    return mac.digest()

def derive_method_key(seed, dex_idx):
    """与 harden.py 的 extract_methods 完全一致：HMAC(seed, "JG|m"+dexIdx)，per-dex 密钥。"""
    mac = HMAC.new(seed, digestmod=SHA256)
    mac.update(b"JG|m" + str(dex_idx).encode("utf-8"))
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
        if "z9" not in names:
            raise RuntimeError("APK 中无 jg 载荷条目")
        tail = z.read("z9")
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
    种子默认从加固产物自身的签名证书派生（与设备端一致）。
    P3.1：若载荷含方法区段，先用其密文把「NOP 化 dex」还原回原始，再比对。"""
    try:
        if seed is None:
            seed = seed_from_apk(apk_path)
        count, dexs = parse_payload(apk_path)
        if count != len(orig_dexes):
            return False, "dex 数量不符: 载荷=%d 原始=%d" % (count, len(orig_dexes))
        # P3.1 还原：若有方法区段，用 per-dex 拼流密文把 NOP 化 dex 还原回原始
        methods_secs = parse_methods(apk_path, seed)
        if methods_secs:
            dexs = [bytearray(d) for d in dexs]
            for (dex_idx, stream_blob, entries) in methods_secs:
                iv = stream_blob[0:12]
                rest = stream_blob[12:]
                key = derive_method_key(seed, dex_idx)
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                comp = cipher.decrypt_and_verify(rest[:-16], rest[-16:])
                buf = zlib.decompress(comp)   # 整体 inflate 得到拼流
                for (method_idx, code_off, insns_size, offset, length) in entries:
                    insns = buf[offset:offset + length]
                    ins_off = code_off + 16
                    dexs[dex_idx][ins_off:ins_off + len(insns)] = insns
            dexs = [bytes(d) for d in dexs]
        for i, (got, exp) in enumerate(zip(dexs, orig_dexes)):
            if got != exp:
                return False, "第 %d 个 dex 解密/还原后与原始不一致 (len %d vs %d)" % (
                    i, len(got), len(exp))
        return True, "ok"
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)

# --------------------------------------------------------------------------
# 资产区段解析与校验（与 harden.py 的 build_payload 资产区段格式对齐）
# 资产区段位于 dex 区段之后：[asset_count][name_len,name,len,blob]...
# --------------------------------------------------------------------------
def parse_assets(apk_path, seed=None):
    """返回 [(name, decrypted_bytes), ...] 或抛异常。无资产区段时返回空列表。"""
    with zipfile.ZipFile(apk_path) as z:
        names = z.namelist()
        if "z9" not in names:
            raise RuntimeError("APK 中无 jg 载荷条目")
        tail = z.read("z9")
    if len(tail) < 8:
        raise RuntimeError("jg 载荷过短")
    if tail[0:4] != config.MAGIC:
        raise RuntimeError("魔数不匹配")
    p = 4
    dex_count = _read_int(tail, p)
    p += 4
    for _ in range(dex_count):
        ln = _read_int(tail, p)
        p += 4
        p += ln
    if p + 4 > len(tail):
        return []  # 无 asset 区段
    asset_count = _read_int(tail, p)
    p += 4
    if asset_count <= 0:
        return []
    if seed is None:
        seed = seed_from_apk(apk_path)
    assets = []
    for i in range(asset_count):
        nl = _read_int(tail, p)
        p += 4
        name = tail[p:p + nl].decode("utf-8")
        p += nl
        ln = _read_int(tail, p)
        p += 4
        blob = tail[p:p + ln]
        p += ln
        iv = blob[0:12]
        rest = blob[12:]
        key = derive_key(seed, i, b"asset")
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        comp = cipher.decrypt_and_verify(rest[:-16], rest[-16:])
        data = zlib.decompress(comp)
        assets.append((name, data))
    return assets

def check_assets(apk_path, orig_assets, seed=None):
    """解密还原并与原始 assets 列表（顺序一致）比对。返回 (ok, detail)。"""
    try:
        if seed is None:
            seed = seed_from_apk(apk_path)
        got = parse_assets(apk_path, seed)
        if len(got) != len(orig_assets):
            return False, "asset 数量不符: 载荷=%d 原始=%d" % (len(got), len(orig_assets))
        for (gn, gd), (on, od) in zip(got, orig_assets):
            if gn != on or gd != od:
                return False, "asset 不一致: %s (len %d vs %d)" % (gn, len(gd), len(od))
        return True, "ok"
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)

# --------------------------------------------------------------------------
# P3.1 方法区段解析（与 harden.py 的 build_payload 方法区段格式对齐）
# 方法区段位于 dex 区段 + 资产区段之后：
#   [method_dex_count]
#   for each: [dex_idx][entry_count][ (method_idx, code_off, insns_size, blob) ]...
# --------------------------------------------------------------------------
def parse_methods(apk_path, seed=None):
    """返回 [(dex_idx, stream_blob, [(method_idx, code_off, insns_size,
    offset_in_stream, len_in_stream), ...]), ...]。无方法区段时返回空列表。

    与 harden.py build_payload / jg_method_restore.c 新格式对齐（P6）：
    每 dex 一条 stream_blob(iv12+AES-GCM(zlib(concat_insns))+tag16)，
    元数据表 meta_blob = zlib( (method_idx,code_off,insns_size)[u32]×count )，
    还原端 inflate 后按序推得 offset/len，故此处重建为 5-tuple 供 check_payload 复用。"""
    with zipfile.ZipFile(apk_path) as z:
        names = z.namelist()
        if "z9" not in names:
            raise RuntimeError("APK 中无 jg 载荷条目")
        tail = z.read("z9")
    if len(tail) < 8:
        raise RuntimeError("jg 载荷过短")
    if tail[0:4] != config.MAGIC:
        raise RuntimeError("魔数不匹配")
    p = 4
    dex_count = _read_int(tail, p); p += 4
    for _ in range(dex_count):              # 跳过 dex 区段
        ln = _read_int(tail, p); p += 4; p += ln
    if p + 4 > len(tail):
        return []
    asset_count = _read_int(tail, p); p += 4
    for _ in range(asset_count):            # 跳过资产区段
        nl = _read_int(tail, p); p += 4; p += nl
        ln = _read_int(tail, p); p += 4; p += ln
    if p + 4 > len(tail):
        return []
    method_dex_count = _read_int(tail, p); p += 4
    if method_dex_count <= 0:
        return []
    sections = []
    for _ in range(method_dex_count):
        dex_idx = _read_int(tail, p); p += 4
        ec = _read_int(tail, p); p += 4
        sln = _read_int(tail, p); p += 4
        stream_blob = tail[p:p + sln]; p += sln
        mlen = _read_int(tail, p); p += 4
        meta_blob = tail[p:p + mlen]; p += mlen
        entries = []
        if mlen > 0 and ec > 0:
            raw = zlib.decompress(meta_blob)
            # 每行 (method_idx, code_off, insns_size) 共 12B；offset/len 由累计推得
            run = 0
            for k in range(ec):
                base = k * 12
                method_idx = struct.unpack_from("<I", raw, base)[0]
                code_off = struct.unpack_from("<I", raw, base + 4)[0]
                insns_size = struct.unpack_from("<I", raw, base + 8)[0]
                offset = run
                length = insns_size * 2
                run += length
                entries.append((method_idx, code_off, insns_size, offset, length))
        sections.append((dex_idx, stream_blob, entries))
    return sections
