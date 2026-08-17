# -*- coding: utf-8 -*-
"""
P3.2 字节级契约验证（沙箱内可执行的“native 写回”模拟器）。

目的：在沙箱无 NDK / 无真机的情况下，严格验证
  harden.py(P3.1 抽取) 产出的载荷格式  <-->  native 写回逻辑  <-->  原始 DEX
三者的字节契约完全一致。native 侧 C 代码必须按本脚本的解析/解密/写回步骤实现。

流程（与 native 将执行的步骤一一对应）：
  1. 读原始 DEX（来自未加固 APK）
  2. seed = SHA256(内置证书)   [与设备端 DeriveKeys.seed 一致]
  3. harden.extract_methods -> (NOP 化 DEX, stream_blob, [(method_idx, code_off, insns_size, offset_in_stream, len_in_stream), ...])
  4. harden.build_payload -> 真实 jg 载荷（dex 段加密 + 方法段）
  5. 【native 视角】按字节偏移解析载荷：
       MAGIC(4) + dex_count(4)
       + 每个 dex: len(4) + blob
       + asset_count(4) + 每个 asset: name_len(4)+name+len(4)+blob
       + method_dex_count(4)
           每个 dex: dex_idx(4) + entry_count(4) + stream_blob_len(4) + stream_blob
               每个 entry: method_idx(4) + code_off(4) + insns_size(4) + offset_in_stream(4) + len_in_stream(4)
  6. 解密 dex 段 -> 得到 NOP 化 DEX，断言 == 步骤3的 NOP 化 DEX
  7. 对每个方法 entry：
        key = HMAC-SHA256(seed, "JG|m"+dexIdx)   # per-dex 密钥，整 dex 方法码一条流
        stream_blob = dex段(stream_blob_len); iv = stream_blob[0:12]; ct = stream_blob[12:-16]; tag = stream_blob[-16:]
        buf = zlib.decompress( AES-GCM(key, iv, ct, tag) )   # 拼流
        insns = buf[offset_in_stream : offset_in_stream+len_in_stream]
        写回 dex[code_off+16 : code_off+16+len(insns)]
     断言写回后的 DEX == 原始 DEX
"""
import os
import sys
import zipfile
import zlib
import struct

import config
import harden
import verify_payload
from Crypto.Cipher import AES

SAMPLES = [os.path.join(config.SAMPLES_DIR, "sample%d.apk" % i) for i in range(1, 11)]


def u32(b, off):
    return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8) \
        | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24)


def gcm_decrypt(key, blob):
    iv = blob[0:12]
    rest = blob[12:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    comp = cipher.decrypt_and_verify(rest[:-16], rest[-16:])
    return zlib.decompress(comp)


def simulate_native_writeback(seed, payload, orig_dexes):
    """复刻 native jg_restore_methods 的解析+解密+写回，返回 (ok, msg)。"""
    if payload[0:4] != config.MAGIC:
        return False, "magic mismatch"
    p = 4
    dex_count = u32(payload, p); p += 4
    # ---- dex 段 ----
    dex_blobs = []
    for _ in range(dex_count):
        ln = u32(payload, p); p += 4
        dex_blobs.append(payload[p:p + ln]); p += ln
    # ---- asset 段（native 跳过）----
    asset_count = u32(payload, p); p += 4
    for _ in range(asset_count):
        nl = u32(payload, p); p += 4; p += nl
        ln = u32(payload, p); p += 4; p += ln
    # ---- 方法段 ----
    if p + 4 > len(payload):
        return False, "no method section"
    method_dex_count = u32(payload, p); p += 4
    if method_dex_count <= 0:
        return False, "empty method section"
    sections = []
    for _ in range(method_dex_count):
        dex_idx = u32(payload, p); p += 4
        ec = u32(payload, p); p += 4
        sln = u32(payload, p); p += 4
        stream_blob = payload[p:p + sln]; p += sln
        entries = []
        for _ in range(ec):
            method_idx = u32(payload, p); p += 4
            code_off = u32(payload, p); p += 4
            insns_size = u32(payload, p); p += 4
            offset = u32(payload, p); p += 4
            length = u32(payload, p); p += 4
            entries.append((method_idx, code_off, insns_size, offset, length))
        sections.append((dex_idx, stream_blob, entries))

    # ---- 解密 dex 段，得到 NOP 化 DEX ----
    nop_dexes = []
    for i, blob in enumerate(dex_blobs):
        key = verify_payload.derive_key(seed, i)
        nop_dexes.append(gcm_decrypt(key, blob))

    total = 0
    for (dex_idx, stream_blob, entries) in sections:
        dex = bytearray(nop_dexes[dex_idx])
        # per-dex 整体解密+inflate 一次，得到拼流
        key = verify_payload.derive_method_key(seed, dex_idx)
        buf = gcm_decrypt(key, stream_blob)
        for (method_idx, code_off, insns_size, offset, length) in entries:
            insns = buf[offset:offset + length]
            ins_off = code_off + 16
            if len(insns) != insns_size * 2:
                return False, ("insns size mismatch dex%d m%d: got %d want %d"
                               % (dex_idx, method_idx, len(insns), insns_size * 2))
            dex[ins_off:ins_off + len(insns)] = insns
            total += 1
        if bytes(dex) != orig_dexes[dex_idx]:
            return False, "write-back dex%d != original" % dex_idx
    return True, "methods=%d" % total


def main():
    seed = harden.load_seed()
    all_ok = True
    grand_total = 0
    for apk in SAMPLES:
        if not os.path.isfile(apk):
            print("[skip] %s" % apk); continue
        with zipfile.ZipFile(apk) as z:
            names = [n for n in z.namelist() if n == "classes.dex"]
            orig_dexes = [z.read(n) for n in names]
        if not orig_dexes:
            print("[skip] %s (no classes.dex)" % apk); continue
        # P3.1 抽取
        msecs = []
        nop_dexes = []
        for i, d in enumerate(orig_dexes):
            nop_d, blob, entries = harden.extract_methods(seed, i, d)
            nop_dexes.append(nop_d)
            msecs.append((i, blob, entries))
        payload = harden.build_payload(seed, nop_dexes, None, msecs)
        ok, msg = simulate_native_writeback(seed, payload, orig_dexes)
        status = "PASS" if ok else "FAIL"
        print("[%s] %-28s %s" % (status, os.path.basename(apk), msg))
        if not ok:
            all_ok = False
        else:
            grand_total += int(msg.split("=")[1])
    print("=" * 60)
    print("契约验证: %s | 总还原方法数=%d" % ("ALL PASS" if all_ok else "FAILED", grand_total))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
