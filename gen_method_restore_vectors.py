# -*- coding: utf-8 -*-
"""
生成 method_restore_vectors.h：用 pycryptodome（与设备端算法一致）算出已知答案，
供 NDK 编译后的 test_method_restore 逐原语断言 C 实现（jg_crypto.h）与加固端完全一致。
无需真机：在任意带 NDK 的机器上 `ndk-build`/clang 编译 test_method_restore 并运行即自校验。
"""
import os
import zlib
import struct
import zipfile

import config
import harden
import verify_payload
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

OUT = os.path.join("src", "native", "method_restore_vectors.h")
SAMPLE1 = os.path.join(config.SAMPLES_DIR, "sample1.apk")
SAMPLE4 = os.path.join(config.SAMPLES_DIR, "sample4.apk")


def hex_arr(name, data):
    lines = []
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        lines.append("  " + ",".join("0x%02x" % b for b in chunk) + ",")
    body = "\n".join(lines).rstrip(",\n")
    return "static const unsigned char %s[%d] = {\n%s\n};\n" % (name, len(data), body)


def gcm_blob_parts(blob):
    iv = blob[0:12]
    rest = blob[12:]
    ct = rest[:-16]
    tag = rest[-16:]
    return iv, ct, tag


def stream_plain(blob, seed, dex_idx):
    """解密 per-dex 方法流 blob，返回 GCM 明文（= zlib(concat_insns)）。"""
    iv = blob[0:12]
    rest = blob[12:]
    key = verify_payload.derive_method_key(seed, dex_idx)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(rest[:-16], rest[-16:])


def main():
    seed = harden.load_seed()

    # ---- sample1：完整写回向量（FULL_PAYLOAD + NOP_DEX + ORIG_DEX）----
    with zipfile.ZipFile(SAMPLE1) as z:
        orig1 = z.read("classes.dex")
    nop1, blob1, entries1 = harden.extract_methods(seed, 0, orig1)
    payload1 = harden.build_payload(seed, [nop1], None, [(0, blob1, entries1)])
    # 取 dex0 整条流 blob 的 GCM 向量（per-dex 密钥 "JG|m0"）
    m0 = entries1[0]
    midx0 = m0[0]
    iv, ct, tag = gcm_blob_parts(blob1)
    insns0 = orig1[(m0[1] + 16):(m0[1] + 16 + m0[2] * 2)]
    plain0 = stream_plain(blob1, seed, 0)  # AES-GCM 明文 = zlib(concat_insns)
    key0 = verify_payload.derive_method_key(seed, 0)

    # ---- sample4：第二个 GCM 向量（同 dex0 per-dex 密钥，不同密文）----
    with zipfile.ZipFile(SAMPLE4) as z:
        orig4 = z.read("classes.dex")
    nop4, blob4, entries4 = harden.extract_methods(seed, 0, orig4)
    m4 = entries4[0]
    midx4 = m4[0]
    iv4, ct4, tag4 = gcm_blob_parts(blob4)
    insns4 = orig4[(m4[1] + 16):(m4[1] + 16 + m4[2] * 2)]
    plain4 = stream_plain(blob4, seed, 0)
    key4 = verify_payload.derive_method_key(seed, 0)

    # HMAC 向量：label "JG|m0"（per-dex 密钥）
    hmac_key = HMAC.new(seed, digestmod=SHA256)
    hmac_key.update(b"JG|m0")
    hmac_vec = hmac_key.digest()

    label0 = b"JG|m0"

    parts = []
    parts.append("/* 自动生成：method_restore_vectors.h — 来自真实加固数据，不可手改 */")
    parts.append("#ifndef JG_METHOD_RESTORE_VECTORS_H")
    parts.append("#define JG_METHOD_RESTORE_VECTORS_H")
    parts.append("")
    parts.append("/* 种子：SHA256(内置签名证书)。所有向量据此派生。 */")
    parts.append(hex_arr("V_SEED", seed))
    parts.append("")
    parts.append("/* HMAC-SHA256(V_SEED, \"JG|m0\") 期望输出 */")
    parts.append(hex_arr("V_HMAC_KEY", hmac_vec))
    parts.append("")
    parts.append("/* AES-256-GCM 向量 1：dex0 method_idx=%d */" % midx0)
    parts.append(hex_arr("V_GCM1_KEY", key0))
    parts.append(hex_arr("V_GCM1_IV", iv))
    parts.append(hex_arr("V_GCM1_CT", ct))
    parts.append(hex_arr("V_GCM1_TAG", tag))
    parts.append("/* 解密后应为 zlib(insns)（未经 inflate 的 GCM 明文） */")
    parts.append(hex_arr("V_GCM1_PLAIN", plain0))
    parts.append("")
    parts.append("/* AES-256-GCM 向量 2：dex0 method_idx=%d */" % midx4)
    parts.append(hex_arr("V_GCM2_KEY", key4))
    parts.append(hex_arr("V_GCM2_IV", iv4))
    parts.append(hex_arr("V_GCM2_CT", ct4))
    parts.append(hex_arr("V_GCM2_TAG", tag4))
    parts.append(hex_arr("V_GCM2_PLAIN", plain4))
    parts.append("")
    parts.append("/* 完整写回向量（sample1）：FULL_PAYLOAD 经 jg_restore_methods 还原 NOP_DEX -> ORIG_DEX */")
    parts.append(hex_arr("V_NOP_DEX", nop1))
    parts.append(hex_arr("V_ORIG_DEX", orig1))
    parts.append(hex_arr("V_FULL_PAYLOAD", payload1))
    parts.append("#define V_LABEL0 \"JG|m0\"")
    parts.append("")
    parts.append("#endif /* JG_METHOD_RESTORE_VECTORS_H */")

    with open(OUT, "w") as f:
        f.write("\n".join(parts) + "\n")
    print("[gen] wrote %s" % OUT)
    print("  seed=%d bytes, hmac_key=%d, gcm1(ct=%d,plain=%d), gcm2(ct=%d,plain=%d)"
          % (len(seed), len(hmac_vec), len(ct), len(plain0), len(ct4), len(plain4)))
    print("  nop_dex=%d, orig_dex=%d, full_payload=%d" % (len(nop1), len(orig1), len(payload1)))
    print("  sample1 methods=%d, sample4 methods=%d" % (len(entries1), len(entries4)))


if __name__ == "__main__":
    main()
