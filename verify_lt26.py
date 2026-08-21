# -*- coding: utf-8 -*-
"""
verify_lt26.py —— <26 落盘路径方法还原完整性离线校验
针对 output/h_ylyk594_lt26.apk (ylyk 5.9.4, dex 035 源, 已实测在 7.1.2 跑通)。

做法：复用 verify_payload 的载荷解析（与设备端 DeriveKeys 同派生算法）：
  1. 解密 19 个 dex 段（GCM 校验在 decrypt_and_verify 已强制通过）
  2. 解密 19 个 method 段（GCM 校验强制通过），把指令写回 NOP 化 dex
  3. 保存还原后完整 dex 到 _lt26_verify/c{idx}.dex
  4. 统计：GCM 全部通过数 / 方法总数 / 指令单位总数 / 每 dex header 合法性
  5. 输出 sha256，供真机落盘 c0.dex 交叉比对

无需原包：验证的是「载荷还原数据无损 + 结构自洽」；
与运行期 native 还原产出交叉比对一致 = <26 路径方法还原正确。
"""
import os
import sys
import zlib
import struct
import hashlib
import zipfile

sys.path.insert(0, os.getcwd())
import verify_payload as vp
from Crypto.Cipher import AES

APK = sys.argv[1] if len(sys.argv) > 1 else "output/h_ylyk594_lt26.apk"
OUT = "_lt26_verify"

def main():
    assert os.path.exists(APK), "加固包不存在: %s" % APK
    os.makedirs(OUT, exist_ok=True)

    seed = vp.seed_from_apk(APK)
    count, dexs = vp.parse_payload(APK, seed)  # 每个 dex 段 GCM 已校验
    print("[1] dex 段解码: %d 个，全部 GCM 校验通过" % count)
    dexs = [bytearray(d) for d in dexs]

    methods = vp.parse_methods(APK, seed)
    print("[2] method 段: %d 个 dex 含方法抽取" % len(methods))
    total_methods = 0
    total_insns = 0
    for (dex_idx, stream_blob, entries) in methods:
        iv = stream_blob[0:12]
        rest = stream_blob[12:]
        key = vp.derive_method_key(seed, dex_idx)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        comp = cipher.decrypt_and_verify(rest[:-16], rest[-16:])  # GCM 强制校验
        buf = zlib.decompress(comp)
        for (m_idx, code_off, insns_size, offset, length) in entries:
            insns = buf[offset:offset + length]
            ins_off = code_off + 16
            dexs[dex_idx][ins_off:ins_off + len(insns)] = insns
            total_methods += 1
            total_insns += insns_size
        run = sum(e[4] for e in entries)
        print("    dex[%d] 还原 %3d 方法, 指令流 %d 字节 (GCM OK, run=%d)" %
              (dex_idx, len(entries), len(buf), run))

    dexs = [bytes(d) for d in dexs]

    print("[3] 每 dex header 合法性:")
    all_ok = True
    for i, d in enumerate(dexs):
        magic = d[0:4]
        ver = d[4:7]
        # DEX header 关键字段
        try:
            file_size = struct.unpack_from("<I", d, 32)[0]
            method_ids_off = struct.unpack_from("<I", d, 88)[0]
            method_ids_size = struct.unpack_from("<I", d, 92)[0]
            valid = (magic == b"dex\n" and file_size == len(d) and
                     method_ids_off > 0 and method_ids_size > 0)
        except Exception:
            valid = False
        all_ok = all_ok and valid
        print("    c%d ver=%s file_size=%d methods=%d header_ok=%s" %
              (i, ver.decode("latin1", "replace"), len(d),
               method_ids_size if valid else -1, valid))

    print("[4] 保存还原后 dex 并输出 sha256:")
    shas = []
    for i, d in enumerate(dexs):
        p = os.path.join(OUT, "c%d.dex" % i)
        with open(p, "wb") as f:
            f.write(d)
        h = hashlib.sha256(d).hexdigest()
        shas.append(h)
        print("    %s  %s" % (p, h))

    # 写一份清单供真机比对
    with open(os.path.join(OUT, "shas.txt"), "w") as f:
        for i, h in enumerate(shas):
            f.write("c%d.dex %s\n" % (i, h))

    print("\n[SUMMARY]")
    print("  dex 段 GCM 校验通过 : %d/%d" % (count, count))
    print("  method 段 GCM 校验 : 全部通过 (逐 dex decrypt_and_verify)")
    print("  还原方法总数       : %d" % total_methods)
    print("  还原指令单位总数   : %d (ushort)" % total_insns)
    print("  header 合法性      : %s" % ("ALL OK" if all_ok else "FAIL"))
    print("  落盘交叉比对目标   : 运行期 pull /data/data/com.zhuomogroup.ylyk/app_jgshell/dex/c0.dex")
    print("  离线 c0.dex sha256 :", shas[0])

if __name__ == "__main__":
    main()
