# -*- coding: utf-8 -*-
"""
test_whitebox_kdf.py - P0-B 真白盒沙箱等价门禁（无需真机）

验证目标（诚实边界，务必读）：
  - 本门禁只证明 Python whitebox_kdf.wb_derive 与标准 SHA-256/HMAC 逐字节一致，
    且确定、且≠clean HMAC；并验证 build_stub 烘焙的 WB_STATE 与 Python 同源一致。
  - native 侧（jg_guard.c / jg_method_restore.c 的 wb_key_for）复用 jg_crypto.h 的
    标准 SHA-256 + HMAC + 同构 sha256_cont，故数学上与本模块逐字节等价（由共享算法
    保证）。但「运行期」wb_key_for 与 wb_derive 真正一致需真机 + frida 反向验证——
    沙箱无法运行 Android .so，这一步留给设备验证，本门禁不覆盖。

门禁项：
  1) wb_derive == hashlib 对「完整拼接消息」的标准 SHA-256（独立参考，证明白盒实现正确）
  2) wb_derive 确定（同输入同输出）
  3) wb_derive != clean HMAC（白盒确实改变派生）
  4) whitebox_kdf.wb_state_c_array 产出 8 个合法 C uint32 字面量
  5) 模拟 build_stub._bake_whitebox_kdf：烘焙头中的 WB_STATE 与 Python 同源一致
"""
import hashlib
import os
import re
import sys

import whitebox_kdf


def _full_message(wb_secret, clean_hmac):
    """重构白盒 SHA-256 实际消费的完整字节序列（block1 || clean）。

    wb_derive = SHA256_cont(WB_STATE, clean)，其中 WB_STATE = SHA256(block1) 的
    中间态，block1 = wb_secret(32B) 的标准填充块（64B）。继续哈希 clean 等价于把
    block1 || clean 作为一段标准 SHA-256 输入从头哈希（clean 自身的填充由 hashlib
    负责，不要在此手工拼接 padding 块，否则 hashlib 会再补一次）。"""
    # block1: 32B 数据 + 0x80 + 填 0 至 56 + 8B 长度(256 bit) = 64B
    b1 = bytearray(wb_secret)
    b1.append(0x80)
    while len(b1) % 64 != 56:
        b1.append(0)
    b1 += (len(wb_secret) * 8).to_bytes(8, "big")
    assert len(b1) == 64
    # 完整消息 = block1 || clean（共 96B）；clean 的填充交给 hashlib
    return bytes(b1) + clean_hmac


def test_wb_derive_matches_standard_sha256():
    for _ in range(20):
        seed = os.urandom(32)
        ws = os.urandom(32)
        msg = os.urandom(7 + (ord(os.urandom(1)) % 12))  # 变长 msg
        got = whitebox_kdf.wb_derive(seed, msg, ws)
        clean = whitebox_kdf.hmac_sha256(seed, msg)
        full = _full_message(ws, clean)
        ref = hashlib.sha256(full).digest()
        assert got == ref, "白盒派生必须等于标准 SHA-256(完整拼接消息)"
        # 确定性
        assert whitebox_kdf.wb_derive(seed, msg, ws) == got
        # 与 clean HMAC 不同
        assert got != clean, "白盒必须改变派生结果"
    print("[OK] wb_derive == 标准 SHA-256(完整消息)，确定且≠clean")


def test_wb_state_c_array():
    for _ in range(20):
        ws = os.urandom(32)
        c = whitebox_kdf.wb_state_c_array(ws)
        nums = re.findall(r"0x[0-9a-fA-F]{8}", c)
        assert len(nums) == 8, "WB_STATE 必须是 8 个 uint32 字面量"
        st = whitebox_kdf.wb_state_from_secret(ws)
        for i, n in enumerate(nums):
            assert int(n, 16) == st[i], "C 数组必须与 wb_state_from_secret 同源"
    print("[OK] wb_state_c_array 产出 8 个合法 uint32 且与 Python 同源")


def test_bake_simulation():
    """模拟 build_stub._bake_whitebox_kdf：把模板中的 WB_STATE 零值替换为烘焙值。"""
    template = ('#ifndef WB_STATE\n'
                '#define WB_STATE {0,0,0,0,0,0,0,0}\n'
                '#endif\n')
    for _ in range(20):
        ws = os.urandom(32)
        baked = template.replace("#define WB_STATE {0,0,0,0,0,0,0,0}",
                                 "#define WB_STATE {%s}" % whitebox_kdf.wb_state_c_array(ws))
        m = re.search(r"#define WB_STATE \{(.*?)\}", baked, re.S)
        got = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]{8}", m.group(1))]
        assert got == whitebox_kdf.wb_state_from_secret(ws), "烘焙头 WB_STATE 必须与 Python 同源"
    print("[OK] build_stub 烘焙 WB_STATE 与 Python 同源一致")


if __name__ == "__main__":
    test_wb_derive_matches_standard_sha256()
    test_wb_state_c_array()
    test_bake_simulation()
    print("\n所有白盒等价门禁通过。运行期 C↔Python 一致性仍须真机+frida 反向验证。")
    sys.exit(0)
