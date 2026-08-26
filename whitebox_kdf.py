# -*- coding: utf-8 -*-
"""
whitebox_kdf.py - JGShield P0-B 真白盒密钥派生（Python 侧：写端 + build_stub 烘焙同源）

与 src/native/jg_crypto.h 的 SHA-256 实现逐位对齐，保证：
  - build_stub 烘焙进 whitebox_kdf.h 的 WB_STATE[8]（C uint32 数组），与本模块
    wb_state_from_secret() 算出的 8 个 uint32 完全一致；
  - build_stub 用本模块烘焙，harden.py / verify_payload.py 用本模块派生密钥
    → 写端(加密)与壳读端(解密)逐字节一致（写读对称铁律）。

白盒思想（诚实边界，务必读）：
  seed = HMAC(salt, cert_hash) 仍可由 APK 证书 + salt 在设备端重建（设计本就如此，
  以便工具自身 verify / 重加固、且证书绑定生效）。故白盒「不增加保密性」，只做
  「混淆融合」：把干净 HMAC(seed, msg) 再经一次以 wb_secret 预处理态 WB_STATE 为
  起点的 SHA256，使 .so 内不再出现连续的 seed 字面量、也不再有可被一行 HMAC()
  直接复用的干净派生；攻击者为写出等价解密脚本，必须先反编译还原 WB_STATE 的融合
  逻辑。→ 提成本，不补秘密。真正的墙是 VMP / 服务端密钥，均不在本次范围。

白盒等式（C 与 Python 同构）：
  final = SHA256_cont( WB_STATE, HMAC(seed, msg) )
  其中 WB_STATE = SHA256 处理完 (wb_secret 的 64B 填充块) 后的中间态(8×uint32)。
  msg = KEY_PREFIX + label + idx （与 clean 派生完全相同的 msg）。
  wb_secret 每 stub 随机生成（build_stub 注入），仅以「融合后的 WB_STATE」形式出现在
  .so 与 build 期，不暴露连续字面量。

沙箱可验证性：本模块的 wb_derive 与 sha256_cont 自洽、确定性可测（见
test_whitebox_kdf.py）；C 侧 wb_key_for 由 jg_crypto.h 同算法实现，编译期由 build_stub
烘焙同一 WB_STATE → 与 Python 写端逐字节一致（数学等价由共享的 SHA256 算法保证，
真机运行期一致性需设备 + frida 反向验证）。
"""
import hashlib

# 与 jg_crypto.h JG_SHA_K 完全一致
_SHA_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_MASK = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK


class _SHA256Ctx:
    """与 jg_crypto.h 的 jg_sha256_ctx / jg_sha256_block / init / update / final 逐位对齐。"""

    def __init__(self, h=None):
        if h is None:
            self.h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        else:
            self.h = list(h)
        self.length = 0   # 已消费字节数
        self.buf = bytearray()

    def _block(self, p):
        w = [0] * 64
        for i in range(16):
            # 注意偏移是 i*4（每字 4 字节），原 jg_crypto.h 用 p+=4 推进指针
            w[i] = int.from_bytes(p[i * 4:i * 4 + 4], "big")
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK
        a, b, c, d, e, f, g, h = self.h
        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = (h + S1 + ch + _SHA_K[i] + w[i]) & _MASK
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & _MASK
            h = g
            g = f
            f = e
            e = (d + t1) & _MASK
            d = c
            c = b
            b = a
            a = (t1 + t2) & _MASK
        self.h = [(self.h[0] + a) & _MASK, (self.h[1] + b) & _MASK,
                  (self.h[2] + c) & _MASK, (self.h[3] + d) & _MASK,
                  (self.h[4] + e) & _MASK, (self.h[5] + f) & _MASK,
                  (self.h[6] + g) & _MASK, (self.h[7] + h) & _MASK]

    def update(self, data):
        self.length += len(data)
        self.buf.extend(data)
        while len(self.buf) >= 64:
            self._block(self.buf[:64])
            del self.buf[:64]

    def final(self):
        bitlen = (self.length * 8) & 0xFFFFFFFFFFFFFFFF
        self.buf.append(0x80)
        while len(self.buf) % 64 != 56:
            self.buf.append(0)
        self.buf += bitlen.to_bytes(8, "big")
        while len(self.buf) >= 64:
            self._block(self.buf[:64])
            del self.buf[:64]
        return b"".join(x.to_bytes(4, "big") for x in self.h)


def sha256_cont(state8, msg):
    """从 8×uint32 中间态继续 SHA256，等价于 C 的 wb_sha256_cont
    （c.len=64, c.buflen=0，即「已消费一个 64B 块」）。"""
    ctx = _SHA256Ctx(h=state8)
    ctx.length = 64
    ctx.buf = bytearray()
    ctx.update(msg)
    return ctx.final()


def wb_state_from_secret(wb_secret):
    """WB_STATE = SHA256 处理完 wb_secret 的 64B 填充块后的中间态(8×uint32)。

    wb_secret 为 32 字节 → 单块：32B 数据 + 0x80 + 31×0x00 + 64bit 长度。
    仅消费该块并取 h[]，即后续 wb_sha256_cont 的起点。"""
    if len(wb_secret) != 32:
        raise ValueError("wb_secret must be 32 bytes, got %d" % len(wb_secret))
    block = bytearray(wb_secret)
    block.append(0x80)
    while len(block) % 64 != 56:
        block.append(0)
    block += (len(wb_secret) * 8).to_bytes(8, "big")
    ctx = _SHA256Ctx()
    ctx._block(bytes(block[:64]))  # 仅消费第一块
    return list(ctx.h)


def wb_state_c_array(wb_secret):
    """生成 whitebox_kdf.h 的 WB_STATE C 数组字面量（与 wb_state_from_secret 同源）。"""
    st = wb_state_from_secret(wb_secret)
    return ", ".join("0x%08x" % x for x in st)


import hmac as _hmac


def hmac_sha256(key, msg):
    return _hmac.new(key, msg, hashlib.sha256).digest()


def wb_derive(seed, msg, wb_secret):
    """白盒密钥派生：final = SHA256_cont(WB_STATE, HMAC(seed, msg))。

    与 native wb_key_for（whitebox_kdf.h）逐字节一致；msg 与 clean 派生完全相同。"""
    clean = hmac_sha256(seed, msg)
    state = wb_state_from_secret(wb_secret)
    return sha256_cont(state, clean)


if __name__ == "__main__":
    # 自测：白盒 ≠ clean，但确定且自洽
    import os
    sd = os.urandom(32)
    ws = os.urandom(32)
    msg = b"Ab9m0"
    a = wb_derive(sd, msg, ws)
    b = wb_derive(sd, msg, ws)
    assert a == b, "white-box must be deterministic"
    assert a != hmac_sha256(sd, msg), "white-box must differ from clean HMAC"
    print("whitebox_kdf self-test OK; WB_STATE =", wb_state_c_array(ws))
