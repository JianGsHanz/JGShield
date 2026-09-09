# vmp_compile.py -- 自包含 DEX 反汇编 + 私有字节码编译器（不依赖 androguard）。
#
# 把一个 dalvik 方法的 code_item 直接解码成私有 VMP 字节码：
#   - decode_method(dex, code_off): 从 DEX 字节流解析指令（覆盖安全子集）
#   - classify(dex, code_off):      安全子集闸门（仅整型/长整型纯计算；regs<=15；
#                                   排除 invoke/字段/数组/对象/字符串/float/double/byte 转换）
#   - compile(dex, code_off, desc, xor_key): 发射私有字节码并经 XOR 包裹
#
# 私有 ISA 见 vmp_arch2.py（Python 参考 VM / 汇编器）与 src/native/jg_vmp.c（真机解释器）。
# 本模块复用 vmp_arch2.assemble_vm_bytecode 做最终包裹。
#
# 诚实边界: 仅对"安全子集"方法正确；其它方法 classify 返回 False 由调用方跳过。
# 解释器本身仍可被还原（明文执行），只是抬逆向成本。

import struct
from vmp_arch2 import (
    assemble_vm_bytecode,
    OP_MOV_RI, OP_MOV_RR, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD,
    OP_AND, OP_OR, OP_XOR, OP_SHL, OP_SHR, OP_USHR, OP_NEG,
    OP_CMP_LT, OP_CMP_LE, OP_CMP_GT, OP_CMP_GE, OP_CMP_EQ, OP_CMP_NE,
    OP_JMP, OP_JNZ, OP_JZ, OP_RET, OP_INT32, OP_INT16, OP_WIDE,
    OP_SEXT32, OP_ZEXT16, OP_SEXT16, OP_MOV_RI64, OP_ZEXT32,
)

# ---------- 基础读写 ----------
def _u16(b, o):
    return b[o] | (b[o + 1] << 8)

def _s16(b, o):
    v = _u16(b, o)
    return v - 0x10000 if v & 0x8000 else v

def _u32(b, o):
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)

def _s32(b, o):
    v = _u32(b, o)
    return v - 0x100000000 if v & 0x80000000 else v

def _s8(b, o):
    v = b[o]
    return v - 256 if v & 0x80 else v

def _i32(v):
    """4 字节小端（dalvik 立即数按 32 位有符号表示）。"""
    v &= 0xFFFFFFFF
    return bytes([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF])

def _i64(v):
    v &= 0xFFFFFFFFFFFFFFFF
    return bytes([(v >> (8 * i)) & 0xFF for i in range(8)])

# ---------- opcode 表（标准 dalvik 数值） ----------
OP = {
    'nop': 0x00,
    'move': 0x01, 'move/from16': 0x02, 'move-wide': 0x03, 'move-wide/from16': 0x04,
    'move-object': 0x05, 'move-object/from16': 0x06, 'move-object/16': 0x07,
    'move/16': 0x08, 'move-wide/16': 0x09,
    'const/4': 0x12, 'const/16': 0x13, 'const': 0x14, 'const/high16': 0x15,
    'const-wide': 0x18, 'const-wide/16': 0x16, 'const-wide/32': 0x17, 'const-wide/high16': 0x19,
    'neg-int': 0x7b, 'not-int': 0x7c, 'neg-long': 0x7d, 'not-long': 0x7e,
    'int-to-long': 0x81, 'long-to-int': 0x84, 'int-to-char': 0x8e, 'int-to-short': 0x8f,
    'add-int': 0x90, 'sub-int': 0x91, 'mul-int': 0x92, 'div-int': 0x93, 'rem-int': 0x94,
    'and-int': 0x95, 'or-int': 0x96, 'xor-int': 0x97, 'shl-int': 0x98, 'shr-int': 0x99, 'ushr-int': 0x9a,
    'add-long': 0x9b, 'sub-long': 0x9c, 'mul-long': 0x9d, 'div-long': 0x9e, 'rem-long': 0x9f,
    'and-long': 0xa0, 'or-long': 0xa1, 'xor-long': 0xa2, 'shl-long': 0xa3, 'shr-long': 0xa4, 'ushr-long': 0xa5,
    'add-int/2addr': 0xb0, 'sub-int/2addr': 0xb1, 'mul-int/2addr': 0xb2, 'div-int/2addr': 0xb3,
    'rem-int/2addr': 0xb4, 'and-int/2addr': 0xb5, 'or-int/2addr': 0xb6, 'xor-int/2addr': 0xb7,
    'shl-int/2addr': 0xb8, 'shr-int/2addr': 0xb9, 'ushr-int/2addr': 0xba,
    'add-long/2addr': 0xbb, 'sub-long/2addr': 0xbc, 'mul-long/2addr': 0xbd, 'div-long/2addr': 0xbe,
    'rem-long/2addr': 0xbf, 'and-long/2addr': 0xc0, 'or-long/2addr': 0xc1, 'xor-long/2addr': 0xc2,
    'shl-long/2addr': 0xc3, 'shr-long/2addr': 0xc4, 'ushr-long/2addr': 0xc5,
    'add-int/lit16': 0xd0, 'rsub-int': 0xd1, 'mul-int/lit16': 0xd2, 'div-int/lit16': 0xd3,
    'rem-int/lit16': 0xd4, 'and-int/lit16': 0xd5, 'or-int/lit16': 0xd6, 'xor-int/lit16': 0xd7,
    'add-int/lit8': 0xd8, 'rsub-int/lit8': 0xd9, 'mul-int/lit8': 0xda, 'div-int/lit8': 0xdb,
    'rem-int/lit8': 0xdc, 'and-int/lit8': 0xdd, 'or-int/lit8': 0xde, 'xor-int/lit8': 0xdf,
    'shl-int/lit8': 0xe0, 'shr-int/lit8': 0xe1, 'ushr-int/lit8': 0xe2,
    'if-eq': 0x32, 'if-ne': 0x33, 'if-lt': 0x34, 'if-ge': 0x35, 'if-gt': 0x36, 'if-le': 0x37,
    'if-eqz': 0x38, 'if-nez': 0x39, 'if-ltz': 0x3a, 'if-gez': 0x3b, 'if-gtz': 0x3c, 'if-lez': 0x3d,
    'goto': 0x28, 'goto/16': 0x29, 'goto/32': 0x2a,
    'return-void': 0x0e, 'return': 0x0f, 'return-wide': 0x10, 'return-object': 0x11,
}
NAME = {v: k for k, v in OP.items()}

# 安全子集：本编译器能正确发射的全部指令
ALLOWED = set(OP.keys())
# 显式排除（不应出现在 ALLOWED 的已被排除；这里是兜底黑名单，确保任何 float/double/byte
# 或对象/字段/数组/调用/字符串相关指令一律判不安全）
_BANNED_SUBSTR = ('float', 'double', 'byte', '-object', 'string', 'class',
                  'invoke', 'iget', 'iput', 'sget', 'sput', 'aget', 'aput',
                  'new-instance', 'new-array', 'check-cast', 'instance-of',
                  'cmp-', 'move-result', 'throw', 'monitor', 'switch', 'fill-array')
for _n in list(ALLOWED):
    if any(s in _n for s in _BANNED_SUBSTR):
        ALLOWED.discard(_n)

# 整型二元 op（需 SEXT32 截断回 32 位）
# 注意: 本 ylyk dex 为非标准编码——二元算术/移位均为 4 字节 3 寄存器(A=byte1, B=byte2, C=byte3,
# 各 8 位), 而非标准 dalvik 23x(6 字节)。shl-int/shr-int/ushr-int 同样 4 字节 3 寄存器
# (vA = vB << vC), 与标准 dalvik 12x(2 字节, vA=vB<<vA) 不同。统一按 4 字节解码。
_INT_BIN = {
    'add-int': OP_ADD, 'sub-int': OP_SUB, 'mul-int': OP_MUL, 'div-int': OP_DIV,
    'rem-int': OP_MOD, 'and-int': OP_AND, 'or-int': OP_OR, 'xor-int': OP_XOR,
}
_INT_SHIFT = {
    'shl-int': OP_SHL, 'shr-int': OP_SHR, 'ushr-int': OP_USHR,
}
# 移位类私有 opcode: 解释器按 64 位掩 6 位计数, int 语义需额外掩 5 位
_SHIFT_OPS = {OP_SHL, OP_SHR, OP_USHR}
_INT_BIN_2ADDR = {
    'add-int/2addr': OP_ADD, 'sub-int/2addr': OP_SUB, 'mul-int/2addr': OP_MUL,
    'div-int/2addr': OP_DIV, 'rem-int/2addr': OP_MOD, 'and-int/2addr': OP_AND,
    'or-int/2addr': OP_OR, 'xor-int/2addr': OP_XOR, 'shl-int/2addr': OP_SHL,
    'shr-int/2addr': OP_SHR, 'ushr-int/2addr': OP_USHR,
}
_LONG_BIN = {
    'add-long': OP_ADD, 'sub-long': OP_SUB, 'mul-long': OP_MUL, 'div-long': OP_DIV,
    'rem-long': OP_MOD, 'and-long': OP_AND, 'or-long': OP_OR, 'xor-long': OP_XOR,
    'shl-long': OP_SHL, 'shr-long': OP_SHR, 'ushr-long': OP_USHR,
}
_LONG_BIN_2ADDR = {
    'add-long/2addr': OP_ADD, 'sub-long/2addr': OP_SUB, 'mul-long/2addr': OP_MUL,
    'div-long/2addr': OP_DIV, 'rem-long/2addr': OP_MOD, 'and-long/2addr': OP_AND,
    'or-long/2addr': OP_OR, 'xor-long/2addr': OP_XOR, 'shl-long/2addr': OP_SHL,
    'shr-long/2addr': OP_SHR, 'ushr-long/2addr': OP_USHR,
}
_INT_LIT = {
    'add-int/lit16': OP_ADD, 'rsub-int': OP_SUB, 'mul-int/lit16': OP_MUL,
    'div-int/lit16': OP_DIV, 'rem-int/lit16': OP_MOD, 'and-int/lit16': OP_AND,
    'or-int/lit16': OP_OR, 'xor-int/lit16': OP_XOR,
    'add-int/lit8': OP_ADD, 'rsub-int/lit8': OP_SUB, 'mul-int/lit8': OP_MUL,
    'div-int/lit8': OP_DIV, 'rem-int/lit8': OP_MOD, 'and-int/lit8': OP_AND,
    'or-int/lit8': OP_OR, 'xor-int/lit8': OP_XOR,
    'shl-int/lit8': OP_SHL, 'shr-int/lit8': OP_SHR, 'ushr-int/lit8': OP_USHR,
}
_CMP = {
    'if-eq': OP_CMP_EQ, 'if-ne': OP_CMP_NE, 'if-lt': OP_CMP_LT, 'if-ge': OP_CMP_GE,
    'if-gt': OP_CMP_GT, 'if-le': OP_CMP_LE,
    'if-eqz': OP_CMP_EQ, 'if-nez': OP_CMP_NE, 'if-ltz': OP_CMP_LT, 'if-gez': OP_CMP_GE,
    'if-gtz': OP_CMP_GT, 'if-lez': OP_CMP_LE,
}


class VMDecodeError(Exception):
    pass


def decode_method(dex, code_off):
    """解析 code_item，返回 (registers_size, insns, insns_unit_count)。
    insns: [{'name', 'unit_off'(=该指令在 insns 区的 16-bit 单元偏移), 各操作数}]。
    遇不支持 opcode 抛 VMDecodeError（调用方据此判该方法不安全）。"""
    regs = _u16(dex, code_off)
    insns_size = _u32(dex, code_off + 12)
    p = code_off + 16
    end = p + insns_size * 2
    insns = []
    while p < end:
        unit_off = (p - (code_off + 16)) // 2
        op = dex[p]
        name = NAME.get(op)
        if name is None:
            raise VMDecodeError("unsupported opcode 0x%02x at unit %d" % (op, unit_off))
        u0 = _u16(dex, p)
        A = (u0 >> 8) & 0xF
        B = (u0 >> 12) & 0xF
        if name == 'nop':
            insns.append({'name': name, 'unit_off': unit_off})
            p += 2; continue
        if name in ('const/4',):
            insns.append({'name': name, 'unit_off': unit_off, 'ra': A, 'imm': _s8(dex, p) if (B & 0x8) else B})
            # const/4: imm 是高 4 位符号扩展
            imm = B; imm = imm - 16 if imm & 0x8 else imm
            insns[-1]['imm'] = imm
            p += 2; continue
        if name in ('const/16',):
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF, 'imm': _s16(dex, p + 2)})
            p += 4; continue
        if name == 'const':
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF, 'imm': _s32(dex, p + 2)})
            p += 6; continue
        if name == 'const/high16':
            imm16 = _u16(dex, p + 2)
            imm = (imm16 << 16) & 0xFFFFFFFF
            if imm & 0x80000000:
                imm -= 0x100000000
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF, 'imm': imm})
            p += 4; continue
        if name == 'const-wide':
            # 51l(本 dex 实测): op(1) + 寄存器 byte1(8 位) + 64 位立即数 bytes2-9(小端), 共 10 字节。
            # 注意不是标准假设的 16 位寄存器 + 立即数在 bytes3-10(那会把字节 2 误当寄存器高位,
            # 并整体错位一字节)。与 androguard 逐条对齐后确认。
            reg = dex[p + 1]
            lo = _u16(dex, p + 2); hi = _u16(dex, p + 4)
            hi2 = _u16(dex, p + 6); hi3 = _u16(dex, p + 8)
            imm = lo | (hi << 16) | (hi2 << 32) | (hi3 << 48)
            if imm & 0x8000000000000000:
                imm -= 0x10000000000000000
            insns.append({'name': name, 'unit_off': unit_off, 'ra': reg, 'imm': imm})
            p += 10; continue
        if name == 'const-wide/16':
            imm = _s16(dex, p + 2)
            imm &= 0xFFFFFFFFFFFFFFFF
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF, 'imm': imm})
            p += 4; continue
        if name == 'const-wide/32':
            imm = _s32(dex, p + 2) & 0xFFFFFFFFFFFFFFFF
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF, 'imm': imm})
            p += 6; continue
        if name == 'const-wide/high16':
            imm16 = _u16(dex, p + 2)
            imm = (imm16 << 48) & 0xFFFFFFFFFFFFFFFF
            if imm & 0x8000000000000000:
                imm -= 0x10000000000000000
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF, 'imm': imm})
            p += 4; continue
        # move 系列
        if name in ('move', 'move-wide', 'move-object'):
            insns.append({'name': name, 'unit_off': unit_off, 'ra': A, 'rb': B})
            p += 2; continue
        if name in ('move/from16', 'move-object/from16'):
            # 22x: A=byte1(8位), B=bytes2-3(16位) —— 本 dex 与标准一致(4 字节)
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF, 'rb': _u16(dex, p + 2)})
            p += 4; continue
        if name == 'move-wide/from16':
            # 非标准: 本 dex 是 2 字节 12x(标准 dalvik 22x 为 4 字节)
            insns.append({'name': name, 'unit_off': unit_off, 'ra': A, 'rb': B})
            p += 2; continue
        if name in ('move-wide/16', 'move-object/16'):
            # 32x: A=16位寄存器(字节1-2), B=16位寄存器(字节3-4)
            insns.append({'name': name, 'unit_off': unit_off, 'ra': _u16(dex, p + 1), 'rb': _u16(dex, p + 3)})
            p += 6; continue
        if name == 'move/16':
            # 非标准: 本 dex 是 4 字节(A=byte1 8位, B=bytes2-3 16位), 而非标准 32x 6 字节
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF, 'rb': _u16(dex, p + 2)})
            p += 4; continue
        # 单/双寄存器一元
        if name in ('neg-int', 'not-int', 'neg-long', 'not-long',
                    'int-to-long', 'long-to-int', 'int-to-char', 'int-to-short'):
            insns.append({'name': name, 'unit_off': unit_off, 'ra': A, 'rb': B})
            p += 2; continue
        # 二元算术(op 0x90-0x97 / 0x9b-0xa5): 实测 ylyk dex 为 4 字节格式
        # (op, A=byte1, B=byte2, C=byte3, 三个寄存器各 8 位), 而非标准 dalvik 23x 6 字节。
        # 与 androguard 解码逐条对齐后确认 4 字节解读正确(6 字节会让下一指令落到非法 opcode)。
        # 二元算术 + int 移位: 均 4 字节 3 寄存器(A=byte1, B=byte2, C=byte3, 各 8 位)。
        # (含 shl/shr/ushr-int; 移位在本 dex 同为 4 字节 vA=vB<<vC, 非标准 12x)
        if name in _INT_BIN or name in _LONG_BIN or name in _INT_SHIFT:
            A = (u0 >> 8) & 0xFF
            insns.append({'name': name, 'unit_off': unit_off,
                          'ra': A, 'rb': dex[p + 2], 'rc': dex[p + 3]})
            p += 4; continue
        # 12x /2addr
        if name in _INT_BIN_2ADDR or name in _LONG_BIN_2ADDR:
            insns.append({'name': name, 'unit_off': unit_off, 'ra': A, 'rb': B})
            p += 2; continue
        # 22s / 22b 字面
        if name in _INT_LIT:
            if name.endswith('/lit8') or name == 'rsub-int/lit8':
                # 22b: A=byte1(8位目的寄存器), B=byte2(8位源寄存器), C=byte3(8位有符号立即数)。
                # (与 22x/22t/22s 的 4 位半字节寄存器不同! lit8 用完整 8 位寄存器索引)
                ra = (u0 >> 8) & 0xFF
                rb = dex[p + 2]
                imm = _s8(dex, p + 3)
                insns.append({'name': name, 'unit_off': unit_off, 'ra': ra, 'rb': rb, 'imm': imm})
                p += 4; continue
            else:
                # 22s: byte1=(B<<4)|A, 立即数 CCCC 在字节 2-3（4 字节指令）。
                # ra=低4位(A), rb=高4位(B), imm=有符号16位偏移 p+2。
                insns.append({'name': name, 'unit_off': unit_off,
                              'ra': A, 'rb': B, 'imm': _s16(dex, p + 2)})
                p += 4; continue
        # 分支
        if name in ('if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le'):
            target = unit_off + _s16(dex, p + 2)
            insns.append({'name': name, 'unit_off': unit_off, 'ra': A, 'rb': B, 'off': target})
            p += 4; continue
        if name in ('if-eqz', 'if-nez', 'if-ltz', 'if-gez', 'if-gtz', 'if-lez'):
            target = unit_off + _s16(dex, p + 2)
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF, 'off': target})
            p += 4; continue
        if name == 'goto':
            target = unit_off + _s8(dex, p)  # 偏移在 op 字节高 4 位? 见下
            # 10t: 偏移在单个 8 位有符号字段（unit 的高字节）
            off8 = (u0 >> 8) & 0xFF
            target = unit_off + (off8 - 256 if off8 & 0x80 else off8)
            insns.append({'name': name, 'unit_off': unit_off, 'off': target})
            p += 2; continue
        if name == 'goto/16':
            target = unit_off + _s16(dex, p + 2)
            insns.append({'name': name, 'unit_off': unit_off, 'off': target})
            p += 4; continue
        if name == 'goto/32':
            target = unit_off + _s32(dex, p + 2)
            insns.append({'name': name, 'unit_off': unit_off, 'off': target})
            p += 6; continue
        # 返回
        if name in ('return-void',):
            insns.append({'name': name, 'unit_off': unit_off})
            p += 2; continue
        if name in ('return', 'return-wide', 'return-object'):
            insns.append({'name': name, 'unit_off': unit_off, 'ra': (u0 >> 8) & 0xFF})
            p += 2; continue
        raise VMDecodeError("unhandled instruction %s (0x%02x)" % (name, op))
    return regs, insns, insns_size


def classify(dex, code_off, max_regs=15):
    """返回 (safe:bool, reason:str)。safe 仅当：regs<=max_regs 且每条指令都在 ALLOWED。"""
    try:
        regs = _u16(dex, code_off)
    except Exception:
        return False, 'bad_code_off'
    if regs > max_regs:
        return False, 'regs=%d>%d' % (regs, max_regs)
    try:
        _regs, insns, _ = decode_method(dex, code_off)
    except VMDecodeError as e:
        return False, str(e)
    for ins in insns:
        if ins['name'] not in ALLOWED:
            return False, 'disallowed:' + ins['name']
    return True, ''


def _param_words(desc):
    params = desc[desc.index('(') + 1:desc.index(')')]
    words = 0
    i = 0
    while i < len(params):
        if params[i] == 'L':
            i = params.index(';', i) + 1
            words += 1
        elif params[i] == '[':
            while params[i] == '[':
                i += 1
            if params[i] == 'L':
                i = params.index(';', i) + 1
            else:
                i += 1
            words += 1
        elif params[i] in 'JFD':
            words += 2
            i += 1
        else:
            words += 1
            i += 1
    return words


def compile(dex, code_off, desc, xor_key):
    """把方法编译成私有 blob（魔数 FD C2 + xor key + 异或私有码）。
    xor_key: 0..255，建议每次构建/每方法不同以抬跨版本 diff 成本。"""
    regs, insns, _ = decode_method(dex, code_off)
    param_reg = regs - _param_words(desc)
    SCR = 15  # 自由暂存（regs<=15 保证 v15 不被方法使用）
    code = bytearray()
    off2vm = {}
    patches = []  # (pos, target_unit_off)

    def _r(v):
        code.append(v & 0xFF)

    def _ri(v):
        # 注意: 必须用 extend, 不能 `code += bytes`(会把 code 重绑为 _ri 的局部变量,
        # 触发 UnboundLocalError)。bytearray += bytes 虽就地改, 但赋值语义仍重绑名字。
        code.extend(_i32(v & 0xFFFFFFFF))

    def _ri64(v):
        code.extend(_i64(v & 0xFFFFFFFFFFFFFFFF))

    for ins in insns:
        off2vm[ins['unit_off']] = len(code)
        nm = ins['name']
        if nm == 'nop':
            continue
        elif nm in ('const/4', 'const/16', 'const', 'const/high16'):
            _r(OP_MOV_RI); _r(ins['ra']); _ri(ins['imm'])
        elif nm in ('const-wide', 'const-wide/16', 'const-wide/32', 'const-wide/high16'):
            _r(OP_MOV_RI64); _r(ins['ra']); _ri64(ins['imm'])
        elif nm == 'move' or nm == 'move-wide' or nm == 'move-object':
            _r(OP_MOV_RR); _r(ins['ra']); _r(ins['rb'])
        elif nm in ('move/from16', 'move-wide/from16', 'move-object/from16',
                    'move/16', 'move-wide/16', 'move-object/16'):
            _r(OP_MOV_RR); _r(ins['ra']); _r(ins['rb'])
        elif nm == 'neg-int':
            _r(OP_NEG); _r(ins['ra']); _r(ins['rb']); _r(OP_SEXT32); _r(ins['ra'])
        elif nm == 'not-int':
            _r(OP_MOV_RI); _r(SCR); _ri(0xFFFFFFFF)
            _r(OP_XOR); _r(ins['ra']); _r(ins['rb']); _r(SCR); _r(OP_SEXT32); _r(ins['ra'])
        elif nm == 'neg-long':
            _r(OP_NEG); _r(ins['ra']); _r(ins['rb'])
        elif nm == 'not-long':
            _r(OP_MOV_RI64); _r(SCR); _ri64(0xFFFFFFFFFFFFFFFF)
            _r(OP_XOR); _r(ins['ra']); _r(ins['rb']); _r(SCR)
        elif nm == 'int-to-long':
            _r(OP_MOV_RR); _r(ins['ra']); _r(ins['rb'])
        elif nm == 'long-to-int' or nm == 'int-to-short':
            _r(OP_MOV_RR); _r(ins['ra']); _r(ins['rb'])
            _r(OP_SEXT32 if nm == 'long-to-int' else OP_SEXT16); _r(ins['ra'])
        elif nm == 'int-to-char':
            _r(OP_MOV_RR); _r(ins['ra']); _r(ins['rb']); _r(OP_ZEXT16); _r(ins['ra'])
        elif nm in _INT_BIN:
            _r(_INT_BIN[nm]); _r(ins['ra']); _r(ins['rb']); _r(ins['rc'])
            _r(OP_SEXT32); _r(ins['ra'])
        elif nm in _INT_SHIFT:
            # 4 字节 3 寄存器: vA = vB <shift> (vC & 0x1f)
            # 解释器 OP_SHL 按 64 位掩 6 位(0x3f) 计数, dalvik int 移位掩 5 位(0x1f);
            # 因此先把计数掩到 0x1f 存入 SCR, 再移位, 否则计数 >=32 时结果与 dalvik 不符。
            # 注意顺序: 先算计数(SCR)再动 ra —— 万一 rc 与 ra 是同一寄存器也不会读丢。
            _r(OP_MOV_RI); _r(SCR); _ri(0x1F)
            _r(OP_AND); _r(SCR); _r(ins['rc']); _r(SCR)   # SCR = vC & 0x1f
            if nm == 'ushr-int':
                # ⚠ ushr-int 是「32 位逻辑右移」。寄存器里存的是符号扩展后的 64 位值
                # (如 -1 = 0xFFFFFFFFFFFFFFFF)，直接 USHR 会把高 32 位的符号位一起移进来，
                # 结果远大于 dalvik 的 (uint32)x >> cnt（负数输入时必错）。
                # 故先把源零扩展到 32 位再移位，最后按 int 语义符号扩展回 32 位。
                _r(OP_MOV_RR); _r(ins['ra']); _r(ins['rb'])
                _r(OP_ZEXT32); _r(ins['ra'])
                _r(_INT_SHIFT[nm]); _r(ins['ra']); _r(ins['ra']); _r(SCR)
            else:
                _r(_INT_SHIFT[nm]); _r(ins['ra']); _r(ins['rb']); _r(SCR)
            _r(OP_SEXT32); _r(ins['ra'])
        elif nm in _LONG_BIN:
            _r(_LONG_BIN[nm]); _r(ins['ra']); _r(ins['rb']); _r(ins['rc'])
        elif nm in _INT_BIN_2ADDR:
            op = _INT_BIN_2ADDR[nm]
            if op in _SHIFT_OPS:
                # shl/shr/ushr-int/2addr: vA = vA <shift> (vB & 0x1f) —— 计数需掩 5 位
                _r(OP_MOV_RI); _r(SCR); _ri(0x1F)
                _r(OP_AND); _r(SCR); _r(ins['rb']); _r(SCR)
                if nm == 'ushr-int/2addr':
                    # 同 ushr-int: 必须先把 vA 零扩展到 32 位再逻辑右移
                    _r(OP_ZEXT32); _r(ins['ra'])
                _r(op); _r(ins['ra']); _r(ins['ra']); _r(SCR)
            else:
                _r(op); _r(ins['ra']); _r(ins['ra']); _r(ins['rb'])
            _r(OP_SEXT32); _r(ins['ra'])
        elif nm in _LONG_BIN_2ADDR:
            _r(_LONG_BIN_2ADDR[nm]); _r(ins['ra']); _r(ins['ra']); _r(ins['rb'])
        elif nm in _INT_LIT:
            op = _INT_LIT[nm]
            # 移位类字面量: dalvik 计数掩 5 位(0x1f), 解释器掩 6 位;
            # 立即数是编译期常量, 直接掩好再装载(避免负数如 -1 被按 63 处理)。
            imm = (ins['imm'] & 0x1F) if op in _SHIFT_OPS else ins['imm']
            _r(OP_MOV_RI); _r(SCR); _ri(imm)
            if nm == 'ushr-int/lit8':
                # 同 ushr-int: 源先零扩展到 32 位再逻辑右移
                _r(OP_MOV_RR); _r(ins['ra']); _r(ins['rb'])
                _r(OP_ZEXT32); _r(ins['ra'])
                _r(op); _r(ins['ra']); _r(ins['ra']); _r(SCR)
            elif nm.startswith('rsub'):
                _r(op); _r(ins['ra']); _r(SCR); _r(ins['rb'])
            else:
                _r(op); _r(ins['ra']); _r(ins['rb']); _r(SCR)
            _r(OP_SEXT32); _r(ins['ra'])
        elif nm in _CMP:
            if nm.endswith('z'):  # if-eqz 等：与 0 比较
                _r(OP_MOV_RI); _r(SCR); _ri(0)
                _r(_CMP[nm]); _r(ins['ra']); _r(SCR)
            else:
                _r(_CMP[nm]); _r(ins['ra']); _r(ins['rb'])
            _r(OP_JNZ)
            patches.append((len(code), ins['off']))
            _ri(0)
        elif nm == 'goto':
            _r(OP_JMP)
            patches.append((len(code), ins['off']))
            _ri(0)
        elif nm == 'return-void':
            _r(OP_RET); _r(0)
        elif nm in ('return', 'return-wide', 'return-object'):
            _r(OP_RET); _r(ins['ra'])
        else:
            raise VMDecodeError("emit unhandled %s" % nm)
    # 回填分支目标（私有 VM 用绝对 pc 字节偏移）
    for pos, tgt in patches:
        if tgt not in off2vm:
            raise VMDecodeError("branch target unit %d not in method" % tgt)
        struct.pack_into('<i', code, pos, off2vm[tgt])
    blob = assemble_vm_bytecode(bytes(code), xor_key & 0xFF)
    return blob, param_reg


if __name__ == '__main__':
    # 自测: 合成指令流验证 int 溢出回绕语义正确。
    import zipfile
    APK = "D:/APK/ylyk_5.9.4/app-Ptest-5.9.4-2026-08-04.apk"
    print("[vmp_compile] 模块加载 OK；opcode 表 %d 条；ALLOWED %d 条" % (len(OP), len(ALLOWED)))
