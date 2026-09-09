# VMP-lite v2: register-based private virtual machine.
# Opcodes are PRIVATE (not dalvik). Code section is XOR-obfuscated with a per-blob
# key so it cannot be mistaken for dalvik bytecode by a memory scanner.
import struct

# ---- private opcode space (deliberately NOT dalvik) ----
OP_MOV_RI   = 0x01   # rd, imm32        r[rd] = imm
OP_MOV_RR   = 0x02   # rd, rs           r[rd] = r[rs]
OP_ADD      = 0x03   # rd, rs1, rs2
OP_SUB      = 0x04
OP_MUL      = 0x05
OP_DIV      = 0x06
OP_MOD      = 0x07
OP_AND      = 0x08
OP_OR       = 0x09
OP_XOR      = 0x0A
OP_SHL      = 0x0B
OP_SHR      = 0x0C   # arithmetic (signed)
OP_USHR     = 0x0D   # logical (unsigned)
OP_NEG      = 0x0E   # rd, rs
OP_CMP_LT   = 0x0F   # r1, r2  -> cond = (r1 < r2)
OP_CMP_LE   = 0x10
OP_CMP_GT   = 0x11
OP_CMP_GE   = 0x12
OP_CMP_EQ   = 0x13
OP_CMP_NE   = 0x14
OP_JMP      = 0x15   # target32 (absolute offset in code)
OP_JNZ      = 0x16   # target32 (jump if cond != 0)
OP_JZ       = 0x17   # target32 (jump if cond == 0)
OP_RET      = 0x18   # r
# ⚠ OP_INT32 语义在两侧不一致，勿当作"零扩展 32"使用：
#   本文件(参考 VM)实现为 r &= MASK32（零扩展），而 src/native/jg_vmp.c 实现为
#   (int64_t)(int32_t)r（符号扩展）。fuzz 只比 ref vs 本 VM，永远抓不到这类差异。
#   需要"零扩展 32"时用下面的 OP_ZEXT32（两侧语义显式一致）。
OP_INT32    = 0x19   # rd           语义见上；编译器当前未发射，保留兼容
OP_INT16    = 0x1A   # rd           r[rd] &= 0xFFFF (dalvik char/short)
OP_WIDE     = 0x1B   # rd           r[rd] &= 0xFFFFFFFFFFFFFFFF
OP_SEXT32   = 0x1C   # rd           r[rd] = (int64)(int32)(r[rd] & 0xFFFFFFFF)  (int 回绕/符号扩展)
OP_ZEXT16   = 0x1D   # rd           r[rd] &= 0xFFFF                              (int-to-char)
OP_SEXT16   = 0x1E   # rd           r[rd] = (int64)(int16)(r[rd] & 0xFFFF)      (int-to-short)
OP_MOV_RI64 = 0x1F   # rd, imm64                                      (64-bit 立即数)
OP_ZEXT32   = 0x20   # rd           r[rd] &= 0xFFFFFFFF (零扩展 32 位)  (dalvik ushr-int 必需)

MASK32 = 0xFFFFFFFF
MASK16 = 0xFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def _signed32(x):
    x &= MASK32
    return x - 0x100000000 if x & 0x80000000 else x


def _signed16(x):
    x &= MASK16
    return x - 0x10000 if x & 0x8000 else x


def _signed64(x):
    x &= MASK64
    return x - 0x10000000000000000 if x & 0x8000000000000000 else x


def _shr(x, n):
    return _signed32(x) >> n if isinstance(x, int) else x


def c_div(a, b):
    """C / dalvik 整数除法语义：向零截断（不是 Python 的向下取整）。

    ⚠ 踩过的坑: 这里原来是 `va // vb`。Python `//` 是 floor，`-7 // 2 == -4`，
    而 ART/dalvik 与 jg_vmp.c（`vb ? va/vb : 0`）都是 C 语义 `-7 / 2 == -3`。
    参考 VM 与真机解释器语义不一致时，fuzz 两边都错得一样 -> 假通过，真机结果错。
    除零与 jg_vmp.c 保持一致返回 0。
    """
    if b == 0:
        return 0
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def c_rem(a, b):
    """C % 语义：余数符号跟被除数（与 c_div 配套）。"""
    if b == 0:
        return 0
    return a - c_div(a, b) * b


class VMPError(Exception):
    pass


# 私有字节码执行步数上限（防死循环挂死；真机 jg_vmp.c 无此上限，靠业务语义本身保证终止）
VM_STEP_CAP = 200000


class VM:
    """Executes an obfuscated VMP blob. All values are 64-bit; INT32/INT16/WIDE
    ops model dalvik's type widths."""
    def __init__(self, blob):
        # blob = magic(2) + xorkey(1) + xor'd code...
        if len(blob) < 3 or blob[0] != 0xFD or blob[1] != 0xC2:
            raise VMPError('bad VMP magic')
        self.key = blob[2]
        self.code = bytearray(b ^ self.key for b in blob[3:])
        self.nregs = 16
        self.reset()

    def reset(self):
        self.r = [0] * self.nregs
        self.cond = 0
        self.pc = 0

    def run(self, args=None):
        if args:
            for i, v in enumerate(args):
                self.r[i] = v & MASK64
        code = self.code
        steps = 0
        # 迭代上限（与 harness 的 REF_STEP_CAP 对齐）：安全子集的私有码允许回跳，
        # 死循环方法会把 fuzz / 调用方挂死。超限抛异常而不是静默跑飞。
        while True:
            steps += 1
            if steps > VM_STEP_CAP:
                raise VMPError('vm step cap %d exceeded' % VM_STEP_CAP)
            if self.pc >= len(code):
                raise VMPError('pc out of range (%d/%d)' % (self.pc, len(code)))
            op = code[self.pc]
            self.pc += 1
            if op == OP_MOV_RI:
                rd = code[self.pc]; self.pc += 1
                imm = struct.unpack_from('<i', code, self.pc)[0]; self.pc += 4
                self.r[rd] = imm & MASK64
            elif op == OP_MOV_RR:
                rd = code[self.pc]; rs = code[self.pc + 1]; self.pc += 2
                self.r[rd] = self.r[rs] & MASK64
            elif op in (OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_AND, OP_OR,
                        OP_XOR, OP_SHL, OP_SHR, OP_USHR):
                rd = code[self.pc]; a = code[self.pc + 1]; b = code[self.pc + 2]; self.pc += 3
                va = _signed64(self.r[a]); vb = _signed64(self.r[b])
                if op == OP_ADD: res = va + vb
                elif op == OP_SUB: res = va - vb
                elif op == OP_MUL: res = va * vb
                elif op == OP_DIV: res = c_div(va, vb)
                elif op == OP_MOD: res = c_rem(va, vb)
                elif op == OP_AND: res = va & vb
                elif op == OP_OR: res = va | vb
                elif op == OP_XOR: res = va ^ vb
                elif op == OP_SHL: res = va << (vb & 63)
                elif op == OP_SHR: res = va >> (vb & 63)
                elif op == OP_USHR: res = (va & MASK64) >> (vb & 63)
                self.r[rd] = res & MASK64
            elif op == OP_NEG:
                rd = code[self.pc]; rs = code[self.pc + 1]; self.pc += 2
                self.r[rd] = (-_signed64(self.r[rs])) & MASK64
            elif op in (OP_CMP_LT, OP_CMP_LE, OP_CMP_GT, OP_CMP_GE, OP_CMP_EQ, OP_CMP_NE):
                a = code[self.pc]; b = code[self.pc + 1]; self.pc += 2
                va = _signed64(self.r[a]); vb = _signed64(self.r[b])
                if op == OP_CMP_LT: c = va < vb
                elif op == OP_CMP_LE: c = va <= vb
                elif op == OP_CMP_GT: c = va > vb
                elif op == OP_CMP_GE: c = va >= vb
                elif op == OP_CMP_EQ: c = va == vb
                elif op == OP_CMP_NE: c = va != vb
                self.cond = 1 if c else 0
            elif op in (OP_JMP, OP_JNZ, OP_JZ):
                tgt = struct.unpack_from('<i', code, self.pc)[0]; self.pc += 4
                if op == OP_JMP or (op == OP_JNZ and self.cond != 0) or (op == OP_JZ and self.cond == 0):
                    self.pc = tgt
            elif op == OP_RET:
                rd = code[self.pc]; self.pc += 1
                return _signed64(self.r[rd])
            elif op == OP_INT32:
                rd = code[self.pc]; self.pc += 1
                self.r[rd] = self.r[rd] & MASK32
            elif op == OP_INT16:
                rd = code[self.pc]; self.pc += 1
                self.r[rd] = self.r[rd] & MASK16
            elif op == OP_WIDE:
                rd = code[self.pc]; self.pc += 1
                self.r[rd] = self.r[rd] & MASK64
            elif op == OP_SEXT32:
                rd = code[self.pc]; self.pc += 1
                self.r[rd] = _signed32(self.r[rd] & MASK32) & MASK64
            elif op == OP_ZEXT16:
                rd = code[self.pc]; self.pc += 1
                self.r[rd] = self.r[rd] & MASK16
            elif op == OP_ZEXT32:
                rd = code[self.pc]; self.pc += 1
                self.r[rd] = self.r[rd] & MASK32
            elif op == OP_SEXT16:
                rd = code[self.pc]; self.pc += 1
                self.r[rd] = _signed16(self.r[rd] & MASK16) & MASK64
            elif op == OP_MOV_RI64:
                rd = code[self.pc]; self.pc += 1
                imm = struct.unpack_from('<q', code, self.pc)[0]; self.pc += 8
                self.r[rd] = imm & MASK64
            else:
                raise VMPError('unknown opcode 0x%02x at pc=%d' % (op, self.pc - 1))


def assemble_vm_bytecode(code_bytes, xor_key=0xC2):
    """Wrap raw VM opcodes with magic + xor obfuscation."""
    out = bytearray([0xFD, 0xC2, xor_key])
    for b in code_bytes:
        out.append(b ^ xor_key)
    return bytes(out)


def disasm(blob):
    """Human-readable disassembly (for inspection / evidence)."""
    key = blob[2]
    code = bytearray(b ^ key for b in blob[3:])
    lines = []
    i = 0
    names = {v: k for k, v in globals().items() if k.startswith('OP_')}
    while i < len(code):
        op = code[i]
        s = names.get(op, '???')
        i += 1
        if op == OP_MOV_RI:
            rd = code[i]; imm = struct.unpack_from('<i', code, i + 1)[0]
            lines.append('%s r%d, %d' % (s, rd, imm)); i += 5
        elif op == OP_MOV_RR:
            lines.append('%s r%d, r%d' % (s, code[i], code[i + 1])); i += 2
        elif op in (OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_AND, OP_OR, OP_XOR, OP_SHL, OP_SHR, OP_USHR):
            lines.append('%s r%d, r%d, r%d' % (s, code[i], code[i + 1], code[i + 2])); i += 3
        elif op == OP_NEG:
            lines.append('%s r%d, r%d' % (s, code[i], code[i + 1])); i += 2
        elif op in (OP_CMP_LT, OP_CMP_LE, OP_CMP_GT, OP_CMP_GE, OP_CMP_EQ, OP_CMP_NE):
            lines.append('%s r%d, r%d' % (s, code[i], code[i + 1])); i += 2
        elif op in (OP_JMP, OP_JNZ, OP_JZ):
            t = struct.unpack_from('<i', code, i)[0]
            lines.append('%s ->%d' % (s, t)); i += 4
        elif op == OP_RET:
            lines.append('%s r%d' % (s, code[i])); i += 1
        elif op in (OP_INT32, OP_INT16, OP_WIDE, OP_SEXT32, OP_ZEXT16, OP_SEXT16,
                    OP_ZEXT32):
            lines.append('%s r%d' % (s, code[i])); i += 1
        elif op == OP_MOV_RI64:
            rd = code[i]; imm = struct.unpack_from('<q', code, i + 1)[0]
            lines.append('%s r%d, %d' % (s, rd, imm)); i += 9
        else:
            lines.append('%s ?' % s); break
    return '\n'.join(lines)
