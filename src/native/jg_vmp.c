/* jg_vmp.c -- native VMP-lite interpreter core (mirror of experiments/vmp_lite/vmp_core.h).
 * Translates a REAL dalvik method body into PRIVATE register-bytecode that only this
 * interpreter understands; the original dalvik body is removed from the DEX at build time.
 *
 * IMPORTANT (honest boundary): this raises reverse-engineering cost, it does NOT make the
 * code un-extractable. The private bytecode is still plaintext in process memory while the
 * interpreter executes it; the win is that a `dd /proc/<pid>/mem` yields PRIVATE instructions
 * (magic 0xFD 0xC2), not the original dalvik body. Pair with OLLVM on this .so for real lift. */
#include "jg_vmp.h"
#include <stdio.h>
#include <string.h>

/* private opcode space (NOT dalvik) */
enum {
    OP_MOV_RI=0x01, OP_MOV_RR=0x02, OP_ADD=0x03, OP_SUB=0x04, OP_MUL=0x05,
    OP_DIV=0x06, OP_MOD=0x07, OP_AND=0x08, OP_OR=0x09, OP_XOR=0x0A,
    OP_SHL=0x0B, OP_SHR=0x0C, OP_USHR=0x0D, OP_NEG=0x0E,
    OP_CMP_LT=0x0F, OP_CMP_LE=0x10, OP_CMP_GT=0x11, OP_CMP_GE=0x12,
    OP_CMP_EQ=0x13, OP_CMP_NE=0x14, OP_JMP=0x15, OP_JNZ=0x16, OP_JZ=0x17,
    OP_RET=0x18, OP_INT32=0x19, OP_INT16=0x1A, OP_WIDE=0x1B,
    OP_SEXT32=0x1C, OP_ZEXT16=0x1D, OP_SEXT16=0x1E, OP_MOV_RI64=0x1F,
    OP_ZEXT32=0x20   /* rd   r[rd] &= 0xFFFFFFFF (零扩展32位) —— dalvik ushr-int 必需:
                        寄存器存的是符号扩展后的 64 位值, 直接 USHR 会把高 32 位符号位
                        一起移进来, 负数结果全错。不能用 OP_INT32 代替: 那个是符号扩展。 */
};

static int64_t jg_vmp_r[16];
static int jg_vmp_cond;

static int64_t jg_vmp_signed64(uint64_t x){
    /* two's-complement targets (all Android ABIs): the cast is well-defined. */
    return (int64_t)x;
}

int64_t jg_vmp_run(const uint8_t *code, size_t len, const int64_t *args, int nargs){
    memset(jg_vmp_r, 0, sizeof(jg_vmp_r));
    for (int i = 0; i < nargs && i < 16; i++) jg_vmp_r[i] = args[i];
    jg_vmp_cond = 0;
    size_t pc = 0;
    while (pc < len){
        uint8_t op = code[pc++];
        switch(op){
            case OP_MOV_RI: {
                uint8_t rd = code[pc++];
                int32_t imm; memcpy(&imm, code+pc, 4); pc += 4;
                jg_vmp_r[rd] = (int64_t)imm;
                break;
            }
            case OP_MOV_RR: {
                uint8_t rd = code[pc++], rs = code[pc++];
                jg_vmp_r[rd] = jg_vmp_r[rs];
                break;
            }
            case OP_ADD: case OP_SUB: case OP_MUL: case OP_DIV: case OP_MOD:
            case OP_AND: case OP_OR: case OP_XOR: case OP_SHL: case OP_SHR: case OP_USHR: {
                uint8_t rd=code[pc++], a=code[pc++], b=code[pc++];
                int64_t va=jg_vmp_signed64(jg_vmp_r[a]), vb=jg_vmp_signed64(jg_vmp_r[b]); int64_t r=0;
                switch(op){
                    case OP_ADD: r=va+vb; break;
                    case OP_SUB: r=va-vb; break;
                    case OP_MUL: r=va*vb; break;
                    case OP_DIV: r = vb? va/vb : 0; break;
                    case OP_MOD: r = vb? va%vb : 0; break;
                    case OP_AND: r=va&vb; break;
                    case OP_OR:  r=va|vb; break;
                    case OP_XOR: r=va^vb; break;
                    case OP_SHL: r=va<<(vb&63); break;
                    case OP_SHR: r=va>>(vb&63); break;
                    case OP_USHR: r=((uint64_t)va)>>(vb&63); break;
                }
                jg_vmp_r[rd]=r; break;
            }
            case OP_NEG: {
                uint8_t rd=code[pc++], rs=code[pc++];
                jg_vmp_r[rd] = -jg_vmp_signed64(jg_vmp_r[rs]); break;
            }
            case OP_CMP_LT: case OP_CMP_LE: case OP_CMP_GT: case OP_CMP_GE:
            case OP_CMP_EQ: case OP_CMP_NE: {
                uint8_t a=code[pc++], b=code[pc++];
                int64_t va=jg_vmp_signed64(jg_vmp_r[a]), vb=jg_vmp_signed64(jg_vmp_r[b]); int c=0;
                switch(op){
                    case OP_CMP_LT: c=va<vb; break;
                    case OP_CMP_LE: c=va<=vb; break;
                    case OP_CMP_GT: c=va>vb; break;
                    case OP_CMP_GE: c=va>=vb; break;
                    case OP_CMP_EQ: c=va==vb; break;
                    case OP_CMP_NE: c=va!=vb; break;
                }
                jg_vmp_cond = c?1:0; break;
            }
            case OP_JMP: case OP_JNZ: case OP_JZ: {
                int32_t t; memcpy(&t, code+pc, 4); pc += 4;
                if (op==OP_JMP || (op==OP_JNZ && jg_vmp_cond) || (op==OP_JZ && !jg_vmp_cond)) pc = (size_t)t;
                break;
            }
            case OP_RET: {
                uint8_t rd=code[pc++];
                return jg_vmp_r[rd];
            }
            case OP_INT32: { uint8_t rd=code[pc++]; jg_vmp_r[rd]=(int64_t)(int32_t)jg_vmp_r[rd]; break; }
            case OP_INT16: { uint8_t rd=code[pc++]; jg_vmp_r[rd]=(int64_t)(int32_t)(jg_vmp_r[rd]&0xFFFF); break; }
            case OP_WIDE: { uint8_t rd=code[pc++]; jg_vmp_r[rd]=(uint64_t)jg_vmp_r[rd]; break; }
            case OP_SEXT32: { uint8_t rd=code[pc++]; jg_vmp_r[rd]=(int64_t)(int32_t)(jg_vmp_r[rd]&0xFFFFFFFFULL); break; }
            case OP_ZEXT16: { uint8_t rd=code[pc++]; jg_vmp_r[rd]=(jg_vmp_r[rd]&0xFFFFULL); break; }
            case OP_SEXT16: { uint8_t rd=code[pc++]; jg_vmp_r[rd]=(int64_t)(int16_t)(jg_vmp_r[rd]&0xFFFFULL); break; }
            case OP_ZEXT32: { uint8_t rd=code[pc++]; jg_vmp_r[rd]=(int64_t)((uint64_t)jg_vmp_r[rd]&0xFFFFFFFFULL); break; }
            case OP_MOV_RI64: {
                uint8_t rd=code[pc++];
                int64_t imm; memcpy(&imm, code+pc, 8); pc += 8;
                jg_vmp_r[rd] = imm;
                break;
            }
            default:
                fprintf(stderr, "JG_VMP: unknown opcode 0x%02x at pc=%zu\n", op, pc-1);
                return -1;
        }
    }
    return jg_vmp_r[0];
}

uint8_t *jg_vmp_deobfuscate(const uint8_t *blob, size_t blen, size_t *outlen){
    if (blen < 3){ *outlen = 0; return NULL; }
    size_t n = blen - 3;
    uint8_t *out = (uint8_t*)malloc(n);
    if (!out){ *outlen = 0; return NULL; }
    uint8_t key = blob[2];
    for (size_t i=0;i<n;i++) out[i] = blob[3+i] ^ key;
    *outlen = n;
    return out;
}
