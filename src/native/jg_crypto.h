/*
 * jg_crypto.h - JGShield native 加解密原语（自包含、header-only、无外部依赖）
 * --------------------------------------------------------------------------
 * 与 harden.py / ShieldApplication.java 的密钥/加密体系严格对齐：
 *   - HMAC-SHA256(seed, "JG|m"+dexIdx+"."+methodIdx)  -> per-method AES-256 密钥
 *   - AES-256-GCM 解密：iv(12) + 密文 + tag(16)  （与 Java AES/GCM/NoPadding 一致）
 *   - 密文 = zlib(RFC1950) 压缩后的方法指令（由调用方 zlib 解压，见 jg_method_restore.c）
 *
 * 所有函数均为 static，可安全被多个翻译单元 include（避免重复符号）。
 * 本文件只做算法，不直接碰 DEX 内存；DEX 写回见 jg_method_restore.c。
 *
 * 正确性兜底：test_method_restore.c 用 Python（pycryptodome）生成的已知答案向量
 * 逐原语断言，编译后运行即可确认本实现与加固端完全一致（无需真机）。
 */
#ifndef JG_CRYPTO_H
#define JG_CRYPTO_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ============================ SHA-256 ============================ */
static const uint32_t JG_SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t jg_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t buflen; } jg_sha256_ctx;

static void jg_sha256_block(jg_sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3], p += 4;
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = jg_rotr(w[i-15],7) ^ jg_rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = jg_rotr(w[i-2],17) ^ jg_rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = jg_rotr(e,6) ^ jg_rotr(e,11) ^ jg_rotr(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + JG_SHA_K[i] + w[i];
        uint32_t S0 = jg_rotr(a,2) ^ jg_rotr(a,13) ^ jg_rotr(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void jg_sha256_init(jg_sha256_ctx *c) {
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len=0; c->buflen=0;
}

static void jg_sha256_update(jg_sha256_ctx *c, const uint8_t *data, size_t len) {
    c->len += len;
    while (len) {
        size_t n = 64 - c->buflen;
        if (n > len) n = len;
        memcpy(c->buf + c->buflen, data, n);
        c->buflen += n; data += n; len -= n;
        if (c->buflen == 64) { jg_sha256_block(c, c->buf); c->buflen = 0; }
    }
}

static void jg_sha256_final(uint8_t out[32], jg_sha256_ctx *c) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    jg_sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56) jg_sha256_update(c, &zero, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8*i));
    jg_sha256_update(c, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[4*i]   = (uint8_t)(c->h[i] >> 24);
        out[4*i+1] = (uint8_t)(c->h[i] >> 16);
        out[4*i+2] = (uint8_t)(c->h[i] >> 8);
        out[4*i+3] = (uint8_t)(c->h[i]);
    }
}

/* ============================ HMAC-SHA256 ============================ */
static void jg_hmac_sha256(const uint8_t *key, size_t klen,
                           const uint8_t *msg, size_t mlen, uint8_t out[32]) {
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (klen > 64) {
        jg_sha256_ctx c; jg_sha256_init(&c); jg_sha256_update(&c, key, klen); jg_sha256_final(k, &c);
    } else {
        memcpy(k, key, klen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = (uint8_t)(k[i] ^ 0x36); opad[i] = (uint8_t)(k[i] ^ 0x5c); }
    uint8_t ih[32];
    jg_sha256_ctx c; jg_sha256_init(&c); jg_sha256_update(&c, ipad, 64); jg_sha256_update(&c, msg, mlen); jg_sha256_final(ih, &c);
    jg_sha256_init(&c); jg_sha256_update(&c, opad, 64); jg_sha256_update(&c, ih, 32); jg_sha256_final(out, &c);
}

/* ============================ AES-256 (ECB) ============================ */
static const uint8_t JG_AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint32_t jg_aes_subw(uint32_t w) {
    return (uint32_t)JG_AES_SBOX[w & 0xff]
         | ((uint32_t)JG_AES_SBOX[(w>>8)&0xff] << 8)
         | ((uint32_t)JG_AES_SBOX[(w>>16)&0xff] << 16)
         | ((uint32_t)JG_AES_SBOX[(w>>24)&0xff] << 24);
}
static uint32_t jg_aes_rotw(uint32_t w) { return ((w << 8) | (w >> 24)); }
static const uint32_t JG_AES_RCON[7] = {0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000};

static void jg_aes256_keyexp(const uint8_t *key, uint32_t rk[60]) {
    for (int i = 0; i < 8; i++)
        rk[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) | ((uint32_t)key[4*i+2] << 8) | key[4*i+3];
    for (int i = 8; i < 60; i++) {
        uint32_t t = rk[i-1];
        if ((i % 8) == 0) t = jg_aes_subw(jg_aes_rotw(t)) ^ JG_AES_RCON[i/8 - 1];
        else if ((i % 8) == 4) t = jg_aes_subw(t);
        rk[i] = rk[i-8] ^ t;
    }
}

static uint8_t jg_aes_rkbyte(const uint32_t *rk, int round, int i) {
    return (uint8_t)((rk[round*4 + (i/4)] >> (24 - 8*(i%4))) & 0xff);
}

static uint8_t jg_aes_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

static void jg_aes256_encrypt_block(const uint8_t *in, uint8_t *out, uint32_t rk[60]) {
    uint8_t st[16];
    for (int i = 0; i < 16; i++) st[i] = in[i];
    for (int i = 0; i < 16; i++) st[i] ^= jg_aes_rkbyte(rk, 0, i);
    for (int r = 1; r <= 14; r++) {
        for (int i = 0; i < 16; i++) st[i] = JG_AES_SBOX[st[i]];
        for (int row = 1; row < 4; row++) {
            uint8_t a = st[row], b = st[4+row], c = st[8+row], d = st[12+row];
            if (row == 1) { st[row]=b; st[4+row]=c; st[8+row]=d; st[12+row]=a; }
            else if (row == 2) { uint8_t t=st[row]; st[row]=st[8+row]; st[8+row]=t; uint8_t t2=st[4+row]; st[4+row]=st[12+row]; st[12+row]=t2; }
            else { uint8_t t=st[row]; st[row]=d; st[12+row]=c; st[8+row]=b; st[4+row]=t; }
        }
        if (r < 14) {
            for (int c = 0; c < 4; c++) {
                uint8_t a = st[c*4], b = st[c*4+1], cc = st[c*4+2], d = st[c*4+3];
                st[c*4]    = (uint8_t)(jg_aes_xtime(a) ^ (jg_aes_xtime(b) ^ b) ^ cc ^ d);
                st[c*4+1]  = (uint8_t)(a ^ jg_aes_xtime(b) ^ (jg_aes_xtime(cc) ^ cc) ^ d);
                st[c*4+2]  = (uint8_t)(a ^ b ^ jg_aes_xtime(cc) ^ (jg_aes_xtime(d) ^ d));
                st[c*4+3]  = (uint8_t)((jg_aes_xtime(a) ^ a) ^ b ^ cc ^ jg_aes_xtime(d));
            }
        }
        for (int i = 0; i < 16; i++) st[i] ^= jg_aes_rkbyte(rk, r, i);
    }
    for (int i = 0; i < 16; i++) out[i] = st[i];
}

/* ============================ AES-256-GCM ============================ */
static void jg_gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *out) {
    uint8_t Z[16] = {0}, V[16];
    memcpy(V, x, 16);
    for (int i = 0; i < 128; i++) {
        int bit = (y[i >> 3] >> (7 - (i & 7))) & 1;
        if (bit) { for (int j = 0; j < 16; j++) Z[j] ^= V[j]; }
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; j--) V[j] = (uint8_t)((V[j] >> 1) | ((V[j-1] & 1) << 7));
        V[0] = (uint8_t)(V[0] >> 1);
        if (lsb) V[0] ^= 0xe1;
    }
    memcpy(out, Z, 16);
}

static void jg_ghash(const uint8_t *H, const uint8_t *data, size_t len, uint8_t *Y) {
    memset(Y, 0, 16);
    for (size_t i = 0; i < len; i += 16) {
        uint8_t block[16]; memset(block, 0, 16);
        size_t n = len - i; if (n > 16) n = 16;
        memcpy(block, data + i, n);
        for (int j = 0; j < 16; j++) Y[j] ^= block[j];
        uint8_t tmp[16]; jg_gf_mult(Y, H, tmp); memcpy(Y, tmp, 16);
    }
}

static void jg_inc32(uint8_t *c) {
    for (int i = 15; i >= 12; i--) { if (++c[i] != 0) break; }
}

/* AES-256-GCM 解密。iv 固定 12 字节；blob 布局 iv(12)+密文+tag(16)。
 * 返回 0 成功（tag 校验通过），-1 失败。 */

/* zlib(RFC1950) 解压：由 jg_method_restore.c 提供定义，供 hook 模块复用。
 * 返回 0 成功，dst 容量由调用方按 insns_size*2 预分配。 */
int jg_inflate_zlib(const uint8_t *src, size_t srclen, uint8_t *dst,
                    size_t dstcap, size_t *outlen);

/* 方法指令还原（由 jg_method_restore.c 提供定义），供 P3.3 hook 模块复用。
 * jg_restore_methods：平台无关核心（不碰 mprotect）。
 * jg_restore_methods_protected：mprotect(RW) 后写回再恢复 RX。
 * 返回 0 成功；<0 各类错误。 */
int jg_restore_methods(uint8_t *dex, size_t dex_len,
                       const uint8_t *payload, size_t payload_len,
                       const uint8_t seed[32], int want_dex);
int jg_restore_methods_protected(uint8_t *dex, size_t dex_len,
                                 const uint8_t *payload, size_t payload_len,
                                 const uint8_t seed[32], int want_dex);

static int jg_aes256gcm_decrypt(const uint8_t *key,
                                 const uint8_t *iv, size_t ivlen,
                                 const uint8_t *ct, size_t ctlen,
                                 const uint8_t *tag,
                                 uint8_t *out) {
    if (ivlen != 12) return -1;
    uint32_t rk[60]; jg_aes256_keyexp(key, rk);
    uint8_t H[16]; { uint8_t z[16] = {0}; jg_aes256_encrypt_block(z, H, rk); }

    uint8_t J0[16];
    memcpy(J0, iv, 12); J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    uint8_t Y[16]; jg_ghash(H, ct, ctlen, Y);
    uint8_t lb[16] = {0};
    uint64_t ctbits = (uint64_t)ctlen * 8;
    for (int i = 0; i < 8; i++) lb[8+i] = (uint8_t)((ctbits >> (56 - 8*i)) & 0xff);
    for (int i = 0; i < 16; i++) Y[i] ^= lb[i];
    jg_gf_mult(Y, H, Y);

    uint8_t ctr[16]; memcpy(ctr, J0, 16);
    for (size_t i = 0; i < ctlen; i += 16) {
        jg_inc32(ctr);
        uint8_t ks[16]; jg_aes256_encrypt_block(ctr, ks, rk);
        size_t n = ctlen - i; if (n > 16) n = 16;
        for (size_t j = 0; j < n; j++) out[i+j] = (uint8_t)(ct[i+j] ^ ks[j]);
    }

    uint8_t ej0[16]; jg_aes256_encrypt_block(J0, ej0, rk);
    uint8_t T[16]; for (int i = 0; i < 16; i++) T[i] = (uint8_t)(Y[i] ^ ej0[i]);
    /* 常数时间比较 GCM 认证标签，防 timing side-channel（非 memcmp 的短路比较） */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)(T[i] ^ tag[i]);
    return (diff == 0) ? 0 : -1;
}

#endif /* JG_CRYPTO_H */
