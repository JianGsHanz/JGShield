/*
 * whitebox_kdf.h - P0-B 真白盒密钥派生（native 侧，header-only）
 * --------------------------------------------------------------------------
 * 仅当 build_stub 以 --wb-kdf（st["wb_kdf"]=True）烘焙、且编译期 -DWB_KDF 时，
 * jg_guard.c / jg_method_restore.c 才 #include 本文件并使用 wb_key_for。
 * clean 构建（默认）完全不 include 本文件、走干净 HMAC，行为不变。
 *
 * 算法与 Python whitebox_kdf.wb_derive 逐字节一致：
 *   final = SHA256_cont(WB_STATE, HMAC-SHA256(seed, msg))
 *   WB_STATE = SHA256 处理完 wb_secret 的 64B 填充块后的中间态(8×uint32)，
 *             由 build_stub 烘焙进本头（见 _bake_whitebox_kdf）。
 *
 * 复用 jg_crypto.h 的 SHA-256 原语（jg_sha256_ctx / update / final），保证与
 * 写端（harden/verify 的 whitebox_kdf.sha256_cont）逐位对齐 → 写读对称。
 *
 * 诚实边界：seed = HMAC(salt, cert_hash) 仍可由 APK 证书 + salt 在设备端重建，
 * 故白盒「不增加保密性」，只做混淆融合：去掉 .so 内连续的 seed 字面量、去掉
 * 可被一行 HMAC() 直接复用的干净派生，迫使攻击者先反编译还原 WB_STATE 融合逻辑。
 * → 提成本，不补秘密。真正的墙是 VMP / 服务端密钥（均不在本次范围）。
 */
#ifndef WHITEBOX_KDF_H
#define WHITEBOX_KDF_H

#include <stdint.h>
#include <string.h>
#include "jg_crypto.h"

/* build_stub 烘焙时把 WB_STATE 替换为具体 8×uint32 字面量；此处默认零值仅供
 * 独立编译/文档参考，clean 构建下本文件不会被 include。 */
#ifndef WB_STATE
#define WB_STATE {0,0,0,0,0,0,0,0}
#endif

static const uint32_t g_wb_state[8] = WB_STATE;

/* 从给定 8×uint32 中间态继续 SHA-256（等价于 Python whitebox_kdf.sha256_cont）。
 * 此处 ctx 已「消费一个 64B 块」，故 len=64、buflen=0。 */
static void wb_sha256_cont(const uint32_t state[8],
                           const uint8_t *msg, size_t len, uint8_t out[32]) {
    jg_sha256_ctx c;
    for (int i = 0; i < 8; i++) c.h[i] = state[i];
    c.len = 64;
    c.buflen = 0;
    jg_sha256_update(&c, msg, len);
    jg_sha256_final(out, &c);
}

/* 白盒密钥派生：final = SHA256_cont(WB_STATE, HMAC-SHA256(seed, msg))。
 * 与 harden/verify 的 whitebox_kdf.wb_derive 逐字节一致；msg 与 clean 派生同名。 */
static void wb_key_for(const uint8_t seed[32],
                       const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint8_t clean[32];
    jg_hmac_sha256(seed, 32, msg, len, clean);
    wb_sha256_cont(g_wb_state, clean, 32, out);
}

#endif /* WHITEBOX_KDF_H */
