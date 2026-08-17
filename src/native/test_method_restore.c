/*
 * test_method_restore.c - JGShield P3.2 native 正确性自校验（无需真机）
 * --------------------------------------------------------------------------
 * 用 method_restore_vectors.h（由 Python/pycryptodome 从真实加固数据生成）断言：
 *   1) HMAC-SHA256 密钥派生与加固端一致
 *   2) AES-256-GCM 解密正确（tag 校验通过且明文匹配）
 *   3) 完整 jg_restore_methods：NOP 化 DEX + 载荷 -> 原始 DEX
 * 任一失败即说明 jg_crypto.h / jg_method_restore.c 与加固端算法不符，需先修 C 再上真机。
 *
 * 编译（Android/NDK，需 zlib）：
 *   $PRE/aarch64-linux-android21-clang test_method_restore.c jg_method_restore.c -llog -lz -o test_method_restore
 * 运行（推到设备）：
 *   adb push test_method_restore /data/local/tmp/ && adb shell /data/local/tmp/test_method_restore
 * 退出码 0 = 全部通过。
 */
#include <stdio.h>
#include <string.h>
#include "jg_crypto.h"
#include "method_restore_vectors.h"

int g_fail = 0;

static void check(const char *name, int cond) {
    printf("[%s] %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) g_fail++;
}

static void check_bytes(const char *name, const unsigned char *got, const unsigned char *want, size_t n) {
    int ok = (got != NULL) && (memcmp(got, want, n) == 0);
    if (!ok) {
        printf("  %s: first mismatch at ", name);
        for (size_t i = 0; i < n; i++) {
            if (got[i] != want[i]) { printf("byte %zu (got 0x%02x want 0x%02x)", i, got[i], want[i]); break; }
        }
        printf("\n");
    }
    check(name, ok);
}

int main(void) {
    /* 1) HMAC 密钥派生 */
    unsigned char hmac_out[32];
    jg_hmac_sha256(V_SEED, 32, (const unsigned char *)"JG|m0.0", 7, hmac_out);
    check_bytes("HMAC derive JG|m0.0", hmac_out, V_HMAC_KEY, 32);

    /* 2) AES-256-GCM 解密向量 1 */
    {
        unsigned char out[sizeof(V_GCM1_PLAIN)];
        int rc = jg_aes256gcm_decrypt(V_GCM1_KEY, V_GCM1_IV, 12,
                                      V_GCM1_CT, sizeof(V_GCM1_CT), V_GCM1_TAG, out);
        check("GCM1 decrypt rc==0", rc == 0);
        check_bytes("GCM1 plaintext", out, V_GCM1_PLAIN, sizeof(V_GCM1_PLAIN));
    }

    /* 3) AES-256-GCM 解密向量 2 */
    {
        unsigned char out[sizeof(V_GCM2_PLAIN)];
        int rc = jg_aes256gcm_decrypt(V_GCM2_KEY, V_GCM2_IV, 12,
                                      V_GCM2_CT, sizeof(V_GCM2_CT), V_GCM2_TAG, out);
        check("GCM2 decrypt rc==0", rc == 0);
        check_bytes("GCM2 plaintext", out, V_GCM2_PLAIN, sizeof(V_GCM2_PLAIN));
    }

    /* 4) 完整写回：NOP_DEX + FULL_PAYLOAD -> ORIG_DEX */
    {
        unsigned char *buf = (unsigned char *)malloc(sizeof(V_NOP_DEX));
        memcpy(buf, V_NOP_DEX, sizeof(V_NOP_DEX));
        int rc = jg_restore_methods(buf, sizeof(V_NOP_DEX),
                                    V_FULL_PAYLOAD, sizeof(V_FULL_PAYLOAD), V_SEED, -1);
        check("restore rc==0", rc == 0);
        check_bytes("restore -> ORIG_DEX", buf, V_ORIG_DEX, sizeof(V_ORIG_DEX));
        free(buf);
    }

    printf("========================================\n");
    if (g_fail == 0) {
        printf("ALL PASS: native method-restore 与加固端字节一致\n");
        return 0;
    }
    printf("FAILED: %d 项向量不符，请修正 jg_crypto.h / jg_method_restore.c\n", g_fail);
    return 1;
}
