/*
 * jg_method_restore.c - JGShield P3.2 native 方法指令还原（解密 + 写回内存 DEX）
 * --------------------------------------------------------------------------
 * 与 harden.py(P3.1) / GxApp.java 完全对齐：
 *   - 载荷 jg 条目布局：MAGIC(4) + dex_count(4) + [dex blob]... + asset_count(4)
 *     + [asset]... + method_dex_count(4) + 每 dex {dex_idx(4)+entry_count(4)
 *     + stream_blob_len(4)+stream_blob + meta_blob_len(4)+meta_blob}。
 *   - meta_blob = zlib( (method_idx,code_off,insns_size)[u32;u32;u32] × entry_count )；
 *     offset_in_stream / len_in_stream 由 insns_size 在还原端按序累加推得（P6 压缩元数据表）。
 *   - 每 dex：per-dex 密钥 key=HMAC-SHA256(seed,"JG|m"+dexIdx)；
 *     stream_blob=iv(12)+AES-256-GCM(密文=zlib(concat_insns))+tag(16)；
 *     整体解密+zlib 解压得到拼流，再按 meta 还原的 offset/len 把 insns
 *     写回/比对 dex[code_off+16 .. +insns_size*2]。
 *
 * 设计：
 *   - jg_restore_methods()：平台无关核心（不碰 mprotect），便于单测。
 *   - jg_restore_methods_protected()：对 DEX 所在内存页 mprotect(RW) 后写回，
 *     再恢复 PROT_READ|PROT_EXEC。对应 P3.2 “确保 DEX 映射可写” 的验证点。
 *   - Java_com_gx_runtime_GxDecryptor_nativeRestoreMethods：JNI 入口，
 *     Decryptor 传入 direct ByteBuffer(dex) + direct ByteBuffer(payload) + byte[](seed)。
 *
 * 失败语义：返回 0 成功；<0 各类错误（魔数/参数/解密失败/长度不符/写越界）。
 * 本模块只做还原，不决定何时调用（P3.3 由 ART hook 触发单方法还原；P3.2 仅全量/单测）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

/* g_seed / g_seed_set 的唯一定义（本文件，全 ABI 编入）。壳解密阶段把种子写入，
 * 供运行期各 native 模块复用（原 VMP 解释器曾复用，现主要用于 DEX 还原等）。
 * nativeRestoreInit（仅 arm64 hook）也会写入。 */
uint8_t g_seed[32];
int     g_seed_set = 0;

/* 把 Java 传来的 32 字节 seed 写入共享 g_seed。失败忽略（长度非 32 视为异常）。 */
static void _capture_seed(JNIEnv *env, jbyteArray seedArr, jbyte *seedp) {
    if (!seedp) return;
    jsize sl = (*env)->GetArrayLength(env, seedArr);
    if (sl == 32) { memcpy(g_seed, seedp, 32); g_seed_set = 1; }
}
#include <zlib.h>
#include <android/log.h>

#include "jg_crypto.h"
#ifdef WB_KDF
/* P0-B 真白盒：仅 -DWB_KDF 时引入白盒 KDF（WB_STATE 已烘焙进该头）。 */
#include "whitebox_kdf.h"
#endif

#define TAG "JG-MethodRestore"
#define JG_PAGE 4096

static uint32_t jg_rd32(const uint8_t *b, size_t off) {
    return ((uint32_t)b[off]) | ((uint32_t)b[off+1] << 8)
         | ((uint32_t)b[off+2] << 16) | ((uint32_t)b[off+3] << 24);
}

/* zlib(RFC1950) 解压；out 容量由调用方按 insns_size*2 预分配。 */
int jg_inflate_zlib(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstcap, size_t *outlen) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflateInit(&strm) != Z_OK) return -1;
    strm.next_in = (Bytef *)src;
    strm.avail_in = (uInt)srclen;
    strm.next_out = (Bytef *)dst;
    strm.avail_out = (uInt)dstcap;
    int rc = inflate(&strm, Z_FINISH);
    if (rc != Z_STREAM_END) { inflateEnd(&strm); return -1; }
    *outlen = strm.total_out;
    inflateEnd(&strm);
    return 0;
}

/* zlib(RFC1950) 解压到自动增长的缓冲区；返回 0 成功，*out/*outlen 由调用方 free。
 * 用于 meta_blob 等解压前未知长度的场景（与 jg_inflate_zlib 仅 dstcap 契约不同）。 */
int jg_inflate_zlib_grow(const uint8_t *src, size_t srclen, uint8_t **out, size_t *outlen) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflateInit(&strm) != Z_OK) return -1;
    size_t cap = srclen * 4 + 4096;
    if (cap < 4096) cap = 4096;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { inflateEnd(&strm); return -1; }
    strm.next_in = (Bytef *)src;
    strm.avail_in = (uInt)srclen;
    int rc;
    while (1) {
        strm.next_out = (Bytef *)(buf + strm.total_out);
        strm.avail_out = (uInt)(cap - strm.total_out);
        rc = inflate(&strm, Z_FINISH);
        if (rc == Z_STREAM_END) break;
        if (rc == Z_BUF_ERROR) {
            size_t ncap = cap * 2 + 4096;
            uint8_t *nb = (uint8_t *)realloc(buf, ncap);
            if (!nb) { free(buf); inflateEnd(&strm); return -1; }
            buf = nb; cap = ncap;
            continue;
        }
        free(buf); inflateEnd(&strm); return -1;
    }
    *out = buf;
    *outlen = strm.total_out;
    inflateEnd(&strm);
    return 0;
}

/*
 * 平台无关核心：把 payload 方法段的解密指令写回 dex 缓冲区。
 * dex 应为「NOP 化后的原始 DEX」（即载荷 dex 段解密所得），长度 dex_len。
 * want_dex：仅还原该 dex_idx 的条目；<0 表示还原载荷内全部 dex 段（单测用）。
 *   关键修复：载荷方法段按 dex_idx 分段，各段的 code_off 是「该 dex 文件内偏移」，
 *   必须只写回「对应 dex 的缓冲区」，否则会把 dex1/2.. 的 insns 错写到 dex0 缓冲区
 *   或越界返回 -1（P3.2 批量回退曾因此 dex1..15 全部 rc=-1）。
 */
int jg_restore_methods(uint8_t *dex, size_t dex_len,
                       const uint8_t *payload, size_t payload_len,
                       const uint8_t seed[32], int want_dex) {
    if (payload_len < 8 || memcmp(payload, "JGS1", 4) != 0) return -1;
    size_t p = 4;
    uint32_t dex_count = jg_rd32(payload, p); p += 4;
    /* 跳过 dex 段 */
    for (uint32_t i = 0; i < dex_count; i++) {
        uint32_t ln = jg_rd32(payload, p); p += 4; p += ln;
    }
    /* 跳过 asset 段 */
    if (p + 4 > payload_len) return -1;
    uint32_t asset_count = jg_rd32(payload, p); p += 4;
    for (uint32_t i = 0; i < asset_count; i++) {
        uint32_t nl = jg_rd32(payload, p); p += 4; p += nl;
        uint32_t ln = jg_rd32(payload, p); p += 4; p += ln;
    }
    if (p + 4 > payload_len) return 0;   /* 无方法段：无需还原 */
    uint32_t mdc = jg_rd32(payload, p); p += 4;
    if (mdc == 0) return 0;

    /* 整段格式（2026-09-14 回退）：每 dex 段 [dex_idx][ec(=1)][stream_blob][meta_blob]。
     * stream_blob = iv(12)+AES-GCM(zlib(concat_insns))+tag(16)，per-dex 密钥 JG|m{dex}；
     * meta_blob = zlib((method_idx,code_off,insns_size)[u32]×n)。加载期整段解密后按 meta
     * 三元组逐条写回（offset 由 Σinsns_size*2 累加推得）。 */
    for (uint32_t s = 0; s < mdc; s++) {
        uint32_t dex_idx = jg_rd32(payload, p); p += 4;
        uint32_t ec = jg_rd32(payload, p); p += 4;   /* 整段方案恒为 1 */
        if (want_dex >= 0 && (int)dex_idx != want_dex) {
            for (uint32_t e = 0; e < ec; e++) {
                uint32_t sbl = jg_rd32(payload, p); p += 4; p += sbl;
                uint32_t mbl = jg_rd32(payload, p); p += 4; p += mbl;
            }
            continue;
        }
        for (uint32_t e = 0; e < ec; e++) {
            uint32_t sbl = jg_rd32(payload, p); p += 4;
            const uint8_t *stream_blob = payload + p; p += sbl;
            uint32_t mbl = jg_rd32(payload, p); p += 4;
            const uint8_t *meta_blob = payload + p; p += mbl;
            if (sbl < 28) continue;       /* iv12 + tag16 至少 28 */
            /* per-dex 密钥 JG|m{dex} */
            char label[64];
            int ll = snprintf(label, sizeof(label), "JG|m%u", dex_idx);
            uint8_t key[32];
#ifdef WB_KDF
            wb_key_for(seed, (const uint8_t *)label, (size_t)ll, key);
#else
            jg_hmac_sha256(seed, 32, (const uint8_t *)label, (size_t)ll, key);
#endif
            const uint8_t *iv = stream_blob;
            const uint8_t *ct = stream_blob + 12;
            size_t ctlen = (size_t)sbl - 12 - 16;
            const uint8_t *tag = stream_blob + sbl - 16;
            uint8_t *comp = (uint8_t *)malloc(ctlen ? ctlen : 1);
            if (!comp) return -1;
            memcpy(comp, ct, ctlen);
            uint8_t *plain = (uint8_t *)malloc(ctlen ? ctlen : 1);
            if (!plain) { free(comp); return -1; }
            if (jg_aes256gcm_decrypt(key, iv, 12, comp, ctlen, tag, plain) != 0) {
                free(comp); free(plain); return -1;
            }
            free(comp);
            /* 解 meta：zlib((method_idx,code_off,insns_size)[u32]×n)，12B/条 */
            uint8_t *metabuf = NULL; size_t metalen = 0;
            if (mbl > 0 && jg_inflate_zlib_grow(meta_blob, mbl, &metabuf, &metalen) != 0) {
                free(plain); return -1;
            }
            /* 先算 total = Σinsns_size*2（stream 解压 dstcap 与写回校验） */
            size_t total = 0;
            uint32_t n = (uint32_t)(metalen / 12);
            for (uint32_t k = 0; k < n; k++) {
                uint32_t insns_size = jg_rd32(metabuf, k * 12 + 8);
                total += (size_t)insns_size * 2;
            }
            uint8_t *concat = (uint8_t *)malloc(total ? total : 1);
            if (!concat) { if (metabuf) free(metabuf); free(plain); return -1; }
            size_t got = 0;
            if (jg_inflate_zlib(plain, ctlen, concat, total, &got) != 0
                || got != total) {
                if (metabuf) free(metabuf); free(plain); free(concat); return -1;
            }
            free(plain);
            /* 按 meta 顺序写回 dex */
            size_t off = 0;
            for (uint32_t k = 0; k < n; k++) {
                uint32_t method_idx = jg_rd32(metabuf, k * 12 + 0);
                uint32_t code_off   = jg_rd32(metabuf, k * 12 + 4);
                uint32_t insns_size = jg_rd32(metabuf, k * 12 + 8);
                (void)method_idx;
                size_t len = (size_t)insns_size * 2;
                size_t ins_off = (size_t)code_off + 16;
                if (off + len > total) {
                    if (metabuf) free(metabuf); free(concat); return -1;
                }
                if (ins_off + len > dex_len) {
                    __android_log_print(ANDROID_LOG_ERROR, TAG,
                        "OOB dex_idx=%u method_idx=%u code_off=%u ins_off=%zu len=%zu dex_len=%zu",
                        dex_idx, method_idx, code_off, ins_off, len, dex_len);
                    if (metabuf) free(metabuf); free(concat); return -1;
                }
                memcpy(dex + ins_off, concat + off, len);
                off += len;
            }
            if (metabuf) free(metabuf);
            free(concat);
        }
    }
    return 0;
}

/* 带 mprotect 的写回：解密期 direct ByteBuffer 本就是 RW，ART 构造 DexFile 时会拷贝，
 * 故只需确保可写并写回，写完保持 RW 即可——绝不改 RX。
 * 改 RX 会因缓冲区非页对齐导致 mprotect 越界污染相邻堆页，引发 GC ConcurrentCopying
 * MarkNonMoving SEGV_ACCERR（实测真机崩溃根因之一）。 */
int jg_restore_methods_protected(uint8_t *dex, size_t dex_len,
                                  const uint8_t *payload, size_t payload_len,
                                  const uint8_t seed[32], int want_dex) {
    uintptr_t addr = (uintptr_t)dex;
    uintptr_t aligned = addr & ~(uintptr_t)(JG_PAGE - 1);
    size_t map_len = ((addr + dex_len + JG_PAGE - 1) & ~(uintptr_t)(JG_PAGE - 1)) - aligned;
    if (mprotect((void *)aligned, map_len, PROT_READ | PROT_WRITE) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "mprotect RW failed (errno maybe ENOMEM)");
        return -2;
    }
    int rc = jg_restore_methods(dex, dex_len, payload, payload_len, seed, want_dex);
    return rc;
}

/* P-INTEGRITY：DEX 还原后自校验——逐方法解密载荷 blob 并与内存中 live dex 比较，
 * 返回不匹配方法数（0 表示还原正确 / 未被篡改）；<0 表示载荷解析错误。
 * 与 jg_restore_methods 共享解密原语，仅比较不写回，可重复调用。
 * max_per_dex>0 时每 dex 仅校验前 max_per_dex 个方法（抽样，控制启动期主线程耗时，
 * 避免 ANR）；=-1 表示全量校验（用于后台线程深度体检）。指针始终按条目前进以保持段对齐。 */
int jg_verify_methods(const uint8_t *dex, size_t dex_len,
                      const uint8_t *payload, size_t payload_len,
                      const uint8_t seed[32], int want_dex, int max_per_dex) {
    if (payload_len < 8 || memcmp(payload, "JGS1", 4) != 0) return -1;
    size_t p = 4;
    uint32_t dex_count = jg_rd32(payload, p); p += 4;
    for (uint32_t i = 0; i < dex_count; i++) { uint32_t ln = jg_rd32(payload, p); p += 4; p += ln; }
    if (p + 4 > payload_len) return -1;
    uint32_t asset_count = jg_rd32(payload, p); p += 4;
    for (uint32_t i = 0; i < asset_count; i++) {
        uint32_t nl = jg_rd32(payload, p); p += 4; p += nl;
        uint32_t ln = jg_rd32(payload, p); p += 4; p += ln;
    }
    if (p + 4 > payload_len) return 0;
    uint32_t mdc = jg_rd32(payload, p); p += 4;
    if (mdc == 0) return 0;
    int mism = 0;
    /* 整段格式（2026-09-14 回退）：整段解密后逐条 memcmp，不写回，可重复调用。 */
    for (uint32_t s = 0; s < mdc; s++) {
        uint32_t dex_idx = jg_rd32(payload, p); p += 4;
        uint32_t ec = jg_rd32(payload, p); p += 4;   /* 整段方案恒为 1 */
        if (want_dex >= 0 && (int)dex_idx != want_dex) {
            for (uint32_t e = 0; e < ec; e++) {
                uint32_t sbl = jg_rd32(payload, p); p += 4; p += sbl;
                uint32_t mbl = jg_rd32(payload, p); p += 4; p += mbl;
            }
            continue;
        }
        uint32_t verified = 0;
        for (uint32_t e = 0; e < ec; e++) {
            uint32_t sbl = jg_rd32(payload, p); p += 4;
            const uint8_t *stream_blob = payload + p; p += sbl;
            uint32_t mbl = jg_rd32(payload, p); p += 4;
            const uint8_t *meta_blob = payload + p; p += mbl;
            if (max_per_dex > 0 && verified >= (uint32_t)max_per_dex) continue;
            verified++;
            if (sbl < 28) { mism++; continue; }
            char label[64];
            int ll = snprintf(label, sizeof(label), "JG|m%u", dex_idx);
            uint8_t key[32];
#ifdef WB_KDF
            wb_key_for(seed, (const uint8_t *)label, (size_t)ll, key);
#else
            jg_hmac_sha256(seed, 32, (const uint8_t *)label, (size_t)ll, key);
#endif
            const uint8_t *iv = stream_blob;
            const uint8_t *ct = stream_blob + 12;
            size_t ctlen = (size_t)sbl - 12 - 16;
            const uint8_t *tag = stream_blob + sbl - 16;
            uint8_t *comp = (uint8_t *)malloc(ctlen ? ctlen : 1);
            if (!comp) return -2;
            memcpy(comp, ct, ctlen);
            uint8_t *plain = (uint8_t *)malloc(ctlen ? ctlen : 1);
            if (!plain) { free(comp); return -2; }
            if (jg_aes256gcm_decrypt(key, iv, 12, comp, ctlen, tag, plain) != 0) {
                free(comp); free(plain); mism++; continue;
            }
            free(comp);
            uint8_t *metabuf = NULL; size_t metalen = 0;
            if (mbl > 0 && jg_inflate_zlib_grow(meta_blob, mbl, &metabuf, &metalen) != 0) {
                free(plain); mism++; continue;
            }
            size_t total = 0;
            uint32_t n = (uint32_t)(metalen / 12);
            for (uint32_t k = 0; k < n; k++) {
                uint32_t insns_size = jg_rd32(metabuf, k * 12 + 8);
                total += (size_t)insns_size * 2;
            }
            uint8_t *concat = (uint8_t *)malloc(total ? total : 1);
            if (!concat) { if (metabuf) free(metabuf); free(plain); return -2; }
            size_t got = 0;
            if (jg_inflate_zlib(plain, ctlen, concat, total, &got) != 0 || got != total) {
                if (metabuf) free(metabuf); free(plain); free(concat); mism++; continue;
            }
            free(plain);
            size_t off = 0;
            for (uint32_t k = 0; k < n; k++) {
                uint32_t method_idx = jg_rd32(metabuf, k * 12 + 0);
                uint32_t code_off   = jg_rd32(metabuf, k * 12 + 4);
                uint32_t insns_size = jg_rd32(metabuf, k * 12 + 8);
                (void)method_idx;
                size_t len = (size_t)insns_size * 2;
                size_t ins_off = (size_t)code_off + 16;
                if (off + len > total || ins_off + len > dex_len) { mism++; break; }
                if (memcmp(dex + ins_off, concat + off, len) != 0) mism++;
                off += len;
            }
            if (metabuf) free(metabuf);
            free(concat);
        }
    }
    return mism;
}

/* JNI 入口：Decryptor.nativeRestoreMethods(ByteBuffer dexBuf, byte[] payload, byte[] seed, int dexIdx)
 * dexBuf 必须为 direct ByteBuffer（allocateDirect），native 直接取其内存地址做 mprotect+写回。
 * payload 为 jg 载荷原始字节（byte[]），seed 为 32 字节，dexIdx 指定仅还原该 dex 的条目。 */
JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxDecryptor_nativeRestoreMethods(JNIEnv *env, jclass clazz,
        jobject dexBuf, jbyteArray payloadArr, jbyteArray seedArr, jint dexIdx) {
    (void)clazz;
    uint8_t *dex = (uint8_t *)(*env)->GetDirectBufferAddress(env, dexBuf);
    jlong dexLen = (*env)->GetDirectBufferCapacity(env, dexBuf);
    if (!dex || dexLen <= 0) return -3;
    jbyte *payloadp = (*env)->GetByteArrayElements(env, payloadArr, NULL);
    jsize payLen = (*env)->GetArrayLength(env, payloadArr);
    if (!payloadp || payLen <= 0) {
        if (payloadp) (*env)->ReleaseByteArrayElements(env, payloadArr, payloadp, JNI_ABORT);
        return -3;
    }
    jbyte *seedp = (*env)->GetByteArrayElements(env, seedArr, NULL);
    if (!seedp) {
        (*env)->ReleaseByteArrayElements(env, payloadArr, payloadp, JNI_ABORT);
        return -3;
    }
    int rc = jg_restore_methods_protected(dex, (size_t)dexLen,
                                          (const uint8_t *)payloadp, (size_t)payLen,
                                          (const uint8_t *)seedp, (int)dexIdx);
    (*env)->ReleaseByteArrayElements(env, seedArr, seedp, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, payloadArr, payloadp, JNI_ABORT);
    return rc;
}

/* JNI 入口：Decryptor.nativeVerifyDex(ByteBuffer dexBuf, byte[] payload, byte[] seed, int dexIdx, int maxPerDex)
 * 还原后自校验：解密载荷方法段并与内存中 live dex[code_off+16] 逐字节比对，
 * 返回不匹配方法数（0 表示还原正确）。maxPerDex>0 抽样（启动期用），-1 全量（后台深度体检）。
 * fail-safe：任何错误返回负值，调用方仅记日志。 */
JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxDecryptor_nativeVerifyDex(JNIEnv *env, jclass clazz,
        jobject dexBuf, jbyteArray payloadArr, jbyteArray seedArr, jint dexIdx, jint maxPerDex) {
    (void)clazz;
    uint8_t *dex = (uint8_t *)(*env)->GetDirectBufferAddress(env, dexBuf);
    jlong dexLen = (*env)->GetDirectBufferCapacity(env, dexBuf);
    if (!dex || dexLen <= 0) return -3;
    jbyte *payloadp = (*env)->GetByteArrayElements(env, payloadArr, NULL);
    jsize payLen = (*env)->GetArrayLength(env, payloadArr);
    if (!payloadp || payLen <= 0) {
        if (payloadp) (*env)->ReleaseByteArrayElements(env, payloadArr, payloadp, JNI_ABORT);
        return -3;
    }
    jbyte *seedp = (*env)->GetByteArrayElements(env, seedArr, NULL);
    if (!seedp) {
        (*env)->ReleaseByteArrayElements(env, payloadArr, payloadp, JNI_ABORT);
        return -3;
    }
    _capture_seed(env, seedArr, seedp);
    int rc = jg_verify_methods(dex, (size_t)dexLen,
                               (const uint8_t *)payloadp, (size_t)payLen,
                               (const uint8_t *)seedp, (int)dexIdx, (int)maxPerDex);
    (*env)->ReleaseByteArrayElements(env, seedArr, seedp, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, payloadArr, payloadp, JNI_ABORT);
    return rc;
}
