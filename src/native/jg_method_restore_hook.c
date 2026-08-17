/*
 * jg_method_restore_hook.c - JGShield P3.3 解释桥 hook（方法首次执行前还原）
 * --------------------------------------------------------------------------
 * 触发点：ART 解释器入口 artInterpreterToInterpreterBridge(self, code_item, ...)。
 * 该函数的第 2 参数(x1)即指向方法 CodeItem 的指针（DEX 内偏移 code_off 处）。
 *
 * 还原定位（刻意避开 ArtMethod 内部结构解析，降低版本耦合）：
 *   1) Java 侧在 DEX 载入后调用 nativeRestoreInit(dexIdx, dexBuf, payload, seed)，
 *      注册各 DEX 的【内存基址区间】(base, len) 与载荷/种子。
 *   2) hook 处理器用 code_item 指针匹配已注册区间 -> 得 dex_idx，code_off = ci - base。
 *   3) 以 (dex_idx, code_off) 查载荷索引 -> 取 blob -> HMAC 派生 key -> AES-GCM 解密
 *      -> zlib 解压 -> mprotect(RW) 写回 code_item+16(insns 起点) -> 恢复 RX。
 *   每方法仅还原一次（幂等，无需加锁）。
 *
 * 失败安全：
 *   - 符号解析 / inline hook 安装失败 -> 回退"整包批量还原"（jg_restore_methods_protected），
 *     保证 App 仍可运行（仅内存 dump 抗性较弱）。
 *   - 所有错误仅记日志，绝不抛异常 / 退出进程。
 *
 * 已知设备相关风险（沙箱不可达，需真机 logcat 确认）：
 *   - code_item 偏移假设：DEX 在内存中与文件同布局（P2 已证 ART 直接读 ByteBuffer）。
 *   - CodeItem 头 16 字节后接 insns（insns 起点 = code_item+16）。
 *   - 解释器桥符号名随 Android 版本变化（本实现以 Android10 arm64 为准，见 HOOK_TARGETS）。
 *   - 若某方法被 JIT 在"首次解释前"编译，则 hook 不触发、执行 NOP -> 崩溃；常态 ART 先解释后 JIT。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <android/log.h>
#include <stdio.h>
#include <elf.h>

#include "jg_crypto.h"
#include "jg_inline_hook.h"

#define TAG "JG-MethodRestoreHook"

/* ---------------- ELF 符号表解析（替代 dlsym，绕过 .dynsym 未导出限制） ----------------
 * dlsym(RTLD_DEFAULT) 只遍历 .dynsym，而 ART 内部解释桥 artInterpreterToInterpreterBridge
 * 不在 .dynsym（未导出），故拿不到。改为从磁盘文件解析 libart.so 的 .symtab（节头/符号表
 * 都在文件里，与运行时映射无关），按名匹配符号，运行时地址 = libart 加载基址 + st_value。
 */
static uintptr_t find_lib_base(const char *name, char *pathbuf, size_t pathlen) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[600];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) {
            unsigned long st, off;
            if (sscanf(line, "%lx-%*x %*s %lx %*s %*s", &st, &off) == 2) {
                if (off == 0 && !base) base = (uintptr_t)st;
                char *sp = line; char *last = NULL;
                while (*sp) { if (*sp == ' ') last = sp; sp++; }
                char *p = last ? last + 1 : line;
                size_t L = strlen(p);
                if (L && p[L-1] == '\n') p[L-1] = 0;
                if (pathbuf && p[0] == '/' && !strstr(p, "[")) {
                    strncpy(pathbuf, p, pathlen - 1);
                    pathbuf[pathlen - 1] = 0;
                }
            }
        }
    }
    fclose(f);
    return base;
}

/* 从磁盘文件解析 libart.so 的符号表，按名返回运行时地址（base + st_value）。
 * 优先 .symtab，回退 .dynsym。 */
static void *elf_find_sym_file(const char *path, uintptr_t base, const char *symname) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    uint8_t e[64];
    if (fread(e, 1, 64, f) != 64) { fclose(f); return NULL; }
    if (e[0] != 0x7f || e[1] != 'E' || e[2] != 'L' || e[3] != 'F') { fclose(f); return NULL; }
    int cls = e[4];
    void *found = NULL;

    if (cls == 2) {
        uint64_t shoff = (uint64_t)e[40] | ((uint64_t)e[41] << 8) | ((uint64_t)e[42] << 16)
                      | ((uint64_t)e[43] << 24) | ((uint64_t)e[44] << 32)
                      | ((uint64_t)e[45] << 40) | ((uint64_t)e[46] << 48) | ((uint64_t)e[47] << 56);
        uint16_t shnum = (uint16_t)(e[60] | (e[61] << 8));
        uint16_t shstrndx = (uint16_t)(e[62] | (e[63] << 8));
        if (shnum == 0 || shoff == 0) { fclose(f); return NULL; }
        Elf64_Shdr *sh = (Elf64_Shdr *)malloc((size_t)shnum * sizeof(Elf64_Shdr));
        if (!sh) { fclose(f); return NULL; }
        fseek(f, (long)shoff, SEEK_SET);
        if (fread(sh, sizeof(Elf64_Shdr), shnum, f) != shnum) { free(sh); fclose(f); return NULL; }
        int si = -1;
        for (int i = 0; i < shnum; i++) if (sh[i].sh_type == SHT_SYMTAB) { si = i; break; }
        if (si < 0) for (int i = 0; i < shnum; i++) if (sh[i].sh_type == SHT_DYNSYM) { si = i; break; }
        if (si >= 0) {
            char *shstr = (char *)malloc(sh[shstrndx].sh_size ? sh[shstrndx].sh_size : 1);
            char *symbuf = (char *)malloc(sh[si].sh_size ? sh[si].sh_size : 1);
            char *strbuf = (char *)malloc(sh[sh[si].sh_link].sh_size ? sh[sh[si].sh_link].sh_size : 1);
            if (shstr && symbuf && strbuf) {
                fseek(f, (long)sh[shstrndx].sh_offset, SEEK_SET);
                fread(shstr, 1, sh[shstrndx].sh_size, f);
                fseek(f, (long)sh[si].sh_offset, SEEK_SET);
                fread(symbuf, 1, sh[si].sh_size, f);
                fseek(f, (long)sh[sh[si].sh_link].sh_offset, SEEK_SET);
                fread(strbuf, 1, sh[sh[si].sh_link].sh_size, f);
                Elf64_Sym *syms = (Elf64_Sym *)symbuf;
                int n = (int)(sh[si].sh_size / sizeof(Elf64_Sym));
                for (int i = 0; i < n; i++) {
                    if (syms[i].st_shndx == SHN_UNDEF) continue;
                    const char *nm = strbuf + syms[i].st_name;
                    if (strcmp(nm, symname) == 0) { found = (void *)(base + syms[i].st_value); break; }
                }
            }
            free(shstr); free(symbuf); free(strbuf);
        }
        free(sh);
    } else if (cls == 1) {
        uint32_t shoff = (uint32_t)e[0x20] | ((uint32_t)e[0x21] << 8)
                       | ((uint32_t)e[0x22] << 16) | ((uint32_t)e[0x23] << 24);
        uint16_t shnum = (uint16_t)(e[0x30] | (e[0x31] << 8));
        uint16_t shstrndx = (uint16_t)(e[0x32] | (e[0x33] << 8));
        if (shnum == 0 || shoff == 0) { fclose(f); return NULL; }
        Elf32_Shdr *sh = (Elf32_Shdr *)malloc((size_t)shnum * sizeof(Elf32_Shdr));
        if (!sh) { fclose(f); return NULL; }
        fseek(f, (long)shoff, SEEK_SET);
        if (fread(sh, sizeof(Elf32_Shdr), shnum, f) != shnum) { free(sh); fclose(f); return NULL; }
        int si = -1;
        for (int i = 0; i < shnum; i++) if (sh[i].sh_type == SHT_SYMTAB) { si = i; break; }
        if (si < 0) for (int i = 0; i < shnum; i++) if (sh[i].sh_type == SHT_DYNSYM) { si = i; break; }
        if (si >= 0) {
            char *shstr = (char *)malloc(sh[shstrndx].sh_size ? sh[shstrndx].sh_size : 1);
            char *symbuf = (char *)malloc(sh[si].sh_size ? sh[si].sh_size : 1);
            char *strbuf = (char *)malloc(sh[sh[si].sh_link].sh_size ? sh[sh[si].sh_link].sh_size : 1);
            if (shstr && symbuf && strbuf) {
                fseek(f, (long)sh[shstrndx].sh_offset, SEEK_SET);
                fread(shstr, 1, sh[shstrndx].sh_size, f);
                fseek(f, (long)sh[si].sh_offset, SEEK_SET);
                fread(symbuf, 1, sh[si].sh_size, f);
                fseek(f, (long)sh[sh[si].sh_link].sh_offset, SEEK_SET);
                fread(strbuf, 1, sh[sh[si].sh_link].sh_size, f);
                Elf32_Sym *syms = (Elf32_Sym *)symbuf;
                int n = (int)(sh[si].sh_size / sizeof(Elf32_Sym));
                for (int i = 0; i < n; i++) {
                    if (syms[i].st_shndx == SHN_UNDEF) continue;
                    const char *nm = strbuf + syms[i].st_name;
                    if (strcmp(nm, symname) == 0) { found = (void *)(base + syms[i].st_value); break; }
                }
            }
            free(shstr); free(symbuf); free(strbuf);
        }
        free(sh);
    }
    fclose(f);
    return found;
}

/* 符号解析：先 dlsym(RTLD_DEFAULT)，失败再解析 libart.so 的 ELF 符号表（从磁盘文件）。 */
static void *resolve_hook_target(const char *name) {
    void *addr = dlsym(RTLD_DEFAULT, name);
    if (addr) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "resolve '%s' via dlsym @ %p", name, addr);
        return addr;
    }
    static uintptr_t libart_base = 0;
    static char libart_path[256] = {0};
    if (!libart_base) {
        libart_base = find_lib_base("libart.so", libart_path, sizeof(libart_path));
        if (libart_base)
            __android_log_print(ANDROID_LOG_INFO, TAG,
                "libart.so base=%p path=%s", (void *)libart_base, libart_path);
    }
    if (libart_base && libart_path[0]) {
        void *a = elf_find_sym_file(libart_path, libart_base, name);
        if (a) {
            __android_log_print(ANDROID_LOG_INFO, TAG,
                "resolve '%s' via ELF symtab @ %p", name, a);
            return a;
        }
    }
    return NULL;
}

/* ---------------- 跨版本 hook 目标（符号名） ---------------- */
/* 仅保留「x1 是 CodeItem（或 CodeItemDataAccessor 包装）」的解释桥，handler 据此还原
 * 指令。其余桥（ArtInterpreterToCompiledCodeBridge / artQuickToInterpreterBridge）的 x1
 * 是 ArtMethod*，装上也无法定位 CodeItem，且会让被抽取方法永久 NOP -> 崩溃，故剔除。
 * 解析顺序：命中第一个即安装。handler 内部用 DEX 区间匹配 + accessor 偏移双解，自动适配
 * Android 9（CodeItemDataAccessor const&，code_item_ @ +8）与 Android 10+（裸 CodeItem*）。 */
static const char *HOOK_TARGETS[] = {
    /* Android 9：C++ 修饰名，x1 = CodeItemDataAccessor const&，code_item_ @ +8 */
    "_ZN3art11interpreter33ArtInterpreterToInterpreterBridgeEPNS_6ThreadERKNS_20CodeItemDataAccessorEPNS_11ShadowFrameEPNS_6JValueE",
    /* Android 10+：C 导出名，x1 = 裸 CodeItem*（多数 ROM 直接导出） */
    "artInterpreterToInterpreterBridge",
    /* Android 10+：C++ 修饰名兜底，x1 = 裸 const DexFile::CodeItem* */
    "_ZN3art11interpreter23ArtInterpreterToInterpreterBridgeEPNS_6ThreadEPKNS_"
    "6DexFile8CodeItemEPNS_11ShadowFrameEPNS_6JValueE",
    NULL
};

/* ---------------- 运行时状态 ---------------- */
#define MAX_DEX 64
typedef struct { int used; int dex_idx; uintptr_t base; size_t len; } dex_range_t;
static dex_range_t g_ranges[MAX_DEX];
static int g_nrange = 0;

static uint8_t   g_seed[32];
static int       g_seed_set = 0;
static uint8_t  *g_payload = NULL;   /* 拷贝自 Java（运行时需常驻） */
static size_t    g_payload_len = 0;

/* 载荷方法条目索引（构建一次，handler O(1) 查表） */
typedef struct {
    uint32_t dex_idx;
    uint32_t method_idx;
    uint32_t code_off;
    uint32_t insns_size;
    uint32_t blob_off;   /* 在 g_payload 中的偏移 */
    uint32_t blob_len;
    uint8_t  restored;
} method_entry_t;

static method_entry_t *g_entries = NULL;
static int g_nentries = 0;
static int *g_buckets = NULL;        /* -1 表示空 */
static int g_hash_n = 0;

static int g_hook_attempted = 0;
static int g_hook_mode = 0;          /* 1=解释桥惰性还原; 0=回退整包批量还原 */
static int g_diag = 0;               /* 诊断日志计数（前若干条） */

/* ---------------- 小工具 ---------------- */
static uint32_t rd32(const uint8_t *b, size_t off) {
    return ((uint32_t)b[off]) | ((uint32_t)b[off+1] << 8)
         | ((uint32_t)b[off+2] << 16) | ((uint32_t)b[off+3] << 24);
}

/* 遍历载荷方法段，回调每个条目（dex_idx, method_idx, code_off, insns_size, blob_off, blob_len）。 */
static int foreach_method_entry(const uint8_t *payload, size_t payload_len,
        void (*cb)(void *ctx, uint32_t dex_idx, uint32_t method_idx,
                   uint32_t code_off, uint32_t insns_size, uint32_t blob_off, uint32_t blob_len),
        void *ctx) {
    if (payload_len < 8 || memcmp(payload, "JGS1", 4) != 0) return -1;
    size_t p = 4;
    uint32_t dex_count = rd32(payload, p); p += 4;
    for (uint32_t i = 0; i < dex_count; i++) {
        uint32_t ln = rd32(payload, p); p += 4; p += ln;
    }
    if (p + 4 > payload_len) return -1;
    uint32_t asset_count = rd32(payload, p); p += 4;
    for (uint32_t i = 0; i < asset_count; i++) {
        uint32_t nl = rd32(payload, p); p += 4; p += nl;
        uint32_t ln = rd32(payload, p); p += 4; p += ln;
    }
    if (p + 4 > payload_len) return 0;   /* 无方法段 */
    uint32_t mdc = rd32(payload, p); p += 4;
    for (uint32_t s = 0; s < mdc; s++) {
        uint32_t dex_idx = rd32(payload, p); p += 4;
        uint32_t ec = rd32(payload, p); p += 4;
        for (uint32_t e = 0; e < ec; e++) {
            uint32_t method_idx = rd32(payload, p); p += 4;
            uint32_t code_off   = rd32(payload, p); p += 4;
            uint32_t insns_size = rd32(payload, p); p += 4;
            uint32_t ln = rd32(payload, p); p += 4;
            uint32_t blob_off = (uint32_t)p;
            p += ln;
            if (cb) cb(ctx, dex_idx, method_idx, code_off, insns_size, blob_off, ln);
        }
    }
    return 0;
}

/* 构建哈希表：回调中收集条目并插入。 */
typedef struct { method_entry_t *arr; int *n; int max; } build_ctx_t;
static void collect_cb(void *ctx, uint32_t dex_idx, uint32_t method_idx,
                       uint32_t code_off, uint32_t insns_size, uint32_t blob_off, uint32_t blob_len) {
    build_ctx_t *b = (build_ctx_t *)ctx;
    if (*b->n >= b->max) return;
    method_entry_t *m = &b->arr[(*b->n)++];
    m->dex_idx = dex_idx; m->method_idx = method_idx; m->code_off = code_off;
    m->insns_size = insns_size; m->blob_off = blob_off; m->blob_len = blob_len;
    m->restored = 0;
}

static void build_hash(void) {
    g_hash_n = 1048573;  /* 素数，~1M，承载至多约 50 万条仍低负载 */
    g_buckets = (int *)malloc((size_t)g_hash_n * sizeof(int));
    if (!g_buckets) { g_hash_n = 0; return; }
    for (int i = 0; i < g_hash_n; i++) g_buckets[i] = -1;
    for (int i = 0; i < g_nentries; i++) {
        uint64_t key = ((uint64_t)g_entries[i].dex_idx << 32) | g_entries[i].code_off;
        uint32_t h = (uint32_t)(key % (uint64_t)g_hash_n);
        while (g_buckets[h] != -1) h = (h + 1) % g_hash_n;
        g_buckets[h] = i;
    }
}

/* 注册一个 DEX 的内存区间 */
static int register_dex(int dex_idx, uintptr_t base, size_t len) {
    if (g_nrange >= MAX_DEX) return -1;
    for (int i = 0; i < g_nrange; i++) {
        if (g_ranges[i].dex_idx == dex_idx) { /* 重复注册：更新 */
            g_ranges[i].base = base; g_ranges[i].len = len; return 0;
        }
    }
    g_ranges[g_nrange].used = 1;
    g_ranges[g_nrange].dex_idx = dex_idx;
    g_ranges[g_nrange].base = base;
    g_ranges[g_nrange].len = len;
    g_nrange++;
    return 0;
}

/* 整包批量还原某个已注册 DEX（回退模式用，保证 App 可运行） */
static void batch_restore_one(int ri) {
    if (g_payload == NULL || !g_seed_set) return;
    int rc = jg_restore_methods_protected(
        (uint8_t *)g_ranges[ri].base, g_ranges[ri].len,
        g_payload, g_payload_len, g_seed, g_ranges[ri].dex_idx);
    __android_log_print(rc == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
        TAG, "batch-restore dex_idx=%d rc=%d", g_ranges[ri].dex_idx, rc);
}

/* ---------------- hook 处理器（由桥调用，x1=code_item 或 CodeItemDataAccessor） ---------------- */
/* 跨版本兼容：Android 9 解释桥的 x1 是 CodeItemDataAccessor(const&) 包装对象，其内
 * code_item_ 成员（offset 8）指向真实 CodeItem；Android 10+ 的 x1 直接是裸 CodeItem*。
 * 两者统一用「DEX 区间匹配」判别：裸 CodeItem* 必落于已注册 DEX 区间；包装对象则不在区间，
 * 需再解引用 offset 8 取真实 CodeItem*。落在系统/未知区间者一律安全跳过（绝不误还原/崩溃）。 */
static int find_range(uintptr_t p, int *dex_idx, uintptr_t *base) {
    for (int i = 0; i < g_nrange; i++) {
        if (p >= g_ranges[i].base && p < g_ranges[i].base + g_ranges[i].len) {
            *dex_idx = g_ranges[i].dex_idx;
            *base = g_ranges[i].base;
            return 1;
        }
    }
    return 0;
}

static void jg_restore_handler(void *x1) {
    uintptr_t p = (uintptr_t)x1;
    if (p == 0 || g_entries == NULL) return;

    /* 1) 定位 CodeItem 与所属 DEX 区间（双模式：裸指针 / accessor 包装） */
    int dex_idx = -1; uintptr_t base = 0;
    if (!find_range(p, &dex_idx, &base)) {
        /* 不在区间 -> 视 x1 为 CodeItemDataAccessor(const&)，取 code_item_ @ +8 */
        uintptr_t ci = *(const uintptr_t *)(p + 8);
        if (!find_range(ci, &dex_idx, &base)) return;   /* 框架/未知，跳过 */
        p = ci;
    }
    uint32_t code_off = (uint32_t)(p - base);

    /* 2) 查表 */
    uint64_t key = ((uint64_t)dex_idx << 32) | code_off;
    uint32_t h = (uint32_t)(key % (uint64_t)g_hash_n);
    int idx = -1;
    while (g_buckets[h] != -1) {
        int e = g_buckets[h];
        if (g_entries[e].dex_idx == dex_idx && g_entries[e].code_off == code_off) { idx = e; break; }
        h = (h + 1) % g_hash_n;
    }
    if (idx < 0) return;                     /* 非抽取方法，跳过 */
    method_entry_t *m = &g_entries[idx];
    if (m->restored) return;

    /* 3) 解密 + 解压 + 写回 code_item+16 */
    const uint8_t *blob = g_payload + m->blob_off;
    uint32_t ln = m->blob_len;
    if (ln < 28) { m->restored = 1; return; }   /* iv12+tag16 至少 28；异常标记避免反复 */
    char label[64];
    int ll = snprintf(label, sizeof(label), "JG|m%u.%u", m->dex_idx, m->method_idx);
    uint8_t key32[32];
    jg_hmac_sha256(g_seed, 32, (const uint8_t *)label, (size_t)ll, key32);

    const uint8_t *iv = blob;
    const uint8_t *ct = blob + 12;
    size_t ctlen = (size_t)ln - 12 - 16;
    const uint8_t *tag = blob + ln - 16;

    uint8_t *comp = (uint8_t *)malloc(ctlen ? ctlen : 1);
    if (!comp) return;
    memcpy(comp, ct, ctlen);
    uint8_t *plain = (uint8_t *)malloc(ctlen ? ctlen : 1);
    if (!plain) { free(comp); return; }
    int rc = jg_aes256gcm_decrypt(key32, iv, 12, comp, ctlen, tag, plain);
    free(comp);
    if (rc != 0) { free(plain); m->restored = 1; return; }

    uint8_t *insns = (uint8_t *)malloc(m->insns_size ? m->insns_size * 2 : 1);
    if (!insns) { free(plain); return; }
    size_t got = 0;
    if (jg_inflate_zlib(plain, ctlen, insns, m->insns_size * 2, &got) != 0
        || got != (size_t)m->insns_size * 2) {
        free(plain); free(insns); m->restored = 1; return;
    }
    free(plain);

    uintptr_t ins_off = p + 16;              /* CodeItem 头 16 字节后接 insns */
    uintptr_t page = ins_off & ~(uintptr_t)4095;
    if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
            "mprotect RW fail dex%d code_off=%u (method not restored)", dex_idx, code_off);
        free(insns); m->restored = 1; return;
    }
    memcpy((void *)ins_off, insns, (size_t)m->insns_size * 2);
    mprotect((void *)page, 4096, PROT_READ | PROT_EXEC);
    free(insns);
    m->restored = 1;

    if (g_diag < 8) {
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[restore] dex%d method_idx=%u code_off=%u insns=%u",
            dex_idx, m->method_idx, code_off, m->insns_size);
        g_diag++;
    }
}

/* ---------------- hook 安装（首次 nativeRestoreInit 时触发） ---------------- */
static void try_install_hook(void) {
    g_hook_attempted = 1;
    if (g_payload == NULL || !g_seed_set) { g_hook_mode = 0; return; }

    /* 1) 收集条目 */
    int cap = 262144;
    g_entries = (method_entry_t *)malloc((size_t)cap * sizeof(method_entry_t));
    if (!g_entries) { g_hook_mode = 0; return; }
    build_ctx_t bc = { g_entries, &g_nentries, cap };
    if (foreach_method_entry(g_payload, g_payload_len, collect_cb, &bc) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "payload parse failed");
        free(g_entries); g_entries = NULL; g_hook_mode = 0; return;
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "collected %d extracted method entries", g_nentries);

    /* 2) 解析符号 + 安装 inline hook（先 dlsym，失败再 ELF 符号表解析） */
    int installed = 0;
    for (int i = 0; HOOK_TARGETS[i]; i++) {
        void *addr = resolve_hook_target(HOOK_TARGETS[i]);
        if (!addr) continue;
        uintptr_t orig = 0;
        int rc = jg_inline_hook_install((uintptr_t)addr, jg_restore_handler, &orig);
        if (rc == 0) {
            __android_log_print(ANDROID_LOG_INFO, TAG,
                "hook installed on '%s' @ %p", HOOK_TARGETS[i], addr);
            installed = 1;
            break;
        } else {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                "inline hook failed on '%s' rc=%d, try next", HOOK_TARGETS[i], rc);
        }
    }
    if (!installed) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
            "NO hook target resolved (dlsym + libart ELF symtab) -> FALLBACK to batch restore");
        free(g_entries); g_entries = NULL;
        g_hook_mode = 0;
        for (int r = 0; r < g_nrange; r++) batch_restore_one(r);
        return;
    }

    /* 3) 建哈希表 */
    build_hash();
    if (g_buckets == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "hash build failed -> FALLBACK");
        g_hook_mode = 0;
        for (int r = 0; r < g_nrange; r++) batch_restore_one(r);
        return;
    }
    g_hook_mode = 1;
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "P3.3 lazy-restore mode ACTIVE (%d entries indexed)", g_nentries);
}

/* ---------------- JNI 入口 ---------------- */
JNIEXPORT jint JNICALL
Java_com_jiagu_shield_Decryptor_nativeRestoreInit(JNIEnv *env, jclass clazz,
        jint dexIdx, jobject dexBuf, jbyteArray payloadArr, jbyteArray seedArr) {
    (void)clazz;

    /* 种子/载荷：首次设入（拷贝常驻，不释放） */
    if (seedArr) {
        jsize sl = (*env)->GetArrayLength(env, seedArr);
        if (sl == 32) {
            jbyte *sp = (*env)->GetByteArrayElements(env, seedArr, NULL);
            if (sp) { memcpy(g_seed, sp, 32); g_seed_set = 1;
                      (*env)->ReleaseByteArrayElements(env, seedArr, sp, JNI_ABORT); }
        }
    }
    if (payloadArr) {
        jsize pl = (*env)->GetArrayLength(env, payloadArr);
        if (pl > 0) {
            jbyte *pp = (*env)->GetByteArrayElements(env, payloadArr, NULL);
            if (pp) {
                uint8_t *buf = (uint8_t *)malloc((size_t)pl);
                if (buf) {
                    if (g_payload) free(g_payload);
                    memcpy(buf, pp, (size_t)pl);
                    g_payload = buf; g_payload_len = (size_t)pl;
                }
                (*env)->ReleaseByteArrayElements(env, payloadArr, pp, JNI_ABORT);
            }
        }
    }

    /* DEX 内存区间（direct ByteBuffer 地址稳定，App 生命周期内有效） */
    if (dexBuf) {
        uint8_t *base = (uint8_t *)(*env)->GetDirectBufferAddress(env, dexBuf);
        jlong cap = (*env)->GetDirectBufferCapacity(env, dexBuf);
        if (base && cap > 0) register_dex((int)dexIdx, (uintptr_t)base, (size_t)cap);
    }

    /* 首次调用：尝试安装 hook；失败则回退批量还原本 DEX */
    if (!g_hook_attempted) {
        try_install_hook();
    } else if (g_hook_mode == 0) {
        /* 回退模式：每注册一个 DEX 立即整包还原 */
        for (int r = 0; r < g_nrange; r++) {
            if (g_ranges[r].dex_idx == (int)dexIdx) { batch_restore_one(r); break; }
        }
    }

    return g_hook_mode;   /* 1=惰性还原; 0=批量回退 */
}
