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
#include <time.h>
/* jg_read_file_raw 就定义在它里面（static __inline__，每个 TU 各自生成一份）。
 * 2026-09-10 回归记录：漏了这行 -> 隐式声明 -> 链接期留下未定义符号，
 * 而 ELF 共享库默认允许未定义符号，链接"成功"，直到真机 dlopen 才炸：
 *   dlopen failed: cannot locate symbol "jg_read_file_raw" referenced by libxxx.so
 * 进而 bootstrap 报 No implementation found -> App 启动即崩。 */
#include "jg_rawsys.h"
#include <sys/mman.h>
#include <dlfcn.h>
#include <android/log.h>
#include <stdio.h>
#include <elf.h>
#include <pthread.h>
#include <time.h>

#include "jg_crypto.h"
#include "jg_inline_hook.h"
#ifdef WB_KDF
#include "whitebox_kdf.h"
#endif

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
    uint8_t  restored;   /* 1=当前内存为明文(已还原); 0=已被空闲擦除/NOP */
    uint64_t last_call;  /* 最近一次执行时间戳(ms)，空闲擦除据此判断 */
} method_entry_t;

static method_entry_t *g_entries = NULL;
static int g_nentries = 0;
static int *g_buckets = NULL;        /* -1 表示空 */
static int g_hash_n = 0;

static int g_hook_attempted = 0;
static int g_hook_mode = 0;          /* 1=解释桥惰性还原; 0=回退整包批量还原 */
static int g_diag = 0;               /* 诊断日志计数（前若干条） */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;  /* 还原/擦除临界区 */

/* 单调毫秒时钟（CLOCK_MONOTONIC，不受系统时间回拨影响） */
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* 查已注册 DEX 的内存基址（按 dex_idx）。返回 0 表示未注册。 */
static uintptr_t range_base(int dex_idx) {
    for (int i = 0; i < g_nrange; i++)
        if (g_ranges[i].dex_idx == dex_idx) return g_ranges[i].base;
    return 0;
}

/* ---------------- 页保护辅助（P3.4 跨页修复） ----------------
 * mprotect 以页为单位，而方法体(insns)在 DEX 内是连续字节流，**经常跨越页边界**。
 * 原实现只保护 ins_off 所在的首页，随后 memcpy/memset 写入 insns_size*2 字节，
 * 一旦跨页，后半段会落到仍为 PROT_READ|PROT_EXEC 的相邻页 -> SIGSEGV。
 * 真机实测：MIX2 A9 上 sweep 擦除一个页内偏移 4056、长度 62 字节的方法体
 * （4056+62=4118 > 4096）即崩溃。故此处按 [addr, addr+len) 覆盖的全部页计算。 */
#define PAGE_SZ 4096UL
static int prot_span(uintptr_t addr, size_t len, int prot) {
    if (len == 0) return -1;
    uintptr_t first = addr & ~(uintptr_t)(PAGE_SZ - 1);
    uintptr_t last  = (addr + len - 1) & ~(uintptr_t)(PAGE_SZ - 1);
    return mprotect((void *)first, (size_t)(last - first) + PAGE_SZ, prot);
}
static int prot_span_rw(uintptr_t addr, size_t len) {
    return prot_span(addr, len, PROT_READ | PROT_WRITE);
}

/* 查询某地址所在 VMA 的当前权限（扫 /proc/self/maps，只读，不做任何修改）。
 * 失败返回 -1。
 *
 * 为什么必须存在：写回方法体 / 擦除方法体之后，必须【恢复该页原本的权限】，
 * 而不是一律设成 PROT_READ|PROT_EXEC。DEX 缓冲是 RW 的 direct ByteBuffer，
 * 强行改成 RX 会撤掉可写位，后续任何写访问（下一次按需还原、ART 自身写、
 * 相邻方法同页写回）都会触发 SEGV_ACCERR。
 * 真机证据（MIX2 / Android 9，2026-09-10）：加固进程 maps 里出现
 *   7ce85000-802f4000 rw-p
 *   802f4000-802f5000 r-xp    <-- 被 mprotect 成 RX 的单页，夹在 ART 堆区中间
 *   802f5000-9d684000 rw-p
 * 而**同一个未加固 APK 一个 4KB 匿名可执行页都没有**。崩溃栈稳定命中
 * memcpy -> System.arraycopy -> ByteArrayOutputStream.write，fault addr 正是
 * 0x802f4000，code=SEGV_ACCERR（写不可写页）。VMP 关闭的对照组同样复现，
 * 故排除 VMP；属方法还原/擦除路径的页权限处理缺陷。 */
static int prot_query(uintptr_t addr) {
    size_t cap = 1u << 19;                 /* 512KB，足够覆盖 maps */
    char *buf = (char *)malloc(cap);
    if (!buf) return -1;
    int n = jg_read_file_raw("/proc/self/maps", buf, (int)cap - 1);
    if (n <= 0) { free(buf); return -1; }
    buf[n] = '\0';
    char *p = buf;
    int out = -1;
    while (*p && out < 0) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = '\0';
        char *q = p;
        unsigned long long s = strtoull(q, &q, 16);
        if (*q == '-') q++;
        unsigned long long e = strtoull(q, &q, 16);
        while (*q == ' ') q++;
        char perms[8] = {0};
        int i = 0;
        while (*q && *q != ' ' && i < 4) perms[i++] = *q++;
        if (addr >= (uintptr_t)s && addr < (uintptr_t)e) {
            out = 0;
            if (perms[0] == 'r') out |= PROT_READ;
            if (perms[1] == 'w') out |= PROT_WRITE;
            if (perms[2] == 'x') out |= PROT_EXEC;
        }
        if (!eol) break;
        p = eol + 1;
    }
    free(buf);
    return out;
}

/* 把 span 恢复成调用前的权限（查询失败则保守退回 RW，绝不留下不可写页）。 */
static void prot_span_back(uintptr_t addr, size_t len, int orig) {
    if (orig < 0) orig = PROT_READ | PROT_WRITE;
    if (!orig) orig = PROT_READ;
    prot_span(addr, len, orig);
}
/* 注意: 写回/擦除之后【不要】再调用它把页设成 RX —— 那会撤掉可写位导致
 * SEGV_ACCERR（见 prot_query 注释里的 MIX2 实测证据）。正确做法是用
 * prot_query() 取原权限、再用 prot_span_back() 还原。保留此函数仅作兼容。 */
__attribute__((unused)) static int prot_span_rx(uintptr_t addr, size_t len) {
    return prot_span(addr, len, PROT_READ | PROT_EXEC);
}

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

    /* 热路径：已还原的方法（绝大多数调用）。必须在本临界区内刷新 last_call，
     * 与 nativeReencryptSweep 锁内的空闲判定构成互斥临界区——否则「刚被解释执行的方法」
     * 会因锁外写入的 last_call 尚未可见，被 sweep 在锁内读到陈旧值而误判空闲、进而在 Mterp
     * 正读其指令流时清零 -> SIGSEGV（TOCTOU 的对称面）。裸 mutex 开销对解释执行方法可忽略
     * （JIT 编译后的热方法不走此路径）。 */
    if (m->restored) {
        pthread_mutex_lock(&g_lock);
        m->last_call = now_ms();
        pthread_mutex_unlock(&g_lock);
        return;
    }

    /* 3) 解密 + 解压 + 写回 code_item+16（临界区：与空闲擦除互斥，避免页权限竞态） */
    pthread_mutex_lock(&g_lock);
    if (!m->restored) {                      /* 双检：擦除可能刚发生 */
        const uint8_t *blob = g_payload + m->blob_off;
        uint32_t ln = m->blob_len;
        if (ln < 28) { m->restored = 1; }    /* iv12+tag16 至少 28；异常标记避免反复 */
        else {
            char label[64];
            int ll = snprintf(label, sizeof(label), "JG|m%u.%u", m->dex_idx, m->method_idx);
            uint8_t key32[32];
#ifdef WB_KDF
            wb_key_for(g_seed, (const uint8_t *)label, (size_t)ll, key32);
#else
            jg_hmac_sha256(g_seed, 32, (const uint8_t *)label, (size_t)ll, key32);
#endif
            const uint8_t *iv = blob;
            const uint8_t *ct = blob + 12;
            size_t ctlen = (size_t)ln - 12 - 16;
            const uint8_t *tag = blob + ln - 16;
            uint8_t *comp = (uint8_t *)malloc(ctlen ? ctlen : 1);
            uint8_t *plain = (uint8_t *)malloc(ctlen ? ctlen : 1);
            /* P3.4 修复：原实现漏了把密文 ct 拷入 comp，导致 GCM 解密的输入是 malloc
             * 出来的未初始化内存 -> 校验必然失败 -> 按需还原永不生效（连 [restore]
             * 日志都打不出来）。此处与 jg_method_restore.c 批量还原路径保持一致。 */
            if (comp && plain) memcpy(comp, ct, ctlen);
            if (comp && plain
                && jg_aes256gcm_decrypt(key32, iv, 12, comp, ctlen, tag, plain) == 0) {
                uint8_t *insns = (uint8_t *)malloc(m->insns_size ? m->insns_size * 2 : 1);
                size_t got = 0;
                if (insns && jg_inflate_zlib(plain, ctlen, insns, m->insns_size * 2, &got) == 0
                    && got == (size_t)m->insns_size * 2) {
                    size_t nb = (size_t)m->insns_size * 2;
                    uintptr_t ins_off = p + 16;   /* CodeItem 头 16 字节后接 insns */
                    /* 跨页安全：按实际长度覆盖全部涉及的页 */
                    /* 原权限必须在改权限【之前】取；写回后恢复原权限, 不能一律 RX */
                    int origp = prot_query(ins_off);
                    if (prot_span_rw(ins_off, nb) == 0) {
                        memcpy((void *)ins_off, insns, nb);
                        prot_span_back(ins_off, nb, origp);
                        m->restored = 1;
                    }
                }
                if (insns) free(insns);
            }
            if (comp) free(comp);
            if (plain) free(plain);
        }
    }
    m->last_call = now_ms();
    if (m->restored && g_diag < 8) {
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[restore] dex%d method_idx=%u code_off=%u insns=%u",
            dex_idx, m->method_idx, code_off, m->insns_size);
        g_diag++;
    }
    pthread_mutex_unlock(&g_lock);
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
        "P3.4 on-call restore ACTIVE (%d entries indexed)", g_nentries);
}

/* ---------------- JNI 入口 ---------------- */
JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxDecryptor_nativeRestoreInit(JNIEnv *env, jclass clazz,
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

    /* 首次调用：尝试安装解释桥 hook（失败则 g_hook_mode=0，仅批量还原）。 */
    if (!g_hook_attempted) {
        try_install_hook();
    }

    /* P3.4 加载期批量还原本 DEX：在 ART DefineClass 校验前把全部方法写回明文，
     * 规避 Android 9 等急切校验 ROM 的 VerifyError（NOP 化方法体无终结指令）。
     * 同时标记本 dex 全部条目 restored=1，使 hook 热路径直接跳过、仅在空闲擦除
     * 后再调用时按需还原。无论 hook 是否安装都执行（保 A9 校验是硬要求）。 */
    if (g_payload && g_seed_set) {
        for (int r = 0; r < g_nrange; r++) {
            if (g_ranges[r].dex_idx == (int)dexIdx) {
                int rrc = jg_restore_methods_protected(
                    (uint8_t *)g_ranges[r].base, g_ranges[r].len,
                    g_payload, g_payload_len, g_seed, (int)dexIdx);
                __android_log_print(rrc == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, TAG,
                    "P3.4 load batch-restore dex_idx=%d rc=%d", (int)dexIdx, rrc);
                break;
            }
        }
        if (g_entries) {
            for (int i = 0; i < g_nentries; i++)
                if (g_entries[i].dex_idx == (uint32_t)dexIdx) g_entries[i].restored = 1;
        }
    }

    return g_hook_mode;   /* 1=解释桥按需还原 ACTIVE; 0=仅批量回退 */
}

/* ---------------- P0-0904 anti-script v3：dex 去结构化 ----------------
 * 2026-09-04 二次报告（dex提取成功_scramble被绕过）实测绕过 v2 的手法：
 *   攻击者不搜 magic，搜【string_ids 表结构特征】（连续严格递增 uint32 数组，
 *   即 d8 布局的 string_data_off），在 header+0x70 标准位置定位表，再写回
 *   dex\n035\0 + file_size=data_off+data_size 恒等式 → 30 分钟完整重建 4 个 dex。
 *   （v2 只擦了 12-16B 身份字段，表/signature/map_list 全部原样=结构指纹全留。）
 * v3 对标梆梆「header 摘除 + table 重排」水位，三层：
 *   L1 header 112B 身份段随机填充：A9 ART 在 DexFile 构造（open/verify）时把全部
 *      header 字段缓存为对象成员（string_ids_/type_ids_/... = begin_+off 指针），
 *      运行期不再回头读 header。0..55 填每进程随机字节（不写固定 tag——0904 三次
 *      报告③实测 dump 里搜「JGSC1」即可精准定位全部壳 dex 且获知表偏移布局；
 *      幂等性由 dex\035 魔数检查 + header_size/endian 复核天然保证）。
 *   L2 string_ids 随机重排（仅 deep=注入期）：string data 在原区间内随机换位、
 *      同步改写表内 string_data_off——ART 按 idx 取偏移照常工作（从不假设偏移
 *      单调；FindStringId 二分按表项序比较字符串内容，表项顺序不动），但
 *      「严格递增 uint32」结构指纹消失，自动重建脚本失效。
 *   L3 map_list 擦除（仅 deep）：map_off 仅 open/verify 时读（fileless 无 oat），
 *      擦掉后攻击者失去整包 section 索引与重建校验锚点。
 * 安全闸：map 交叉验证 string_data 区失败 / 表连续性或 MUTF-8 终止符校验失败 →
 * 只做 L1，绝不动 data（防误伤其他结构按绝对偏移的引用）。deep 只在注入期调用
 * （verify 已完成、业务类未加载，近单线程窗口）；周期重扫走浅模式（仅 L1），
 * 避免与运行期 ART 并发读同区产生撕裂。
 * 诚实边界：确定型攻击者仍可解析 ULEB 链逐项重建（成本分钟级→小时级+）；dex body
 * 照旧明文（梆梆同级），更彻底需私有解释器/VMP（P3.5 已证 A9 不可行）。 */

static uint32_t g_xr = 0;
static uint32_t xs_rand(void) {
    g_xr ^= g_xr << 13; g_xr ^= g_xr >> 17; g_xr ^= g_xr << 5;
    return g_xr;
}

static void wr32(uint8_t *b, size_t off, uint32_t v) {
    b[off] = (uint8_t)(v & 0xff); b[off + 1] = (uint8_t)((v >> 8) & 0xff);
    b[off + 2] = (uint8_t)((v >> 16) & 0xff); b[off + 3] = (uint8_t)((v >> 24) & 0xff);
}

/* mprotect 任意 span（自动页对齐）。返回 0=成功 */
static int mp_any(uintptr_t a, uintptr_t b, int prot) {
    a &= ~(uintptr_t)(PAGE_SZ - 1);
    b = (b + PAGE_SZ - 1) & ~(uintptr_t)(PAGE_SZ - 1);
    if (b <= a) return -1;
    return mprotect((void *)a, (size_t)(b - a), prot);
}

static void mp_restore(uintptr_t a, uintptr_t b, int orig_prot) {
    if (orig_prot & PROT_WRITE) mp_any(a, b, PROT_READ | PROT_WRITE);
    else if (orig_prot & PROT_EXEC) mp_any(a, b, PROT_READ | PROT_EXEC);
    else mp_any(a, b, PROT_READ);
}

/* v3 单 dex 全量处理。base 必须可读。返回 1=已处理（含幂等 tag 命中）。
 * orig_prot=所在区域原权限（处理完恢复）；deep=1 时附加 L2/L3（仅注入期）。 */
static int scramble_dex_full_at(uint8_t *base, int orig_prot, int deep) {
    if (base == NULL) return 0;
    /* 幂等性不依赖 tag（0904 三次报告③：固定 tag「JGSC1」等于在 dump 里自报家门）：
     * 已处理区 0..3 不再是 dex\n 魔数 → 下面魔数检查直接 return 0 跳过；
     * 即便随机字节极小概率凑出 dex\n，header_size(0x70)/endian_tag 复核也会拦住。 */
    if (!(base[0] == 'd' && base[1] == 'e' && base[2] == 'x' && base[3] == '\n')) return 0;
    if (!(base[4] == '0' && base[5] == '3' && base[6] >= '5' && base[6] <= '9' && base[7] == 0))
        return 0;
    /* header_size(36..39)==0x70 且 endian_tag(40..43)==0x12345678：误报近乎为零 */
    if (!(base[36] == 0x70 && base[37] == 0 && base[38] == 0 && base[39] == 0)) return 0;
    if (!(base[40] == 0x78 && base[41] == 0x56 && base[42] == 0x34 && base[43] == 0x12))
        return 0;
    const uint32_t file_size = rd32(base, 32);
    if (file_size < 112 || file_size > 0x10000000u) return 0;

    const uint32_t nstr = rd32(base, 56);   /* string_ids_size */
    const uint32_t stro = rd32(base, 60);   /* string_ids_off  */
    const uint32_t mapo = rd32(base, 28);   /* map_off         */

    uintptr_t sa[4], sb[4];
    int sn = 0;
    uint8_t *tmp = NULL;
    int perm_done = 0, map_done = 0;

    if (deep && nstr > 0 && nstr <= 4000000u && stro >= 112 &&
        (uint64_t)stro + (uint64_t)nstr * 4 <= file_size) {
        uint32_t *offs = (uint32_t *)malloc(nstr * sizeof(uint32_t));
        if (offs) {
            for (uint32_t i = 0; i < nstr; i++) offs[i] = rd32(base, stro + i * 4);
            /* d8 布局闸：off 严格递增、每项以 0x00 终止（MUTF-8），且 map_list 的
             * string_data_item 条目（type=0x0001）offset==offs[0]、size==nstr——
             * 确认 [offs[0], last_end) 内只有连续排布的 string data、无其他 item
             * 混入（否则重排会破坏其他结构按绝对偏移的引用）。任一不满足→只做 L1。 */
            int ok = (offs[0] > stro + nstr * 4 && offs[0] < file_size);
            uint32_t last_end = 0;
            if (ok) {
                for (uint32_t i = 0; ok && i + 1 < nstr; i++) {
                    if (offs[i + 1] <= offs[i] || offs[i + 1] > file_size) { ok = 0; break; }
                    if (base[offs[i + 1] - 1] != 0x00) { ok = 0; break; }
                    if (offs[i + 1] - offs[i] < 1) { ok = 0; break; } /* 最小项=1B（空串） */
                }
                if (ok) {
                    uint32_t lim = offs[nstr - 1] + 65536;
                    if (lim > file_size) lim = file_size;
                    for (uint32_t p = offs[nstr - 1]; p < lim; p++) {
                        if (base[p] == 0x00) { last_end = p + 1; break; }
                    }
                    if (last_end <= offs[nstr - 1]) ok = 0;
                }
            }
            /* 逐项 ULEB/MUTF-8 一致性校验（锚点；不依赖 map——本工程输入 dex 的
             * map_off 常被上游混淆成垃圾值，0904 二次实测）：
             * 每项首字节须解析为合法 ULEB utf16 长度 v，且（终止符前）UTF-8 字节数
             * m 满足 v<=m<=3v+2（MUTF-8：ASCII 1B/char，CJK 3B/char，代理对 2 单元
             * 6B，\0 记 2B）。混入的非字符串 item 逐项骗过该链的概率可忽略。 */
            if (ok) {
                for (uint32_t i = 0; ok && i < nstr; i++) {
                    uint32_t end = (i + 1 < nstr) ? offs[i + 1] : last_end;
                    uint32_t v = 0, m = 0;
                    int shift = 0;
                    uint32_t p = offs[i];
                    while (p < end) {
                        uint8_t byte = base[p++];
                        v |= (uint32_t)(byte & 0x7f) << shift;
                        if (!(byte & 0x80)) break;
                        shift += 7;
                        if (shift > 21) { ok = 0; break; }
                    }
                    if (!ok) break;
                    m = (end > p) ? (end - 1 - p) : 0;   /* 去掉终止符 0x00 */
                    if (v == 0 && m == 0) continue;      /* 空串项 */
                    if (m < v || m > 3u * v + 2) { ok = 0; break; }
                }
            }
            if (!ok) {
                free(offs);
                goto l1_only;   /* 闸失败：不做 L2/L3，仅 L1 */
            }

            if (1) {
                const uint32_t s0 = offs[0];
                const size_t span = (size_t)(last_end - s0);
                tmp = (uint8_t *)malloc(span);
                uint32_t *idx = (uint32_t *)malloc(nstr * sizeof(uint32_t));
                if (tmp && idx) {
                    memcpy(tmp, base + s0, span);
                    for (uint32_t i = 0; i < nstr; i++) idx[i] = i;
                    for (uint32_t i = nstr - 1; i > 0; i--) {   /* Fisher-Yates */
                        uint32_t j = xs_rand() % (i + 1);
                        uint32_t t = idx[i]; idx[i] = idx[j]; idx[j] = t;
                    }
                    sa[sn] = (uintptr_t)base; sb[sn] = (uintptr_t)base + 112; sn++;
                    sa[sn] = (uintptr_t)base + stro;
                    sb[sn] = (uintptr_t)base + stro + nstr * 4; sn++;
                    sa[sn] = (uintptr_t)base + s0;
                    sb[sn] = (uintptr_t)base + last_end; sn++;
                    int mp_ok = mp_any(sa[0], sb[0], PROT_READ | PROT_WRITE) == 0
                             && mp_any(sa[1], sb[1], PROT_READ | PROT_WRITE) == 0
                             && mp_any(sa[2], sb[2], PROT_READ | PROT_WRITE) == 0;
                    if (mp_ok) {
                        uint32_t cur = s0;
                        for (uint32_t k = 0; k < nstr; k++) {
                            uint32_t j = idx[k];
                            uint32_t jsz = (j + 1 < nstr) ? offs[j + 1] - offs[j]
                                                          : last_end - offs[j];
                            memcpy(base + cur, tmp + (offs[j] - s0), jsz);
                            wr32(base, stro + j * 4, cur);   /* 表项指向新位置 */
                            cur += jsz;
                        }
                        perm_done = 1;
                    }
                }
                free(idx);
            }
            free(offs);
        }
    }

    /* L3：map_list 整段擦除——仅当 map_off 自洽（合法偏移 + 合理条目数 + 各条目
     * off 未越界）。本工程输入 dex 的 map_off 常已是垃圾值（无从擦也无须擦）。
     * map_off 字段本身已在 L1 身份段被清零。 */
    if (deep && mapo >= 112 && mapo + 4 <= file_size) {
        uint32_t mc = rd32(base, mapo);
        if (mc > 0 && mc <= 4096 && mapo + 4 + (uint64_t)mc * 12 <= file_size) {
            int sane = 1;
            for (uint32_t i = 0; i < mc; i++) {
                if (rd32(base, mapo + 4 + i * 12 + 8) >= file_size) { sane = 0; break; }
            }
            if (sane && sn < 4 &&
                mp_any((uintptr_t)base + mapo, (uintptr_t)base + mapo + 4 + mc * 12,
                       PROT_READ | PROT_WRITE) == 0) {
                memset(base + mapo, 0, 4 + mc * 12);
                sa[sn] = (uintptr_t)base + mapo;
                sb[sn] = (uintptr_t)base + mapo + 4 + mc * 12;
                sn++;
                map_done = 1;
            }
        }
    }

l1_only:
    /* L1：header 身份段（0..55：magic/checksum/signature/file_size/header_size/
     * endian_tag、link 与 map_off 各字段）全擦 + 每进程随机字节填充（不写任何固定
     * tag——「JGSC1」明文等于给攻击者插路标；随机字节同时让已处理区无法被
     * dex\n 魔数/结构指纹二次命中，幂等性见函数头部注释）。
     * 【MIX2 实测铁律】56..111（各表 size/off + data_size/off）绝不能擦——A9 的
     * art::DexFile 只缓存 header_ 指针而非字段值，NumClassDefs() 等运行期直接读
     * header_->class_defs_size_；全 112B 擦除 = class_defs_size=0 → CNFE 崩。
     * 身份段字段全部仅在 open/verify 时读，运行期安全。 */
    if (prot_span_rw((uintptr_t)base, 112) == 0) {
        for (int i = 0; i < 56; i++) base[i] = (uint8_t)xs_rand();
    }

    /* 恢复所有触碰过的 span 到原权限（mirror 常为 r--p；g_ranges buffer 为 rw） */
    for (int i = 0; i < sn; i++) mp_restore(sa[i], sb[i], orig_prot);
    free(tmp);
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "anti-dump v3: dex de-structured (deep=%d strings=%u perm=%d map=%d)",
        deep, nstr, perm_done, map_done);
    return 1;
}

/* maps 自扫：遍历本进程全部匿名映射，处理其中的 dex（deep=1 时含 L2/L3）。 */
static int scramble_dex_copies_in_maps(int deep) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t lo = 0, hi = 0;
        char perms[8] = {0};
        /* 形如：768bf9c000-768de00000 r--p 00000000 00:00 0   [可选路径] */
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3) continue;
        if (!(perms[0] == 'r')) continue;            /* 不可读不可能是 dex */
        if (perms[3] != 'p') continue;               /* 只处理私有映射 */
        /* 跳过文件路径映射（fileless 模式下 dex 全在匿名区；避免误伤其他文件页） */
        char *path = strchr(line, '/');
        if (path) continue;
        int prot = 0;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;
        prot |= PROT_READ;
        size_t len = hi - lo;
        if (len < 112) continue;
        uint8_t *base = (uint8_t *)lo;
        for (size_t off = 0; off + 112 <= len; off += PAGE_SZ) {
            n += scramble_dex_full_at(base + off, prot, deep);
        }
    }
    fclose(f);
    return n;
}

/* deep=1：注入期（verify 完成、业务类未加载）→ L1+L2+L3 全量去结构化；
 * deep=0：周期重扫（App 已运行）→ 仅 L1 header 全擦，不碰 data（防与 ART 并发撕裂）。 */
JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxDecryptor_nativeScrambleDexHeaders(JNIEnv *env, jclass clazz,
                                                         jboolean deep) {
    (void)env; (void)clazz;
    if (g_xr == 0)
        g_xr = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)env ^ ((uint32_t)getpid() << 16);
    int n = 0;
    /* v1：注册的 g_ranges（in-place 打开的版本/OEM 上即 DexFile::begin_ 本体） */
    for (int r = 0; r < g_nrange; r++) {
        if (!g_ranges[r].used) continue;
        uint8_t *base = (uint8_t *)g_ranges[r].base;
        if (base == NULL || g_ranges[r].len < 112) continue;
        n += scramble_dex_full_at(base, PROT_READ | PROT_WRITE, deep ? 1 : 0);
    }
    /* v2：maps 自扫（A9+ ART 拷贝出的 DexFile mirror r--p 区） */
    int m = scramble_dex_copies_in_maps(deep ? 1 : 0);
    n += m;
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "anti-dump v3: processed %d dex (ranges=%d, maps-scan=%d, deep=%d)",
        n, n - m, m, deep ? 1 : 0);
    return n;
}

/* ---------------- 空闲擦除（P3.4 抗内存 dump 核心） ----------------
 * nativeReencryptSweep(idleMs)：主线程空闲时由 Java 周期调用。
 * 扫描全部已还原条目，将「最近一次执行距今 > idleMs」的方法体 NOP 擦除
 * （mprotect RW -> memset 0 -> 恢复 RX），并置 restored=0。下次执行时解释桥
 * hook 检测到 restored==0 会重新单方法解密写回（O(1)），实现「即用即擦」。
 * 热方法（idleMs 内持续被调用）不被擦除，避免高频解密开销。
 * 返回本次擦除的方法数（诊断用）。失败安全：任何异常仅记日志，绝不抛错/退出。
 *
 * 线程安全（2026-09-08 修复）：空闲判定与 m->last_call 的写入均须持 g_lock。
 * handler 在「方法体开始被解释执行之前」即于锁内写 last_call=now；sweep 在锁内
 * 重判 idle。二者互斥，故「正在执行 / 刚执行完」的方法 last_call 必新鲜、必被跳过，
 * 杜绝 TOCTOU 导致的 Mterp 读全 0 指令 -> SIGSEGV。空闲阈值(10s) ≫ 单次解释耗时。 */
JNIEXPORT jint JNICALL
Java_com_gx_runtime_GxDecryptor_nativeReencryptSweep(JNIEnv *env, jclass clazz,
        jint idleMs) {
    (void)env; (void)clazz;
    if (!g_entries || g_payload == NULL || !g_seed_set) return 0;
    uint64_t now = now_ms();
    int erased = 0;
    for (int i = 0; i < g_nentries; i++) {
        method_entry_t *m = &g_entries[i];
        if (!m->restored) continue;                          /* 已擦除，跳过 */
        pthread_mutex_lock(&g_lock);
        /* 空闲判定必须在锁内做：与解释桥 handler 在锁内写 m->last_call 构成临界区，
         * 消除 TOCTOU。否则「刚好被解释执行的方法」会因锁外读到陈旧 last_call 被判空闲，
         * 进而在 Mterp 正读其指令流时被 memset 清零 -> SIGSEGV（MIX2 A9 实锤的崩溃根因）。
         * 锁内重判后：方法若在擦除窗口内被进入，handler 已把 last_call 刷为 now，必被跳过。
         * 由 handler 入口（jg_restore_handler）保证：方法体在 last_call 写入之后才开始被
         * 解释执行，且 64 位时间戳写入在 arm64 下原子，故「正在执行」<=> last_call 新鲜。 */
        if (m->restored) {                                   /* 双检 */
            if (idleMs > 0 && (now - m->last_call) < (uint64_t)idleMs) {
                pthread_mutex_unlock(&g_lock);
                continue;                                    /* 仍热 / 正在被解释执行 */
            }
            uintptr_t base = range_base((int)m->dex_idx);
            if (base) {
                size_t nb = (size_t)m->insns_size * 2;
                uintptr_t ins_off = base + m->code_off + 16;
                /* 跨页安全：按实际长度覆盖全部涉及的页 */
                /* 同上：擦除后恢复原权限, 不能一律 RX（撤掉可写位 = 后续写访问 SEGV） */
                int origp = prot_query(ins_off);
                if (prot_span_rw(ins_off, nb) == 0) {
                    memset((void *)ins_off, 0, nb);  /* DEX NOP = 0x0000 */
                    prot_span_back(ins_off, nb, origp);
                    m->restored = 0;
                    erased++;
                }
            }
        }
        pthread_mutex_unlock(&g_lock);
    }
    if (erased > 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[sweep] erased %d idle methods (idleMs=%d)", erased, (int)idleMs);
    }
    return erased;
}
