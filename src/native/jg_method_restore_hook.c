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
#include <signal.h>
#include <ucontext.h>

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

/* 2026-09-10：壳自身 DEX 的字节长度，由 GxBootstrap 在注入前 nativeMarkOwnDex() 登记。
 * anti-dump v3 必须【整份跳过】这份 dex —— 它是 ART 正在执行 GxApp/GxBootstrap 的活
 * dex，L2/L3 会与 ART 并发撕裂其元数据（实测：boot 帧全丢 / 异常穿过 catch(Throwable)
 * / 冒出 Byte.valueOf 污染帧 → 冷启动约 4% 直接起不来）。0 = 未登记。 */
static uint32_t g_own_dex_len = 0;

/* 该地址是否落在本进程自己持有、尚未交给 ART 的 dex 缓冲内（g_ranges 注册）。
 * L2/L3 只允许作用于这类区域：maps 自扫发现的按定义都是 ART 已在使用中的活映射
 * （壳自身 dex、ART 镜像副本、OEM 附加 dex），对其搬迁数据区是竞态根源。 */
static int is_owned_range(const uint8_t *base) {
    for (int i = 0; i < g_nrange; i++) {
        if (!g_ranges[i].used || g_ranges[i].base == NULL) continue;
        if (base >= (const uint8_t *)g_ranges[i].base &&
            base < (const uint8_t *)g_ranges[i].base + g_ranges[i].len) return 1;
    }
    return 0;
}

/* g_seed / g_seed_set 的唯一定义在 jg_method_restore.c（全 ABI 编入）。本文件（仅 arm64）只引用，
 * 并在 nativeRestoreInit 中写入；所有 ABI 的 nativeRestoreMethods 也会写入（见 jg_method_restore.c）。 */
extern uint8_t   g_seed[32];
extern int       g_seed_set;
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
/* 2026-09-10：解释桥 inline hook 总开关（默认由 Java 侧 METHOD_RESTORE_ONCALL_HOOK 设置）。
 * 关时走纯 P3.2 批量还原：不改 libart 任何字节，绕过整个 hook/trampoline 代码路径。 */
static int g_hook_enabled = 1;
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
 * 为什么必须存在：写回方法体 / 擦除方法体之后，必须【保持该页可写】，
 * 而不是一律设成 PROT_READ|PROT_EXEC。DEX 缓冲是 RW 的 direct ByteBuffer，
 * 强行改成 RX 会撤掉可写位，后续任何写访问（下一次按需还原、ART 自身写、
 * 相邻方法同页写回）都会触发 SEGV_ACCERR。
 *
 * 【2026-09-10 更正：下面这段旧结论已被证伪，务必以新结论为准】
 * 旧文（错误）：声称 802f4000-802f5000 r-xp 是"我们自己的还原/擦除路径 mprotect 成 RX 造成"。
 * 证伪过程：逐行核查后确认，jg_method_restore_hook.c 的还原(jg_restore_handler:576-578 强制 RW) /
 *   擦除(nativeReencryptSweep:1070-1072 强制 RW) / scramble(mp_restore 强制 RW) 全部已是 RW；
 *   jg_method_restore.c 的批量还原只 mprotect(RW) 且不恢复 RX；jg_inline_hook.c 的 RX 只作用于
 *   libart .text 与跳板（地址 0x7c…/0x7d…），从不碰 dex 区。→ 该 r-x 页【不是本工程 code 制造】。
 * 真根因（现已修复）：4 个 dex 的 direct ByteBuffer 落在同一个巨型匿名区
 *   （MIX2 A9 实测 ~522MB，内含 7ce85000-802f3fff rw- / 802f4000-802f4fff r-x / 802f5000-9d683fff rw-），
 *   该区内存在 ROM/ART 造成的孤立 r-x 页；而 0x802f4000 落在 dex0 自身地址范围之外、
 *   另一 dex 缓冲范围之内。decryptBuffers 逐个处理，dex0 的 fixDexChecksum（整段连续 buf.get
 *   -> peekByteArray -> SetByteArrayRegion -> memcpy，会跨页访问）先撞上这张尚未被保护的页。
 *   故即便"逐缓冲 mprotect"返回 rc=0 也照样崩 —— 那是【顺序缺口】，不是保护失败。
 *   修复见 force_dex_regions_writable()：在所有 fixDexChecksum 之前按【全部 dex 区间并集】统一扫 maps。
 * 仍有参考价值的事实：未加固 APK 确实没有这种 4KB 匿名可执行页；VMP 关闭的对照组同样复现，故排除 VMP。 */
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

/* 把 span 恢复成调用前的权限（查询失败则保守退回 RW，绝不留下不可写页）。
 * 2026-09-10：run-time 写回/擦除路径已统一改为强制 RW（见 prot_query 注释与
 * jg_restore_handler/nativeReencryptSweep），此函数仅作兼容保留。 */
__attribute__((unused)) static void prot_span_back(uintptr_t addr, size_t len, int orig) {
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

/* ---------------- 崩溃诊断 SIGSEGV 处理器 ----------------
 * 2026-09-10：偶发 SEGV_ACCERR(fault 0x802f4000, glide 线程) 在 crash_dump 被拦截时
 * 拿不到 tombstone。这里在 ART 之前抢先捕获，记录 fault 地址、是否落在已注册 dex 区间、
 * 以及 /proc/self/maps 中该地址所在 VMA，再链式转交原 handler（保留 ART/debuggerd 行为）。
 * 仅作只读记录，不改任何状态，绝不吞掉信号。 */
static struct sigaction g_old_segv;
static int g_segv_installed = 0;

static void jg_segv_handler(int sig, siginfo_t *si, void *uc) {
    /* 异步信号安全：handler 内【禁止】malloc/文件IO/加锁(g_lock)/读共享结构，否则会
     * 在 ART 内部故意触发的 SIGSEGV（隐式空指针检查等）临界区里死锁/撕裂，反而把良性
     * 信号当真崩溃杀进程（MIX2 实测：glide 线程 si_code=0 假崩即此）。只记录最关键的
     * PC + fault_addr + si_code（__android_log_print 足够安全），随后【立即】转交原
     * handler（ART 自己的）。完整 maps/backtrace 由 debuggerd tombstone 提供，无需在此 dump。 */
    if (sig == SIGSEGV && si && si->si_addr) {
        uintptr_t fa = (uintptr_t)si->si_addr;
        uintptr_t pc = 0;
        ucontext_t *ucp = (ucontext_t *)uc;
        if (ucp) pc = (uintptr_t)ucp->uc_mcontext.pc;
        __android_log_print(ANDROID_LOG_ERROR, TAG,
            "[SEGV] pc=%p fault_addr=%p si_code=%d",
            (void *)pc, (void *)fa, si->si_code);
    }
    if (g_old_segv.sa_flags & SA_SIGINFO) g_old_segv.sa_sigaction(sig, si, uc);
    else if (g_old_segv.sa_handler == SIG_DFL) signal(sig, SIG_DFL);
    else if (g_old_segv.sa_handler != SIG_IGN) g_old_segv.sa_handler(sig);
}

static void install_segv_handler(void) {
    /* 2026-09-10：诊断用全局 SIGSEGV 处理器已于定位完成后【关闭】。
     * 仅原样转发同伴信号时也有风险：ART 会故意触发良性 SIGSEGV（隐式空指针检查，
     * si_code=0/SI_USER），任何额外 handler 都会接管它的处理路径；且 handler 内
     * 即便只做 __android_log_print 也不是完全无代价。诊断结论（fault 0x802f4000
     * 落在 dex 并集区内的孤立 r-x 页）已转为 force_dex_regions_writable 的正式修复，
     * 交付版本必须关闭此拦截器，绝不让第三方 handler 抢在 ART 之前。 */
    return;
    if (g_segv_installed) return; /* [2026-09-10] 诊断用全局 SIGSEGV 处理器，默认关闭。 */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = jg_segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &g_old_segv);
    g_segv_installed = 1;
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
                /* 2026-09-10 修复：DEX 字节码缓冲是 RW 的 direct ByteBuffer，ART 运行期
                 * 仍需对其做 quicken 重写，故写回后【必须保持 RW】，绝不能恢复成 RX。
                 * 旧逻辑 prot_query+prot_span_back 把页恢复成 maps 快照里的权限，在并发
                 * mprotect 下快照可能失真（甚至读到已被误置 RX 的页），形成正反馈把相邻
                 * Java 堆页一并置为不可写 -> glide 线程写 ByteArrayOutputStream 时
                 * SEGV_ACCERR(fault 0x802f4000)。这里强制 RW，消除整类失败模式。 */
                int origp = prot_query(ins_off);
                if (origp & PROT_EXEC)
                    __android_log_print(ANDROID_LOG_WARN, TAG,
                        "[perm] dex page had EXEC bit @%p (old logic would leave it RX)",
                        (void *)ins_off);
                if (prot_span_rw(ins_off, nb) == 0) {
                    memcpy((void *)ins_off, insns, nb);
                    prot_span(ins_off, nb, PROT_READ | PROT_WRITE);
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
    /* 2026-09-10：接线 TOCTOU 之后仍残留 Glide 线程间歇崩溃（SI_USER SIGSEGV，pc 落在
     * JIT 代码区）。排查指向「改写 libart 解释桥 + 跳板」这条最激进的路径；本开关关即
     * 完全不碰 libart，回退纯 P3.2 批量还原（ loader 期一次性写回全部方法体）。 */
    if (!g_hook_enabled) {
        g_hook_mode = 0;
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "on-call hook DISABLED by config -> pure P3.2 batch restore");
        return;
    }
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

    /* 2026-09-10 根因修复（TYPE-B 间歇崩溃真正的源头）：
     * 默认构建（未开 --method-extract）载荷里 method_dex_count=0，即【没有任何被抽取的
     * 方法】，惰性还原对象为空。此前这里不做判定、径直往下装 hook，于是每次启动都白白去
     * inline hook ART 解释器最热路径 ArtInterpreterToInterpreterBridge —— 它是「任何线程
     * 从编译码进入解释执行」的必经函数，而我们在 attachBaseContext 阶段【没有停止世界】
     * 就地改写了正在被多线程执行的 libart 代码字节。这是教科书级的竞态：指令取指可能读到
     * 半个新指令 / 半旧半新，表现为随机线程（主线程 / glide-source-th / glide-disk-cach）
     * 在启动后 10~20s 间歇 SIGSEGV（ART fault manager 转成 SI_USER），pc 落在 JIT/anon 区。
     * 实测对照：hook 开 3/8 崩、hook 关 0/8 崩；未加固原包 6/6 全绿 ⇒ 确由该 hook 引入。
     * 既然无方法可惰性还原，hook 是纯负收益 ⇒ 条目为 0 直接跳过，完全不碰 libart，
     * 回退纯 P3.2 批量还原（保 A9 校验，与既有生产策略一致）。
     * 注意：本闸门与 Java 侧 METHOD_RESTORE_ONCALL_HOOK 开关互补——即便有人误开开关，
     * 只要没有抽取方法，这里也绝不会去改 libart。 */
    if (g_nentries <= 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "no extracted methods in payload -> skip hook (nothing to restore lazily), pure P3.2 batch");
        free(g_entries); g_entries = NULL;
        g_hook_mode = 0;
        return;
    }

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
    install_segv_handler();

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

/* 2026-09-10 修复（根因）：scramble 触碰的 span 全部是【DEX 数据】，绝不可恢复成
 * PROT_EXEC。DEX 字节由 ART 解释执行，CPU 不直接执行 dex 字节，故不需要任何 exec 位；
 * 反而 ART 运行期会对 DEX 做 quicken 重写（写 data_items/string_ids 等），且壳自身用
 * DirectByteBuffer 读写它。一旦被置成 r-xp，任何写访问（memcpy / SetByteArrayRegion /
 * ART quicken）都 SEGV_ACCERR。真机实测崩溃页 802f4000-802f5000 r-xp 正是 mp_restore
 * 在 orig_prot 带 EXEC 时写回 RX 造成的——这里不论 orig_prot 是什么，一律恢复成 RW。
 * 注：本函数仅服务于 scramble 的 dex 副本；libart hook 目标（机器码）的 RX 由
 * jg_inline_hook.c 单独 mprotect，不经此函数，不受影响。 */
static void mp_restore(uintptr_t a, uintptr_t b, int orig_prot) {
    (void)orig_prot;
    mp_any(a, b, PROT_READ | PROT_WRITE);
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
    /* 2026-09-10 修复：与按需还原/擦除共享 g_lock，避免并发改同一 dex 页
     * （scramble 此前无锁，会与 jg_restore_handler/nativeReencryptSweep 的 mprotect
     * 交错，导致页权限/字节在两者临界区之间撕裂）。本函数内所有 mprotect 自此处起
     * 均在锁内，return 1 前解锁（所有早期 return 均在本行之前，无需解锁）。 */
    pthread_mutex_lock(&g_lock);
    const uint32_t file_size = rd32(base, 32);
    /* 注：此处必须解锁后返回——原实现持锁直接 return，会让 g_lock 永久泄漏给本线程，
     * 后续周期重扫/按需还原全部阻塞在锁上。 */
    if (file_size < 112 || file_size > 0x10000000u) { pthread_mutex_unlock(&g_lock); return 0; }
    /* 2026-09-10 修复：壳自身 dex 整份跳过（见 g_own_dex_len 注释）。它是 ART 正在
     * 执行中的活 dex，任何结构改写都可能让 ART 的惰性解析读到垃圾；而壳 DEX 本身
     * 不承载需要防 dump 的业务资产（APK 内即密文、密钥由证书派生、本地可解）。 */
    if (g_own_dex_len != 0 && file_size == g_own_dex_len) {
        pthread_mutex_unlock(&g_lock);
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "anti-dump v3: SKIP own shell dex (base=%p file_size=%u)",
            (void *)base, file_size);
        return 0;
    }

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
    /* 2026-09-10 修复：L1 头部随机化后恢复权限时【强制 RW】。orig_prot 可能带 EXEC
     * （dex 副本落在 r-xp 映射时），恢复成 RX 会让该页不可写 -> ART quicken / 壳读写
     * -> SEGV_ACCERR（实测崩溃页 802f4000 即此路径）。DEX 是数据，永远 RW 即可。 */
    if (prot_span_rw((uintptr_t)base, 112) == 0) {
        for (int i = 0; i < 56; i++) base[i] = (uint8_t)xs_rand();
        prot_span((uintptr_t)base, 112, PROT_READ | PROT_WRITE);
    }

    /* 恢复所有触碰过的 span 到原权限（mirror 常为 r--p；g_ranges buffer 为 rw） */
    for (int i = 0; i < sn; i++) mp_restore(sa[i], sb[i], orig_prot);
    free(tmp);
    pthread_mutex_unlock(&g_lock);
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "anti-dump v3: dex de-structured (base=%p len=%u deep=%d strings=%u perm=%d map=%d)",
        (void *)base, file_size, deep, nstr, perm_done, map_done);
    return 1;
}

/* 2026-09-11 性能闸：maps 自扫的逐页探测上限。
 *
 * 旧实现对【所有】匿名私有可读 VMA 逐 4KB 页探测。MIX2/A9 同一启动实测：
 *   675 个候选 VMA / 3.89 GB ⇒ 1,018,843 次探测 ⇒ 冷启动两段合计 ~777ms；
 * 且每 10s 的周期重扫（deep=0，后台线程）也在付同一笔账（旧注释"无命中时纯页
 * 遍历 <100ms"是错的，实测 ~420ms，等于常驻烧掉约 4% 一个核）。
 *
 * 为什么可以设上限（同一启动的 maps × 日志交叉取证）：
 *   全部 5 个真实命中目标 = ART 为 4 个业务 dex 建的 [1 页 rw-p][N 页 r--p] 映射
 *   （7c5c39b000/779000/0ad000/916000）+ 1 个 6676B 小 dex（7d028f7000），
 *   **每个目标所在的 VMA 都 <= 9.2MB**；
 *   而占 99.5% 探测次数的巨型 VMA（2044MB r--p、520MB rw-p …）实测从未命中任何
 *   dex 副本。业务 dex 本体落在 520MB VMA 的中段且**非页对齐**（基址 …010），
 *   逐页扫描按定义就找不到它们 —— 那 4 个由 v1 的 g_ranges 注册表覆盖。
 *
 * 覆盖面收窄只发生在一种情形：某 dex 副本位于【巨型 VMA 的中段且非起始页】。
 *   那是攻击者已在进程内自行拷贝出明文的场景 —— 彼时他已持有原字节，这一层对他
 *   已无意义（L1 只是抹掉魔数指纹，防的是「dump 下来一眼认出是 dex」）。
 *
 * ⚠ 反向约束（不许做）：不得把该上限做成 system property / 文件 / 环境变量可覆盖
 *   —— 那等于给攻击者一个「关闭防护」的降级开关。必须是编译期常量。
 *   取值 32MB 留了余量：整份 30MB 级 dex 的独立映射仍会被完整扫描。 */
#ifndef JG_MAPS_SCAN_MAX_VMA
#define JG_MAPS_SCAN_MAX_VMA (32u << 20)
#endif

/* maps 自扫：遍历本进程全部匿名映射，处理其中的 dex（deep=1 时含 L2/L3）。
 * 2026-09-11：改为「每 VMA 必探起始页 + 仅 <= 32MB 的 VMA 逐页扫」。 */
static int scramble_dex_copies_in_maps(int deep) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int n = 0;
    int nvma = 0, nstart = 0, nskip = 0;
    unsigned long long nprobe = 0, skip_bytes = 0;
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
        nvma++;

        /* (1) 起始页：无论 VMA 多大都探一次（巨型 VMA 里也可能有 dex 副本的首页）。 */
        nprobe++;
        {
            int h = scramble_dex_full_at(base, prot,
                                         (deep && is_owned_range(base)) ? 1 : 0);
            n += h; nstart += h;
        }

        /* (2) 逐页：仅对小 VMA。命中目标按定义都是 ART 为单个 dex 建的独立映射，
         *     落在 <=9.2MB 的 VMA 内；巨型 VMA 逐页扫是纯开销（见上方代价闸注释）。
         *
         * 2026-09-10 修复（根因）仍然有效，作用域不变：maps 自扫发现的区域按定义
         * 都是 ART 已在使用的活映射——壳自身 dex、ART 从内存 dex 拷出的 mirror、
         * OEM 附加 dex。对活 dex 做 L2（string_ids 表换位 + 数据区搬迁）/L3
         * （map_list 擦除）会与 ART 的惰性解析并发撕裂元数据，实测表现为 boot 栈帧
         * 全丢、异常穿过 catch(Throwable)、冒出 Byte.valueOf 之类污染帧（MIX2/A9
         * 冷启动约 4% 起不来）。故：deep 仅对本进程自己持有、尚未交给 ART 的
         * g_ranges 缓冲生效；maps 命中一律降级为 L1（header 身份段随机化，仍是
         * 「dex 魔数=0」的压制手段，且与既有 10s 周期重扫的 deep=false 语义一致）。 */
        if (len <= (size_t)JG_MAPS_SCAN_MAX_VMA) {
            for (size_t off = PAGE_SZ; off + 112 <= len; off += PAGE_SZ) {
                nprobe++;
                n += scramble_dex_full_at(base + off, prot,
                                          (deep && is_owned_range(base + off)) ? 1 : 0);
            }
        } else {
            nskip++; skip_bytes += len;
        }
    }
    fclose(f);
    /* 埋点：deep（引导期）必打，用于确认覆盖面没有随 ROM/ART 变化而静默塌缩；
     * 周期重扫仅在真有命中时打（否则每 10s 一条噪声）。 */
    if (deep || n > 0)
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "anti-dump v3: maps-scan v2 vma=%d probes=%llu hits=%d start_hits=%d "
            "skip_vma=%d skip_mb=%llu cap_mb=%u deep=%d",
            nvma, nprobe, n, nstart, nskip, skip_bytes >> 20,
            (unsigned)(JG_MAPS_SCAN_MAX_VMA >> 20), deep ? 1 : 0);
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

/* 2026-09-10：由引导壳（GxBootstrap.bootShell，早于 GxApp.boot）登记壳自身 DEX 的
 * 字节长度。anti-dump v3 全程据此跳过该 dex —— 保护正在执行中的活 dex 元数据。
 * 语义：登记一次即常驻；重复登记（多壳/多 dex）取最后一次。 */
JNIEXPORT void JNICALL
Java_com_gx_runtime_GxBootstrap_nativeMarkOwnDex(JNIEnv *env, jclass clazz, jint len) {
    (void)env; (void)clazz;
    if (len < 112) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "markOwnDex: rejected len=%d", (int)len);
        return;
    }
    g_own_dex_len = (uint32_t)len;
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "markOwnDex: own shell dex len=%u will be skipped by anti-dump v3", g_own_dex_len);
}

/* 2026-09-10 修复（真正的根因，第二次修正）：把所有已注册 DEX 区间【合并成一整段】，
 * 扫描 /proc/self/maps，把落在该段内的任何不可写 VMA（尤其孤立的 r-x 页）统一强制
 * mprotect 为 RW。
 *
 * 为什么必须做「并集 + 循环前一次性」而不是「逐缓冲」：
 *   1) 4 个 dex 的 direct ByteBuffer 落在同一个巨型匿名区（MIX2 A9 实测约 522MB）内部，
 *      该区存在被 ROM/ART 映射成 r-x 的孤立页 802f4000-802f4fff。
 *   2) 逐缓冲方案 nativeEnsureDexWritable 只在【轮到某个 dex 自己的 fixDexChecksum 时】
 *      才 mprotect 自己那一段（记作 U_i）。而 0x802f4000 落在 dex0 的 U_0 之外、
 *      另一个 dex 缓冲 U_x 之内；decryptBuffers 是 for 循环逐个处理，dex0 的
 *      fixDexChecksum 会先访问到它 -> 但 U_x 要等到轮到 dex_x 才被 mprotect，
 *      于是 dex0 就已经崩了。这就是「顺序缺口」。
 *   3) 真机证据 d_3.log：dex0 的 ensure-dex-writable 覆盖 [0x81ab2000,0x82424000) 且 rc=0，
 *      但紧接着的 buf.get(sigSrc) 立刻 SEGV_ACCERR 于 0x802f4000 —— 该地址低于 dex0 起点，
 *      而校验和读取是整段连续拷贝（peekByteArray -> SetByteArrayRegion -> memcpy），
 *      会跨页/跨缓冲边界访问。
 * 因此必须在进入 fixDexChecksum 循环【之前】，对全部 DEX 区间的并集统一扫一遍。
 *
 * DEX 字节是数据：ART 运行期要对其做 quicken 重写，壳也要写回 checksum/signature，
 * CPU 并不执行 dex 字节（无需 exec 位），故 RW 是唯一正确且不危险的权限。
 * 返回被强制置为 RW 的 VMA 数。 */
static int force_dex_regions_writable(void) {
    if (g_nrange <= 0) return 0;
    uintptr_t lo = 0, hi = 0;
    for (int i = 0; i < g_nrange; i++) {
        if (!g_ranges[i].used || g_ranges[i].len == 0) continue;
        uintptr_t b = g_ranges[i].base & ~(uintptr_t)(PAGE_SZ - 1);
        uintptr_t e = (g_ranges[i].base + g_ranges[i].len + PAGE_SZ - 1)
                      & ~(uintptr_t)(PAGE_SZ - 1);
        if (lo == 0 || b < lo) lo = b;
        if (e > hi) hi = e;
    }
    if (lo == 0 || hi <= lo) return 0;

    size_t cap = 1u << 19;                 /* 512KB，足够覆盖 maps */
    char *buf = (char *)malloc(cap);
    if (!buf) return 0;
    int n = jg_read_file_raw("/proc/self/maps", buf, (int)cap - 1);
    if (n <= 0) { free(buf); return 0; }
    buf[n] = '\0';

    int fixed = 0;
    char *p = buf;
    while (*p) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = '\0';
        char *q = p;
        unsigned long long s = strtoull(q, &q, 16);
        if (*q == '-') q++;
        unsigned long long e = strtoull(q, &q, 16);
        while (*q == ' ') q++;
        char perms[8] = {0};
        int k = 0;
        while (*q && *q != ' ' && k < 4) perms[k++] = *q++;
        /* 仅处理【与 DEX 并集区间相交】的 VMA；DEX 字节必须可写。
         * 跳过不可读页（--- / --x）与已可写页，避免误伤 ART JIT/代码页。 */
        if (perms[0] == 'r' && perms[1] != 'w'
            && e > (unsigned long long)lo && s < (unsigned long long)hi) {
            uintptr_t a = ((uintptr_t)s > lo) ? (uintptr_t)s : lo;
            uintptr_t z = ((uintptr_t)e < hi) ? (uintptr_t)e : hi;
            if (a < z) {
                size_t l = (size_t)(z - a);
                if (mprotect((void *)a, l, PROT_READ | PROT_WRITE) == 0) {
                    fixed++;
                    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "dex-region-writable: forced RW [%p,%zu) was perms=%s", (void *)a, l, perms);
                } else {
                    __android_log_print(ANDROID_LOG_WARN, TAG,
                        "dex-region-writable: mprotect RW FAILED [%p,%zu) perms=%s",
                        (void *)a, l, perms);
                }
            }
        }
        if (!eol) break;
        p = eol + 1;
    }
    free(buf);
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "dex-region-writable: done, fixed=%d union=[%p,%p)",
        fixed, (void *)lo, (void *)hi);
    return fixed;
}

/* JNI: 在所有 fixDexChecksum 之前一次性调用（见 force_dex_regions_writable 注释）。 */
JNIEXPORT void JNICALL
Java_com_gx_runtime_GxDecryptor_nativeSetHookEnabled(JNIEnv *env, jclass clazz,
                                                    jboolean enabled) {
    (void)env; (void)clazz;
    g_hook_enabled = enabled ? 1 : 0;
}

JNIEXPORT void JNICALL
Java_com_gx_runtime_GxDecryptor_nativeEnsureAllDexWritable(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    force_dex_regions_writable();
}

/* 2026-09-10 修复（根因兜底）：fixDexChecksum 写回 DEX 头前，把 direct ByteBuffer
 * 整段强制 mprotect 成 RW。部分 ROM/ART 把该缓冲首页映射成 r-x（不可写），直接 put
 * 即 SEGV_ACCERR(fault 0x802f4000)。DEX 是数据，CPU 不执行其字节，ART 运行期还要
 * quicken 改写，故 RW 对 DEX 缓冲是安全且必需的（绝不能留 RX）。 */
JNIEXPORT void JNICALL
Java_com_gx_runtime_GxDecryptor_nativeEnsureDexWritable(JNIEnv *env, jclass clazz,
                                                        jobject dexBuf) {
    (void)clazz;
    if (!dexBuf) return;
    uint8_t *base = (uint8_t *)(*env)->GetDirectBufferAddress(env, dexBuf);
    jlong cap = (*env)->GetDirectBufferCapacity(env, dexBuf);
    if (!base || cap <= 0) return;
    uintptr_t a = (uintptr_t)base & ~(uintptr_t)(PAGE_SZ - 1);
    size_t off = (uintptr_t)base - a;
    size_t len = (size_t)cap + off;
    len = (len + PAGE_SZ - 1) & ~(uintptr_t)(PAGE_SZ - 1);
    int rc = mprotect((void *)a, len, PROT_READ | PROT_WRITE);
    __android_log_print(rc == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_WARN, TAG,
        "ensure-dex-writable: base=%p cap=%lld -> mprotect(%p,%zu,RW) rc=%d",
        (void *)base, (long long)cap, (void *)a, len, rc);
}

/* ---------------- DEX 头校验和（native 版，2026-09-10 根因修复） ----------------
 * 为什么必须搬到 native：
 *   Java 版 fixDexChecksum 为了算 checksum/signature，会 new 出【两个约 9MB 的 byte[]】
 *   （sigSrc/tail），再用 buf.get() 把整段 DEX 拷进这两个数组 -> peekByteArray ->
 *   SetByteArrayRegion -> memcpy，**写入**这两块超大 Java 数组。这些 9MB 数组落在 ART
 *   大对象空间；MIX2 A9 实测该区内存在一张异常的 r-x 页 0x802f4000，落恰恰落在
 *   sigSrc 数组的地址范围内（数组起于 0x7fb4400c，长 ~9.3MB，即 [0x7fb4400c,0x8042D20C)）——
 *   于是 memcpy 写到该只读页 -> SEGV_ACCERR(fault 0x802f4000)。
 *   这正是「给 DEX 缓冲 mprotect(RW) 返回 rc=0 却照样崩」的原因：**崩溃写的是 Java 数组，
 *   不是 DEX 缓冲**，两者根本不是同一块内存（0x802f4000 甚至低于 dex0 基址 0x81ab2010）。
 * 解法：直接在 direct ByteBuffer 的内存上算 SHA-1/adler32，彻底不再分配大 byte[]、
 *   不再有任何对堆数组的整段写入。顺带省掉 2×9MB 分配与两次 9MB 拷贝（启动更快）。
 *
 * 语义必须与 Java 版完全一致（否则 ART 报 Bad checksum）：
 *   - signature(偏移12, 20B) = SHA-1(d[32, fileSize))
 *   - checksum (偏移8,  4B) = adler32(d[12, fileSize))
 *   - 顺序：先算 SHA-1 写入 [12,32)，再算 adler32 —— 后者覆盖区间含刚写入的新签名
 *   - file_size(偏移32) 为覆盖边界；越界则回退为 capacity（与 Java 版同样的 clamp）
 *   - DEX 头整数一律 little-endian */
typedef struct { uint32_t h[5]; uint8_t blk[64]; size_t blen; uint64_t total; } jg_sha1_ctx;

static uint32_t jg_sha1_rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void jg_sha1_init(jg_sha1_ctx *c) {
    c->h[0] = 0x67452301u; c->h[1] = 0xEFCDAB89u; c->h[2] = 0x98BADCFEu;
    c->h[3] = 0x10325476u; c->h[4] = 0xC3D2E1F0u;
    c->blen = 0; c->total = 0;
}
static void jg_sha1_block(jg_sha1_ctx *c, const uint8_t *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16)
             | ((uint32_t)p[i*4+2] << 8)  | (uint32_t)p[i*4+3];
    for (int i = 16; i < 80; i++) w[i] = jg_sha1_rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & cc) | ((~b) & d);                k = 0x5A827999u; }
        else if (i < 40) { f = b ^ cc ^ d;                           k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d);        k = 0x8F1BBCDCu; }
        else             { f = b ^ cc ^ d;                           k = 0xCA62C1D6u; }
        uint32_t t = jg_sha1_rol(a, 5) + f + e + k + w[i];
        e = d; d = cc; cc = jg_sha1_rol(b, 30); b = a; a = t;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}
static void jg_sha1_update(jg_sha1_ctx *c, const uint8_t *d, size_t l) {
    c->total += l;
    while (l) {
        if (c->blen == 0 && l >= 64) { jg_sha1_block(c, d); d += 64; l -= 64; continue; }
        size_t n = 64 - c->blen; if (n > l) n = l;
        memcpy(c->blk + c->blen, d, n);
        c->blen += n; d += n; l -= n;
        if (c->blen == 64) { jg_sha1_block(c, c->blk); c->blen = 0; }
    }
}
static void jg_sha1_final(jg_sha1_ctx *c, uint8_t out[20]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80; jg_sha1_update(c, &pad, 1);
    uint8_t z = 0; while (c->blen != 56) jg_sha1_update(c, &z, 1);
    uint8_t lenb[8]; for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    jg_sha1_update(c, lenb, 8);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24); out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);  out[i*4+3] = (uint8_t)(c->h[i]);
    }
}
/* 标准 adler32（NMAX 取模优化，与 java.util.zip.Adler32 完全一致） */
static uint32_t jg_adler32(const uint8_t *d, size_t l) {
    uint32_t a = 1, b = 0;
    const size_t NMAX = 5552;
    while (l) {
        size_t n = (l < NMAX) ? l : NMAX;
        l -= n;
        while (n--) { a += *d++; b += a; }
        a %= 65521u; b %= 65521u;
    }
    return (b << 16) | a;
}

JNIEXPORT jboolean JNICALL
Java_com_gx_runtime_GxDecryptor_nativeFixDexChecksum(JNIEnv *env, jclass clazz,
                                                    jobject dexBuf) {
    (void)clazz;
    if (!dexBuf) return JNI_FALSE;
    uint8_t *base = (uint8_t *)(*env)->GetDirectBufferAddress(env, dexBuf);
    jlong cap = (*env)->GetDirectBufferCapacity(env, dexBuf);
    if (!base || cap < 32) return JNI_FALSE;

    uint32_t fileSize = rd32(base, 32);
    if (fileSize <= 12 || fileSize > (uint64_t)cap) fileSize = (uint32_t)cap;
    if (fileSize < 32) return JNI_FALSE;

    /* 写入 [8,12) 与 [12,32) 前，确保 DEX 头所在页可写（DEX 是数据，RW 是唯一正确权限）。
     * 只读部分 [32,fileSize) 即便处于 r-x 也照样可读（r-x 含读权限），无需处理。 */
    uintptr_t ha = (uintptr_t)base & ~(uintptr_t)(PAGE_SZ - 1);
    size_t need = (size_t)((uintptr_t)base + 112 - ha);
    need = (need + PAGE_SZ - 1) & ~(uintptr_t)(PAGE_SZ - 1);
    if (mprotect((void *)ha, need, PROT_READ | PROT_WRITE) != 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "fix-dex-checksum: mprotect RW header failed base=%p", (void *)base);
        return JNI_FALSE;
    }

    /* 1) signature = SHA-1([32, fileSize)) -> 写入 [12,32) */
    jg_sha1_ctx c; uint8_t sig[20];
    jg_sha1_init(&c);
    jg_sha1_update(&c, base + 32, (size_t)fileSize - 32);
    jg_sha1_final(&c, sig);
    memcpy(base + 12, sig, 20);

    /* 2) checksum = adler32([12, fileSize)) -> 写入 [8,12)（含刚写入的新签名） */
    uint32_t sum = jg_adler32(base + 12, (size_t)fileSize - 12);
    base[8]  = (uint8_t)(sum);        base[9]  = (uint8_t)(sum >> 8);
    base[10] = (uint8_t)(sum >> 16);  base[11] = (uint8_t)(sum >> 24);
    return JNI_TRUE;
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
                /* 2026-09-10 修复：擦除后强制恢复 RW（理由同 jg_restore_handler），
                 * 不再 prot_query 还原（避免把页留成 RX 引发 SEGV_ACCERR）。 */
                if (prot_span_rw(ins_off, nb) == 0) {
                    memset((void *)ins_off, 0, nb);  /* DEX NOP = 0x0000 */
                    prot_span(ins_off, nb, PROT_READ | PROT_WRITE);
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
