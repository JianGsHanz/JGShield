/*
 * JGShield OpenCommon 预载校验层 (jg_preload.c)
 * --------------------------------------------------------------------------
 * P0-B（2026-09-07 四步打穿复盘的核心修正）：
 * 打穿链的决定性一击是 hook libart 的 ArtDexFileLoader::OpenCommon——dex 必须以
 * 完整合法形态交给 ART（架构硬约束），该门口必被经过。原方案（周期性巡检）输在
 * spawn 竞态：实测 OpenCommon 在启动 1-3s 内全部命中落盘，而探针 3.9s 才杀进程。
 *
 * 修正：把校验放到【解密任何业务 DEX 之前】一次性同步执行——spawn 注入的 hook
 * 必然先于壳代码运行，壳一睁眼就能看到入口跳板；此时业务 DEX 尚未解密，
 * 命中即裸 syscall 自毁 = 攻击者零收获。这是唯一能赢 spawn 竞态的窗口。
 * guard 线程周期复查兜底（防 attach 后新 hook）。
 *
 * 定位方式（不走 dlsym——dlsym 可被 hook 欺骗）：
 *   1. 裸读 /proc/self/maps 找首个 "/libart.so" 映射行 → load_bias + 磁盘路径；
 *   2. 裸打开磁盘 libart，解析 ELF .dynsym/.dynstr 找 OpenCommon 符号 st_value，
 *      再减第一个 PT_LOAD 的 p_vaddr 得运行时偏移；
 * 解析失败 → 返回"不确定"(-1)，fail-safe 跳过，绝不误杀。
 *
 * 铁律（bit6 教训）：只查 OpenCommon 这一个符号，绝不扫全 libc 表。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <android/log.h>
#include "jg_rawsys.h"

#define PTAG "JG-Preload"

extern void jg_hard_exit(void);   /* jg_guard.c：裸 syscall 自毁 */

static volatile const void *g_opencommon = NULL;  /* 运行时入口缓存 */
static int g_resolved = 0;

/* ---------------- 入口跳板指纹（按 ABI） ---------------- */
int jg_entry_is_trampoline(const void *fn) {
    if (!fn) return 0;
    const unsigned char *p = (const unsigned char *)fn;
#if defined(__aarch64__)
    /* frida gum inline hook: ldr x17,[pc,#8]; br x17（或直接 br/blr/b）。
     * LDR(literal) 固定位 [31:23]=0b010110000 → mask 0xFF80001F，Rt=x16/x17。 */
    unsigned int w0 = 0;
    memcpy(&w0, p, 4);
    if ((w0 & 0xFFFFFC1Fu) == 0xD61F0000u) return 1;  /* br  xN */
    if ((w0 & 0xFFFFFC1Fu) == 0xD63F0000u) return 1;  /* blr xN */
    if ((w0 & 0xFF80001Fu) == 0x58000010u) return 1;  /* ldr x16,[pc,#imm] */
    if ((w0 & 0xFF80001Fu) == 0x58000011u) return 1;  /* ldr x17,[pc,#imm] */
    if ((w0 & 0xFC000000u) == 0x14000000u) return 1;  /* b .（入口直跳他处） */
#elif defined(__arm__)
    if ((uintptr_t)fn & 1u) {
        /* thumb: ldr pc,[pc,#imm](0xF8DF) 或 bx pc(0x4778) */
        unsigned short h0 = 0, h1 = 0;
        memcpy(&h0, p, 2);
        memcpy(&h1, p + 2, 2);
        if (h0 == 0xF8DFu) return 1;
        if (h0 == 0x4778u) return 1;
        (void)h1;
    } else {
        unsigned int w = 0;
        memcpy(&w, p, 4);
        if (w == 0xE51FF004u) return 1;                    /* ldr pc,[pc,#-4] */
        if ((w & 0xFFFFF000u) == 0xE59FF000u) return 1;    /* ldr pc,[pc,#imm] */
    }
#elif defined(__i386__) || defined(__x86_64__)
    if (p[0] == 0xFF && p[1] == 0x25) return 1;   /* jmp [rip+disp32] */
    if (p[0] == 0xE9) return 1;                   /* jmp rel32 */
    if (p[0] == 0x68 && p[5] == 0xC3) return 1;   /* push addr; ret */
#endif
    return 0;
}

/* ---------------- raw maps 中找 libart ----------------
 * 输出：bias（首个 libart.so 映射起始 = load_bias）、path（磁盘路径）。
 * 返回 0 成功，-1 失败。 */
static int _find_libart(long *bias_out, char *path_out, int path_cap) {
    long fd = jg_open_ro("/proc/self/maps");
    if (fd < 0) return -1;
    char chunk[16 * 1024];
    char carry[512];
    int carry_n = 0;
    int found = 0;
    for (;;) {
        long n = jg_read((int)fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        int len = (int)n;
        /* 行级解析：carry + chunk 拼接后按 \n 切行 */
        static char linebuf[16 * 1024 + 512];
        memcpy(linebuf, carry, (size_t)carry_n);
        memcpy(linebuf + carry_n, chunk, (size_t)len);
        int total = carry_n + len;
        linebuf[total] = '\0';
        /* 保留最后一个不完整行做 carry——必须在把 last_nl 改写 '\0' 之前取，
         * 否则 carry 首字节变 NUL，下一轮 strchr 在开头即停、整块跳过（踩过的坑） */
        char *last_nl = strrchr(linebuf, '\n');
        int consume = last_nl ? (int)(last_nl - linebuf) : 0;
        carry_n = total - consume;
        if (carry_n > (int)sizeof(carry)) carry_n = (int)sizeof(carry);
        memcpy(carry, linebuf + consume, (size_t)carry_n);
        if (last_nl) {
            *last_nl = '\0';
            /* 逐行 */
            char *line = linebuf;
            char *nl;
            while (!found && (nl = strchr(line, '\n')) != NULL) {
                *nl = '\0';
                /* 路径列 = 最后一个空格之后的 token；匹配必须在路径列内
                 * （注意不能查 *(m-1)=='/'：/system/lib64/libart.so 中 /libart.so
                 *   的前一个字符是 '4'，守卫会误拒所有正常路径——踩过的坑） */
                char *last = NULL, *s = line;
                while (*s) { if (*s == ' ') last = s + 1; s++; }
                if (last && last[0] == '/' && strstr(last, "/libart.so") != NULL) {
                    /* addr = 行首十六进制，直到 '-' */
                    unsigned long long a = 0;
                    char *q = line;
                    while (*q && *q != '-') {
                        char c = *q;
                        a = a * 16ULL +
                            (unsigned long long)((c >= '0' && c <= '9') ? (c - '0')
                                                 : (c | 32) - 'a' + 10);
                        q++;
                    }
                    if (a != 0) {
                        *bias_out = (long)a;
                        snprintf(path_out, (size_t)path_cap, "%s", last);
                        found = 1;
                    }
                }
                line = nl + 1;
            }
        }
        if (found) break;
    }
    jg_close((int)fd);
    return found ? 0 : -1;
}

/* ---------------- ELF .dynsym 解析（裸 IO） ----------------
 * 在 libart 磁盘文件的 .dynsym 里找名字含 "OpenCommon" 的 FUNC 符号，返回 st_value。 */
static long _elf_find_opencommon(const char *path) {
    long fd = jg_open_ro(path);
    if (fd < 0) return -1;

    unsigned char ehdr[64];
    if (jg_read((int)fd, ehdr, sizeof(ehdr)) != (long)sizeof(ehdr)) { jg_close((int)fd); return -1; }
    if (ehdr[0] != 0x7F || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') { jg_close((int)fd); return -1; }
    int is64 = (ehdr[4] == 2);

    unsigned long long shoff; unsigned short shentsize, shnum;
    if (is64) {
        memcpy(&shoff, ehdr + 0x28, 8);
        memcpy(&shentsize, ehdr + 0x3A, 2);
        memcpy(&shnum, ehdr + 0x3C, 2);
    } else {
        unsigned int shoff32; memcpy(&shoff32, ehdr + 0x20, 4); shoff = shoff32;
        memcpy(&shentsize, ehdr + 0x2E, 2);
        memcpy(&shnum, ehdr + 0x30, 2);
    }
    if (shoff == 0 || shnum == 0 || shentsize == 0 ||
        shnum > 4096 || shentsize > 256) { jg_close((int)fd); return -1; }

    /* 0907 修复：第一个 PT_LOAD 的 p_vaddr（= vaddr bias）。
     * bionic linker: runtime = base - phdr0.p_vaddr + st_value。libart 实测
     * phdr0.p_vaddr=0x27000，漏减会把入口查偏 0x27000（h_v9 首版踩坑）。 */
    unsigned long long phoff; unsigned short phentsize, phnum;
    if (is64) {
        memcpy(&phoff, ehdr + 0x20, 8);
        memcpy(&phentsize, ehdr + 0x36, 2);
        memcpy(&phnum, ehdr + 0x38, 2);
    } else {
        unsigned int phoff32; memcpy(&phoff32, ehdr + 0x1C, 4); phoff = phoff32;
        memcpy(&phentsize, ehdr + 0x2A, 2);
        memcpy(&phnum, ehdr + 0x2C, 2);
    }
    unsigned long long vaddr0 = 0;
    if (phoff != 0 && phnum != 0 && phentsize != 0 && phnum < 256) {
        unsigned char *ph = (unsigned char *)malloc((size_t)phnum * phentsize);
        if (ph) {
            if (jg_lseek((int)fd, (long)phoff, SEEK_SET) == (long)phoff &&
                jg_read((int)fd, ph, (size_t)phnum * phentsize) == (long)((size_t)phnum * phentsize)) {
                for (unsigned short i = 0; i < phnum; i++) {
                    unsigned char *pp = ph + (size_t)i * phentsize;
                    unsigned int p_type;
                    memcpy(&p_type, pp, 4);
                    if (p_type != 1) continue;              /* PT_LOAD */
                    if (is64) memcpy(&vaddr0, pp + 0x10, 8); /* Elf64_Phdr.p_vaddr */
                    else      memcpy(&vaddr0, pp + 0x08, 4); /* Elf32_Phdr.p_vaddr */
                    break;                                   /* 第一个 PT_LOAD */
                }
            }
            free(ph);
        }
    }

    /* 读节头表 */
    size_t shtab_sz = (size_t)shnum * shentsize;
    unsigned char *shtab = (unsigned char *)malloc(shtab_sz);
    if (!shtab) { jg_close((int)fd); return -1; }
    if (jg_lseek((int)fd, (long)shoff, SEEK_SET) != (long)shoff ||
        jg_read((int)fd, shtab, shtab_sz) != (long)shtab_sz) {
        free(shtab); jg_close((int)fd); return -1;
    }

#define SH_OFF(idx) (is64 ? *(unsigned long long*)(shtab + (size_t)(idx)*shentsize + 0x18) \
                          : *(unsigned int*)(shtab + (size_t)(idx)*shentsize + 0x10))
#define SH_SIZE(idx) (is64 ? *(unsigned long long*)(shtab + (size_t)(idx)*shentsize + 0x20) \
                           : *(unsigned int*)(shtab + (size_t)(idx)*shentsize + 0x14))
#define SH_NAMEOFF(idx) *(unsigned int*)(shtab + (size_t)(idx)*shentsize + 0)

    /* 读 shstrtab（节名表），定位 .dynsym / .dynstr */
    unsigned short shstrndx = 0;
    if (is64) memcpy(&shstrndx, ehdr + 0x3E, 2); else memcpy(&shstrndx, ehdr + 0x32, 2);
    if (shstrndx >= shnum) { free(shtab); jg_close((int)fd); return -1; }
    unsigned long long str_off = SH_OFF(shstrndx), str_sz = SH_SIZE(shstrndx);
    if (str_sz == 0 || str_sz > (1u << 22)) { free(shtab); jg_close((int)fd); return -1; }
    char *shstr = (char *)malloc((size_t)str_sz + 1);
    if (!shstr) { free(shtab); jg_close((int)fd); return -1; }
    if (jg_lseek((int)fd, (long)str_off, SEEK_SET) != (long)str_off ||
        jg_read((int)fd, shstr, (size_t)str_sz) != (long)str_sz) {
        free(shstr); free(shtab); jg_close((int)fd); return -1;
    }
    shstr[str_sz] = '\0';

    long sym_off = -1, sym_sz = -1, strtab_off = -1, strtab_sz = -1;
    unsigned long long sym_ent = 0;
    for (unsigned short i = 0; i < shnum; i++) {
        unsigned int no = SH_NAMEOFF(i);
        if (no >= str_sz) continue;
        const char *nm = shstr + no;
        if (strcmp(nm, ".dynsym") == 0) {
            sym_off = (long)SH_OFF(i); sym_sz = (long)SH_SIZE(i);
            sym_ent = is64 ? *(unsigned long long *)(shtab + (size_t)i * shentsize + 0x38)
                           : *(unsigned int *)(shtab + (size_t)i * shentsize + 0x24);
        } else if (strcmp(nm, ".dynstr") == 0) {
            strtab_off = (long)SH_OFF(i); strtab_sz = (long)SH_SIZE(i);
        }
    }
    free(shstr); free(shtab);
    if (sym_off < 0 || strtab_off < 0 || sym_sz <= 0 || strtab_sz <= 0 ||
        strtab_sz > (1 << 24)) { jg_close((int)fd); return -1; }
    if (sym_ent == 0) sym_ent = is64 ? 24 : 16;
    if (sym_ent == 0 || sym_ent > 128) { jg_close((int)fd); return -1; }

    char *dynstr = (char *)malloc((size_t)strtab_sz + 1);
    unsigned char *dynsym = (unsigned char *)malloc((size_t)sym_sz);
    if (!dynstr || !dynsym) { free(dynstr); free(dynsym); jg_close((int)fd); return -1; }
    if (jg_lseek((int)fd, strtab_off, SEEK_SET) != strtab_off ||
        jg_read((int)fd, dynstr, (size_t)strtab_sz) != strtab_sz ||
        jg_lseek((int)fd, sym_off, SEEK_SET) != sym_off ||
        jg_read((int)fd, dynsym, (size_t)sym_sz) != sym_sz) {
        free(dynstr); free(dynsym); jg_close((int)fd); return -1;
    }
    dynstr[strtab_sz] = '\0';
    jg_close((int)fd);

    long value = -1;
    size_t nsym = (size_t)sym_sz / (size_t)sym_ent;
    for (size_t i = 0; i < nsym; i++) {
        const unsigned char *sp = dynsym + i * (size_t)sym_ent;
        unsigned int st_name;
        unsigned char st_info;
        unsigned short st_shndx;
        unsigned long long st_value;
        if (is64) {
            memcpy(&st_name, sp, 4);
            st_info = sp[4];
            memcpy(&st_shndx, sp + 6, 2);
            memcpy(&st_value, sp + 8, 8);
        } else {
            memcpy(&st_name, sp, 4);
            memcpy(&st_value, sp + 4, 4);
            memcpy(&st_shndx, sp + 14, 2);   /* Elf32_Sym: name,value,size,info,other,shndx */
            st_info = sp[12];
        }
        if (st_name == 0 || st_name >= (unsigned int)strtab_sz) continue;
        if (st_value == 0 || st_shndx == 0) continue;             /* 未定义符号 */
        if ((st_info & 0xF) != 2) continue;                        /* STT_FUNC */
        /* 0908 P1：低版本 ART（API<29）无 ArtDexFileLoader::OpenCommon 导出符号，改用
         * OpenMemory（dex 内存加载入口，frida 同样 hook 它从 ByteBuffer 抽 dex）兜底匹配，
         * 让预载校验在老版本上也能定位校验点。仍只查这一个符号，绝不全表扫描（bit6 铁律）。 */
        if (strstr(dynstr + st_name, "OpenCommon") != NULL
                || strstr(dynstr + st_name, "OpenMemory") != NULL) {
            /* runtime 偏移 = st_value - phdr0.p_vaddr（见上方 vaddr0 说明） */
            value = (st_value >= vaddr0) ? (long)(st_value - vaddr0) : (long)st_value;
            break;
        }
    }
    free(dynstr); free(dynsym);
    return value;
}

/* ---------------- 对外接口 ----------------
 * 返回：1 = OpenCommon 入口被下跳板（硬信号）
 *       0 = 干净
 *      -1 = 不确定（libart 未找到 / 解析失败）——fail-safe 跳过，绝不误杀 */
int jg_preload_check(void) {
    if (!g_resolved) {
        long bias = 0;
        char path[256];
        if (_find_libart(&bias, path, (int)sizeof(path)) != 0) {
            __android_log_print(ANDROID_LOG_WARN, PTAG, "libart not found in maps -> inconclusive");
            g_resolved = 1;   /* 不再重试（maps 里没有就是没有） */
            return -1;
        }
        long v = _elf_find_opencommon(path);
        if (v < 0) {
            __android_log_print(ANDROID_LOG_WARN, PTAG, "OpenCommon symbol resolve failed -> inconclusive");
            g_resolved = 1;
            return -1;
        }
        g_opencommon = (const void *)(bias + v);
        g_resolved = 1;
        __android_log_print(ANDROID_LOG_INFO, PTAG, "OpenCommon @ %p (bias=%lx off=%lx)",
                            g_opencommon, bias, v);
    }
    if (!g_opencommon) return -1;
    return jg_entry_is_trampoline((const void *)(uintptr_t)g_opencommon) ? 1 : 0;
}

/* JNI：GxGuard.preloadCheck() —— 预载期调用。命中即在 native 内裸 syscall 自毁
 * （不返回 Java，Java 侧 hook 拦不住）。不确定/干净时正常返回。
 *
 * 0907 竞态修复：frida17 的 Interceptor 字节写入晚于 resume，壳预载检查可能跑在
 * hook 落盘之前 → 入口字节干净 → 放行 → 解密后数据全失（实测复现）。
 * 故预载路径加第二信号：agent 线程残留（gum-js-loop/pool-frida/frida*）。
 * spawn 注入的 agent 在进程挂起期就存在，【不依赖 hook 安装时机】，竞速必赢。
 * 两信号任一命中即自毁。 */
extern int jg_af_thread_names(void);
extern void jg_hard_exit(void);

JNIEXPORT void JNICALL
Java_com_gx_runtime_GxGuard_nativePreloadCheck(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    int r = jg_preload_check();
    if (r == 1) {
        __android_log_print(ANDROID_LOG_WARN, PTAG,
            "OpenCommon entry patched BEFORE dex decrypt -> raw exit (P0-B)");
        jg_hard_exit();
    }
    /* spawn 竞态兜底：agent 线程先于 app 代码存在（挂起期注入） */
    if (jg_af_thread_names()) {
        __android_log_print(ANDROID_LOG_WARN, PTAG,
            "frida agent threads present BEFORE dex decrypt -> raw exit (P0-B2)");
        jg_hard_exit();
    }
}
