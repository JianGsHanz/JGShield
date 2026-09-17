/*
 * jg_strcrypt.h  (P4: 明文锚点 XOR(0x37) 编码)
 * 所有 /proc 路径、frida/gum 等检测特征串在 .so 中以编码形式存储，
 * 运行时由 jg_strcrypt.c 的 jgx_dec / jgx_tbl 解码后使用，使得 strings+grep
 * 无法在二进制中直接命中明文。
 * 与 jg_anti_frida.c 的 FRIDA_SIGS 使用同一密钥 0x37。
 * 编码数组以裸 0x00 结尾哨兵；解码遇 0x00 停止。
 *
 * 关键设计（修复 -O2 常量折叠导致明文落 .rodata 的问题）：
 *   jgx_dec / jgx_tbl 与所有 JGX_* 编码表均定义在【独立翻译单元 jg_strcrypt.c】，
 *   本头文件只做 extern 声明。-O2 下编译器无法跨 TU 内联/常量折叠，
 *   故编码字节必然保留在 .rodata，明文只在运行时展开到栈缓冲区，strings 抓不到。
 */
#ifndef JG_STRCRYPT_H
#define JG_STRCRYPT_H
#include <stddef.h>

#define JGX_KEY 0x37

/* 运行时 XOR(0x37) 解码（实现见 jg_strcrypt.c，非 inline，跨 TU 不可折叠） */
void jgx_dec(const unsigned char *enc, char *out, size_t outcap);
const char *jgx_tbl(const unsigned char tbl[][24], int idx, char *buf, size_t bufsz);

/* ===== single strings (XOR 0x37, sentinel 0x00) —— 定义见 jg_strcrypt.c ===== */
extern const unsigned char JGX_MAPS[];          /* "/proc/self/maps" */
extern const unsigned char JGX_STATUS[];        /* "/proc/self/status" */
extern const unsigned char JGX_TASK[];          /* "/proc/self/task" */
extern const unsigned char JGX_TASK_COMM[];     /* "/proc/self/task/%s/comm" */
extern const unsigned char JGX_TASK_STATUS[];   /* "/proc/self/task/%s/status" */
extern const unsigned char JGX_FRIDA_SRV[];     /* "/data/local/tmp/re.frida.server" */
extern const unsigned char JGX_GUM[];           /* "gum-js-loop" */
extern const unsigned char JGX_POOL[];          /* "pool-frida" */
extern const unsigned char JGX_FRIDA[];         /* "frida" */
extern const unsigned char JGX_LOG_PORT_OPEN[]; /* "frida port %d open" */
extern const unsigned char JGX_LOG_SRV[];       /* "frida server file exists" */
extern const unsigned char JGX_LOG_HARD_PT[];   /* "frida port/thread detected (hard signal) -> raw exit" */
extern const unsigned char JGX_LOG_HARD_PA[];   /* "frida port (any) via handshake detected (hard signal) -> raw exit" */
extern const unsigned char JGX_LOG_AGENT[];     /* "frida agent threads present BEFORE dex decrypt -> raw exit (P0-B2)" */

/* 范围外补齐：原本的裸字面量明文，一并编码 */
extern const unsigned char JGX_SELF_MEM[];           /* "/proc/self/mem" */
extern const unsigned char JGX_MAGISK_CORE[];        /* "/magisk/.core" */
extern const unsigned char JGX_LOG_HOOK_MEM_PW[];    /* "[hook] /proc/self/mem pwrite rc=%ld ..." */
extern const unsigned char JGX_LOG_HOOK_MEM_FAIL[];  /* "[hook] open /proc/self/mem failed ..." */
extern const unsigned char JGX_HOOK_SKIP_GLOBAL[];   /* "hook-patched detected (frida/lsposed active) -> skip inline hook, pure P3.2 batch restore" */
extern const unsigned char JGX_HOOK_SKIP_TRAMP[];    /* "target @ %p already hooked (MOVZ/MOVK trampoline), skip to avoid double-hook" */

/* ===== tables (each entry XOR 0x37, raw 0x00 terminator) ===== */
extern const unsigned char JGX_MAP_KEYWORDS[][24];
extern const unsigned char JGX_BAD[][24];
extern const int JGX_MAP_KEYWORDS_N;
extern const int JGX_BAD_N;

#endif /* JG_STRCRYPT_H */
