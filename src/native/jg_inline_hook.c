/*
 * jg_inline_hook.c - ARM64 inline hook 安装 (JGShield P3.3)
 * --------------------------------------------------------------------------
 * 仅覆盖目标函数首条指令（4 字节），跳板里先执行该指令再进入寄存器桥调用
 * handler，最后跳回 target+4 续跑。PC 相关首指令 / 跳板超 ±128MB 时安全 abort。
 *
 * 桥 jg_hook_bridge（见 jg_hook_bridge.S，仅 aarch64 提供）引用本文件的全局：
 *   g_handler         : 被调用的 C handler（void(*)(void*)）
 *   g_orig_continue   : 原函数续跑地址（target+4）
 *
 * 非 aarch64 架构不提供桥，jg_inline_hook_install 直接返回 -99（不支持），
 * 调用方据此回退批量还原。
 */
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <android/log.h>
#include "jg_strcrypt.h"  /* P4: 明文锚点 XOR(0x37) 编码，运行时解码 */

/* process_vm_writev 在 Bionic 里【到 API 23 才提供】，而本项目 min-api=21。
 * 直接调用有两个后果：
 *   1) 编译期只是 implicit-declaration 警告，链接期留下未定义符号；ELF 共享库默认
 *      放行未定义符号，于是"链接成功"，直到真机 dlopen 才报
 *      dlopen failed: cannot locate symbol "process_vm_writev" —— 在 Android 5.x 上
 *      整个壳 .so 加载失败，App 启动即崩。
 *   2) 即使能链接，API 21/22 设备上该符号也不存在。
 * 故声明为 weak：链接期允许缺失（配合 -Wl,--no-undefined 也不会报错），
 * 运行期用取址判空，缺失则自动走下面的 fork 写手 / mprotect 兜底路径。 */
extern ssize_t process_vm_writev(pid_t __pid, const struct iovec *__local_iov,
                                 unsigned long __liovcnt,
                                 const struct iovec *__remote_iov,
                                 unsigned long __riovcnt, unsigned long __flags)
    __attribute__((weak));

#include "jg_inline_hook.h"

#define TAG "JG-InlineHook"

#ifndef __WALL
#define __WALL 0x40000000
#endif

#if defined(__aarch64__)

/* ---- 路径2.5：fork 短命写手子进程，以 tracer 身份 ptrace 代写（B 方案，2026-09-07）----
 * 华为 SEA-AL10（Android10/EMUI/kernel4.14）实测：路径1 open(/proc/self/mem,O_RDWR) 被
 * SELinux 拒、路径2 process_vm_writev 自进程被 ROM 收紧为需 tracer 关系，直接落路径3
 * 用户态写 W^X text 即 SEGV_ACCERR 闪退（真机 tombstone 实锤）。
 * 本进程 fork 出的子进程 PTRACE_ATTACH 调用线程后即为 tracer，ptrace_may_access 必过，
 * PTRACE_POKEDATA 走内核 FOLL_FORCE —— 与 ROM 的 W^X/SELinux 对用户态写的限制无关。
 * 铁律（对齐 jg_ptrace_guard.c）：
 *   1. 子进程内仅 async-signal-safe 调用（ptrace/waitpid/_exit/syscall），绝不 malloc/stdio/ART；
 *   2. 不设 PTRACE_O_EXITKILL，DETACH 后 _exit —— 写手任何异常绝不连累父进程；
 *   3. POKEDATA 以 8 字节(word)为粒度，必须 PEEK 对齐字→替换本指令 4B→POKE 回。
 *      绝不能直接 POKE 8B：会把 target+4 的下一条指令（hook 后续跑地址）覆盖掉；
 *   4. 父进程侧 3s 超时上限；超时 SIGKILL 写手（tracer 死亡自动 detach tracee，无副作用）。
 * 真机已验证（SEA-AL10，shell 域 R-X 页）：8B 对齐与跨字(shift=32)两用例均写入成功、
 * 相邻指令无损。返回 1=写入成功；0=失败（继续走路径3 / 最终降级批量还原）。 */
static int write4_via_fork_writer(uintptr_t target, uint32_t insn) {
    /* 父进程（调用线程）tid：fork 前取好，经 fork 内存拷贝传给子进程。
     * 坑（真机踩过）：SYS_gettid 在子进程里返回的是【子进程】自己的 tid，
     * 用它 ATTACH 会变成自 attach 必失败（华为 SEA-AL10 实测 _exit(1)）。 */
    pid_t self_tid = (pid_t)syscall(SYS_gettid);
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) {
        /* 子进程：attach 调用线程 → 等停 → 8B RMW → detach → _exit */
        pid_t tid = self_tid;
        if (ptrace(PTRACE_ATTACH, tid, 0, 0) != 0) _exit(1);
        int st;
        pid_t r;
        do { r = waitpid(tid, &st, __WALL); } while (r < 0 && errno == EINTR);
        if (r != tid || !WIFSTOPPED(st)) _exit(2);
        uintptr_t waddr = target & ~(uintptr_t)7;   /* aarch64 指令 4B 对齐，偏移 0 或 4 */
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, tid, (void *)waddr, 0);
        if (errno != 0) _exit(3);
        int shift = (int)((target - waddr) * 8);    /* 小端：低位字节在低地址 */
        unsigned long uw = (unsigned long)word;
        unsigned long mask = (shift == 0) ? 0xFFFFFFFFUL : (0xFFFFFFFFUL << shift);
        long nword = (long)((uw & ~mask) | ((unsigned long)(unsigned int)insn << shift));
        if (ptrace(PTRACE_POKEDATA, tid, (void *)waddr, (void *)nword) != 0) _exit(4);
        ptrace(PTRACE_DETACH, tid, 0, 0);
        _exit(0);
    }
    /* 父进程：轮询等写手退出，上限 3s（10ms 步进）。本线程在轮询中被 ATTACH 停住
     * 属预期（毫秒级），DETACH 后自动续跑并立即收割子进程退出码。 */
    int ok = 0;
    int st = 0;
    pid_t r = 0;
    for (int i = 0; i < 300; i++) {
        r = waitpid(pid, &st, WNOHANG);
        if (r == pid) { ok = (WIFEXITED(st) && WEXITSTATUS(st) == 0); break; }
        if (r < 0 && errno != EINTR) break;
        usleep(10000);
    }
    if (r != pid) {   /* 超时/异常：杀掉短命写手（未设 EXITKILL，父进程安全） */
        kill(pid, SIGKILL);
        do { r = waitpid(pid, &st, 0); } while (r < 0 && errno == EINTR);
    }
    return ok;
}

/* 寄存器桥（见 jg_hook_bridge.S），cross-TU 引用需声明 */
extern void jg_hook_bridge(void);

/* 桥引用的全局（DSO 内部局部符号，hidden：使 .S 的 adrp/ldr 用相对重定位）。 */
__attribute__((visibility("hidden"))) jg_hook_handler_t g_handler = NULL;
__attribute__((visibility("hidden"))) uintptr_t g_orig_continue = 0;

static uint32_t page_of(uintptr_t a) {
    return (uint32_t)(a & ~(uintptr_t)4095);
}

/* 编码 ARM64 B 指令（imm26，±128MB）。超出范围返回 0 表示失败。 */
static uint32_t encode_b(uintptr_t from, uintptr_t to) {
    int64_t off = (int64_t)to - (int64_t)(from + 4);
    if (off < -(1LL << 27) || off >= (1LL << 27)) return 0;
    uint32_t imm26 = (uint32_t)((off >> 2) & 0x3FFFFFFu);
    return 0x14000000u | imm26;
}

/* 首条指令是否 PC 相关（跳板无法安全重定位）。 */
static int is_pc_relative(uint32_t insn) {
    if ((insn & 0x9F000000u) == 0x90000000u) return 1;   /* ADRP / ADR */
    if ((insn & 0xFC000000u) == 0x14000000u) return 1;   /* B    */
    if ((insn & 0xFC000000u) == 0x94000000u) return 1;   /* BL   */
    if ((insn & 0xFC000000u) == 0x54000000u) return 1;   /* B.cond */
    if ((insn & 0x7E000000u) == 0x34000000u) return 1;   /* CBZ / CBNZ */
    if ((insn & 0x7E000000u) == 0x36000000u) return 1;   /* TBZ / TBNZ */
    if ((insn & 0xFFFFFC00u) == 0xD61F0000u) return 1;   /* BR   */
    if ((insn & 0xFFFFFC00u) == 0xD63F0000u) return 1;   /* BLR  */
    /* LDR/PRFM/LDRSW 字面量加载：[PC, #imm] 也是 PC 相关（PC=本条指令地址）。
     * 0x18000000(LDR 32) / 0x58000000(LDR 64) / 0x98000000(LDRSW) / 0x1C000000(PRFM)。 */
    if ((insn & 0x3B000000u) == 0x18000000u) return 1;
    return 0;
}

/* 识别 frida / LSPosed(Zygisk) 的 inline hook 跳板首部：
 *   MOVZ xN, #imm        (0xD2800000 | (imm16<<5) | Rd)
 *   MOVK xN, #imm, ...   (0xF2A00000 | ... | Rd)
 * 这类形态 is_pc_relative() 认不出（非 B/BL/BR/ADRP 类），会在【已被 hook 的目标】
 * 上叠加我们的跳板 -> 续跑点 target+4 落在 frida 残留 trampoline 中段 -> 跳飞 SIGSEGV。
 * 命中即放弃本目标，交由调用方回退批量还原（不 double-hook）。 */
static int is_frida_trampoline(uintptr_t target) {
    uint32_t first  = *(const uint32_t *)target;
    uint32_t second = *(const uint32_t *)(target + 4);
    int rd1 = first  & 0x1F;
    int rd2 = second & 0x1F;
    if (((first  & 0xFFE00000u) == 0xD2800000u) &&   /* MOVZ */
        ((second & 0xFFE00000u) == 0xF2A00000u) &&   /* MOVK */
        (rd1 == rd2))                                /* 同一寄存器：地址加载序列 */
        return 1;
    return 0;
}

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* 路径3 直接写的 SIGSEGV guard（安装只在启动期主线程执行一次，单 buffer 无竞争） */
static sigjmp_buf g_write_jb;
static void _write_segv_handler(int sig) {
    (void)sig;
    siglongjmp(g_write_jb, 1);
}

/* 在 target 的 ±128MB 内找一个空闲 4KB 页并固定映射为 RWX。普通 mmap(hint) 的 hint 会被
 * 内核忽略，跳板常落到远处导致 target->trampoline 单条 B（±128MB）越界。故解析
 * /proc/self/maps 的空闲间隙，用 MAP_FIXED_NOREPLACE 落到间隙内，保证 trampoline 与 target
 * 相距 <=128MB。cand 只取映射间隙（空闲页），即便旧内核不支持 NOREPLACE 而按 MAP_FIXED 处理，
 * 也只会映射到空闲页，不会踩踏已有映射，安全。 */
static void *mmap_near(uintptr_t target) {
    uintptr_t lo = (target > 0x07FFFFF0u) ? (target - 0x07FFFFF0u) : 0x10000u;
    uintptr_t hi = target + 0x07FFFFF0u;
    if (hi < target) hi = (uintptr_t)-4096;          /* 溢出保护 */
    uintptr_t r[2048]; int nr = 0;
    char path[64];
    jgx_dec(JGX_MAPS, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f) && nr < 1024) {
            uintptr_t a, b;
            if (sscanf(line, "%lx-%lx", &a, &b) == 2) { r[nr*2] = a; r[nr*2+1] = b; nr++; }
        }
        fclose(f);
    }
    uintptr_t cur = lo;
    for (int i = 0; i < nr; i++) {
        uintptr_t seg_s = r[i*2], seg_e = r[i*2+1];
        if (seg_s > cur) {
            uintptr_t c = (cur + 4095) & ~(uintptr_t)4095;
            while (c + 4096 <= seg_s && c + 4096 <= hi) {
                void *p = mmap((void *)c, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
                if (p != MAP_FAILED) return p;
                c += 4096;
            }
        }
        if (seg_e > cur) cur = seg_e;
        if (cur >= hi) break;
    }
    if (cur < hi) {
        uintptr_t c = (cur + 4095) & ~(uintptr_t)4095;
        while (c + 4096 <= hi) {
            void *p = mmap((void *)c, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (p != MAP_FAILED) return p;
            c += 4096;
        }
    }
    return NULL;
}

int jg_inline_hook_install(uintptr_t target, jg_hook_handler_t handler,
                           uintptr_t *out_orig) {
    if (!target || !handler) return -1;

    uint32_t first = *(const uint32_t *)target;
    if (is_pc_relative(first)) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
            "first insn 0x%08x is PC-relative, abort hook", first);
        return -2;
    }
    /* 防 double-hook 自爆：frida/LSPosed 已对本目标下 MOVZ/MOVK+BR 跳板时，
     * 不再叠加我们自己的跳板（否则续跑点 target+4 落进 frida 残留 trampoline 中段）。 */
    if (is_frida_trampoline(target)) {
        char msg[128];
        jgx_dec(JGX_HOOK_SKIP_TRAMP, msg, sizeof(msg));
        __android_log_print(ANDROID_LOG_WARN, TAG, msg, (void*)target);
        return -2;
    }

    /* 在 target 的 ±128MB 内找空闲页固定映射（保证 target->trampoline 单条 B 不越界）。
     * trampoline->bridge 用绝对跳转（ldr x16,[PC,#4]; br x16），不受 ±128MB 限制。 */
    void *tp = mmap_near(target);
    if (!tp) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "no nearby page for trampoline (±128MB)");
        return -3;
    }
    uintptr_t tramp = (uintptr_t)tp;

    /* target -> trampoline 必须单条 B（4 字节），要求 ±128MB。 */
    uint32_t b_to_tramp = encode_b(target + 4, tramp);
    if (b_to_tramp == 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "target->trampoline out of range");
        munmap(tp, 4096);
        return -4;
    }

    /* 跳板内容（4 字节/槽）：[首条指令][ldr x16,[PC,#8]][br x16][bridge_addr 8B]
     * 布局：tp+0=首条指令, tp+4=ldr, tp+8=br, tp+12..19=bridge 绝对地址（8 字节）。
     * ldr x16,[PC,#8] 编码 0x58000050：AArch64 的 LDR 字面量以【本条指令自身地址】为 PC
     * 基址（非下一条指令地址），故在 tp+4 处执行时 PC=tp+4，+8 => tp+12 = bridge 地址。
     * 历史坑：曾误以为 PC=下一条(tp+8) 而写成 imm=4 / 0x58000030，会错误地把 br 指令的
     * 机器码字节当地址加载进 x16，导致 br 跳飞到非法地址 -> 首次触发即 SIGSEGV。 */
    uint32_t ldr_x16_pc8 = 0x58000050;
    uint32_t br_x16      = 0xD61F0200;
    ((uint32_t *)tp)[0] = first;
    ((uint32_t *)tp)[1] = ldr_x16_pc8;
    ((uint32_t *)tp)[2] = br_x16;
    *(uint64_t *)((uint32_t *)tp + 3) = (uint64_t)&jg_hook_bridge;
    __builtin___clear_cache((char *)tp, (char *)((uint32_t *)tp + 5));
    mprotect(tp, 4096, PROT_READ | PROT_EXEC);

    /* 覆盖目标首条指令为 B -> 跳板。
     * 关键坑（已真机验证，小米 MIX2 / Android9）：libart.so 的 .text 页启用 W^X，
     * mprotect(PROT_READ|PROT_WRITE) 返回 0 但页仍为只读/执行，【用户态直接写目标首指令
     * 会 SEGV_ACCERR 并杀死进程】。因此绝不直接做用户态写，统一经内核 FOLL_FORCE 路径写入：
     *   路径1 /proc/self/mem pwrite（最通用，FOLL_FORCE 写任意权限页）
     *   路径2 process_vm_writev(getpid(),...)（部分 ROM 对 /proc/self/mem 限 SELinux 时）
     *   路径3 mprotect RW + 直接写（仅上述均不可用的兜底；W^X 设备走此路径仍会崩，属 fail-safe）
     * FOLL_FORCE 在“可写页”上也正常原地写，故前两条路径对任意设备都安全。 */
    uintptr_t p = page_of(target);
    g_handler = handler;
    g_orig_continue = target + 4;

    int written_ok = 0;

    /* 路径1：/proc/self/mem（FOLL_FORCE 写只读/执行页，绕 W^X）。路径串运行时解码，不落明文 */
    char mempath[32];
    jgx_dec(JGX_SELF_MEM, mempath, sizeof(mempath));
    int fd = open(mempath, O_RDWR);
    if (fd >= 0) {
        ssize_t n = pwrite(fd, &b_to_tramp, 4, (off_t)(intptr_t)target);
        close(fd);
        char logpw[128];
        jgx_dec(JGX_LOG_HOOK_MEM_PW, logpw, sizeof(logpw));
        __android_log_print(ANDROID_LOG_INFO, TAG, logpw,
            (long)n, (void*)target, b_to_tramp);
        if (n == 4) written_ok = 1;
    } else {
        char logfail[128];
        jgx_dec(JGX_LOG_HOOK_MEM_FAIL, logfail, sizeof(logfail));
        __android_log_print(ANDROID_LOG_WARN, TAG, logfail);
    }

    /* 路径2：process_vm_writev 自进程（同样 FOLL_FORCE）
     * weak 符号：API<23 的 Bionic 没有它，取址为 NULL 时跳过，落 fork 写手/兜底路径。 */
    if (!written_ok && process_vm_writev) {
        struct iovec local, remote;
        local.iov_base  = &b_to_tramp; local.iov_len  = 4;
        remote.iov_base = (void *)(intptr_t)target; remote.iov_len = 4;
        ssize_t n = process_vm_writev(getpid(), &local, 1, &remote, 1, 0);
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[hook] process_vm_writev rc=%ld target=%p b_to_tramp=%08x",
            (long)n, (void*)target, b_to_tramp);
        if (n == 4) written_ok = 1;
    } else if (!written_ok) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "[hook] process_vm_writev unavailable (API<23), skip path2");
    }

    /* 路径2.5：fork 短命写手子进程 tracer 代写（B 方案，华为 EMUI 实测路径1/2 全被封）。
     * 成功则跳过路径3 —— 在 W^X 设备上既保住 P3.4 解释桥 hook，又不触发用户态直写崩溃。 */
    if (!written_ok) {
        written_ok = write4_via_fork_writer(target, b_to_tramp);
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[hook] fork-writer path rc=%d target=%p b_to_tramp=%08x",
            written_ok, (void*)target, b_to_tramp);
    }

    /* 路径3：mprotect RW + 直接写（兜底，已被 A 方案 SIGSEGV guard 包住）。
     * 0907 华为/荣耀 A10 (API29, 未 root) 实测：SELinux 拦掉 /proc/self/mem 写与
     * process_vm_writev，落到本路径；而 .text 页 W^X，mprotect 返回 0 但页仍不可写，
     * 直接写 = SEGV_ACCERR 闪退（修复前 exe 构建包在 A10 必崩）。
     * 修复：直接写用 SIGSEGV guard 包住——写崩即 siglongjmp 恢复，munmap 跳板后
     * 返回 -6，调用方回退 P3.2 批量还原（P3.4 铁律：批量还原是生产统一方案）。 */
    if (!written_ok) {
        int rc_rw = mprotect((void *)p, 4096, PROT_READ | PROT_WRITE);
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[hook] mprotect RW fallback rc=%d target=%p", rc_rw, (void*)target);
        if (rc_rw == 0) {
            struct sigaction sa, old_sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = _write_segv_handler;
            sigemptyset(&sa.sa_mask);
            sigaction(SIGSEGV, &sa, &old_sa);
            if (sigsetjmp(g_write_jb, 1) == 0) {
                *(volatile uint32_t *)target = b_to_tramp;
                written_ok = 1;
            }
            sigaction(SIGSEGV, &old_sa, NULL);
            if (written_ok) {
                mprotect((void *)p, 4096, PROT_READ | PROT_EXEC);
            } else {
                __android_log_print(ANDROID_LOG_WARN, TAG,
                    "[hook] direct write faulted (W^X page) -> degrade to batch restore");
            }
        }
    }

    if (written_ok) {
        __builtin___clear_cache((char *)target, (char *)(target + 4));
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[hook] B written OK; readback=%08x expect=%08x",
            *(volatile uint32_t *)target, b_to_tramp);
    }

    int rc_rx = mprotect((void *)p, 4096, PROT_READ | PROT_EXEC);
    __android_log_print(ANDROID_LOG_INFO, TAG, "[hook] mprotect target RX rc=%d, install done", rc_rx);

    if (!written_ok) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "CANNOT write target first insn -> abort hook");
        munmap(tp, 4096);
        return -6;
    }

    if (out_orig) *out_orig = target + 4;
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "hook installed: target=%p trampoline=%p bridge=%p",
        (void *)target, (void *)tramp, (void *)&jg_hook_bridge);
    return 0;
}

#else /* 非 aarch64：不支持 inline hook，回退批量还原 */

int jg_inline_hook_install(uintptr_t target, jg_hook_handler_t handler,
                           uintptr_t *out_orig) {
    (void)target; (void)handler; (void)out_orig;
    return -99;   /* inline hook unsupported on this arch */
}

#endif
