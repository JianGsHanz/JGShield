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
#include <sys/mman.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <android/log.h>

#include "jg_inline_hook.h"

#define TAG "JG-InlineHook"

#if defined(__aarch64__)

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

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

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
    FILE *f = fopen("/proc/self/maps", "r");
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

    /* 路径1：/proc/self/mem（FOLL_FORCE 写只读/执行页，绕 W^X） */
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd >= 0) {
        ssize_t n = pwrite(fd, &b_to_tramp, 4, (off_t)(intptr_t)target);
        close(fd);
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[hook] /proc/self/mem pwrite rc=%ld target=%p b_to_tramp=%08x",
            (long)n, (void*)target, b_to_tramp);
        if (n == 4) written_ok = 1;
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "[hook] open /proc/self/mem failed (errno), try process_vm_writev");
    }

    /* 路径2：process_vm_writev 自进程（同样 FOLL_FORCE） */
    if (!written_ok) {
        struct iovec local, remote;
        local.iov_base  = &b_to_tramp; local.iov_len  = 4;
        remote.iov_base = (void *)(intptr_t)target; remote.iov_len = 4;
        ssize_t n = process_vm_writev(getpid(), &local, 1, &remote, 1, 0);
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[hook] process_vm_writev rc=%ld target=%p b_to_tramp=%08x",
            (long)n, (void*)target, b_to_tramp);
        if (n == 4) written_ok = 1;
    }

    /* 路径3：mprotect RW + 直接写（兜底） */
    if (!written_ok) {
        int rc_rw = mprotect((void *)p, 4096, PROT_READ | PROT_WRITE);
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "[hook] mprotect RW fallback rc=%d target=%p (W^X device will SEGV here)",
            rc_rw, (void*)target);
        if (rc_rw == 0) {
            *(uint32_t *)target = b_to_tramp;
            written_ok = 1;
            mprotect((void *)p, 4096, PROT_READ | PROT_EXEC);
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
