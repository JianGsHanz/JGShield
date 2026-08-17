/*
 * jg_hook_bridge.S - ARM64 寄存器桥 (JGShield P3.3 inline hook)
 * --------------------------------------------------------------------------
 * 由 trampoline 跳入。进入时：目标函数首条指令已在 trampoline 里执行过，
 * 故 x1 仍等于原函数入口时的第 2 参数（对解释器桥即 CodeItem*）。
 *
 * 职责：保存 caller-saved 寄存器 -> 以 x1 为参调用 g_handler -> 恢复 -> 跳回原函数
 * 续跑地址 g_orig_continue（= target + 4）。不返回，用 br 续跑。
 *
 * 帧布局（sp 向下 0x220 字节，16 对齐）：
 *   GPR x0-x18  : 0x00 .. 0x98   (x0-x17 成对 9*16=144, x18 单独 8)
 *   FP/SIMD v0-v7   : 0x98 .. 0x118
 *   FP/SIMD v16-v31 : 0x118 .. 0x218
 */
    .text
    .align 4
    .global jg_hook_bridge
    .type jg_hook_bridge, %function
jg_hook_bridge:
    sub sp, sp, #0x220

    // ---- 保存 GPR caller-saved (x0-x18) ----
    stp x0,  x1,  [sp, #0x00]
    stp x2,  x3,  [sp, #0x10]
    stp x4,  x5,  [sp, #0x20]
    stp x6,  x7,  [sp, #0x30]
    stp x8,  x9,  [sp, #0x40]
    stp x10, x11, [sp, #0x50]
    stp x12, x13, [sp, #0x60]
    stp x14, x15, [sp, #0x70]
    stp x16, x17, [sp, #0x80]
    str x18,       [sp, #0x90]

    // ---- 保存 FP/SIMD caller-saved (v0-v7, v16-v31)，每条 stp 占 0x20，偏移须 16 对齐 ----
    stp q0,  q1,  [sp, #0xA0]
    stp q2,  q3,  [sp, #0xC0]
    stp q4,  q5,  [sp, #0xE0]
    stp q6,  q7,  [sp, #0x100]
    stp q16, q17, [sp, #0x120]
    stp q18, q19, [sp, #0x140]
    stp q20, q21, [sp, #0x160]
    stp q22, q23, [sp, #0x180]
    stp q24, q25, [sp, #0x1A0]
    stp q26, q27, [sp, #0x1C0]
    stp q28, q29, [sp, #0x1E0]
    stp q30, q31, [sp, #0x200]

    // x0 = code_item (原 x1)，调用 g_handler(x0)
    mov x0, x1
    adrp x1, g_handler
    ldr  x1, [x1, #:lo12:g_handler]
    blr  x1

    // ---- 恢复（偏移须与保存完全一致） ----
    ldp q30, q31, [sp, #0x200]
    ldp q28, q29, [sp, #0x1E0]
    ldp q26, q27, [sp, #0x1C0]
    ldp q24, q25, [sp, #0x1A0]
    ldp q22, q23, [sp, #0x180]
    ldp q20, q21, [sp, #0x160]
    ldp q18, q19, [sp, #0x140]
    ldp q16, q17, [sp, #0x120]
    ldp q6,  q7,  [sp, #0x100]
    ldp q4,  q5,  [sp, #0xE0]
    ldp q2,  q3,  [sp, #0xC0]
    ldp q0,  q1,  [sp, #0xA0]
    ldr x18,       [sp, #0x90]
    ldp x16, x17, [sp, #0x80]
    ldp x14, x15, [sp, #0x70]
    ldp x12, x13, [sp, #0x60]
    ldp x10, x11, [sp, #0x50]
    ldp x8,  x9,  [sp, #0x40]
    ldp x6,  x7,  [sp, #0x30]
    ldp x4,  x5,  [sp, #0x20]
    ldp x2,  x3,  [sp, #0x10]
    ldp x0,  x1,  [sp, #0x00]
    add sp, sp, #0x220

    // 跳回原函数续跑地址
    adrp x16, g_orig_continue
    ldr  x16, [x16, #:lo12:g_orig_continue]
    br   x16

    .size jg_hook_bridge, .-jg_hook_bridge
