/*
 * jg_hook_bridge.S - ARM64 寄存器桥 (JGShield P3.3 inline hook)
 * --------------------------------------------------------------------------
 * 由 trampoline 跳入。进入时：目标函数首条指令已在 trampoline 里执行过，
 * 故 x1 仍等于原函数入口时的第 2 参数（对解释器桥即 CodeItem*）。
 *
 * 职责：保存 caller-saved 寄存器 -> 以 x1 为参调用 g_handler -> 恢复 -> 跳回原函数
 * 续跑地址 g_orig_continue（= target + 4）。不返回，用 br 续跑。
 *
 * ⚠⚠ 2026-09-10 根因修复：必须保存/恢复 x30(LR) ⚠⚠
 *   被 hook 的函数（如 ArtInterpreterToInterpreterBridge）把自己的返回地址【在函数体内】
 *   才存栈，而不是在首条指令里。实测 MIX2 libart.so 序言为：
 *     25a4f0: sub  sp, sp, #128        <- 被偷到跳板执行的正是这条（不碰 x30）
 *     25a4f4: str  x25, [sp, #48]
 *     ...
 *     25a504: stp  x29, x30, [sp, #112] <- x30 到这里才落栈
 *   而本桥的 `blr x1` 指令【会写 x30】。若不保存 x30，则上面那条 stp 把桥内地址
 *   当成返回地址存栈；函数 epilogue 的 ret 便跳回【本桥中间】，而此时本桥的 0x220
 *   栈帧早已撤销 -> 对着调用方栈做 ldp q30,q31,[sp,#0x200]、add sp,sp,#0x220，
 *   寄存器与 SP 全面损坏，再 br 回 target+4 执行垃圾。
 *   历史症状（长期被误判为 TOCTOU/擦除竞态）：启动后 10~20s 随机线程（主线程 /
 *   glide-source-th / glide-disk-cach）间歇 SIGSEGV(SI_USER)，pc 落在 JIT 匿名区，
 *   或 SIGABRT 'invalid-method-idx'（art_method.cc found_virtual）。因属纯 ABI bug，
 *   与抽取/擦除/handler 逻辑无关，故此前所有"关擦除/改锁序/关守护"的修法均无效。
 *   修复：进入时把 x30 存入帧内空闲的 0x98（x18 占用 0x90..0x97，q0 起于 0xA0），
 *   调用 handler 之后、br 续跑之前恢复。x19-x28/x29 为 callee-saved，handler 依 ABI
 *   自行保持，无需额外保存。
 *
 * 帧布局（sp 向下 0x220 字节，16 对齐）：
 *   GPR x0-x18  : 0x00 .. 0x98   (x0-x17 成对 9*16=144, x18 单独 8)
 *   x30(LR)     : 0x98 .. 0xA0   (关键：见上)
 *   FP/SIMD v0-v7   : 0xA0 .. 0x120
 *   FP/SIMD v16-v31 : 0x120 .. 0x220
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

    // ⚠ 必须保存 x30：blr 会覆盖它，而被 hook 函数是在函数体内才存 LR（见文件头说明）
    str x30,       [sp, #0x98]

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
    ldr x30,       [sp, #0x98]   // ⚠ 恢复 LR：否则被 hook 函数的 ret 会跳回本桥中间
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
