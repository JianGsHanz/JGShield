/*
 * jg_inline_hook.h - 极简 ARM64 inline hook 引擎 (JGShield P3.3 用)
 * --------------------------------------------------------------------------
 * 设计目标：在 ART 解释器入口装一个"方法首次执行前还原"的钩子。
 * 只做最小必要的事，能编译、能安全失败（装不上就返回 <0，由调用方回退）。
 *
 * 限制（已知，调用方负责兜底）：
 *   - 仅覆盖目标函数【首条】指令（4 字节）。若首条指令是 PC 相关指令
 *     (ADRP/ADR/B/BL/B.cond/BR/BLR/CBZ/CBNZ/TBZ/TBNZ)，直接 abort，避免跳板重定位出错。
 *     解析器函数入口首条几乎都是 stp/sub sp，非 PC 相关，故常态可用。
 *   - trampoline 必须落在目标 ±128MB 内（B 指令 imm26 范围），否则 abort。
 *   - 不处理并发安装：必须在 DEX 加载期、其它线程启动前调用（单次初始化）。
 *
 * handler 约定：被调用时 x1 仍为原函数的第 2 个参数。对 Android 10 的
 *   artInterpreterToInterpreterBridge(self, code_item, shadow_frame, result)
 *   而言 x1 = 指向 CodeItem 的指针，正是还原所需。其它版本若 code_item 不在 x1，
 *   须在跨版本表里标注并调整桥（本实现固定取 x1）。
 */
#ifndef JG_INLINE_HOOK_H
#define JG_INLINE_HOOK_H

#include <stdint.h>

/* 由桥调用的 handler：code_item = 原函数第 2 参数（DEX 方法 CodeItem 指针）。 */
typedef void (*jg_hook_handler_t)(void *code_item);

/*
 * 在 target（函数入口地址）安装 inline hook。
 *   handler     : 原函数执行前被调用（x1=code_item）。
 *   out_orig    : 回传"原函数继续执行地址"(target+4)，备用（本实现桥内已用全局）。
 * 返回 0 成功；<0 失败（调用方应回退到批量还原）。
 */
int jg_inline_hook_install(uintptr_t target, jg_hook_handler_t handler,
                           uintptr_t *out_orig);

#endif /* JG_INLINE_HOOK_H */
