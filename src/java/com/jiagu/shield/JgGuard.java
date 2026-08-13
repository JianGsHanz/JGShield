package com.jiagu.shield;

import android.util.Log;

/**
 * JgGuard - native 反篡改/反调试桥接层。
 *
 * 把检测逻辑下沉到 native (.so)，相比纯 Java 的 AntiTamper 更难被 frida 一行 hook 废掉。
 * 设计要点（与「别让补强导致 App 崩溃」的硬约束一致）：
 *   - 加载/调用全程 try-catch；libjgguard.so 缺失或任何异常都「优雅降级」，
 *     仅跳过 native 防护，绝不影响解密与 App 正常启动。
 *   - 实际的检测与响应在 native 守护线程里完成（命中即静默 exit）。
 *   - 与现有 Java AntiTamper 互为备份：native 为主，Java 为辅，任一可用即提供防护。
 */
public final class JgGuard {
    private static final String TAG = "JG-Native";

    private JgGuard() {}

    /** 启动 native 守护线程；失败则静默跳过（不影响 App 运行）。 */
    static void start() {
        try {
            System.loadLibrary("jgguard");
            Log.i(TAG, "native guard loaded");
            nativeStart();
            Log.i(TAG, "native guard thread started");
        } catch (Throwable t) {
            // .so 缺失 / 架构不匹配 / 任何异常：降级，仅失去 native 层防护
            Log.w(TAG, "native guard unavailable, skip", t);
        }
    }

    private static native void nativeStart();
}
