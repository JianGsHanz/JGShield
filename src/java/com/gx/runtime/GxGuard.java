package com.gx.runtime;

import android.util.Log;

/**
 * GxGuard - native 反篡改/反调试桥接层。
 *
 * 把检测逻辑下沉到 native (.so)，相比纯 Java 的 GxTamper 更难被 frida 一行 hook 废掉。
 * 设计要点（与「别让补强导致 App 崩溃」的硬约束一致）：
 *   - 加载/调用全程 try-catch；libjgguard.so 缺失或任何异常都「优雅降级」，
 *     仅跳过 native 防护，绝不影响解密与 App 正常启动。
 *   - 实际的检测与响应在 native 守护线程里完成（命中即静默 exit）。
 *   - 与现有 Java GxTamper 互为备份：native 为主，Java 为辅，任一可用即提供防护。
 */
public final class GxGuard {
    private static final String TAG = "GX-Native";
    private static boolean loaded = false;

    private GxGuard() {}

    /** 加载 libjgguard.so（幂等，失败静默降级）。
     *  必须在任何依赖该 .so 的 native 方法被调用前执行（P3 的 nativeRestoreInit /
     *  nativeRestoreMethods 以及反篡改都依赖它）。 */
    static void ensureLoaded() {
        if (loaded) return;
        try {
            System.loadLibrary(Obf.d(new byte[]{0x79, 0x30, 0x4D, 0x19, 0x2F, 0x69, 0x52}));
            loaded = true;
            Log.i(TAG, "native guard loaded");
        } catch (Throwable t) {
            Log.w(TAG, "native guard load failed, skip", t);
        }
    }

    /** 启动 native 守护线程；失败则静默跳过（不影响 App 运行）。 */
    static void start() {
        ensureLoaded();
        if (!loaded) return;
        try {
            nativeStart();
            Log.i(TAG, "native guard thread started");
        } catch (Throwable t) {
            // .so 缺失 / 架构不匹配 / 任何异常：降级，仅失去 native 层防护
            Log.w(TAG, "native guard unavailable, skip", t);
        }
    }

    private static native void nativeStart();
    private static native void nativeSetResponse(String mode);

    /** 把 Java 侧统一的响应开关传给 native（native 据此决定命中后是退出还是仅记录）。
     *  必须在 GxGuard.start() 之前调用，确保 native 守护线程启动即读到正确模式。 */
    static void configureResponse() {
        ensureLoaded();
        if (!loaded) return;
        try {
            nativeSetResponse(GxApp.STRENGTHEN_RESPONSE);
            Log.i(TAG, "response mode -> native: " + GxApp.STRENGTHEN_RESPONSE);
        } catch (Throwable t) {
            Log.w(TAG, "set response skipped", t);
        }
    }

    /** 环境检测（root/模拟器）：返回位掩码，0 表示干净。fail-safe（异常时返回 0，不阻断启动）。 */
    static int envCheck() {
        ensureLoaded();
        if (!loaded) return 0;
        try {
            int m = nativeEnvCheck();
            if (m != 0) Log.w(TAG, "env check flags=0x" + Integer.toHexString(m));
            else Log.i(TAG, "env check: clean");
            respondIfNeeded("env check", m != 0);
            return m;
        } catch (Throwable t) {
            Log.w(TAG, "env check skipped", t);
            return 0;
        }
    }

    /** 运行时自校验（自 hook/篡改）：返回命中数，0 表示干净。fail-safe。 */
    static int integrityScan() {
        ensureLoaded();
        if (!loaded) return 0;
        try {
            int n = nativeIntegrityScan();
            if (n != 0) Log.w(TAG, "integrity issues=" + n);
            else Log.i(TAG, "integrity: clean");
            respondIfNeeded("integrity scan", n != 0);
            return n;
        } catch (Throwable t) {
            Log.w(TAG, "integrity scan skipped", t);
            return 0;
        }
    }

    /** 命中且生产开关为 exit 时静默退出；默认 log 模式仅记录。fail-safe，异常不抛出。 */
    private static void respondIfNeeded(String what, boolean hit) {
        if (!hit) return;
        if (!"exit".equals(GxApp.STRENGTHEN_RESPONSE)) return;
        try {
            Log.w(TAG, what + " -> System.exit (STRENGTHEN_RESPONSE=exit)");
            System.exit(1);
        } catch (Throwable ignored) {}
    }

    private static native int nativeEnvCheck();
    private static native int nativeIntegrityScan();
}
