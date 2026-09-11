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
    private static native void nativeHardExit();
    private static native void nativePreloadCheck();

    /**
     * P0-B（2026-09-07 四步打穿复盘）：OpenCommon 入口预载校验。
     * 必须在解密任何业务 DEX 之前调用——spawn 注入的 hook 必然先于壳代码运行，
     * 此时校验能发现入口跳板并直接在 native 内裸 syscall 自毁（业务 DEX 尚未
     * 解密，攻击者零收获）。这是唯一能赢 spawn 竞态的窗口（实测 OpenCommon
     * 1-3s 落盘 vs 检测型探针 3.9s 杀进程）。
     * fail-safe：.so 未加载/任何异常 → 跳过，绝不影响正常启动。
     */
    static void preloadCheck() {
        ensureLoaded();
        if (!loaded) return;
        try {
            nativePreloadCheck();
        } catch (Throwable t) {
            Log.w(TAG, "preload check skipped", t);
        }
    }

    /** 裸 syscall 自毁（绕开 libc，frida hook kill/exit/raise/abort 拦不住）。
     *  所有硬信号（外部 tracer / frida 端口+线程名 / 入口跳板 / env+完整性）统一走这里。
     *  .so 未加载时退化到 System.exit（干净启动不应走到这，且 frida 未注入前拦截无意义）。 */
    static void hardExit() {
        ensureLoaded();
        if (!loaded) {
            // native 未加载：反篡改层已失效。绝不应回落到可被 frida hook 的 libc 路径
            // （System.exit/raise/abort 均拦得住），否则反而暴露"检测已触发"且自毁被废。
            // 仅记录，交给其余检测层。
            Log.w(TAG, "hardExit: native guard not loaded, skip (no hookable exit path)");
            return;
        }
        try {
            nativeHardExit();   // 裸 syscall 自毁，frida 拦不住
        } catch (Throwable t) {
            Log.w(TAG, "hardExit: nativeHardExit failed", t);
        }
    }

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
            Log.w(TAG, what + " -> hardExit (raw syscall, STRENGTHEN_RESPONSE=exit)");
            hardExit();
        } catch (Throwable ignored) {}
    }

    /**
     * P0-0904 持久 self-ptrace 防护：fork 守护子进程持续 trace 本进程全部线程，
     * 使外部（含 root）的 /proc/pid/mem 直读、process_vm_readv、frida-server
     * 注入、gdb attach 全部 EPERM —— 堵死 5.9.5 实测被拿走全部 4 dex 的那条通道。
     * 守护死亡(EXITKILL)则本进程被内核 SIGKILL，防「杀守护再 dump」。
     * 阻塞（握手最长 3s），调用方必须放在后台线程。
     * 返回守护 pid（>0=生效）；0=启动失败降级（不影响 App）；-1=启动时已检测到外部 tracer。
     */
    static int ptraceGuardStart() {
        ensureLoaded();
        if (!loaded) return 0;
        try {
            int pid = nativePtraceGuardStart();
            if (pid > 0) {
                Log.i(TAG, "ptrace guard active, tracer pid=" + pid);
            } else if (pid == -1) {
                // 硬信号（0904 三次报告①分级响应）：启动时已存在【外部】tracer
                // （frida spawn 先于壳代码注入的必经状态），正常设备恒不出现 → 无条件 exit。
                Log.w(TAG, "ptrace guard: external tracer at start -> hardExit (raw syscall, hard signal)");
                hardExit();
            } else {
                Log.w(TAG, "ptrace guard start failed, degrade (rc=0)");
            }
            return pid;
        } catch (Throwable t) {
            Log.w(TAG, "ptrace guard unavailable, skip", t);
            return 0;
        }
    }

    private static native int nativePtraceGuardStart();
    private static native int nativeEnvCheck();
    private static native int nativeIntegrityScan();
}
