package com.gx.runtime;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.os.Debug;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.lang.ref.WeakReference;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import java.net.InetSocketAddress;
import java.net.Socket;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.net.NetworkInterface;

/**
 * JGShield - 差异化 APK 加固壳 (参考 mocika-shield 的设计目标，但实现完全不同)
 *
 * 相对开源项目 mocika-shield 的差异点：
 *   1. 算法：AES-256-GCM(AEAD) + DEFLATE 压缩（而非 ChaCha20-Poly1305 + Zstd）。
 *   2. 载荷藏匿：加密后的原始 DEX 不是放在 assets，而是作为一个自定义顶层 ZIP 条目
 *      (条目名 "jg"，魔数 "JGS1") 随 APK 一起打包；classes.dex 保持为标准干净壳 DEX，
 *      任何反编译/安装工具都不会因尾部垃圾数据报错；与 mocika-shield 的 assets/app.bin 不同。
 *   3. 密钥派生：以 APK 签名证书 SHA-256 作为 seed，再 HMAC-SHA256 派生每 dex 独立密钥
 *      (而非 HKDF + 随机 IKM)；换签/重签即解密失败（反篡改）。
 *   4. 加载：纯 Java PathClassLoader 注入 + 替换 LoadedApk/ActivityThread 中的 Application 与
 *      ClassLoader，使原 Application 与四大组件均可被系统正常实例化（而非 Rust native 注入）。
 *   5. 反调试：启动期对 /proc/self/maps 做 Frida/Substrate/Xposed 特征扫描 + debugger 检测。
 */
/**
 * P8 变更：GxApp 不再 extends Application（Manifest 入口改为 GxBootstrap）。
 * 改为被引导壳加载的普通类，所有初始化逻辑收口到 static Application boot(Context, Application)。
 * 系统不会再把 GxApp 当 Application 实例化，生命周期转发由 GxBootstrap 负责。
 */
public class GxApp {
    private static final String TAG = "GX";
    static final String MAGIC = Obf.d(new byte[]{0x59, 0x10, 0x79, 0x5D});
    private static final String META_ORIG = "gx.orig_app";
    static final String PAYLOAD_ENTRY = "z9";

    // ===== 反篡改（保命版）开关 =====
    // 改为 false 并重新编译 stub.dex 即可完全关闭反篡改；响应方式 / 轮询间隔同理。
    static final boolean ANTI_TAMPER_ENABLED = true;
    // P0-0904 持久 self-ptrace 防护（堵 root /proc/pid/mem 直读 —— 5.9.5 实测被拿走
    // 全部 4 个业务 dex 的那条通道）。fork 守护子进程持续 trace 全线程，外部读取/注入
    // 一律 EPERM；守护死亡(EXITKILL)则本进程随之退出，防「杀守护再 dump」。
    // 诚实边界：挡不住内核模块级攻击者与已在进程内运行的 frida-gadget（与梆梆/360 同天花板）。
    static final boolean PTRACE_GUARD_ENABLED = true;
    // [已废弃] 原 GxTamper 响应开关；现统一收口到 STRENGTHEN_RESPONSE（含 frida 检测）。
    // 保留仅供兼容，不再被读取。
    static final String ANTI_TAMPER_RESPONSE = "exit";
    // 后台轮询间隔（毫秒）
    static final long ANTI_TAMPER_INTERVAL_MS = 2000;
    // 统一响应开关（覆盖全部检测层）：root/模拟器检测、运行时自校验（自 hook/篡改）、
    // 反调试/反注入（frida/substrate/xposed 等）、native jg_guard 端口/maps 扫描。
    // "log"=仅打印日志便于调试（默认，fail-safe，避免误杀正常设备）；
    // "exit"=确认命中即静默退出进程（生产加固可用）。所有层共用此开关，行为一致。
    // 注意：非 final —— 运行期可被 manifest meta「gx.strengthen」覆盖（加固期注入），
    // 以便同一份 stub.dex 同时支持两种姿态，无需维护两份 dex。
    static String STRENGTHEN_RESPONSE = "log";

    /**
     * P8 引导入口（替换原 attachBaseContext）。
     * 由 GxBootstrap.attachBaseContext 反射调用：完成壳自身的全部初始化
     * （loadLibrary / 反调试 / 解密原 App DEX / 注入 / 启动 realApp / swap）。
     *
     * @param base   应用 Context（来自 Bootstrap.attachBaseContext 的 base）
     * @param proxy  Bootstrap 实例（系统真正的 Application），用于 swap 替换
     * @return realApp（可能为 null，表示原 App 用默认 Application）
     */
    public static Application boot(Context base, Application proxy) {
        Application realApp = null;
        File shellDir = proxy.getDir("gxshell", Context.MODE_PRIVATE);

        // P-CAPTURE 统一响应姿态：优先从加固期注入的 manifest meta 读取（默认 log，fail-safe）。
        // 必须在 GxGuard.configureResponse() 之前设置，确保 native 守护线程拿到正确姿态。
        try {
            android.os.Bundle mb = base.getPackageManager()
                    .getApplicationInfo(base.getPackageName(),
                            android.content.pm.PackageManager.GET_META_DATA).metaData;
            if (mb != null) {
                String s = mb.getString("gx.strengthen");
                if ("exit".equals(s) || "log".equals(s)) STRENGTHEN_RESPONSE = s;
                // P0-C 内存级 anti-dump 总开关：默认开启（拦内存映射型 dump），
                // 加固期可注入 meta "gx.antidump"="0" 显式关闭（仅特殊兼容场景）。
                String ad = mb.getString("gx.antidump");
                GxAntiDump.ANTI_DUMP_ENABLED = !"0".equals(ad);
                // A·强反 Frida 总开关：默认开启（被动信号，命中经 STRENGTHEN_RESPONSE 收口），
                // 加固期可注入 meta "gx.antifrida"="0" 显式关闭。
                String af = mb.getString("gx.antifrida");
                GxAntiFrida.ANTI_FRIDA_ENABLED = !"0".equals(af);
            }
        } catch (Throwable ignored) {}

        // 必须在调用任何依赖 libjgguard.so 的 native 方法前加载该库
        // （P3 的 nativeRestoreInit / nativeRestoreMethods 与本壳反篡改都依赖它）。
        // 否则 decryptBuffers 内的 native 还原调用会抛 UnsatisfiedLinkError 被 catch 吞掉，
        // 导致 DEX 始终停在 NOP 化状态、ART 因校验和失效拒载。
        GxGuard.ensureLoaded();
        GxGuard.configureResponse();   // 把统一响应开关传给 native（在 native 守护线程启动前）
        // P0-B（2026-09-07 打穿复盘）：OpenCommon 入口预载校验——必须在 load()（解密任何
        // 业务 DEX）之前。spawn 注入的 frida hook 先于壳代码运行，此检查可发现入口跳板并
        // 直接裸 syscall 自毁（此刻业务 DEX 未解密，攻击者零收获）。详见 jg_preload.c。
        GxGuard.preloadCheck();
        // P-CAPTURE 壳通用防抓包：SSL 证书固定 + 代理/VPN 检测（配置来自加固期注入的 manifest meta）
        try { GxPinning.install(base); } catch (Throwable t) { Log.w(TAG, "ssl pinning init skipped", t); }
        // 代理/VPN 检测命中 exit 姿态即抛 SecurityException 向上传播终止进程；此处不吞掉该异常（否则等于没阻断）。
        // 默认姿态为 log，仅记日志不阻断，避免误杀正常 VPN/海外用户。
        try {
            GxProxy.check(base);
        } catch (SecurityException se) {
            throw se;   // 阻断异常必须向上传播，不能当 "skipped" 吞掉
        } catch (Throwable t) {
            Log.w(TAG, "proxy/vpn check skipped", t);
        }
        // 不再做「强制直连」（清空系统代理属性）：该动作会让依赖代理/WiFi 代理上网的设备
        // （含部分海外 VPN 用户）的 HttpsURLConnection 流量被强制直连而断网，属不可接受误伤，故移除。
        // 防抓包改以 SSL pinning（按服务器证书公钥，不关心用户是否走 VPN，故不误伤）为主手段，
        // 代理/VPN 检测仅记录日志（fail-safe），不做阻断。
        try {
            GxAntiDebug.check();
            realApp = load(base, proxy, shellDir);
        } catch (Throwable t) {
            Log.e(TAG, "init failed", t);
            if (realApp == null) {
                throw new RuntimeException("GX init failed: " + t, t);
            }
        }

        // P-DEFER：启动期反篡改/anti-dump/anti-frida 防御推迟到主线程空闲(首屏渲染后)再启动，
        // 不在「壳解密+原App初始化+静态Receiver.onReceive」冷启动窗口内与主线程抢CPU/IO。
        // 根因：②默认开 anti 起的 GxAntiFrida/GxAntiDump 守护线程在冷启动窗口抢资源，叠加 app
        // 自身首次初始化(JPush/极光等)阻塞，进程被广播(如 com.xiaomi.mipush.ERROR)冷启动唤醒时
        // onReceive 超 10s 触发 Broadcast ANR。延迟后主线程独占完成 onCreate+onReceive，恢复 <10s。
        // 功能不丢：IdleHandler 在首屏后回调一次，各防御随后自行周期轮询。
        //
        // P-MAINPROC（2026-09-03 闪屏卡死修复 A 方案）：防御只在【主进程】启动。
        // :pushcore 等子进程（无 UI、无敏感代码）跳过整套防御——子进程内 anti-frida 守护线程
        // （含已移除的 fork+PTRACE_ATTACH 自检）与 native guard/扫描徒增引导耗时并可能干扰其
        // binder 服务就绪（极光 JPush DataShare 主↔辅进程握手竞争 → 主线程同步 binder 死等 → 闪屏 ANR）。
        if (isMainProcess(base)) {
            try {
                // 壳 boot() 运行在 Application 主线程，Looper.myQueue() (API 1+) 即主线程消息队列；
                // 注意不能用 Looper.getQueue() (API 23+)，否则 min-api 21 的壳编译失败。
                android.os.Looper.myQueue().addIdleHandler(new android.os.MessageQueue.IdleHandler() {
                    @Override
                    public boolean queueIdle() {
                        startDefensesOnce(base);
                        return false; // 只执行一次
                    }
                });
            } catch (Throwable t) {
                Log.w(TAG, "defer defenses failed, fallback immediate", t);
                startDefensesOnce(base);
            }
            // F1 超时兜底（2026-09-04 frida spawn 实测）：bare spawn（无 Activity 首屏）时主线程
            // 消息队列长期不空闲，IdleHandler 迟迟不回调 → 防御晚启动约 60s（攻击窗口）。
            // 看门狗线程 4s 后仍未启动则强制启动；startDefensesOnce 幂等，双路径安全。
            Thread f1 = new Thread(new Runnable() {
                @Override public void run() {
                    try { Thread.sleep(4000); } catch (InterruptedException e) { return; }
                    if (sDefensesStarted.compareAndSet(false, true)) {
                        Log.w(TAG, "F1 watchdog: defenses not started in 4s, forcing start");
                        startDefenses(base);
                    }
                }
            }, "gx-defenses-watchdog");
            f1.setDaemon(true);
            f1.start();
        } else {
            Log.i(TAG, "non-main process: deferred defenses skipped (isMainProcess=false)");
        }

        // 返回 realApp 给 Bootstrap 做生命周期转发（可能为 null）
        return realApp;
    }

    /** F1 幂等闸：IdleHandler 与看门狗线程双路径，防御只启动一次。 */
    private static final java.util.concurrent.atomic.AtomicBoolean sDefensesStarted =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    /** F1：CAS 抢占式启动，IdleHandler 与看门狗双路径只允许一次真正启动。 */
    private static void startDefensesOnce(Context base) {
        if (sDefensesStarted.compareAndSet(false, true)) {
            startDefenses(base);
        }
    }

    /**
     * 启动期防御集合（反篡改/anti-dump/anti-frida/native guard/env+完整性扫描）。
     * 由 boot() 经主线程 IdleHandler 推迟到首屏后调用，避免在冷启动窗口抢主线程导致 Broadcast ANR。
     */
    private static void startDefenses(Context base) {
        // P0-0904 持久 self-ptrace 防护（对比报告 P0）：必须先于其余防御上线。
        // 后台线程执行（fork+全线程 attach+握手最长 3s，不占主线程）；失败降级不影响启动。
        // 随后 anti-frida / native guard 的 TracerPid 检测会自动放行自己的守护子进程。
        if (PTRACE_GUARD_ENABLED) {
            new Thread(new Runnable() {
                @Override public void run() {
                    try {
                        GxGuard.ptraceGuardStart();
                    } catch (Throwable t) {
                        Log.w(TAG, "ptrace guard start skipped", t);
                    }
                }
            }, "gx-ptrace-guard").start();
        }

        // 启动反篡改后台守护线程：与加载器完全隔离，异常不向外传播，绝不导致 App 闪退
        if (ANTI_TAMPER_ENABLED) {
            try {
                GxTamper.start();
            } catch (Throwable t) {
                Log.w(TAG, "anti-tamper start skipped", t);
            }
        }

        // P-ANTIDUMP 反内存 dump（检测层）：独立守护线程，启动即查 + 周期轮询，
        // 检测 FART/Youpk/BlackDex 等脱壳工具的 dump 产物路径；异常全吞，不影响启动。
        try {
            GxAntiDump.start(base);
        } catch (Throwable t) {
            Log.w(TAG, "anti-dump start skipped", t);
        }
        // A·强反 Frida（检测层）：独立守护线程，启动即查 + 周期轮询，命中经 STRENGTHEN_RESPONSE 收口。
        // 默认 ANTI_FRIDA_ENABLED=false 时 start() 直接返回，不浪费线程/扫描（满足「默认关」铁律）。
        try {
            GxAntiFrida.start(base);
        } catch (Throwable t) {
            Log.w(TAG, "anti-frida start skipped", t);
        }

        // 启动 native 反篡改守护线程（下沉到 .so，更难被 hook；与 Java 层互为备份）。
        // 加载/调用全程已 try-catch，失败仅跳过 native 防护，不影响 App 启动。
        try {
            GxGuard.start();
        } catch (Throwable t) {
            Log.w(TAG, "native guard start skipped", t);
        }

        // 补强：环境检测（root/模拟器）+ 运行时自校验（自 hook/篡改）。fail-safe，
        // 任何异常仅记日志、不影响启动；默认响应为「记录」而非退出，避免误杀正常设备。
        try {
            GxGuard.envCheck();
        } catch (Throwable t) {
            Log.w(TAG, "envCheck skipped", t);
        }
        try {
            GxGuard.integrityScan();
        } catch (Throwable t) {
            Log.w(TAG, "integrityScan skipped", t);
        }

        // P3.4 空闲擦除调度（抗内存 dump「即用即擦」）：仅主进程 + 解释桥 hook 生效 + 开关开时启动。
        // 主线程 Handler 周期轮询；每次扫描把「空闲 > METHOD_RESTORE_IDLE_MS」的已还原方法 NOP 擦除，
        // 被擦方法下次执行由解释桥 hook 重新单方法还原（O(1)）。热方法保留明文避免高频解密开销。
        // 若 hook 未生效（sHookActive=false，回退批量模式）绝不启动——否则被擦方法无 hook 还原会崩。
        if (GxDecryptor.METHOD_RESTORE_ENABLED && GxDecryptor.METHOD_RESTORE_ERASE
                && GxDecryptor.sHookActive) {
            try {
                final android.os.Handler sweepHandler =
                        new android.os.Handler(android.os.Looper.getMainLooper());
                final int idle = GxDecryptor.METHOD_RESTORE_IDLE_MS;
                final Runnable sweep = new Runnable() {
                    @Override public void run() {
                        try {
                            GxDecryptor.nativeReencryptSweep(idle);
                        } catch (Throwable t) {
                            Log.w(TAG, "method sweep tick skipped", t);
                        }
                        sweepHandler.postDelayed(this, idle / 2);
                    }
                };
                sweepHandler.postDelayed(sweep, idle);
                Log.i(TAG, "P3.4 idle erase scheduled (idleMs=" + idle + ")");
            } catch (Throwable t) {
                Log.w(TAG, "P3.4 idle erase schedule skipped", t);
            }
        }
    }

    /** 是否主进程（processName==包名）。:pushcore 等子进程返回 false。
     *  用于跳过仅主进程需要的启动期重活（防御套件/完整性校验）。判定失败保守按主进程处理。 */
    static boolean isMainProcess(Context ctx) {
        try {
            String pn = ctx.getApplicationInfo().processName;
            return pn == null || pn.equals(ctx.getPackageName());
        } catch (Throwable t) {
            return true;
        }
    }

    private static Application load(Context base, Application proxy, File shellDir) throws Exception {
        String origApp = readMeta(base, META_ORIG);
        // 相对类名（以 '.' 开头）需拼接包名，与 PackageParser.buildClassName 一致；
        // 否则 Class.forName(".App4") 抛 "Invalid name" 导致壳启动崩溃。
        if (origApp != null && origApp.startsWith(".")) {
            origApp = base.getPackageName() + origApp;
        }
        File dexDir = new File(shellDir, "dex");
        if (!dexDir.exists()) dexDir.mkdirs();

        // 注入目标 = App 自身 ClassLoader（base.getClassLoader()），而非框架/system classloader。
        // 类加载域正确性修复：用 App 自身 classloader（含 nativeLib 路径、app 域隐藏 API 豁免）
        // 而非框架 classloader 注入/定义原 App DEX，可同时恢复 native lib 可达性与隐藏 API 豁免，
        // 避免类加载器分裂导致原 App 原生线程 FindClass/GetFieldID 拿不到类。
        // 注：华为 A10 的 0xa01 SIGBUS 与此无关——BISIM 二分已证实其根因在 ylyk 自带的
        //     libSecShell.so（DEX 完整性校验在加固后的新布局下失效），JGShield 壳 so 在 tombstone 出现 0 次。
        ClassLoader appLoader = base.getClassLoader();

        // P2：fileless 内存加载（API>=26）。解密进 ByteBuffer 直接注入 App 自身 ClassLoader，
        // 磁盘不落明文文件；解密后源 byte[] 立即清零。失败不再回退明文落盘方案（P0-a）。
        // P0-a（0908）：关闭"明文 dex 落盘"泄漏口（逆向报告证实 API<26 + fileless 异常静默
        // 回退会把解密正文明文写到 app_gxshell/dex/ 并持久保留，root 一条 adb pull 即拿走）。
        //  - API>=26：内存加载（decryptBuffers + InMemoryDexClassLoader），磁盘绝不落明文；
        //    失败不再静默回退到明文落盘方案——宁可启动失败也绝不泄露明文 dex。
        //  - API<26：无 InMemoryDexClassLoader，DEX 借 cache 临时文件加载，加载完成后立即
        //    unlink 源码与 odex（目录项消失，"adb pull 固定路径"攻击失效）。root 经
        //    /proc/pid/fd 仍可读已删除 inode，属物理边界（与 memfd 同级）。
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            List<ByteBuffer> bufs = GxDecryptor.decryptBuffers(base);
            GxLoader.injectDexFromBuffers(appLoader, bufs);
            Log.i(TAG, "load: fileless inject OK (no plaintext on disk)");
        } else {
            List<ByteBuffer> bufs = GxDecryptor.decryptBuffers(base);
            GxLoader.injectDexFromTemp(appLoader, bufs, base);
            Log.i(TAG, "load: temp-file inject OK (source+odex unlinked after load)");
        }
        Log.i(TAG, "load: injectDexElements OK");

        restoreAssets(base);  // 自包含 try-catch，失败仅记日志、不影响启动

        GxLoader.setClassLoader(base, appLoader);

        Log.i(TAG, "load: origApp=" + origApp);
        Application realApp = null;
        if (origApp != null && !origApp.isEmpty()
                && !origApp.equals(Application.class.getName())
                && !origApp.equals(GxApp.class.getName())) {
            Class<?> cls = Class.forName(origApp, true, appLoader);
            realApp = (Application) cls.newInstance();
            Log.i(TAG, "load: realApp=" + realApp.getClass().getName());

            GxLoader.swap(proxy, realApp);
            Log.i(TAG, "load: swap OK");

            Method attach = Application.class.getDeclaredMethod("attach", Context.class);
            attach.setAccessible(true);
            attach.invoke(realApp, base);
            Log.i(TAG, "load: attach OK");

            // 同步调用 realApp.onCreate()——不依赖系统 callApplicationOnCreate（EMUI 可能跳过）
            try {
                realApp.onCreate();
                Log.i(TAG, "load: realApp.onCreate() OK");
            } catch (Throwable t) {
                Log.e(TAG, "load: realApp.onCreate() FAILED", t);
            }
        }
        return realApp;
    }

    private static String readMeta(Context ctx, String key) {
        try {
            ApplicationInfo ai = ctx.getPackageManager().getApplicationInfo(
                    ctx.getPackageName(), PackageManager.GET_META_DATA);
            if (ai.metaData != null && ai.metaData.containsKey(key)) {
                return ai.metaData.getString(key);
            }
        } catch (Exception e) {
            Log.w(TAG, "readMeta", e);
        }
        return null;
    }

    // ===== 资产运行时还原（关闭 APK 内 assets 明文）=====
    // 自包含：任何异常都只记日志、绝不外抛，避免影响 App 启动。
    // 解密后的 assets 写入应用私有目录的 zip（非公开可读），仅关闭 APK 内明文泄漏。
    private static void restoreAssets(Context base) {
        try {
            File zip = new File(base.getCacheDir(), "gx_assets.zip");
            String zipPath = GxAssets.restore(base, zip);
            if (zipPath == null) return;
            android.content.res.AssetManager am = mergeAssetManager(base, zipPath);
            if (am != null) {
                replaceAssetManager(base, am);
                Log.i(TAG, "restoreAssets: merged AssetManager OK");
            } else {
                Log.e(TAG, "restoreAssets: merge returned null —— assets 缺失！"
                        + "本 ROM/版本可能因隐藏 API 限制导致还原失败，"
                        + "请去掉 --assets-encrypt 重新加固", null);
            }
        } catch (Throwable t) {
            Log.e(TAG, "restoreAssets: FAILED (assets 可能缺失)，"
                    + "去掉 --assets-encrypt 重新加固即可恢复", t);
        }
    }

    private static android.content.res.AssetManager mergeAssetManager(Context base, String extraPath) {
        try {
            bypassHiddenApi();
            Class<?> amClass = Class.forName("android.content.res.AssetManager");
            String src = base.getApplicationInfo().sourceDir;
            // 优先：隐藏构造器 AssetManager(String[]) 一次性注入全部路径（调用更短、部分 ROM 更稳）
            try {
                Constructor<?> ctor = amClass.getDeclaredConstructor(String[].class);
                ctor.setAccessible(true);
                return (android.content.res.AssetManager) ctor.newInstance(
                        (Object) new String[]{src, extraPath});
            } catch (Throwable t1) {
                Log.w(TAG, "mergeAssetManager: AssetManager(String[]) 不可用，回退 addAssetPath", t1);
            }
            // 回退：无参构造 + addAssetPath
            android.content.res.AssetManager am =
                (android.content.res.AssetManager) amClass.getDeclaredConstructor().newInstance();
            Method add = am.getClass().getDeclaredMethod("addAssetPath", String.class);
            add.setAccessible(true);
            add.invoke(am, src);       // 原 APK（assets 已剥离）
            add.invoke(am, extraPath); // 解密后的 assets zip
            return am;
        } catch (Throwable t) {
            Log.e(TAG, "mergeAssetManager failed (hidden API 可能被本 ROM 限制)", t);
            return null;
        }
    }

    private static void replaceAssetManager(Context base, android.content.res.AssetManager am) {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object thread = at.getMethod("currentActivityThread").invoke(null);
            Field fPkgs = at.getDeclaredField("mPackages");
            fPkgs.setAccessible(true);
            Object pkgs = fPkgs.get(thread);
            for (Object ref : ((Map<?, WeakReference<?>>) pkgs).values()) {
                Object loadedApk = ((WeakReference<?>) ref).get();
                if (loadedApk != null) {
                    try {
                        Field f = loadedApk.getClass().getDeclaredField("mAssets");
                        f.setAccessible(true);
                        f.set(loadedApk, am);
                    } catch (Throwable ignored) {}
                    try {
                        Field fRes = loadedApk.getClass().getDeclaredField("mResources");
                        fRes.setAccessible(true);
                        Object resMap = fRes.get(loadedApk);
                        if (resMap instanceof Map) {
                            for (Object wr : ((Map<?, ?>) resMap).values()) {
                                Object res = (wr instanceof WeakReference) ? ((WeakReference<?>) wr).get() : wr;
                                if (res != null) {
                                    try {
                                        Field fa = res.getClass().getDeclaredField("mAssets");
                                        fa.setAccessible(true);
                                        fa.set(res, am);
                                    } catch (Throwable ignored) {}
                                }
                            }
                        }
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "replaceAssetManager failed", t);
        }
    }

    private static void bypassHiddenApi() {
        try {
            Method forName = Class.class.getDeclaredMethod("forName", String.class);
            Method getDeclaredMethod = Class.class.getDeclaredMethod("getDeclaredMethod", String.class, Class[].class);
            Class<?> vmRuntimeClass = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
            Method getRuntime = (Method) getDeclaredMethod.invoke(vmRuntimeClass, "getRuntime", (Object) null);
            Object vmRuntime = getRuntime.invoke(null);
            Method setHiddenApiExemptions = vmRuntimeClass.getDeclaredMethod("setHiddenApiExemptions", String[].class);
            setHiddenApiExemptions.invoke(vmRuntime, (Object) new String[]{"L"});
        } catch (Throwable ignored) {}
    }

    // ===== 生命周期转发：由 GxBootstrap 持有 realApp 并转发，GxApp 不再 override =====
}

/** 解密 + 解压原始 DEX 区段 */
class GxDecryptor {
    /** 方法级指令还原总开关（P3）。
     *  默认关闭。开启需先重编 libjgguard.so（含 jg_method_restore*.c / jg_inline_hook*），
     *  且仅在真机验证通过后使用。 */
    static final boolean METHOD_RESTORE_ENABLED = true;

    /** P3.4 空闲擦除总开关（抗内存 dump 的「即用即擦」）。
     *  开启需先重编 libjgguard.so（含 jg_method_restore*.c / jg_inline_hook*）。
     *  仅当解释桥 hook 成功安装（nativeRestoreInit 返回 1）时才真正擦除；
     *  若 hook 不可用（回退批量模式），绝不擦除——否则被擦方法无 hook 还原会崩。
     *
     *  ⚠ 2026-09-04 真机实测（MIX2 A9, ylyk 5.9.4）：空闲擦除会崩——根因是 jg_method_restore_hook.c
     *    的 nativeReencryptSweep 把「空闲判定」放在锁外（TOCTOU），导致「刚好被解释执行的方法」
     *    因读到陈旧 last_call 被判空闲、在 Mterp 正读其指令流时被 memset 清零 -> SIGSEGV
     *    （崩溃栈: glide-source-th + MterpInvoke* -> ExecuteMterpImpl）。
     *  ⚠ 2026-09-08 曾据「把空闲判定移入 g_lock 临界区」宣称已修根因，并把本开关改成 true；
     *    2026-09-10 真机复核证明【该修复不充分，属假阴性】（见下）——同一类崩溃仍在 Glide 线程复现。
     *
     *  ❌ 2026-09-10 真机实测结论（MIX2 A9, ylyk 5.9.4，冷启动 6 组）：
     *     ERASE=true 时，App 在首次 sweep（METHOD_RESTORE_IDLE_MS=10s）之后短窗口内**间歇性崩溃**，
     *     tombstone: `signal 11 (SIGSEGV) code 0 (SI_USER)`，崩于 glide-disk-cach 线程，
     *     pc/lr 落在 32MB 匿名可执行区 <anonymous:9f684000>（运行期即时编译代码）；
     *     对照组：①未加固原包 6/6 全绿 ⇒ 崩溃由加固引入；②关闭 ptrace 守护后仍复现 ⇒ 与守护无关。
     *     锁内判定只挡住「同一时刻正被解释执行」这一种竞态，挡不住"方法体被 memset 成 NOP 后，
     *     后续按需重解释 / deopt / 重新编译再读该指令流"读到的是被改写的字节——此时执行的是垃圾。
     *     （SI_USER 是 ART fault manager 判定无法处理后自行重发信号所致，会掩盖原始 fault addr。）
     *  ⇒ 修复（按既有铁律）：空闲擦除默认关闭，改为就地保留明文，走纯 P3.2 批量还原（生产稳健路径）。
     *     即 "不能容忍偶发崩溃" 优先于 "即用即擦" 的额外抗 dump 收益。 */
    static final boolean METHOD_RESTORE_ERASE = false;

    /** P3 解释桥 inline hook 总开关（2026-09-10 新增，同日修复根因后置回 true）。
     *  true  = P3.4：hook libart 解释桥，按方法粒度按需还原（激进，需改 libart 代码字节）。
     *  false = P3.2：纯整包批量还原，加载期一次性写回全部方法体，不改 libart 任何字节。
     *
     *  2026-09-10 根因已定位并修复：此前残留的间歇崩溃（SI_USER SIGSEGV，pc 落在 JIT 区，
     *  崩溃线程每次不同的主线程 / glide-source-th / glide-disk-cach）**不是** TOCTOU、
     *  也**不是** 擦除竞态，而是 jg_hook_bridge.S **未保存/恢复 x30(LR)** 的纯 ABI bug：
     *  被 hook 的 ArtInterpreterToInterpreterBridge 是在【函数体内】(stp x29,x30,[sp,#112])
     *  才把返回地址落栈，而桥内 `blr` 调 handler 时会覆盖 x30 -> 该 stp 存下桥内地址 ->
     *  函数 ret 跳回桥中间、此时桥帧已撤销 -> 寄存器与 SP 全面损坏。详见 jg_hook_bridge.S 头注。
     *  铁证：崩溃构建日志为 "collected 0 extracted method entries" + "ACTIVE (0 entries indexed)"
     *  —— 即 handler 全程走早退分支、几乎无逻辑执行，却仍 3/8 崩，故与 handler 无关。
     *  另：native 侧新增闸门——载荷无抽取方法时直接跳过 hook（无对象可惰性还原，装它纯负收益），
     *  故本开关即使误置 true，默认(未开 --method-extract)构建也不会去改 libart，双重保险。
     *  ⚠ 2026-09-10 结论：默认关闭。x30 修复解决了 hook 自身在【默认构建】下的间歇崩溃，
     *  但实测开启 --method-extract（抽取 185752 方法）后，无论 hook 开关，
     *  仍出现两类独立崩溃（bootShell 反射期 Java AIOOBE「执行到被破坏代码」+
     *  ART FaultManager 在 FindOatMethodFor 解析 NULL ArtMethod 时二次崩），
     *  属抽取链路自身缺陷，未修好前不启用 hook。 */
    static final boolean METHOD_RESTORE_ONCALL_HOOK = false;

    /** 空闲擦除阈值（毫秒）：仅当 METHOD_RESTORE_ERASE=true 生效。
     *  ⚠ ERASE 默认关（见上，真机擦除会崩），故本值当前 inert，保留供 opt-in 时使用。
     *  语义：方法体「最近一次执行距今 > 此值」才 NOP 擦除；热方法保留明文。 */
    static final int METHOD_RESTORE_IDLE_MS = 10000;

    /** 运行期标记：nativeRestoreInit 是否成功安装解释桥 hook（=1）。
     *  驱动空闲擦除调度（仅 hook 生效时才擦，确保擦后有按需还原兜底）。 */
    static volatile boolean sHookActive = false;

    /** P3.4 还原模式（已统一）：
     *  加载期 nativeRestoreInit 总是「批量还原本 DEX」——在 ART DefineClass 校验前把全部方法
     *  写回明文，规避 Android 9 等急切校验 ROM 的 VerifyError（NOP 化方法体无终结指令）。
     *  同时安装解释桥 inline hook：方法被解释执行前若已被空闲擦除(restored==0)，hook 会
     *  O(1) 单方法解密写回（per-method 密钥 JG|m{dex}.{method}），实现「即用即擦」。
     *  ⚠ Android 9 急切校验限制（2026-08-17 MIX2 A9 实测）：真「惰性还原」与急切校验架构
     *    不兼容——校验早于解释执行，hook 永不触发会崩。故加载期必须批量还原保校验（P3.4 已
     *    如此），hook 仅负责「擦除后的按需再还原」，与急切校验不冲突。
     *  METHOD_RESTORE_LAZY 保留为 A10+ 实验开关（true=加载期不批量、纯 hook 还原），
     *    生产默认 false。P3.4 生产路径：加载批量 + hook 按需 + 空闲擦除。 */
    static final boolean METHOD_RESTORE_LAZY = false;

    /** P3.2 JNI 入口：把 NOP 版 DEX 直接缓冲区整体解密写回（批量，安全默认路径，仍可用作回退）。 */
    public static native int nativeRestoreMethods(java.nio.ByteBuffer dexBuf, byte[] payload, byte[] seed, int dexIdx);

    /** P3.4 JNI 入口：注册 DEX 内存区间 + 加载期批量还原本 DEX（保 A9 校验）+ 尝试安装
     *  解释桥 inline hook（按需再还原）。返回 1=解释桥 hook 生效（可安全空闲擦除）;
     *  0=hook 不可用已回退批量还原（不擦除，避免崩）。 */
    public static native int nativeRestoreInit(int dexIdx, java.nio.ByteBuffer dexBuf, byte[] payload, byte[] seed);

    /** P3.4 JNI 入口：空闲擦除扫描——把「最近执行距今 > idleMs」的已还原方法 NOP 擦除，
     *  返回本次擦除方法数。仅当 nativeRestoreInit 返回 1（hook 生效）时由 Java 周期调用；
     *  被擦方法下次执行由 hook 重新单方法还原，实现即用即擦。fail-safe：异常仅返回 0。 */
    public static native int nativeReencryptSweep(int idleMs);

    /** P-INTEGRITY JNI 入口：还原后自校验——逐方法解密载荷并与内存 live dex 比对，
     *  返回不匹配方法数（0 表示还原正确 / 未被篡改）。maxPerDex>0 抽样（启动期用），-1 全量。
     *  fail-safe：错误返回负值。 */
    public static native int nativeVerifyDex(java.nio.ByteBuffer dexBuf, byte[] payload, byte[] seed, int dexIdx, int maxPerDex);

    /** P0-0904 JNI 入口：把全部已注册 dex 的 header 身份字段（magic 8B/checksum 4B/
     *  file_size 4B）就地打乱——ART open/verify 已完成，运行期不再读这三个字段；
     *  任何 magic 扫描型 dump 脚本立即 0 命中。必须在 InMemoryDexClassLoader 构造
     *  成功之后调用（open 前打乱会导致 open 失败）。返回打乱的 dex 数。fail-safe。
     *  deep=true（仅注入期）：附加 string_ids 随机重排 + map_list 擦除（v3 去结构化，
     *  对抗 0904 报告的「string_ids 结构指纹扫描重建」手法）；deep=false（周期重扫）：
     *  仅 header 全擦，不碰 data（防与运行期 ART 并发撕裂）。 */
    public static native int nativeScrambleDexHeaders(boolean deep);

    /** 2026-09-10 修复（根因兜底）：fixDexChecksum 要向 direct ByteBuffer 写回 DEX 头
     *  校验和/签名，但真机实测该缓冲首页在某些 ROM/ART 下被映射成 r-x（不可写），
     *  直接 put 即 SEGV_ACCERR(0x802f4000)。本调用在写回前把整段缓冲强制 mprotect 成
     *  RW（DEX 是数据，CPU 不执行其字节，ART 运行期还要 quicken 改写，故 RW 安全且必需）。
     *  即便上游（ART / allocateDirect）把页置成 r-x，此处也保证可写，根除偶发崩溃。
     *  fail-safe：异常/失败仅记日志，不阻断启动。 */
    public static native void nativeEnsureDexWritable(java.nio.ByteBuffer dexBuf);

    /** 2026-09-10 真正的根因修复：在【所有】fixDexChecksum 之前，把【全部】已注册 DEX 区间的
     *  并集一次性扫.maps 强制 mprotect 为 RW。
     *  为什么不能只靠逐缓冲的 nativeEnsureDexWritable：4 个 dex 缓冲落在同一巨型匿名区内，
     *  其中存在被 ROM/ART 映射成 r-x 的孤立页（实测 0x802f4000）。该页落在 dex0 自己的地址范围
     *  [0x81ab2000,0x82424000) 之外、但落在另一 dex 缓冲的范围内。decryptBuffers 是逐个处理的
     *  for 循环，dex0 的 fixDexChecksum（整段连续 buf.get -> peekByteArray -> memcpy，会跨页访问）
     *  会先撞上这张还没轮到被保护的页 -> 顺序缺口导致偶发 SEGV_ACCERR。
     *  故必须在循环之前对【并集】统一兜底，与顺序解耦。
     *  fail-safe：异常/失败仅记日志，不阻断启动。 */
    public static native void nativeEnsureAllDexWritable();

    /** 2026-09-10 根因修复：在 native 侧直接于 direct ByteBuffer 内存上重算 DEX 头的
     *  checksum(偏移8, adler32) 与 signature(偏移12, sha1)，返回是否成功。
     *  取代原 Java 实现（后者需 new 两个 ~9MB byte[]，其整段写入会撞上 ART 大对象空间里
     *  那张异常的 r-x 页 0x802f4000 -> 偶发 SEGV_ACCERR）。详见 fixDexChecksum 注释。
     *  彻底不再依赖 Java 堆大数组，故与该崩溃路径解耦。 */
    /** 2026-09-10：解释桥 inline hook 的 native 开关。false => 纯 P3.2 批量还原，
     *  完全不改写 libart 任何字节（规避跳板/trampoline 相关的间歇崩溃）。 */
    public static native void nativeSetHookEnabled(boolean enabled);

    public static native boolean nativeFixDexChecksum(java.nio.ByteBuffer dexBuf);


    static List<File> decrypt(Context ctx, File dexDir) throws Exception {
        // 多进程竞态防护：主进程与 :pushcore 等子进程共用同一 dexDir。
        // 先完成的进程写出 DEX 文件，后续进程直接复用，避免并发写导致
        // PathClassLoader mmap 半成品 DEX → DexFileVerifier SIGBUS。
        File[] existing = dexDir.listFiles(
                (dir, name) -> name.matches("c\\d+\\.dex") && new File(dir, name).length() > 0);
        if (existing != null && existing.length > 0) {
            Arrays.sort(existing, (a, b) -> a.getName().compareTo(b.getName()));
            return Arrays.asList(existing);
        }

        // 清理上次崩溃可能残留的 .tmp 文件
        File[] tmps = dexDir.listFiles((dir, name) -> name.endsWith(".dex.tmp"));
        if (tmps != null) for (File t : tmps) t.delete();

        List<File> out = new ArrayList<>();
        String apk = ctx.getApplicationInfo().sourceDir;
        byte[] payload = readPayload(apk);
        if (payload == null || payload.length < 8) {
            throw new IllegalStateException("payload missing");
        }
        // 先读载荷取 per-build salt，再 HKDF-Extract 派生 seed（证书绑定 + 抗跨构建 diff）
        byte[] seed = GxKeys.seed(ctx, GxKeys.extractSalt(payload));
        int p = 0;
        for (int i = 0; i < 4; i++) {
            if (payload[p] != (byte) GxApp.MAGIC.charAt(i)) {
                throw new IllegalStateException("bad magic");
            }
            p++;
        }
        int count = readInt(payload, p);
        p += 4;
        for (int i = 0; i < count; i++) {
            int len = readInt(payload, p);
            p += 4;
            byte[] blob = Arrays.copyOfRange(payload, p, p + len);
            p += len;
            byte[] key = GxKeys.keyFor(seed, "dex" + i);
            byte[] comp = aesGcmDecrypt(key, blob);
            byte[] dex = inflate(comp);
            // P3 方法抽取还原 + DEX 头校验和重算（与 ≥26 decryptBuffers 路径完全一致）。
            // 抽取后方法指令被 NOP 化，落盘路径若不经此步写回原指令并修 header 校验和，
            // dex2oat 会因 Bad checksum 拒载（fileless 内存路径由 ART 拷贝前已修好，落盘路径必须落盘前修好）。
            // 使用 direct buffer 与 ≥26 路径一致，确保 native 还原调用行为相同。
            ByteBuffer buf = ByteBuffer.allocateDirect(dex.length);
            buf.put(dex);
            buf.position(0);
            if (METHOD_RESTORE_ENABLED) {
                try {
                    int realMode = nativeRestoreInit(i, buf, payload, seed);
                    if (realMode == 1) sHookActive = true;
                    buf.position(0);
                    Log.i("GX", "method restore effective mode="
                            + (realMode == 1 ? "batch+on-call-hook ACTIVE(P3.4)"
                                : "batch FALLBACK(P3.2), erase disabled")
                            + " on dex[" + i + "] (file path <26)");
                } catch (Throwable t) {
                    Log.w("GX", "method restore skipped dex[" + i + "] (file path <26)", t);
                }
                // 2026-09-11 冷启动优化：同上，头已自洽则跳过 30MB 级 SHA-1 重算。
                try {
                    if (!dexHeaderConsistent(buf)) fixDexChecksum(buf);
                } catch (Throwable t) {
                    Log.w("GX", "fixDexChecksum skipped dex[" + i + "] (file path <26)", t);
                }
                // P-INTEGRITY：还原后自校验（抽样），fail-safe。仅在主进程执行
                // （P-MAINPROC：子进程跳过，缩短引导；还原本身仍需，故在校验外层判断）。
                if (GxApp.isMainProcess(ctx)) {
                    try {
                        int mism = nativeVerifyDex(buf, payload, seed, i, 64);
                        Log.i("GX", "integrity dex_idx=" + i + " mismatches=" + mism + " (file path <26)");
                    } catch (Throwable t) {
                        Log.w("GX", "integrity check skipped dex[" + i + "] (file path <26)", t);
                    }
                }
            }
            // 取回修正后的字节落盘：先写 .tmp，flush+close 后 rename 为 .dex，
            // 确保其他进程 mmap 时文件已完整。
            byte[] outBytes = new byte[buf.capacity()];
            buf.position(0);
            buf.get(outBytes);
            File f = new File(dexDir, "c" + i + ".dex");
            writeFileAtomic(f, outBytes);
            out.add(f);
        }
        return out;
    }

    /**
     * P2：fileless 解密。与 decrypt() 相同解密流程，但明文 DEX 不落盘，
     * 直接写入直接 ByteBuffer（ART 在构造 DexFile 时会拷贝进自身内存），
     * 随后把源 byte[] 清零。返回的 ByteBuffer 由 GxLoader 注入 sysLoader 后整体弃用。
     *
     * 安全性边界：DEX 被 ART 加载运行后，优化代码仍存在于进程内存，无法仅靠此步
     * 做到 100% 防内存 dump（那需要 native 指令抽取，属 P3）。本步关闭的是
     * “磁盘明文文件 + 启动期整段明文大块”两个泄漏点。
     */
    static List<ByteBuffer> decryptBuffers(Context ctx) throws Exception {
        String apk = ctx.getApplicationInfo().sourceDir;
        byte[] payload = readPayload(apk);
        if (payload == null || payload.length < 8) {
            throw new IllegalStateException("payload missing");
        }
        // 先读载荷取 per-build salt，再 HKDF-Extract 派生 seed
        byte[] seed = GxKeys.seed(ctx, GxKeys.extractSalt(payload));
        int p = 0;
        for (int i = 0; i < 4; i++) {
            if (payload[p] != (byte) GxApp.MAGIC.charAt(i)) {
                throw new IllegalStateException("bad magic");
            }
            p++;
        }
        int count = readInt(payload, p);
        p += 4;
        List<ByteBuffer> out = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int len = readInt(payload, p);
            p += 4;
            byte[] blob = Arrays.copyOfRange(payload, p, p + len);
            p += len;
            byte[] key = GxKeys.keyFor(seed, "dex" + i);
            byte[] comp = aesGcmDecrypt(key, blob);
            byte[] dex = inflate(comp);
            // 直接缓冲区：ART 的 DexFile(ByteBuffer) 要求 direct buffer
            ByteBuffer buf = ByteBuffer.allocateDirect(dex.length);
            buf.put(dex);
            buf.position(0);
            // 源明文立即清零（缓冲区随后由 ART 拷贝，加载后可被 GC 回收）
            Arrays.fill(dex, (byte) 0);
            // P0-C：登记本段直接缓冲区的真实内存基址，供 anti-dump 内存扫描排除「自己的 DEX」，
            // 避免扫描命中自有 InMemoryDexClassLoader DEX 导致自爆（best-effort，取不到基址则不排除）。
            GxAntiDump.addSelfDex(directAddress(buf), dex.length);
            out.add(buf);
        }
        // P3 方法还原接入点（受 METHOD_RESTORE_ENABLED 总开关控制，fail-safe）。
        // P3.4：加载期 nativeRestoreInit 总是批量还原（保 A9 校验）+ 安装解释桥 hook（按需再还原）。
        if (METHOD_RESTORE_ENABLED) {
            try {
                // 2026-09-10：hook 总开关先下发 native，必须在首次 nativeRestoreInit 之前生效。
                GxDecryptor.nativeSetHookEnabled(METHOD_RESTORE_ONCALL_HOOK);
                int realMode = 0;   /* native 返回：1=解释桥 hook 生效(P3.4); 0=回退批量(P3.2) */
                for (int i = 0; i < out.size(); i++) {
                    ByteBuffer buf = out.get(i);
                    buf.position(0);
                    realMode = nativeRestoreInit(i, buf, payload, seed);
                    if (realMode == 1) sHookActive = true;
                    buf.position(0);
                }
                String mode = realMode == 1 ? "batch+on-call-hook ACTIVE(P3.4)"
                        : "batch FALLBACK(P3.2), erase disabled";
                Log.i("GX", "method restore effective mode=" + mode + " on " + out.size() + " dex buffer(s)");
            } catch (Throwable t) {
                Log.w("GX", "method restore skipped", t);
            }
            // P3 抽取后 DEX 指令被 NOP 化，但加固期未重算 DEX 头校验和，ART 加载会因
            // Bad checksum 拒载。此处按当前缓冲区内容重算 checksum(偏移8, adler32[12:])
            // 与 signature(偏移12, sha1[32:])，使 NOP 化 DEX 可通过加载期校验。
            // P3.2 整包还原写回原指令后同样需重算以匹配还原后的内容。
            // 2026-09-10 根因修复：必须在逐个 fixDexChecksum【之前】，先把全部 DEX 区间的并集
            // 统一扫 maps 强制 RW。逐缓冲保护存在顺序缺口（dex0 会先访问到另一 dex 缓冲地址
            // 范围内那张孤立的 r-x 页 -> 0x802f4000 SEGV_ACCERR），详见 nativeEnsureAllDexWritable。
            try { GxDecryptor.nativeEnsureAllDexWritable(); } catch (Throwable t) { /* best-effort */ }
            // 2026-09-11 冷启动优化（MIX2 实测：这段 2878ms -> 数十 ms，占冷启动 51%）：
            // fixDexChecksum 的本职是「P3 方法抽取把指令 NOP 化后重算头」。但方法抽取默认关
            // （载荷方法区段=0）时，进内存的 DEX 与原始字节完全一致、头本来就自洽 —— 此时整段
            // SHA-1(30MB) 只是把相同的值又写回去，纯空转（且 OLLVM -fla/-bcf 会把该热循环劣化
            // 到 ~11MB/s，30MB 要 2.8s）。改为先用 adler32 单遍自检头是否已自洽：一致则跳过，
            // 不一致（真被 NOP 化/构建期改过字节）才走原 SHA-1 重算 —— 语义与旧版完全等价。
            int hdrSkipped = 0;
            for (int i = 0; i < out.size(); i++) {
                if (dexHeaderConsistent(out.get(i))) { hdrSkipped++; continue; }
                fixDexChecksum(out.get(i));
            }
            if (hdrSkipped > 0) {
                Log.i("GX", "dex header already consistent -> skipped SHA-1 recompute on "
                        + hdrSkipped + "/" + out.size() + " dex");
            }
            // P-INTEGRITY：DEX 还原后自校验——抽样解密载荷并与内存 live dex 比对，
            // 不匹配数 >0 表示还原失败或已被篡改。采样上限控制主线程耗时，避免启动期 ANR。
            // fail-safe：异常仅记日志不阻断启动。仅在主进程执行（P-MAINPROC：子进程跳过）。
            if (GxApp.isMainProcess(ctx)) {
                for (int i = 0; i < out.size(); i++) {
                    try {
                        int mism = nativeVerifyDex(out.get(i), payload, seed, i, 64);
                        Log.i("GX", "integrity dex_idx=" + i + " mismatches=" + mism);
                    } catch (Throwable t) {
                        Log.w("GX", "integrity check skipped dex " + i, t);
                    }
                }
            } else {
                Log.i("GX", "non-main process: integrity verify skipped (" + out.size() + " dex)");
            }
        }
        return out;
    }

    /** best-effort 取 direct ByteBuffer 的真实内存基址（java.nio.DirectByteBuffer.address 私有字段）。
     *  取不到返回 0（调用方据此跳过排除，属已知残留风险）。仅用于 P0-C 内存扫描排除自有 DEX。 */
    private static long directAddress(ByteBuffer buf) {
        if (buf == null || !buf.isDirect()) return 0;
        try {
            java.lang.reflect.Field f = buf.getClass().getDeclaredField("address");
            f.setAccessible(true);
            return f.getLong(buf);
        } catch (Throwable t) {
            return 0;
        }
    }

    /** 重算 DEX 头校验和：checksum(偏移8)=adler32(data[12:])，signature(偏移12)=sha1(data[32:])。
     *  失败静默跳过（不抛异常），交还给上层 fail-safe。
     *
     *  2026-09-10 根因修复：原来用 Java 实现，需要 new 两个约 9MB 的 byte[](sigSrc/tail)
     *  并用 buf.get() 把整段 DEX 拷进去 -> memcpy 写入这两个超大型堆数组。MIX2 A9 实测
     *  这些数组会落在 ART 大对象空间，而该区内存在一张异常的 r-x 页 0x802f4000，
     *  恰好落在 sigSrc 的地址范围内 -> 写入即 SEGV_ACCERR(偶发崩溃)。
     *  这也是「给 DEX 缓冲 mprotect(RW) 成功却照样崩」的真相：崩溃写的是 Java 数组，
     *  不是 DEX 缓冲（0x802f4000 甚至低于 dex0 基址）。
     *  现全部下沉到 native 直接在 direct ByteBuffer 内存上计算：
     *      - 不再分配 9MB 级的临时 Java 数组 -> 不存在对堆数组的整段写入 -> 根除该崩溃
     *      - 顺带省掉 2×9MB 分配和两次 9MB 拷贝，启动更快
     *  native 内部语义与旧 Java 版完全一致（含 file_size 边界 clamp 与「先签名后校验和」顺序）。 */
    /** 2026-09-11 冷启动优化：DEX 头 checksum(偏移8) 与当前内容是否已自洽（只读）。
     *
     *  用途：跳过 fixDexChecksum 里整段 SHA-1(30MB) 的空转。方法抽取默认关时，进内存的
     *  DEX 与构建期产出一致、头本来就自洽；此时原重算只是把完全相同的值写回去。
     *
     *  为什么必须放 Java 侧：本逻辑曾在 native 实现（同 TU 被 OLLVM -fla/-bcf 处理），
     *  实测 30.4MB adler32 要 753ms（~40MB/s）；改用 libcore 的 java.util.zip.Adler32
     *  （boot 镜像已 AOT）后同语义自检降到数十 ms，快约 25 倍。
     *
     *  语义与 native 版完全一致：DEX 头 file_size(偏移32, LE) clamp 到 capacity；
     *  checksum = adler32(data[12, file_size))。异常/参数异常一律返回 false（保守，
     *  绝不误跳过，宁可多跑一次 SHA-1）。只读：duplicate() 不改调用方 position。 */
    static boolean dexHeaderConsistent(ByteBuffer buf) {
        try {
            if (buf == null) return false;
            int cap = buf.capacity();
            if (cap < 32) return false;
            int fileSize = (buf.get(32) & 0xff) | ((buf.get(33) & 0xff) << 8)
                    | ((buf.get(34) & 0xff) << 16) | ((buf.get(35) & 0xff) << 24);
            if (fileSize <= 12 || fileSize > cap) fileSize = cap;
            if (fileSize < 32) return false;
            java.util.zip.Adler32 a = new java.util.zip.Adler32();
            byte[] chunk = new byte[65536];
            ByteBuffer d = buf.duplicate();
            d.position(12);
            d.limit(fileSize);
            while (d.hasRemaining()) {
                int n = Math.min(chunk.length, d.remaining());
                d.get(chunk, 0, n);
                a.update(chunk, 0, n);
            }
            int want = (buf.get(8) & 0xff) | ((buf.get(9) & 0xff) << 8)
                    | ((buf.get(10) & 0xff) << 16) | ((buf.get(11) & 0xff) << 24);
            return (int) a.getValue() == want;
        } catch (Throwable t) {
            return false;   /* 保守：不确定就做完整重算 */
        }
    }

    private static void fixDexChecksum(ByteBuffer buf) {
        if (buf == null) return;
        if (buf.capacity() < 32) return;
        try {
            boolean ok = GxDecryptor.nativeFixDexChecksum(buf);
            if (!ok) Log.w("GX", "fixDexChecksum skipped (native returned false)");
        } catch (Throwable t) {
            Log.w("GX", "fixDexChecksum skipped", t);
        }
    }

    static byte[] readPayload(String apk) throws IOException {
        ZipFile zf = new ZipFile(apk);
        try {
            ZipEntry ze = zf.getEntry(GxApp.PAYLOAD_ENTRY);
            if (ze == null) return null;
            InputStream is = zf.getInputStream(ze);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            is.close();
            return bos.toByteArray();
        } finally {
            zf.close();
        }
    }

    static byte[] inflate(byte[] data) throws Exception {
        Inflater inf = new Inflater();
        inf.setInput(data);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        try {
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && inf.needsInput()) break;
                bos.write(buf, 0, n);
            }
        } finally {
            inf.end();
        }
        return bos.toByteArray();
    }

    static byte[] aesGcmDecrypt(byte[] key, byte[] blob) throws Exception {
        if (blob.length < 28) throw new IllegalStateException("blob too short");
        byte[] iv = Arrays.copyOfRange(blob, 0, 12);
        byte[] rest = Arrays.copyOfRange(blob, 12, blob.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return c.doFinal(rest);
    }

    static int readInt(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    private static void writeFile(File f, byte[] data) throws IOException {
        OutputStream os = new FileOutputStream(f);
        os.write(data);
        os.close();
    }

    /** 原子写入：先写 .tmp，flush+close 后 rename，防止其他进程读到半成品 */
    private static void writeFileAtomic(File f, byte[] data) throws IOException {
        File tmp = new File(f.getParentFile(), f.getName() + ".tmp");
        FileOutputStream os = new FileOutputStream(tmp);
        os.write(data);
        os.flush();
        os.getFD().sync();
        os.close();
        if (!tmp.renameTo(f)) {
            // rename 失败（极少数跨文件系统场景），回退直接写入
            writeFile(f, data);
            tmp.delete();
        }
    }
}

/** 运行时还原加密的 assets 区段：解密写入 zip，供 AssetManager.addAssetPath 合并 */
class GxAssets {
    static String restore(Context ctx, File outZip) {
        try {
            String apk = ctx.getApplicationInfo().sourceDir;
            byte[] payload = GxDecryptor.readPayload(apk);
            if (payload == null || payload.length < 8) return null;
            // 先读载荷取 per-build salt，再 HKDF-Extract 派生 seed
            byte[] seed = GxKeys.seed(ctx, GxKeys.extractSalt(payload));
            int p = 0;
            for (int i = 0; i < 4; i++) {
                if (payload[p] != (byte) GxApp.MAGIC.charAt(i)) return null;
                p++;
            }
            int dexCount = GxDecryptor.readInt(payload, p);
            p += 4;
            for (int i = 0; i < dexCount; i++) {
                int len = GxDecryptor.readInt(payload, p);
                p += 4;
                p += len;
            }
            if (p + 4 > payload.length) return null;  // 无 asset 区段（旧格式/无 assets）
            int assetCount = GxDecryptor.readInt(payload, p);
            p += 4;
            if (assetCount <= 0) return null;
            java.util.zip.ZipOutputStream zos =
                new java.util.zip.ZipOutputStream(new java.io.FileOutputStream(outZip));
            try {
                for (int i = 0; i < assetCount; i++) {
                    int nl = GxDecryptor.readInt(payload, p);
                    p += 4;
                    String name = new String(payload, p, nl, "UTF-8");
                    p += nl;
                    int len = GxDecryptor.readInt(payload, p);
                    p += 4;
                    byte[] blob = Arrays.copyOfRange(payload, p, p + len);
                    p += len;
                    byte[] key = GxKeys.keyFor(seed, "asset" + i);
                    byte[] comp = GxDecryptor.aesGcmDecrypt(key, blob);
                    byte[] data = GxDecryptor.inflate(comp);
                    java.util.zip.ZipEntry ze = new java.util.zip.ZipEntry(name);
                    zos.putNextEntry(ze);
                    zos.write(data);
                    zos.closeEntry();
                }
            } finally {
                zos.close();
            }
            return outZip.getAbsolutePath();
        } catch (Throwable t) {
            Log.e("GX", "GxAssets.restore failed", t);
            return null;
        }
    }
}

/**
 * 密钥派生（抗跨构建 diff + 证书绑定，对齐 mocika 的 HKDF 思路）：
 *   cert_hash = SHA256(签名证书DER)            // 证书绑定材料：换签即失败
 *   seed = HMAC-SHA256(build_salt, cert_hash)  // RFC5869 HKDF-Extract：PRK = HMAC(salt, IKM)
 *   per-dex/asset/method key = HMAC-SHA256(seed, "JG|"+info)
 * build_salt 每次构建随机 (os.urandom(32))，藏于 jg 载荷末尾 32 字节；
 * 故同一证书多次加固密文不同（抗跨构建差分），且仍硬绑定证书（换签 PRK 变 → GCM 标签失败）。
 */
class GxKeys {
    /** 核心密钥派生下沉 native（libjgguard.so 的 jg_hmac_sha256），避免 HMAC 逻辑留在 DEX 被 jadx 直接分析。
     *  Java 侧仅取证书 DER（需反射隐藏 API），其余 HMAC 派生在 .so 内完成。 */
    private static native byte[] nativeDeriveSeed(byte[] certDer, byte[] salt);
    private static native byte[] nativeKeyFor(byte[] seed, byte[] info);

    /** HKDF-Extract：PRK = HMAC(build_salt, SHA256(certDER))。 */
    static byte[] seed(Context ctx, byte[] salt) throws Exception {
        byte[] cert = certDer(ctx);
        return nativeDeriveSeed(cert, salt);
    }

    /** 从 jg 载荷尾部取 32 字节 per-build salt（HKDF-Extract 的 salt 输入）。 */
    static byte[] extractSalt(byte[] payload) {
        if (payload == null || payload.length < 32) {
            throw new IllegalStateException("payload too short to hold salt");
        }
        return Arrays.copyOfRange(payload, payload.length - 32, payload.length);
    }

    static byte[] keyFor(byte[] seed, String info) throws Exception {
        return nativeKeyFor(seed, ("JG|" + info).getBytes("UTF-8"));
    }

    private static byte[] certDer(Context ctx) throws Exception {
        PackageManager pm = ctx.getPackageManager();
        String pkg = ctx.getPackageName();
        try {
            int flag = PackageManager.class.getField("GET_SIGNING_CERTIFICATES").getInt(null);
            Method gp = PackageManager.class.getMethod("getPackageInfo", String.class, int.class);
            Object pi = gp.invoke(pm, pkg, flag);
            Object si = pi.getClass().getMethod("getSigningInfo").invoke(pi);
            if (si != null) {
                Object[] sigs = (Object[]) si.getClass().getMethod("getApkContentsSigners").invoke(si);
                if (sigs != null && sigs.length > 0) {
                    return (byte[]) sigs[0].getClass().getMethod("toByteArray").invoke(sigs[0]);
                }
            }
        } catch (Throwable t) { /* fall through to legacy */ }
        int flag = PackageManager.class.getField("GET_SIGNATURES").getInt(null);
        Method gp = PackageManager.class.getMethod("getPackageInfo", String.class, int.class);
        Object pi = gp.invoke(pm, pkg, flag);
        Object sigs = pi.getClass().getField("signatures").get(pi);
        Object[] arr = (Object[]) sigs;
        if (arr != null && arr.length > 0) {
            return (byte[]) arr[0].getClass().getMethod("toByteArray").invoke(arr[0]);
        }
        throw new IllegalStateException("no cert");
    }
}

/**
 * 轻量反调试 / 反注入特征扫描（DEX 解密前硬网关）。
 * 统一收口到 STRENGTHEN_RESPONSE：默认 "log"=仅记录、不阻断（fail-safe，避免误杀正常设备）；
 * "exit"=命中即抛 SecurityException 阻断启动。与 native jg_guard / GxTamper 守护线程行为一致。
 */
class GxAntiDebug {
    private static final String TAG = "GX";
    /** 检测 + 按统一开关响应。命中且 STRENGTHEN_RESPONSE=exit 才阻断；否则仅记录并继续。 */
    static void check() {
        try {
            String hit = detect();
            if (hit != null) {
                boolean block = "exit".equals(GxApp.STRENGTHEN_RESPONSE);
                Log.w(TAG, "anti-debug hit: " + hit + " -> "
                        + (block ? "block" : "log-only (STRENGTHEN_RESPONSE)"));
                if (block) {
                    throw new SecurityException("hook/debug framework: " + hit);
                }
                // log 模式：继续启动（fail-safe）
            }
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) { /* 容忍扫描失败 */ }
    }

    /** 返回命中的特征描述；未命中返回 null。 */
    private static String detect() throws IOException {
        if (Debug.isDebuggerConnected()) return "debugger connected";
        BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"));
        try {
            String line;
            while ((line = br.readLine()) != null) {
                String l = line.toLowerCase();
                if (l.contains(Obf.d(new byte[]{0x75, 0x25, 0x43, 0x08, 0x2F})) || l.contains(Obf.d(new byte[]{0x60, 0x22, 0x48, 0x1F, 0x3A, 0x69, 0x57, 0x0D, 0x68})) || l.contains(Obf.d(new byte[]{0x6B, 0x27, 0x45, 0x1F, 0x2B, 0x7F}))
                        || l.contains(Obf.d(new byte[]{0x7F, 0x3E, 0x48, 0x1F, 0x2F, 0x75, 0x52, 0x11, 0x62, 0x3E, 0x03})) || l.contains(Obf.d(new byte[]{0x7F, 0x3E, 0x48, 0x01, 0x3D, 0x7A, 0x59, 0x18, 0x64, 0x35, 0x1B, 0x11, 0x48}))) {
                    return "hook framework: " + line.trim();
                }
            }
        } finally {
            br.close();
        }
        return null;
    }
}

/**
 * 反篡改守护（保命版，纯只读检测，与加载器物理隔离）
 *
 * 设计红线（保证不引入新崩溃）：
 *   1. 仅做只读检测：扫 /proc/self/maps、探测 frida 默认端口、检查 re.frida.server 文件、
 *      读 /proc/self/status 的 TracerPid。任何检测异常都被吞掉，绝不外抛。
 *   2. 运行在独立守护线程，不阻塞启动、不进入 DEX 加载路径。
 *   3. 后台周期轮询（不只启动那一次），可捕获延迟注入的 Frida。
 *   4. 响应（退出/降级）只在“确认被篡改”时触发；干净设备永远走不到这一步。
 *
 * 说明：本版 Java 层已做 fileless 加载（DEX 不落盘、源缓冲区清零，见 GxDecryptor.decryptBuffers /
 *      GxLoader.injectDexFromBuffers），关闭了“磁盘明文文件 + 启动期整段明文大块”两个泄漏点。
 *      但 DEX 一旦被 ART 加载运行，优化代码仍存在于进程内存，无法仅靠 Java 层做到 100% 防内存
 *      dump（那需要 native 指令抽取，属 P3，高风险）。本层只屏蔽用于 dump 的主流框架
 *      （Frida/Substrate/Xposed 等）；native 层由 libjgguard.so 补充。
 */
class GxTamper {
    private static final String TAG = "GX-AT";

    // 扩展特征库：覆盖改名后的 frida-gadget / magisk / 各类 hook 框架
    private static final String[] MAP_KEYWORDS = {
        Obf.d(new byte[]{0x75, 0x25, 0x43, 0x08, 0x2F}), Obf.d(new byte[]{0x74, 0x36, 0x4E, 0x0B, 0x2B, 0x6F}), Obf.d(new byte[]{0x7F, 0x3E, 0x48, 0x0A, 0x3C, 0x72, 0x52, 0x18}), Obf.d(new byte[]{0x75, 0x25, 0x43, 0x08, 0x2F, 0x36, 0x57, 0x1E, 0x68, 0x3F, 0x1C}), Obf.d(new byte[]{0x60, 0x22, 0x48, 0x1F, 0x3A, 0x69, 0x57, 0x0D, 0x68}),
        Obf.d(new byte[]{0x6B, 0x27, 0x45, 0x1F, 0x2B, 0x7F}), Obf.d(new byte[]{0x7F, 0x3E, 0x48, 0x1F, 0x2F, 0x75, 0x52, 0x11, 0x62, 0x3E, 0x03}), Obf.d(new byte[]{0x7F, 0x3E, 0x48, 0x02, 0x2F, 0x6F, 0x5F, 0x0F, 0x68, 0x39, 0x07, 0x1B, 0x40}),
        Obf.d(new byte[]{0x70, 0x2E, 0x4E, 0x05, 0x2F}), Obf.d(new byte[]{0x7E, 0x36, 0x4D, 0x05, 0x3D, 0x70}), Obf.d(new byte[]{0x61, 0x32, 0x04, 0x0A, 0x3C, 0x72, 0x52, 0x18}), Obf.d(new byte[]{0x75, 0x25, 0x43, 0x08, 0x2F, 0x36, 0x45, 0x1C, 0x7F, 0x27, 0x0D, 0x06})
    };
    // 已删 "libmsaoaidsec"（0904 报告①误杀分析）：MSA OAID SDK 合法库，集成 OAID 的包
    // maps 里必有，出现≠被攻击——留着只会在 exit 模式下 100% 误杀该包全部真实用户。

    // frida-server 默认监听端口
    private static final int[] SCAN_PORTS = {27042, 27043};

    /** 启动独立守护线程，整段 try-catch，任何异常都不向外传播 */
    static void start() {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    loop();
                } catch (Throwable ignored) {
                    Log.w(TAG, "guard loop ended", ignored);
                }
            }
        });
        t.setName("gx-anti-tamper");
        t.setDaemon(true);
        t.start();
    }

    private static void loop() {
        // 启动即查一次；之后周期轮询。分级响应（0904 三次报告①）：硬信号无条件 exit。
        check();
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(GxApp.ANTI_TAMPER_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            check();
        }
    }

    /** 分级响应：硬信号（外部 TracerPid，正常设备恒 0、自家 ptrace 守护已放行，
     *  误杀率≈0）→ 无条件 hardExit（裸 syscall），不受 STRENGTHEN_RESPONSE 门控；
     *  模糊信号（maps 关键词/端口/特征文件，有误报面）→ 走 respond() 由
     *  STRENGTHEN_RESPONSE 统一收口。 */
    private static void check() {
        if (checkTracerPid()) {
            Log.w(TAG, "tamper hard signal: external TracerPid -> hardExit (raw syscall)");
            GxGuard.hardExit();
            return;
        }
        if (scanMaps() || probePorts() || checkServerFile()) respond();
    }

    private static boolean scanMaps() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                String l = line.toLowerCase();
                for (String k : MAP_KEYWORDS) {
                    if (l.contains(k)) {
                        Log.w(TAG, "tamper: maps hit '" + k + "' -> " + line.trim());
                        return true;
                    }
                }
            }
        } catch (Throwable t) {
            // 读取失败不视为篡改
        } finally {
            if (br != null) try { br.close(); } catch (Throwable ignored) {}
        }
        return false;
    }

    private static boolean probePorts() {
        for (int port : SCAN_PORTS) {
            Socket s = null;
            try {
                s = new Socket();
                s.connect(new InetSocketAddress("127.0.0.1", port), 200);
                Log.w(TAG, "tamper: " + Obf.d(new byte[]{0x75, 0x25, 0x43, 0x08, 0x2F, 0x3B, 0x46, 0x16, 0x7F, 0x25, 0x48}) + " " + port + " open");
                return true;
            } catch (Throwable t) {
                // 连接失败 = 未监听，属正常
            } finally {
                if (s != null) try { s.close(); } catch (Throwable ignored) {}
            }
        }
        return false;
    }

    private static boolean checkServerFile() {
        try {
            if (new File(Obf.d(new byte[]{0x3C, 0x33, 0x4B, 0x18, 0x2F, 0x34, 0x5A, 0x16, 0x6E, 0x30, 0x04, 0x5B, 0x5F, 0x52, 0x34, 0x7D, 0x61, 0x32, 0x04, 0x0A, 0x3C, 0x72, 0x52, 0x18, 0x23, 0x22, 0x0D, 0x06, 0x5D, 0x5A, 0x36})).exists()) {
                Log.w(TAG, "tamper: " + Obf.d(new byte[]{0x3C, 0x33, 0x4B, 0x18, 0x2F, 0x34, 0x5A, 0x16, 0x6E, 0x30, 0x04, 0x5B, 0x5F, 0x52, 0x34, 0x7D, 0x61, 0x32, 0x04, 0x0A, 0x3C, 0x72, 0x52, 0x18, 0x23, 0x22, 0x0D, 0x06, 0x5D, 0x5A, 0x36}) + " exists");
                return true;
            }
        } catch (Throwable t) { /* ignore */ }
        return false;
    }

    /** 判断 tracer pid 是否本进程 fork 出的 ptrace 守护子进程（读 /proc/<tpid>/status
     *  的 PPid==self）。是 → 放行，否则按外部 tracer 处理。读不到保守按"不是"。 */
    private static boolean isOwnGuardTracer(int tpid) {
        if (tpid <= 0) return false;
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/" + tpid + "/status"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("PPid:")) {
                    int ppid = Integer.parseInt(line.split(":")[1].trim());
                    return ppid == android.os.Process.myPid();
                }
            }
        } catch (Throwable t) {
            return false;
        } finally {
            if (br != null) try { br.close(); } catch (Throwable ignored) {}
        }
        return false;
    }

    private static boolean checkTracerPid() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    int pid = Integer.parseInt(line.split(":")[1].trim());
                    if (pid != 0 && !isOwnGuardTracer(pid)) {
                        Log.w(TAG, "tamper: TracerPid=" + pid);
                        return true;
                    }
                    break;
                }
            }
        } catch (Throwable t) {
            // 读取失败不视为篡改
        } finally {
            if (br != null) try { br.close(); } catch (Throwable ignored) {}
        }
        return false;
    }

    private static void respond() {
        // 统一收口到 STRENGTHEN_RESPONSE（与 GxAntiDebug / native jg_guard 一致）。
        // 默认 "log"=仅记录、不阻断（fail-safe，避免误杀正常设备）；"exit"=静默退出进程。
        if (!"exit".equals(GxApp.STRENGTHEN_RESPONSE)) {
            Log.w(TAG, "tamper detected but STRENGTHEN_RESPONSE="
                    + GxApp.STRENGTHEN_RESPONSE + " (log-only)");
            return;
        }
            Log.w(TAG, "tamper confirmed -> hardExit (raw syscall, STRENGTHEN_RESPONSE=exit)");
            GxGuard.hardExit();
    }
}

/**
 * P-ANTIDUMP 反内存 dump（检测层）。
 * 定位：检测 FART / Youpk / BlackDex / dumpDex 等脱壳工具的 dump 产物路径。
 * 诚实边界：只挡「默认配置」的脱壳工具；改过输出路径/特征的定制工具挡不住；
 *          根治方案（VMP 指令虚拟化）超出本工程能力，本层目标是把"拿来即用"的脱壳党挡掉。
 * 红线（与 GxTamper 一致）：
 *   1. 只读检测，异常全吞，绝不外抛、绝不影响启动。
 *   2. 独立守护线程：启动即查一次 + 周期轮询（可捕获启动后的延迟 dump）。
 *   3. 统一收口 STRENGTHEN_RESPONSE：默认 log 仅记录；exit 才阻断。
 *   4. 零误报优先：仅匹配脱壳工具的默认输出目录/标记名，宁可漏检不可误伤正常用户。
 */
class GxAntiDump {
    private static final String TAG = "GX-AD";
    // 500ms：脱壳工具常驻/周期性写产物，2s 窗口有漏抓风险，500ms 足够。
    private static final long INTERVAL_MS = 500;
    private static volatile java.io.File appDataDir;   // /data/data/<pkg>

    // P0-C 内存级 anti-dump 总开关：默认开启（拦内存映射型 dump；meta "gx.antidump"="0" 才关）。
    static volatile boolean ANTI_DUMP_ENABLED = true;
    // 自有 DEX 直接缓冲区内存区间 [start, start+len)，由解密加载时登记（best-effort），扫描时排除，
    // 避免命中自家 InMemoryDexClassLoader DEX 导致自爆。仅在该表非空后内存扫描才生效（规避启动竞态）。
    private static final java.util.List<long[]> SELF_DEX = new java.util.ArrayList<>();

    static void addSelfDex(long addr, long len) {
        if (addr != 0 && len > 0) {
            synchronized (SELF_DEX) { SELF_DEX.add(new long[]{addr, addr + len}); }
        }
    }

    static void start(Context ctx) {
        try {
            java.io.File fd = ctx.getFilesDir();
            if (fd != null) appDataDir = fd.getParentFile();
        } catch (Throwable ignored) {}
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    loop();
                } catch (Throwable ignored) {
                    Log.w(TAG, "anti-dump loop ended", ignored);
                }
            }
        });
        t.setName("gx-anti-dump");
        t.setDaemon(true);
        t.start();
    }

    private static void loop() {
        // 启动即查一次（FART 主动调用发生在进程早期，越早查越好）；之后周期轮询
        if (detect()) respond();
        // P0-0904 周期重扫 dex 头：inject 时刻的自扫之后，仍可能有 dex 身份头
        // 后续才落进堆（真机实证：壳 stub dex 的堆内副本晚于 inject 出现，46KB、
        // 带完整 magic）。每 10s 重打乱一次（native 幂等、无命中时纯页遍历 <100ms），
        // 保证「magic 扫描 0 命中」在整个生命周期内成立。
        int ticks = 0;
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (detect()) respond();
            if (++ticks >= 20) {   /* 500ms × 20 = 10s */
                ticks = 0;
                try {
                    GxDecryptor.nativeScrambleDexHeaders(false);
                } catch (Throwable t) {
                    Log.w(TAG, "periodic dex-header scramble skipped", t);
                }
            }
        }
    }

    /** 综合检测，任一命中即视为正在被脱壳。每个子检测独立 try-catch，互不影响。
     *  诚实边界（2026-09-04 真机实测）：app 在 SELinux(untrusted_app) 下读不到任何其他
     *  进程（root/shell）的 /proc/<pid>/cmdline，故「扫全系统命令行抓外部 dd」这条
     *  路在真实设备上根本看不到攻击者（攻击者必然不同 uid）——已删除对应 native 扫描
     *  （jg_anti_dump.c），它只会给虚假安全感。本层只保留「读自己空间」的本地检测：
     *  dump 输出目录 / /data/local/tmp 工具标记 / 自身 maps 里的匿名 DEX 魔数
     *  （frida-dexdump 类内存 dump 的本质特征）。这些不需要跨 uid 读，真实有效。
     *  至于 root 直接 `dd /proc/<pid>/mem`：app 级无法看见也无法阻止（梆梆/360 靠内核
     *  级 hook 才做得到），本工程无内核组件，故该攻击面如实标注为「未覆盖」。 */
    private static boolean detect() {
        return dumpDirsExist() || localTmpMarkers() || scanMemoryForDex();
    }

    /** 脱壳工具默认输出目录（目录存在即命中；正常 App 不会创建 dump/app_dump 这类名字）。 */
    private static boolean dumpDirsExist() {
        String[] names = {"dump", "app_dump", "dexdump", "dump_dex"};
        try {
            if (appDataDir == null) return false;
            for (String n : names) {
                if (new File(appDataDir, n).isDirectory()) {
                    Log.w(TAG, "anti-dump: dump dir " + new File(appDataDir, n).getAbsolutePath());
                    return true;
                }
            }
            java.io.File files = new java.io.File(appDataDir, "files");
            if (files.isDirectory()) {
                for (String n : names) {
                    if (new File(files, n).isDirectory()) {
                        Log.w(TAG, "anti-dump: dump dir " + new File(files, n).getAbsolutePath());
                        return true;
                    }
                }
            }
            java.io.File cache = new java.io.File(appDataDir, "cache");
            if (cache.isDirectory()) {
                for (String n : names) {
                    if (new File(cache, n).isDirectory()) {
                        Log.w(TAG, "anti-dump: dump dir " + new File(cache, n).getAbsolutePath());
                        return true;
                    }
                }
            }
        } catch (Throwable t) {
            // 读取失败不视为被 dump（fail-safe）
        }
        return false;
    }

    /** /data/local/tmp 脱壳框架标记（BlackDex/Youpk 注入常在此留文件；普通 App 无读权限，
     *  但检测代码无害，命中即表明设备具备 root 注入环境）。 */
    private static boolean localTmpMarkers() {
        String[] keywords = {"blackdex", "youpk", "fart", "dexdump", "dump_dex", "dumpdex"};
        try {
            java.io.File tmp = new java.io.File("/data/local/tmp");
            if (!tmp.isDirectory()) return false;
            java.io.File[] all = tmp.listFiles();
            if (all == null) return false;
            for (java.io.File f : all) {
                String n = f.getName().toLowerCase();
                for (String k : keywords) {
                    if (n.contains(k)) {
                        Log.w(TAG, "anti-dump: local tmp marker " + f.getAbsolutePath());
                        return true;
                    }
                }
            }
        } catch (Throwable t) {
            // ignore
        }
        return false;
    }

    /** P0-C 内存级脱壳检测：扫 /proc/self/maps，对匿名(/memfd)区域读首 4 字节是否 DEX 魔数
     *  （"dex\n"=0x64 65 78 0A，或 compact "dey\n"=0x64 65 79 0A）。这是 frida-dexdump / memfd
     *  内存 dump 的本质特征：解密后的 DEX 以匿名/共享内存形态驻留，首 4 字节即 DEX 魔数。
     *  ⚠ 诚实边界：本扫描是「检测」不是「杜绝」——DEX 必被 ART 明文执行，内存里永远有明文副本，
     *     只能提高 dump 成本、给运行期一个告警/阻断信号，无法让 AI 逆向器读不到。
     *  ⚠ 误报残留：若 ART 把本壳 DEX 另拷到匿名区（SELF_DEX 未覆盖），可能误命中自家 DEX → 自爆。
     *     故仅当 SELF_DEX 非空（已登记自家 DEX 区间）才扫描，且排除这些区间；开关默认关，需真机验证。
     *  fail-safe：任何异常都视为未命中，绝不因扫描失败而阻断正常启动。 */
    private static boolean scanMemoryForDex() {
        if (!ANTI_DUMP_ENABLED) return false;
        // 启动竞态保护：自家 DEX 尚未登记时不扫描（避免命中尚未排除的自家 DEX）。
        synchronized (SELF_DEX) { if (SELF_DEX.isEmpty()) return false; }
        try {
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(new java.io.FileInputStream("/proc/self/maps")));
            String line;
            while ((line = br.readLine()) != null) {
                int sp = line.indexOf('-');
                if (sp <= 0) continue;
                // pathname：maps 行末尾（若无则为匿名映射）；/memfd: 是 memfd_create 内存 dump 特征。
                int idx = line.indexOf('/', sp);
                String path = (idx >= 0) ? line.substring(idx).trim() : "";
                boolean anon = path.isEmpty();
                boolean memfd = path.startsWith("/memfd:") || path.contains("memfd");
                if (!anon && !memfd) continue;   // 文件映射（含 APK 自身）一律跳过，属合法
                long start = parseMapsStart(line, sp);
                if (start < 0) continue;
                if (inSelfDex(start)) continue;  // 排除自家加载的 DEX 区间
                if (readDexMagic(start)) {
                    Log.w(TAG, "anti-dump(memory): DEX magic @0x" + Long.toHexString(start)
                            + " region=" + (path.isEmpty() ? "<anonymous>" : path));
                    return true;
                }
            }
            br.close();
        } catch (Throwable t) {
            // fail-safe：扫描异常不阻断
        }
        return false;
    }

    /** 解析 maps 行起始地址（十六进制，行首到首个 '-'）。失败返回 -1。 */
    private static long parseMapsStart(String line, int sp) {
        try {
            return Long.parseLong(line.substring(0, sp).trim(), 16);
        } catch (Throwable t) {
            return -1;
        }
    }

    /** 地址是否落在已登记的自家 DEX 区间内（排除自检误报）。 */
    private static boolean inSelfDex(long addr) {
        synchronized (SELF_DEX) {
            for (long[] r : SELF_DEX) {
                if (addr >= r[0] && addr < r[1]) return true;
            }
        }
        return false;
    }

    /** 读 /proc/self/mem 指定地址首 4 字节，判断是否 DEX 魔数。fail-safe：异常返回 false。 */
    private static boolean readDexMagic(long start) {
        java.io.RandomAccessFile mem = null;
        try {
            mem = new java.io.RandomAccessFile("/proc/self/mem", "r");
            mem.seek(start);
            byte[] head = new byte[4];
            int n = mem.read(head);
            if (n != 4) return false;
            // "dex\n" / "dey\n"
            return (head[0] == 0x64 && head[1] == 0x65 && head[3] == 0x0a
                    && (head[2] == 0x78 || head[2] == 0x79));
        } catch (Throwable t) {
            return false;   // 读不可访问地址会抛 IOException/EOFException -> 视为非 DEX
        } finally {
            if (mem != null) {
                try { mem.close(); } catch (Throwable ignored) {}
            }
        }
    }

    private static void respond() {
        // 本地检测（dump 目录 / tmp 标记 / 自身 maps 匿名 DEX 魔数）均为弱特征：
        // 存在误报可能（例如用户自己建了个 dump 目录、或 ART 把壳 DEX 拷到匿名区被
        // 自检误命中），故统一走 STRENGTHEN_RESPONSE 收口——默认仅记录(log)、不阻断。
        // 注意：不再对「外部进程读我内存」做硬杀——app 在 SELinux 下读不到别进程
        // cmdline，那条路（jg_anti_dump.c）已删；强行硬杀只会误伤正常设备。
        if (!"exit".equals(GxApp.STRENGTHEN_RESPONSE)) {
            Log.w(TAG, "anti-dump hit but STRENGTHEN_RESPONSE="
                    + GxApp.STRENGTHEN_RESPONSE + " (log-only)");
            return;
        }
            Log.w(TAG, "anti-dump confirmed -> hardExit (raw syscall, STRENGTHEN_RESPONSE=exit)");
            GxGuard.hardExit();
    }

    /** 纯 Java 本地检测层（dump 目录 / tmp 标记 / 自身 maps 匿名 DEX 魔数），
     *  无 native 依赖。跨 uid 的「外部进程读我内存」检测在 SELinux 下不可行，已删除。 */
}

/**
 * A·强反 Frida 检测层（被动检测）：壳运行期经 native GxAntiFrida_scanJNI 扫描
 *   frida / Xposed 特征（maps 路径签名 / TracerPid / 默认端口 / 主动 ptrace 自检 /
 *   Xposed-LSPosed 签名），返回位掩码，命中经统一 STRENGTHEN_RESPONSE 收口。
 *   属于「检测」而非「杜绝」：攻击者仍可 patch 响应函数或自定义 dump，故本层只发信号、
 *   断不断由 STRENGTHEN_RESPONSE 统一决定。签名串在 native 端 XOR 混淆（A1），
 *   抗 string+grep+patch 攻击路。
 * 铁律：
 *   1. 默认关闭（meta "gx.antifrida"="1" 才启用）；ANTI_FRIDA_ENABLED=false 时
 *      start() 直接返回，native 根本不被调用，零运行期开销。
 *   2. 异常全吞，绝不外抛、绝不影响 App 启动。
 *   3. 误报红线：native 仅匹配 frida 明确签名串，宁可漏检不可误伤正常设备。
 */
class GxAntiFrida {
    private static final String TAG = "GX-AF";
    private static final long INTERVAL_MS = 2000;
    // A·强反 Frida 总开关：默认开启（命中经 STRENGTHEN_RESPONSE 收口；meta "gx.antifrida"="0" 才关）。
    static volatile boolean ANTI_FRIDA_ENABLED = true;

    static void start(Context ctx) {
        // 默认关：不浪费线程/扫描，native 不被调用
        if (!ANTI_FRIDA_ENABLED) return;
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    loop();
                } catch (Throwable ignored) {
                    Log.w(TAG, "anti-frida loop ended", ignored);
                }
            }
        });
        // 线程名绝不含 "frida"/"gum" 等关键字：jg_integrity scan_threads 会枚举 /proc/self/task
        // 匹配可疑线程名，若守护线程自身含 "frida" 必然自误报（thread_hits=1，每次启动必现）。
        t.setName("gx-sec-mon");
        t.setDaemon(true);
        t.start();
    }

    private static void loop() {
        // 启动即查一次；之后周期轮询。分级响应（0904 三次报告①）：按信号强度分流。
        handle(scan());
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            handle(scan());
        }
    }

    /** 调 native 扫描。native 未加载/异常 → 0（fail-safe，绝不外抛）。 */
    private static int scan() {
        try {
            return scanJNI();
        } catch (Throwable t) {
            return 0;
        }
    }

    /** 分级响应：
     *  硬信号 bit1(TracerPid)/bit3(ptrace 自检)/bit2(端口 27042/27043)/bit5(gum-js-loop
     *  等线程名)/bit7(改名端口 frida 握手命中)——正常用户设备恒 0（自家 ptrace 守护已在
     *  native 按 PPid==self 放行；自有线程统一 gx- 前缀不会撞 gum-js-loop；frida17 spawn
     *  注入完即 detach、agent 走 memfd 无路径；bit7 抓改名端口）→ 无条件 hardExit（裸 syscall，
     *  frida 拦不了），不受 STRENGTHEN_RESPONSE 门控。已知代价：root 机为其他 App 跑
     *  frida-server 会被杀（拍板接受）。
     *  模糊信号 bit0(maps 关键词)/bit4(Xposed 签名)——有误报面（改名 so、LSPosed 模块圈了
     *  本包）→ 走 respond() 仍由 STRENGTHEN_RESPONSE 统一收口。
     *  诊断信号 bit6(hook-patched=libc/libart 入口疑似跳板)：保留检测与日志，但【不击杀】——
     *  MIUI/部分 OEM ROM 上个别 libc 函数入口会被误判为跳板（h_v6 实测 MIX2 干净机误杀），
     *  误杀率不可接受，故降级为纯诊断，待跳板指纹收紧到 frida 专用模式后再升硬信号。 */
    // hook-patched 诊断信号(bit6)在 MIX2/MIUI/Magisk 上恒为误报(见下方 handle 注释)。
    // 仅当与其他信号同时命中时才记日志(关联判定)；单独命中视为 ROM/root 误报，做进程级限流抑制，
    // 杜绝 1s 周期扫描导致的循环刷屏(脚本刷屏同属不可接受噪声)。
    private static final long HOOK_DIAG_COOLDOWN_MS = 10L * 60 * 1000; // 10 分钟
    private static long sLastHookDiagLog = 0;

    private static void handle(int mask) {
        if (mask == 0) return;
        boolean hard  = (mask & 0xAE) != 0;   // 硬: bit1(2)|bit2(4)|bit3(8)|bit5(32)|bit7(128)
        boolean fuzzy = (mask & 0x11) != 0;    // 模糊: bit0(frida maps)|bit4(xposed)
        boolean diagOnly = ((mask & 0x40) != 0) && !hard && !fuzzy; // 仅诊断信号(bit6)单独命中
        if (diagOnly) {
            // 关联判定：无其它信号佐证 -> 视为 ROM/root 误报，限流后静默抑制。
            long now = System.currentTimeMillis();
            if (now - sLastHookDiagLog < HOOK_DIAG_COOLDOWN_MS) return;
            sLastHookDiagLog = now;
            Log.w(TAG, "hook signal mask=0x" + Integer.toHexString(mask)
                    + " [" + maskDesc(mask) + "] (diagnostic-only, no correlation -> suppressed/limited)");
            return;
        }
        Log.w(TAG, "hook signal mask=0x" + Integer.toHexString(mask) + " [" + maskDesc(mask) + "]");
        if (hard) {
            Log.w(TAG, "frida hard signal (tracer/ptrace/port/thread-name/port-any) -> hardExit (raw syscall)");
            GxGuard.hardExit();
            return;
        }
        if (fuzzy) {   // 模糊: bit0(frida maps)|bit4(xposed)；bit6 仅诊断不杀
            respond();
        }
    }

    /** 位掩码解码为可读描述（真机 logcat 验证用）。 */
    private static String maskDesc(int mask) {
        StringBuilder sb = new StringBuilder();
        if ((mask & 1)  != 0) sb.append("maps-frida ");
        if ((mask & 2)  != 0) sb.append("tracerpid ");
        if ((mask & 4)  != 0) sb.append("port ");
        if ((mask & 8)  != 0) sb.append("ptrace ");
        if ((mask & 16) != 0) sb.append("xposed ");
        if ((mask & 32) != 0) sb.append("gum-thread ");
        if ((mask & 64) != 0) sb.append("hook-patched ");
        if ((mask & 128) != 0) sb.append("port-any ");
        if (sb.length() == 0) sb.append("raw(0x").append(Integer.toHexString(mask)).append(")");
        return sb.toString().trim();
    }

    /** 与 GxGuard 同一 .so（libjgguard）：Java_com_gx_runtime_GxAntiFrida_scanJNI。 */
    static native int scanJNI();

    private static void respond() {
        // 统一收口到 STRENGTHEN_RESPONSE（与 GxAntiDump / GxTamper / GxAntiDebug / native jg_guard 一致）。
        if (!"exit".equals(GxApp.STRENGTHEN_RESPONSE)) {
            Log.w(TAG, "frida detected but STRENGTHEN_RESPONSE="
                    + GxApp.STRENGTHEN_RESPONSE + " (log-only)");
            return;
        }
        Log.w(TAG, "frida confirmed -> hardExit (raw syscall, STRENGTHEN_RESPONSE=exit)");
        GxGuard.hardExit();
    }
}

/** 运行期把真实 Application 与 ClassLoader 注入到系统 */
class GxLoader {
    static void setClassLoader(Context base, ClassLoader loader) {
        try {
            Field f = base.getClass().getDeclaredField("mClassLoader");
            f.setAccessible(true);
            f.set(base, loader);
        } catch (Throwable t) { /* ignore */ }

        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object thread = at.getMethod("currentActivityThread").invoke(null);
            Field fPkgs = at.getDeclaredField("mPackages");
            fPkgs.setAccessible(true);
            Object pkgs = fPkgs.get(thread);
            for (Object ref : ((Map<?, WeakReference<?>>) pkgs).values()) {
                Object loadedApk = ((WeakReference<?>) ref).get();
                if (loadedApk != null) {
                    Field fcl = loadedApk.getClass().getDeclaredField("mClassLoader");
                    fcl.setAccessible(true);
                    fcl.set(loadedApk, loader);
                }
            }
        } catch (Throwable t) { /* ignore */ }
    }

    /**
     * 将解密出的原始 DEX 文件注入到【App 自身 ClassLoader】的 DexPathList.dexElements 中。
     * 用 App 自身 classloader（含 nativeLib 路径、app 域隐藏 API）而非框架 classloader，
     * 以避免类加载器分裂导致原 App 原生线程 FindClass 失败→native 崩溃（见 load() 注释）。
     */
    @SuppressWarnings("unchecked")
    static void injectDexElements(ClassLoader loader, List<File> dexFiles) throws Exception {
        Class<?> bdc = Class.forName("dalvik.system.BaseDexClassLoader");
        Field fPathList = bdc.getDeclaredField("pathList");
        fPathList.setAccessible(true);
        Object pathList = fPathList.get(loader);
        Class<?> dpl = pathList.getClass();

        // 读取已有的 dexElements（壳 DEX）
        Field fDexElements = dpl.getDeclaredField("dexElements");
        fDexElements.setAccessible(true);
        Object[] existing = (Object[]) fDexElements.get(pathList);
        if (existing == null) existing = new Object[0];

        // 逐文件加载 DEX 并构造 Element。分版本处理：
        //  - API>=26: DexFile(File) + Element(File,boolean,File,DexFile) 四参构造器可用（本分支）。
        //  - API< 26: 上述两个 API 不存在（会 NoSuchMethodError）。改用公开的 DexClassLoader
        //    (API1 起) 加载解密 DEX，偷取其内部 dexElements 并入 sysLoader.pathList；
        //    定义加载器仍是 sysLoader（clns-6 原生库命名空间不受影响，方案B延续）。
        Class<?> elementClass = existing.getClass().getComponentType(); // dalvik.system.DexPathList$Element
        java.util.List<Object> elementList = new ArrayList<>(); // 用 Object 列表兜底泛型推断

        if (android.os.Build.VERSION.SDK_INT >= 26) {
            for (File f : dexFiles) {
                try {
                    dalvik.system.DexFile df = new dalvik.system.DexFile(f);  // loadDex 语义; API 26+
                    // Element(File, boolean, File, DexFile) - API 26+; Android 12+ 只允许 dir 或 dexFile 二选一
                    java.lang.reflect.Constructor<?> ctor = elementClass.getDeclaredConstructor(
                            File.class, boolean.class, File.class, dalvik.system.DexFile.class);
                    ctor.setAccessible(true);
                    Object elem = ctor.newInstance(null, false, null, df);
                    elementList.add(elem);
                } catch (Throwable t) {
                    Log.w("GX", "injectDexElements: failed " + f, t);
                }
            }
        } else {
            // API<26 兼容分支：
            //  - <26 没有 InMemoryDexClassLoader，DEX 必须落盘才能加载（fileless 不落盘保护在
            //    <26 下天然不可得，平台能力限制，非 bug）。
            //  - DexFile(File) 单参构造与 4 参 Element(File,boolean,File,DexFile) 构造在 <26 不存在，
            //    DexClassLoader 在该 ROM 上对多 dex 拼串 + 子目录 optimizedDirectory 行为不稳
            //    （实测 7.1.2 报 "No original dex files found"）。
            //  - 改用逐文件 DexFile.loadDex(source, outputOdex, 0)（公开 API，API1 起）：
            //    outputOdex 指向 app 私有可写目录下的 .odex，绕开 DexClassLoader 的优化目录黑盒；
            //    逐文件加载也规避了多 dex 拼串的解析差异。
            //  - 构造 Element 用反射兼容两种 ROM 签名：优先 2 参 (File,DexFile)，回退 4 参
            //    (File,boolean,File,DexFile)。
            File optDir = new File(dexFiles.get(0).getParentFile().getParentFile(), "gxdexopt");
            optDir.mkdirs();
            optDir.setWritable(true, false);
            Constructor<?> ctor2 = null, ctor4 = null;
            try {
                ctor2 = elementClass.getDeclaredConstructor(File.class, dalvik.system.DexFile.class);
                ctor2.setAccessible(true);
            } catch (Throwable t) { /* 回退 4 参 */ }
            try {
                ctor4 = elementClass.getDeclaredConstructor(
                        File.class, boolean.class, File.class, dalvik.system.DexFile.class);
                ctor4.setAccessible(true);
            } catch (Throwable t) { /* 回退 2 参 */ }
            for (File f : dexFiles) {
                try {
                    String out = new File(optDir,
                            f.getName().replaceAll("\\.dex$", ".odex")).getAbsolutePath();
                    dalvik.system.DexFile df = dalvik.system.DexFile.loadDex(f.getAbsolutePath(), out, 0);
                    Object elem = null;
                    if (ctor2 != null) {
                        elem = ctor2.newInstance(f, df);
                    } else if (ctor4 != null) {
                        elem = ctor4.newInstance(f, false, null, df);
                    }
                    if (elem != null) elementList.add(elem);
                } catch (Throwable t) {
                    Log.w("GX", "injectDexElements[<26]: failed " + f, t);
                }
            }
        }

        if (elementList.isEmpty()) {
            throw new IOException("injectDexElements: all dex files failed to load");
        }

        Object[] newElements = elementList.toArray(
                (Object[]) java.lang.reflect.Array.newInstance(elementClass, elementList.size()));

        // 合并：解密 DEX 在前 → 壳 DEX 在后（原 App 类优先，壳在 com.gx.runtime 不重名）
        Object[] merged = (Object[]) java.lang.reflect.Array.newInstance(
                elementClass, newElements.length + existing.length);
        System.arraycopy(newElements, 0, merged, 0, newElements.length);
        System.arraycopy(existing, 0, merged, newElements.length, existing.length);
        fDexElements.set(pathList, merged);
    }

    /**
     * P2：fileless 注入。用公开 API InMemoryDexClassLoader 在内存中加载 DEX（不产生 odex 文件，
     * 因此磁盘不落明文），再偷取其 dexElements 注入【App 自身 ClassLoader】的 pathList。
     * 定义加载器仍是 App 自身 classloader（Element 在其 pathList 内），原生库可达性不变。
     *
     * 之所以用 InMemoryDexClassLoader 而非 dalvik.system.DexFile(ByteBuffer)：后者是隐藏构造器，
     * 在部分 OEM（如华为 EMUI）的 ART 上被阉割（NoSuchMethodException），且编译期静态引用
     * 隐藏类会让校验器拒绝整个 GxLoader 类。InMemoryDexClassLoader 是 API 26+ 公开标准 API，
     * 跨 OEM 可靠。构造器通过 Class.forName 反射获取，避免编译期静态引用隐藏 API。
     */
    @SuppressWarnings("unchecked")
    static void injectDexFromBuffers(ClassLoader loader, List<ByteBuffer> bufs) throws Exception {
        Class<?> bdc = Class.forName("dalvik.system.BaseDexClassLoader");
        Field fPathList = bdc.getDeclaredField("pathList");
        fPathList.setAccessible(true);
        Object pathList = fPathList.get(loader);
        Class<?> dpl = pathList.getClass();

        Field fDexElements = dpl.getDeclaredField("dexElements");
        fDexElements.setAccessible(true);
        Object[] existing = (Object[]) fDexElements.get(pathList);
        if (existing == null) existing = new Object[0];

        // InMemoryDexClassLoader(ByteBuffer[], ClassLoader) —— 内存加载，无 odex 文件
        Class<?> imdcClass = Class.forName("dalvik.system.InMemoryDexClassLoader");
        Constructor<?> imdcCtor = imdcClass.getConstructor(ByteBuffer[].class, ClassLoader.class);
        ByteBuffer[] arr = bufs.toArray(new ByteBuffer[0]);
        Object imdc = imdcCtor.newInstance(arr, loader);

        // 偷取内存加载器的 dexElements，注入 sysLoader（保留定义加载器 = sysLoader）
        Object imPathList = fPathList.get(imdc);
        Object[] imElements = (Object[]) fDexElements.get(imPathList);
        if (imElements == null || imElements.length == 0) {
            throw new IOException("InMemoryDexClassLoader produced no dex elements");
        }

        Class<?> elementClass = existing.getClass().getComponentType();
        Object[] merged = (Object[]) java.lang.reflect.Array.newInstance(
                elementClass, imElements.length + existing.length);
        System.arraycopy(imElements, 0, merged, 0, imElements.length);
        System.arraycopy(existing, 0, merged, imElements.length, existing.length);
        fDexElements.set(pathList, merged);

        // P0-0904 v3 anti-dump（deep）：ART 已完成 dex open/verify（header 全部字段
        // 已缓存进 DexFile 对象，运行期不再读），此窗口内做全量去结构化：
        // L1 header 112B 全擦 + 幂等 tag / L2 string_ids 随机重排（打掉「严格递增
        // uint32」结构指纹——0904 报告即靠该指纹绕过 v2 的 16B 擦除）/ L3 map_list
        // 擦除（断掉整包 section 索引与重建校验锚点）。native 侧有多重安全闸，任何
        // 校验失败自动退化为仅 L1。诚实边界：确定型攻击者可解析 ULEB 链重建（成本
        // 分钟级→小时级+）；body 仍明文（梆梆同级水位）。
        try {
            // 2026-09-07 荣耀 A10 (HarmonyOS/SDK29) 实测：ART 把 InMemory dex 的校验
            // 挪到了后台线程（BackgroundVerificationTask），此刻校验【尚未完成】——
            // deep=1 的 L2 string 换位 / L3 map 擦除会与后台校验并发撕裂结构 →
            // "Unknown descriptor: e" SIGABRT 闪退。A9 的「verify 同步完成后再撕」
            // 时序假设在 A10 上不成立。
            // 处置（OEM 脆弱特性默认关铁律）：SDK>=29 注入期跳过 deep，交由 10s 周期
            // deep=false 重扫（仅 L1 header，且校验届时早已完成）继续压制 magic 指纹。
            if (android.os.Build.VERSION.SDK_INT >= 29) {
                android.util.Log.i("GX",
                    "anti-dump v3: deep skipped on SDK>=29 (background-verification race)");
            } else {
                int ns = GxDecryptor.nativeScrambleDexHeaders(true);
                android.util.Log.i("GX", "anti-dump v3: de-structured " + ns + " dex (deep)");
            }
        } catch (Throwable t) {
            android.util.Log.w("GX", "anti-dump scramble skipped", t);
        }
    }

    /**
     * P0-a（0908）：API<26 的 fileless 兼容路径。
     * 该版本无 InMemoryDexClassLoader，DEX 必须借文件加载；改为写到 cache 临时目录，
     * 加载完成后立即 unlink 源码与 odex——目录项消失，"adb pull 固定路径"攻击失效。
     * 已 mmap 的 inode 仍可被 ART 使用，运行期不受影响；root 经 /proc/pid/fd 仍可读
     * 已删除 inode，属物理边界（与 memfd 同级）。不再使用持久化的 app_gxshell/dex 目录，
     * 从根上关掉报告里的"明文 dex 落盘 + 一行命令提取"。
     */
    static void injectDexFromTemp(ClassLoader loader, List<ByteBuffer> bufs, Context ctx) throws Exception {
        Class<?> bdc = Class.forName("dalvik.system.BaseDexClassLoader");
        Field fPathList = bdc.getDeclaredField("pathList");
        fPathList.setAccessible(true);
        Object pathList = fPathList.get(loader);
        Class<?> dpl = pathList.getClass();
        Field fDexElements = dpl.getDeclaredField("dexElements");
        fDexElements.setAccessible(true);
        Object[] existing = (Object[]) fDexElements.get(pathList);
        if (existing == null) existing = new Object[0];

        File tmpDir = new File(ctx.getCacheDir(), "gx_tmp");
        tmpDir.mkdirs();
        Class<?> elementClass = existing.getClass().getComponentType();
        java.util.List<Object> elementList = new ArrayList<>();
        Constructor<?> ctor2 = null, ctor4 = null;
        try {
            ctor2 = elementClass.getDeclaredConstructor(File.class, dalvik.system.DexFile.class);
            ctor2.setAccessible(true);
        } catch (Throwable t) { /* 回退 4 参 */ }
        try {
            ctor4 = elementClass.getDeclaredConstructor(
                    File.class, boolean.class, File.class, dalvik.system.DexFile.class);
            ctor4.setAccessible(true);
        } catch (Throwable t) { /* 回退 2 参 */ }

        java.util.List<File> toDelete = new ArrayList<>();
        for (int i = 0; i < bufs.size(); i++) {
            ByteBuffer b = bufs.get(i);
            ByteBuffer dup = b.duplicate();
            dup.position(0);
            byte[] data = new byte[dup.remaining()];
            dup.get(data);
            File f = new File(tmpDir, "t" + i + ".dex");
            writeFileAtomic(f, data);          // 写入 cache 临时文件（非持久化目录）
            toDelete.add(f);
            File out = new File(tmpDir, "t" + i + ".odex");
            toDelete.add(out);
            try {
                dalvik.system.DexFile df = dalvik.system.DexFile.loadDex(
                        f.getAbsolutePath(), out.getAbsolutePath(), 0);
                Object elem = null;
                if (ctor2 != null) {
                    elem = ctor2.newInstance(f, df);
                } else if (ctor4 != null) {
                    elem = ctor4.newInstance(f, false, null, df);
                }
                if (elem != null) elementList.add(elem);
            } catch (Throwable t) {
                Log.w("GX", "injectDexFromTemp: failed " + f, t);
            }
        }

        Object[] newElements = elementList.toArray(
                (Object[]) java.lang.reflect.Array.newInstance(elementClass, elementList.size()));
        Object[] merged = (Object[]) java.lang.reflect.Array.newInstance(
                elementClass, newElements.length + existing.length);
        System.arraycopy(newElements, 0, merged, 0, newElements.length);
        System.arraycopy(existing, 0, merged, newElements.length, existing.length);
        fDexElements.set(pathList, merged);

        // 加载完成：立即 unlink 源码与 odex，抹掉磁盘明文路径。
        for (File f : toDelete) {
            try { if (f.exists()) f.delete(); } catch (Throwable ignored) {}
        }
    }

    /** 原子写文件：先写临时名再 rename 覆盖，避免半截文件被 pull。 */
    static void writeFileAtomic(File target, byte[] data) throws Exception {
        File tmp = new File(target.getParentFile(), target.getName() + ".w");
        FileOutputStream fos = new FileOutputStream(tmp);
        try {
            fos.write(data);
        } finally {
            fos.close();
        }
        if (target.exists() && !target.delete()) {
            // 删除失败也继续 rename（同名覆盖）
        }
        if (!tmp.renameTo(target)) {
            // rename 跨设备会失败，回退直接写目标
            FileOutputStream fos2 = new FileOutputStream(target);
            try {
                fos2.write(data);
            } finally {
                fos2.close();
            }
            tmp.delete();
        }
    }

    static void swap(Application proxy, Application real) {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object thread = at.getMethod("currentActivityThread").invoke(null);
            Field f = at.getDeclaredField("mInitialApplication");
            f.setAccessible(true);
            f.set(thread, real);
            Field f2 = at.getDeclaredField("mAllApplications");
            f2.setAccessible(true);
            ArrayList<Application> list = (ArrayList<Application>) f2.get(thread);
            if (list != null) {
                list.remove(proxy);
                if (!list.contains(real)) list.add(real);
            }
            Field fPkgs = at.getDeclaredField("mPackages");
            fPkgs.setAccessible(true);
            Object pkgs = fPkgs.get(thread);
            for (Object ref : ((Map<?, WeakReference<?>>) pkgs).values()) {
                Object loadedApk = ((WeakReference<?>) ref).get();
                if (loadedApk != null) {
                    Field fApp = loadedApk.getClass().getDeclaredField("mApplication");
                    fApp.setAccessible(true);
                    fApp.set(loadedApk, real);
                }
            }
        } catch (Throwable t) { /* ignore */ }
    }
}

/**
 * P-CAPTURE 壳通用防抓包（一）：SSL 证书固定。
 * 配置来自加固期注入的 manifest meta-data(gx.ssl_pins)，不依赖被加固 app 源码。
 * 格式： host=sha256/Base64;host2=sha256/Base64 （与 OkHttp CertificatePinner 同构，可复用）。
 * 覆盖：走平台默认 SSLContext / HttpsURLConnection 的流量（含 root+系统证书 MITM，因严格按主机 pin 绕过设备 CA store）。
 * 局限（诚实）：自定义 TrustManager 的 OkHttpClient、X5 WebView(native SSL) 不在本层覆盖范围内。
 * 兼容：API>=24 用 X509ExtendedTrustManager 拿主机名做严格按主机 pin；<24 回退 cert-lock（额外信任锚）。
 */
class GxPinning {
    private static final String TAG = "GX-SSL";
    private static final String META_PINS = "gx.ssl_pins";

    static void install(Context ctx) {
        try {
            String raw = readMeta(ctx, META_PINS);
            if (raw == null || raw.trim().isEmpty()) {
                Log.i(TAG, "pinning disabled (no " + META_PINS + ")");
                return;
            }
            Map<String, String> pins = parse(raw);
            if (pins.isEmpty()) {
                Log.i(TAG, "pinning disabled (empty pins)");
                return;
            }
            X509TrustManager base = systemDefaultTrustManager();
            TrustManager tm;
            try {
                tm = buildExtended(base, pins);   // API>=24 主机名感知严格 pin
                Log.i(TAG, "pinning installed (host-aware, API>=24)");
            } catch (Throwable t) {
                tm = new PlainPinningTM(base, pins); // <24 回退 cert-lock
                Log.w(TAG, "pinning installed (fallback cert-lock): " + t);
            }
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{tm}, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            tryInstallIntoDefaultSSLContext(tm);
            Log.i(TAG, "pinning covers " + pins.size() + " host(s): " + pins.keySet());
        } catch (Throwable t) {
            Log.w(TAG, "pinning install skipped", t);
        }
    }

    private static Map<String, String> parse(String raw) {
        Map<String, String> m = new HashMap<>();
        for (String part : raw.split(";")) {
            part = part.trim();
            if (part.isEmpty()) continue;
            int idx = part.indexOf('=');
            if (idx < 0) continue;
            String host = part.substring(0, idx).trim();
            String pin = part.substring(idx + 1).trim();
            if (!pin.startsWith("sha256/")) continue;
            m.put(host, pin);
        }
        return m;
    }

    private static X509TrustManager systemDefaultTrustManager() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) return (X509TrustManager) tm;
        }
        throw new IllegalStateException("no X509TrustManager");
    }

    private static void tryInstallIntoDefaultSSLContext(TrustManager tm) {
        try {
            // 用公开 API 替换进程默认 SSLContext，覆盖所有走 SSLContext.getDefault() 的调用方
            // （反射改 trustManagers 字段名随 ROM 变化，小米 A9 实测 NoSuchFieldException，故改用 setDefault）。
            SSLContext def = SSLContext.getInstance("TLS");
            def.init(null, new TrustManager[]{tm}, null);
            SSLContext.setDefault(def);
            Log.i(TAG, "default SSLContext replaced");
        } catch (Throwable t) {
            Log.w(TAG, "default SSLContext replace skipped (best-effort)", t);
        }
    }

    private static String readMeta(Context ctx, String key) {
        try {
            ApplicationInfo ai = ctx.getPackageManager().getApplicationInfo(
                    ctx.getPackageName(), PackageManager.GET_META_DATA);
            if (ai.metaData != null && ai.metaData.containsKey(key)) {
                return ai.metaData.getString(key);
            }
        } catch (Exception e) {
            Log.w(TAG, "readMeta", e);
        }
        return null;
    }

    /** API>=24：主机名感知，严格按主机 pin（绕过设备 CA store）。 */
    private static X509ExtendedTrustManager buildExtended(final X509TrustManager base,
                                                          final Map<String, String> pins) {
        return new X509ExtendedTrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException { base.checkClientTrusted(chain, authType); }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException { base.checkServerTrusted(chain, authType); }
            @Override public X509Certificate[] getAcceptedIssuers() { return base.getAcceptedIssuers(); }
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                    throws CertificateException { base.checkClientTrusted(chain, authType); }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                    throws CertificateException { base.checkServerTrusted(chain, authType); pinCheck(pins, chain, hostOf(socket)); }
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                    throws CertificateException { base.checkClientTrusted(chain, authType); }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                    throws CertificateException { base.checkServerTrusted(chain, authType); pinCheck(pins, chain, hostOf(engine)); }
        };
    }

    private static String hostOf(Socket s) {
        return (s != null && s.getInetAddress() != null) ? s.getInetAddress().getHostName() : null;
    }
    private static String hostOf(SSLEngine e) { return e != null ? e.getPeerHost() : null; }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    private static void pinCheck(Map<String, String> pins, X509Certificate[] chain, String host)
            throws CertificateException {
        if (host == null || host.isEmpty()) return;
        String pin = pins.get(host);
        if (pin == null) return; // 该主机未配置 pin，放行
        for (X509Certificate c : chain) {
            String h = "sha256/" + android.util.Base64.encodeToString(
                    sha256(c.getPublicKey().getEncoded()), android.util.Base64.NO_WRAP);
            if (pin.equals(h)) return; // 命中即放行
        }
        throw new CertificateException("GX: pin mismatch for " + host + " (MITM?)");
    }

    /** API<24 回退：pin 作为额外信任锚（cert-lock）。仅挡“不在设备 CA store 且未 pin”的 MITM。 */
    private static class PlainPinningTM implements X509TrustManager {
        private final X509TrustManager base;
        private final Map<String, String> pins;
        PlainPinningTM(X509TrustManager base, Map<String, String> pins) { this.base = base; this.pins = pins; }
        @Override public X509Certificate[] getAcceptedIssuers() { return base.getAcceptedIssuers(); }
        @Override public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException {
            base.checkClientTrusted(c, a);
        }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                base.checkServerTrusted(chain, authType); // 先过平台 CA
            } catch (CertificateException ce) {
                // 平台不信任 → 检查是否被 pin：链中含 pin 的 SPKI 则放行（自签/私有 CA 场景）
                for (X509Certificate cert : chain) {
                    String h = "sha256/" + android.util.Base64.encodeToString(
                            sha256(cert.getPublicKey().getEncoded()), android.util.Base64.NO_WRAP);
                    if (pins.containsValue(h)) return;
                }
                throw ce;
            }
        }
    }
}

/**
 * P-CAPTURE 壳通用防抓包（二）：代理 / VPN 接口检测。
 * ⚠ 已与全局 STRENGTHEN_RESPONSE 解耦：无论该开关是 "log" 还是 "exit"，本检测
 * 一律仅记日志、永不阻断。原因：命中 VPN/代理 tunnel 不能等同于攻击——大量正常用户
 * （企业内网、海外加速、隐私 VPN）也会命中，杀进程属于不可接受的误伤。真正的运行时
 * 防御（frida / xposed / magisk / memfd / TracerPid 等）由其它独立模块负责，不受此处影响。
 */
class GxProxy {
    private static final String TAG = "GX-VPN";

    static void check(Context ctx) {
        try {
            if (detected(ctx)) {
                // 仅记日志：与 STRENGTHEN_RESPONSE 解耦，永不阻断正常 VPN/海外用户。
                Log.w(TAG, "proxy/vpn detected -> log-only (decoupled from STRENGTHEN_RESPONSE, never blocks)");
            }
        } catch (Throwable t) {
            Log.w(TAG, "check skipped", t);
        }
    }

    private static boolean detected(Context ctx) {
        // 注意：强制直连会把 proxyHost 设为空串，故必须判「非空」才算有代理，
        // 否则在已执行强制直连的干净设备上会误报。
        String ph = System.getProperty("http.proxyHost");
        String sph = System.getProperty("https.proxyHost");
        if ((ph != null && !ph.trim().isEmpty()) || (sph != null && !sph.trim().isEmpty())) {
            Log.w(TAG, "system proxy host set: http=" + ph + " https=" + sph);
            return true;
        }
        try {
            java.util.Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            if (nis != null) {
                while (nis.hasMoreElements()) {
                    NetworkInterface ni = nis.nextElement();
                    String n = ni.getName();
                    if (n != null && ni.isUp()
                            && (n.toLowerCase().contains("tun") || n.toLowerCase().contains("ppp")
                                || n.toLowerCase().contains("vpn"))) {
                        Log.w(TAG, "vpn interface: " + n);
                        return true;
                    }
                }
            }
        } catch (Throwable t) { /* ignore */ }
        try {
            if (ctx != null) {
                Object cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    Method getNet = cm.getClass().getMethod("getActiveNetwork");
                    Object net = getNet.invoke(cm);
                    if (net != null) {
                        Method getNc = cm.getClass().getMethod("getNetworkCapabilities", net.getClass());
                        Object nc = getNc.invoke(cm, net);
                        if (nc != null) {
                            int vpnCap = 15; // NET_CAPABILITY_VPN
                            try {
                                vpnCap = Class.forName("android.net.NetworkCapabilities")
                                        .getField("NET_CAPABILITY_VPN").getInt(null);
                            } catch (Throwable ignored) {}
                            if ((Boolean) nc.getClass().getMethod("hasCapability", int.class).invoke(nc, vpnCap)) {
                                Log.w(TAG, "ConnectivityManager: VPN capability");
                                return true;
                            }
                        }
                    }
                }
            }
        } catch (Throwable t) { /* ignore */ }
        return false;
    }
}

/** P1 字符串混淆助手（XOR）。密钥/算法与密文同源，属混淆非加密：防静态 grep，不防动态分析。 */
class Obf {
    // 密钥不再以现成明文字节数组出现：由几个整数常量在运行期拼装，
    // 逆向者需分析 deriveKey() 才能还原 XOR 密钥（比现成字节数组门槛高；
    // 本质仍是混淆非加密——DEX 内逻辑必可分析，仅提高静态扫描/jadx 成本）。
    private static final int[] K_SEED = {0x13572A6C, 0x4E1B3679, 0x0D516874, 0x2B3F4452};
    private static byte[] K;
    private static byte[] deriveKey() {
        if (K != null) return K;
        byte[] k = new byte[16];
        for (int i = 0; i < 4; i++) {
            int v = K_SEED[i];
            k[i*4]   = (byte)(v >>> 24);
            k[i*4+1] = (byte)(v >>> 16);
            k[i*4+2] = (byte)(v >>> 8);
            k[i*4+3] = (byte)v;
        }
        K = k;
        return k;
    }
    static String d(byte[] c) {
        byte[] key = deriveKey();
        char[] r = new char[c.length];
        for (int i = 0; i < c.length; i++) r[i] = (char) (c[i] ^ key[i % key.length]);
        return new String(r);
    }
}
