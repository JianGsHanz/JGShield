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
public class GxApp extends Application {
    private static final String TAG = "GX";
    static final String MAGIC = Obf.d(new byte[]{0x59, 0x10, 0x79, 0x5D});
    private static final String META_ORIG = "gx.orig_app";
    static final String PAYLOAD_ENTRY = "z9";

    // ===== 反篡改（保命版）开关 =====
    // 改为 false 并重新编译 stub.dex 即可完全关闭反篡改；响应方式 / 轮询间隔同理。
    static final boolean ANTI_TAMPER_ENABLED = true;
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

    private Application realApp;
    private boolean realOnCreateCalled = false;
    private File shellDir;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        shellDir = getDir("gxshell", Context.MODE_PRIVATE);

        // P-CAPTURE 统一响应姿态：优先从加固期注入的 manifest meta 读取（默认 log，fail-safe）。
        // 必须在 GxGuard.configureResponse() 之前设置，确保 native 守护线程拿到正确姿态。
        try {
            android.os.Bundle mb = base.getPackageManager()
                    .getApplicationInfo(base.getPackageName(),
                            android.content.pm.PackageManager.GET_META_DATA).metaData;
            if (mb != null) {
                String s = mb.getString("gx.strengthen");
                if ("exit".equals(s) || "log".equals(s)) STRENGTHEN_RESPONSE = s;
            }
        } catch (Throwable ignored) {}

        // 必须在调用任何依赖 libjgguard.so 的 native 方法前加载该库
        // （P3 的 nativeRestoreInit / nativeRestoreMethods 与本壳反篡改都依赖它）。
        // 否则 decryptBuffers 内的 native 还原调用会抛 UnsatisfiedLinkError 被 catch 吞掉，
        // 导致 DEX 始终停在 NOP 化状态、ART 因校验和失效拒载。
        GxGuard.ensureLoaded();
        GxGuard.configureResponse();   // 把统一响应开关传给 native（在 native 守护线程启动前）
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
            load(base);
        } catch (Throwable t) {
            Log.e(TAG, "init failed", t);
            if (realApp == null) {
                throw new RuntimeException("GX init failed: " + t, t);
            }
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
    }

    private void load(Context base) throws Exception {
        String origApp = readMeta(base, META_ORIG);
        File dexDir = new File(shellDir, "dex");
        if (!dexDir.exists()) dexDir.mkdirs();

        ClassLoader sysLoader = getClass().getClassLoader();

        // P2：fileless 内存加载（API>=26）。解密进 ByteBuffer 直接注入 sysLoader，
        // 磁盘不落明文文件；解密后源 byte[] 立即清零。失败（含 OEM 限制）自动回退文件方案。
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            try {
                List<ByteBuffer> bufs = GxDecryptor.decryptBuffers(base);
                GxLoader.injectDexFromBuffers(sysLoader, bufs);
                Log.i(TAG, "load: fileless inject OK (no plaintext on disk)");
            } catch (Throwable t) {
                Log.w(TAG, "load: fileless failed, fallback to file", t);
                List<File> dexFiles = GxDecryptor.decrypt(base, dexDir);
                GxLoader.injectDexElements(sysLoader, dexFiles);
            }
        } else {
            List<File> dexFiles = GxDecryptor.decrypt(base, dexDir);
            GxLoader.injectDexElements(sysLoader, dexFiles);
        }
        Log.i(TAG, "load: injectDexElements OK");

        restoreAssets(base);  // 自包含 try-catch，失败仅记日志、不影响启动

        GxLoader.setClassLoader(base, sysLoader);

        Log.i(TAG, "load: origApp=" + origApp);
        if (origApp != null && !origApp.isEmpty()
                && !origApp.equals(Application.class.getName())
                && !origApp.equals(GxApp.class.getName())) {
            Class<?> cls = Class.forName(origApp, true, sysLoader);
            realApp = (Application) cls.newInstance();
            Log.i(TAG, "load: realApp=" + realApp.getClass().getName());

            GxLoader.swap(this, realApp);
            Log.i(TAG, "load: swap OK");

            Method attach = Application.class.getDeclaredMethod("attach", Context.class);
            attach.setAccessible(true);
            attach.invoke(realApp, base);
            Log.i(TAG, "load: attach OK");

            // 同步调用 realApp.onCreate()——不依赖系统 callApplicationOnCreate（EMUI 可能跳过）
            try {
                realOnCreateCalled = true;
                realApp.onCreate();
                Log.i(TAG, "load: realApp.onCreate() OK");
            } catch (Throwable t) {
                Log.e(TAG, "load: realApp.onCreate() FAILED", t);
            }
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

    // ===== 资产运行时还原（关闭 APK 内 assets 明文）=====
    // 自包含：任何异常都只记日志、绝不外抛，避免影响 App 启动。
    // 解密后的 assets 写入应用私有目录的 zip（非公开可读），仅关闭 APK 内明文泄漏。
    private void restoreAssets(Context base) {
        try {
            File zip = new File(getCacheDir(), "gx_assets.zip");
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

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "onCreate: called, realApp=" + (realApp != null ? realApp.getClass().getName() : "null") + " realOnCreateCalled=" + realOnCreateCalled);
        if (realApp != null && !realOnCreateCalled) {
            realOnCreateCalled = true;
            try {
                realApp.onCreate();
                Log.i(TAG, "onCreate: realApp.onCreate() OK");
            } catch (Throwable t) {
                Log.e(TAG, "onCreate: realApp.onCreate() FAILED", t);
            }
        }
    }

    @Override
    public void onConfigurationChanged(Configuration c) {
        super.onConfigurationChanged(c);
        if (realApp != null) realApp.onConfigurationChanged(c);
    }

    @Override
    public void onLowMemory() {
        super.onLowMemory();
        if (realApp != null) realApp.onLowMemory();
    }

    @Override
    public void onTrimMemory(int l) {
        super.onTrimMemory(l);
        if (realApp != null) realApp.onTrimMemory(l);
    }

    @Override
    public void onTerminate() {
        super.onTerminate();
        if (realApp != null) realApp.onTerminate();
    }
}

/** 解密 + 解压原始 DEX 区段 */
class GxDecryptor {
    /** 方法级指令还原总开关（P3）。
     *  默认关闭。开启需先重编 libjgguard.so（含 jg_method_restore*.c / jg_inline_hook*），
     *  且仅在真机验证通过后使用。 */
    static final boolean METHOD_RESTORE_ENABLED = true;

    /** 还原模式：
     *  false = 整包批量还原（P3.2，nativeRestoreMethods）。写回发生在 DEX 交给
     *         InMemoryDexClassLoader 之前，无论 ART 是否拷贝 ByteBuffer 都保证运行期
     *         指令正确 —— 安全默认。代价：内存中存在完整明文 DEX（抗 dump 较弱）。
     *  true  = 解释桥惰性还原（P3.3，nativeRestoreInit + inline hook）。方法仅在首次被
     *         解释执行前于运行期还原，内存抗 dump 最强。
     *         前置条件：ART 必须原地使用 direct ByteBuffer（不拷贝）才生效；若设备 ART 在
     *         构造 InMemoryDexClassLoader 时拷贝了 Buffer，惰性还原不会触发、App 会在首个
     *         抽取方法处崩溃 —— 故须先在真机 logcat 确认有 JG-MethodRestoreHook [restore]
     *         日志后再开启。hook 安装失败会自动回退批量还原。
     *  ⚠ Android 9 及其它急切校验 ROM 的根本限制（2026-08-17 小米 MIX2 Android9 实测）：
     *         ART 在 DefineClass 阶段就急切校验类的全部方法（发生在任何解释执行之前）。
     *         NOP 化方法体末尾无 return/throw 终结指令 → VerifyError "Execution can walk
     *         off end of code area" → 类校验失败、App 启动即崩。此时 inline hook 虽已成功
     *         安装(realMode=1)，但校验早于解释执行，hook 永不触发（[dbg] handler 为空）。
     *         结论：真惰性还原与急切校验架构不兼容，需 hook ART 校验器(VerifyClass/改
     *         mirror::Class 状态)才能绕过——ROM 极脆弱，暂不采用。故生产默认用 false(批量)。
     *         lazy=true 仅适用于校验被延迟/hook 落在执行路径上的机型(部分 Android 10+)。 */
    static final boolean METHOD_RESTORE_LAZY = false;

    /** P3.2 JNI 入口：把 NOP 版 DEX 直接缓冲区整体解密写回（批量，安全默认路径）。 */
    public static native int nativeRestoreMethods(java.nio.ByteBuffer dexBuf, byte[] payload, byte[] seed, int dexIdx);

    /** P3.3 JNI 入口：注册 DEX 内存区间 + 尝试安装解释桥 inline hook（惰性还原）。
     *  返回 1=惰性还原模式生效; 0=hook 不可用已回退批量还原。 */
    public static native int nativeRestoreInit(int dexIdx, java.nio.ByteBuffer dexBuf, byte[] payload, byte[] seed);

    /** P-INTEGRITY JNI 入口：还原后自校验——逐方法解密载荷并与内存 live dex 比对，
     *  返回不匹配方法数（0 表示还原正确 / 未被篡改）。maxPerDex>0 抽样（启动期用），-1 全量。
     *  fail-safe：错误返回负值。 */
    public static native int nativeVerifyDex(java.nio.ByteBuffer dexBuf, byte[] payload, byte[] seed, int dexIdx, int maxPerDex);
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
                    int realMode = 0;   /* native 返回：1=惰性 hook(P3.3); 0=回退批量(P3.2) */
                    if (METHOD_RESTORE_LAZY) {
                        realMode = nativeRestoreInit(i, buf, payload, seed);
                    } else {
                        nativeRestoreMethods(buf, payload, seed, i);
                    }
                    buf.position(0);
                    Log.i("GX", "method restore effective mode="
                            + (!METHOD_RESTORE_LAZY ? "batch(P3.2)"
                                : (realMode == 1 ? "lazy-hook ACTIVE(P3.3)"
                                    : "lazy unavailable -> batch FALLBACK(P3.2)"))
                            + " on dex[" + i + "] (file path <26)");
                } catch (Throwable t) {
                    Log.w("GX", "method restore skipped dex[" + i + "] (file path <26)", t);
                }
                try {
                    fixDexChecksum(buf);
                } catch (Throwable t) {
                    Log.w("GX", "fixDexChecksum skipped dex[" + i + "] (file path <26)", t);
                }
                // P-INTEGRITY：还原后自校验（抽样），fail-safe
                try {
                    int mism = nativeVerifyDex(buf, payload, seed, i, 64);
                    Log.i("GX", "integrity dex_idx=" + i + " mismatches=" + mism + " (file path <26)");
                } catch (Throwable t) {
                    Log.w("GX", "integrity check skipped dex[" + i + "] (file path <26)", t);
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
            out.add(buf);
        }
        // P3 方法还原接入点（受 METHOD_RESTORE_ENABLED 总开关控制，fail-safe）。
        // 默认 lazy=false -> 整包批量还原（P3.2，安全）；lazy=true -> 解释桥惰性还原（P3.3）。
        if (METHOD_RESTORE_ENABLED) {
            try {
                int realMode = 0;   /* native 返回：1=惰性 hook 生效(P3.3); 0=回退批量(P3.2) */
                for (int i = 0; i < out.size(); i++) {
                    ByteBuffer buf = out.get(i);
                    buf.position(0);
                    if (METHOD_RESTORE_LAZY) {
                        realMode = nativeRestoreInit(i, buf, payload, seed);
                    } else {
                        nativeRestoreMethods(buf, payload, seed, i);
                    }
                    buf.position(0);
                }
                String mode = !METHOD_RESTORE_LAZY ? "batch(P3.2)"
                        : (realMode == 1 ? "lazy-hook ACTIVE(P3.3)" : "lazy unavailable -> batch FALLBACK(P3.2)");
                Log.i("GX", "method restore effective mode=" + mode + " on " + out.size() + " dex buffer(s)");
            } catch (Throwable t) {
                Log.w("GX", "method restore skipped", t);
            }
            // P3 抽取后 DEX 指令被 NOP 化，但加固期未重算 DEX 头校验和，ART 加载会因
            // Bad checksum 拒载。此处按当前缓冲区内容重算 checksum(偏移8, adler32[12:])
            // 与 signature(偏移12, sha1[32:])，使 NOP 化 DEX 可通过加载期校验。
            // P3.2 整包还原写回原指令后同样需重算以匹配还原后的内容。
            for (int i = 0; i < out.size(); i++) {
                fixDexChecksum(out.get(i));
            }
            // P-INTEGRITY：DEX 还原后自校验——抽样解密载荷并与内存 live dex 比对，
            // 不匹配数 >0 表示还原失败或已被篡改。采样上限控制主线程耗时，避免启动期 ANR。
            // fail-safe：异常仅记日志不阻断启动。
            for (int i = 0; i < out.size(); i++) {
                try {
                    int mism = nativeVerifyDex(out.get(i), payload, seed, i, 64);
                    Log.i("GX", "integrity dex_idx=" + i + " mismatches=" + mism);
                } catch (Throwable t) {
                    Log.w("GX", "integrity check skipped dex " + i, t);
                }
            }
        }
        return out;
    }

    /** 重算 DEX 头校验和：checksum(偏移8)=adler32(data[12:])，signature(偏移12)=sha1(data[32:])。
     *  失败静默跳过（不抛异常），交还给上层 fail-safe。 */
    private static void fixDexChecksum(ByteBuffer buf) {
        if (buf == null) return;
        int len = buf.capacity();
        if (len < 32) return;
        ByteOrder bo = buf.order();
        buf.order(ByteOrder.LITTLE_ENDIAN);
        try {
            /* ART 以 DEX 头 file_size(偏移32) 为校验和/签名覆盖边界，必须与之完全一致，
             * 否则即使内容正确，ART 计算的 adler32 范围也不同 -> Bad checksum。 */
            int fileSize = buf.getInt(32);
            if (fileSize <= 12 || fileSize > len) fileSize = len;
            /* 顺序必须：先写签名，再算校验和（与 ART 校验器一致）。
             * ART 校验时 adler32 覆盖 [12, fs)（含 [12,32) 的签名区），SHA-1 覆盖 [32, fs)。
             * 故先算 SHA-1([32,fs)) 写入 [12,32)，再算 adler32([12,fs))（此时已含新签名）写 [8,12)。 */
            byte[] sigSrc = new byte[fileSize - 32];
            buf.position(32); buf.get(sigSrc);
            byte[] sig = java.security.MessageDigest.getInstance("SHA-1").digest(sigSrc);
            buf.position(12); buf.put(sig);
            byte[] tail = new byte[fileSize - 12];
            buf.position(12); buf.get(tail);
            java.util.zip.Adler32 adler = new java.util.zip.Adler32();
            adler.update(tail);
            buf.putInt(8, (int) (adler.getValue() & 0xffffffffL));
    } catch (Throwable t) {
        Log.w("GX", "fixDexChecksum skipped", t);
    } finally {
        buf.order(bo);
        buf.position(0);
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
        Obf.d(new byte[]{0x6B, 0x27, 0x45, 0x1F, 0x2B, 0x7F}), Obf.d(new byte[]{0x7F, 0x3E, 0x48, 0x1F, 0x2F, 0x75, 0x52, 0x11, 0x62, 0x3E, 0x03}), Obf.d(new byte[]{0x7F, 0x3E, 0x48, 0x01, 0x3D, 0x7A, 0x59, 0x18, 0x64, 0x35, 0x1B, 0x11, 0x48}), Obf.d(new byte[]{0x7F, 0x3E, 0x48, 0x02, 0x2F, 0x6F, 0x5F, 0x0F, 0x68, 0x39, 0x07, 0x1B, 0x40}),
        Obf.d(new byte[]{0x70, 0x2E, 0x4E, 0x05, 0x2F}), Obf.d(new byte[]{0x7E, 0x36, 0x4D, 0x05, 0x3D, 0x70}), Obf.d(new byte[]{0x61, 0x32, 0x04, 0x0A, 0x3C, 0x72, 0x52, 0x18}), Obf.d(new byte[]{0x75, 0x25, 0x43, 0x08, 0x2F, 0x36, 0x45, 0x1C, 0x7F, 0x27, 0x0D, 0x06})
    };

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
        // 启动即查一次；之后周期轮询
        if (detect()) respond();
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(GxApp.ANTI_TAMPER_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (detect()) {
                respond();
                // respond() 在默认 "exit" 模式下已退出进程；"none" 模式则继续轮询
            }
        }
    }

    /** 综合检测，任一命中即视为被篡改。每个子检测独立 try-catch，互不影响。 */
    private static boolean detect() {
        return scanMaps() || probePorts() || checkServerFile() || checkTracerPid();
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

    private static boolean checkTracerPid() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    int pid = Integer.parseInt(line.split(":")[1].trim());
                    if (pid != 0) {
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
        Log.w(TAG, "tamper confirmed -> System.exit");
        try { System.exit(1); } catch (Throwable ignored) {}
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
    private static final long INTERVAL_MS = 2000;
    private static volatile java.io.File appDataDir;   // /data/data/<pkg>

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
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (detect()) respond();
        }
    }

    /** 综合检测，任一命中即视为正在被脱壳。每个子检测独立 try-catch，互不影响。 */
    private static boolean detect() {
        return dumpDirsExist() || localTmpMarkers();
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

    private static void respond() {
        // 统一收口到 STRENGTHEN_RESPONSE（与 GxTamper / GxAntiDebug / native jg_guard 一致）。
        if (!"exit".equals(GxApp.STRENGTHEN_RESPONSE)) {
            Log.w(TAG, "anti-dump hit but STRENGTHEN_RESPONSE="
                    + GxApp.STRENGTHEN_RESPONSE + " (log-only)");
            return;
        }
        Log.w(TAG, "anti-dump confirmed -> System.exit");
        try { System.exit(1); } catch (Throwable ignored) {}
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
     * 将解密出的原始 DEX 文件注入到框架 ClassLoader 的 DexPathList.dexElements 中。
     * 替代新建 PathClassLoader 方案，使原 App 与壳共享 ClassLoader 及原生库命名空间。
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
     * 因此磁盘不落明文），再偷取其 dexElements 注入 sysLoader 的 pathList。
     * 定义加载器仍是 sysLoader（Element 在其 pathList 内），原生库命名空间不变（方案 B 延续）。
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
 * 命中且 STRENGTHEN_RESPONSE=exit 则杀进程（⚠ 不推荐：会误杀正常 VPN/海外用户，仅限明确接受该代价的场景）；
 * 否则仅记日志（fail-safe，避免误杀正常 VPN 用户）。默认姿态为 log，永不阻断。
 */
class GxProxy {
    private static final String TAG = "GX-VPN";

    static void check(Context ctx) {
        try {
            if (detected(ctx)) {
                boolean block = "exit".equals(GxApp.STRENGTHEN_RESPONSE);
                Log.w(TAG, "proxy/vpn detected -> " + (block ? "block" : "log-only"));
                if (block) {
                    throw new SecurityException("proxy/vpn tunnel active (possible MITM)");
                }
            }
        } catch (SecurityException se) {
            throw se;
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
