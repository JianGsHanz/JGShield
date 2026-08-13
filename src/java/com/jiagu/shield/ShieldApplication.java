package com.jiagu.shield;

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
import java.security.MessageDigest;
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
public class ShieldApplication extends Application {
    private static final String TAG = "JG";
    private static final String MAGIC = "JGS1";
    private static final String META_ORIG = "com.jiagu.orig_app";
    static final String PAYLOAD_ENTRY = "jg";

    // ===== 反篡改（保命版）开关 =====
    // 改为 false 并重新编译 stub.dex 即可完全关闭反篡改；响应方式 / 轮询间隔同理。
    static final boolean ANTI_TAMPER_ENABLED = true;
    // 发现篡改时的响应："exit"=静默退出进程（默认，仅在被篡改环境触发）；"none"=仅打印日志便于调试
    static final String ANTI_TAMPER_RESPONSE = "exit";
    // 后台轮询间隔（毫秒）
    static final long ANTI_TAMPER_INTERVAL_MS = 2000;

    private Application realApp;
    private boolean realOnCreateCalled = false;
    private File shellDir;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        shellDir = getDir("jgshell", Context.MODE_PRIVATE);
        try {
            AntiDebug.check();
            load(base);
        } catch (Throwable t) {
            Log.e(TAG, "init failed", t);
            if (realApp == null) {
                throw new RuntimeException("JG init failed: " + t, t);
            }
        }

        // 启动反篡改后台守护线程：与加载器完全隔离，异常不向外传播，绝不导致 App 闪退
        if (ANTI_TAMPER_ENABLED) {
            try {
                AntiTamper.start();
            } catch (Throwable t) {
                Log.w(TAG, "anti-tamper start skipped", t);
            }
        }

        // 启动 native 反篡改守护线程（下沉到 .so，更难被 hook；与 Java 层互为备份）。
        // 加载/调用全程已 try-catch，失败仅跳过 native 防护，不影响 App 启动。
        try {
            JgGuard.start();
        } catch (Throwable t) {
            Log.w(TAG, "native guard start skipped", t);
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
                List<ByteBuffer> bufs = Decryptor.decryptBuffers(base);
                Loader.injectDexFromBuffers(sysLoader, bufs);
                Log.i(TAG, "load: fileless inject OK (no plaintext on disk)");
            } catch (Throwable t) {
                Log.w(TAG, "load: fileless failed, fallback to file", t);
                List<File> dexFiles = Decryptor.decrypt(base, dexDir);
                Loader.injectDexElements(sysLoader, dexFiles);
            }
        } else {
            List<File> dexFiles = Decryptor.decrypt(base, dexDir);
            Loader.injectDexElements(sysLoader, dexFiles);
        }
        Log.i(TAG, "load: injectDexElements OK");

        restoreAssets(base);  // 自包含 try-catch，失败仅记日志、不影响启动

        Loader.setClassLoader(base, sysLoader);

        Log.i(TAG, "load: origApp=" + origApp);
        if (origApp != null && !origApp.isEmpty()
                && !origApp.equals(Application.class.getName())
                && !origApp.equals(ShieldApplication.class.getName())) {
            Class<?> cls = Class.forName(origApp, true, sysLoader);
            realApp = (Application) cls.newInstance();
            Log.i(TAG, "load: realApp=" + realApp.getClass().getName());

            Loader.swap(this, realApp);
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
            File zip = new File(getCacheDir(), "jg_assets.zip");
            String zipPath = AssetRestorer.restore(base, zip);
            if (zipPath == null) return;
            android.content.res.AssetManager am = mergeAssetManager(base, zipPath);
            if (am != null) {
                replaceAssetManager(base, am);
                Log.i(TAG, "restoreAssets: merged AssetManager OK");
            } else {
                Log.w(TAG, "restoreAssets: merge returned null (assets 可能不可用)");
            }
        } catch (Throwable t) {
            Log.w(TAG, "restoreAssets: skipped (assets may be unavailable)", t);
        }
    }

    private static android.content.res.AssetManager mergeAssetManager(Context base, String extraPath) {
        try {
            bypassHiddenApi();
            android.content.res.AssetManager am =
                (android.content.res.AssetManager) Class.forName("android.content.res.AssetManager")
                    .getDeclaredConstructor().newInstance();
            Method add = am.getClass().getDeclaredMethod("addAssetPath", String.class);
            add.setAccessible(true);
            add.invoke(am, base.getApplicationInfo().sourceDir);  // 原 APK（assets 已剥离）
            add.invoke(am, extraPath);                            // 解密后的 assets zip
            return am;
        } catch (Throwable t) {
            Log.w(TAG, "mergeAssetManager failed", t);
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
class Decryptor {
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
        byte[] seed = DeriveKeys.seed(ctx);
        String apk = ctx.getApplicationInfo().sourceDir;
        byte[] payload = readPayload(apk);
        if (payload == null || payload.length < 8) {
            throw new IllegalStateException("payload missing");
        }
        int p = 0;
        for (int i = 0; i < 4; i++) {
            if (payload[p] != (byte) "JGS1".charAt(i)) {
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
            byte[] key = DeriveKeys.keyFor(seed, "dex" + i);
            byte[] comp = aesGcmDecrypt(key, blob);
            byte[] dex = inflate(comp);
            // 原子写入：先写 .tmp，flush+close 后 rename 为 .dex，
            // 确保其他进程 mmap 时文件已完整。
            File f = new File(dexDir, "c" + i + ".dex");
            writeFileAtomic(f, dex);
            out.add(f);
        }
        return out;
    }

    /**
     * P2：fileless 解密。与 decrypt() 相同解密流程，但明文 DEX 不落盘，
     * 直接写入直接 ByteBuffer（ART 在构造 DexFile 时会拷贝进自身内存），
     * 随后把源 byte[] 清零。返回的 ByteBuffer 由 Loader 注入 sysLoader 后整体弃用。
     *
     * 安全性边界：DEX 被 ART 加载运行后，优化代码仍存在于进程内存，无法仅靠此步
     * 做到 100% 防内存 dump（那需要 native 指令抽取，属 P3）。本步关闭的是
     * “磁盘明文文件 + 启动期整段明文大块”两个泄漏点。
     */
    static List<ByteBuffer> decryptBuffers(Context ctx) throws Exception {
        byte[] seed = DeriveKeys.seed(ctx);
        String apk = ctx.getApplicationInfo().sourceDir;
        byte[] payload = readPayload(apk);
        if (payload == null || payload.length < 8) {
            throw new IllegalStateException("payload missing");
        }
        int p = 0;
        for (int i = 0; i < 4; i++) {
            if (payload[p] != (byte) "JGS1".charAt(i)) {
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
            byte[] key = DeriveKeys.keyFor(seed, "dex" + i);
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
        return out;
    }

    static byte[] readPayload(String apk) throws IOException {
        ZipFile zf = new ZipFile(apk);
        try {
            ZipEntry ze = zf.getEntry(ShieldApplication.PAYLOAD_ENTRY);
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
class AssetRestorer {
    static String restore(Context ctx, File outZip) {
        try {
            byte[] seed = DeriveKeys.seed(ctx);
            String apk = ctx.getApplicationInfo().sourceDir;
            byte[] payload = Decryptor.readPayload(apk);
            if (payload == null || payload.length < 8) return null;
            int p = 0;
            for (int i = 0; i < 4; i++) {
                if (payload[p] != (byte) "JGS1".charAt(i)) return null;
                p++;
            }
            int dexCount = Decryptor.readInt(payload, p);
            p += 4;
            for (int i = 0; i < dexCount; i++) {
                int len = Decryptor.readInt(payload, p);
                p += 4;
                p += len;
            }
            if (p + 4 > payload.length) return null;  // 无 asset 区段（旧格式/无 assets）
            int assetCount = Decryptor.readInt(payload, p);
            p += 4;
            if (assetCount <= 0) return null;
            java.util.zip.ZipOutputStream zos =
                new java.util.zip.ZipOutputStream(new java.io.FileOutputStream(outZip));
            try {
                for (int i = 0; i < assetCount; i++) {
                    int nl = Decryptor.readInt(payload, p);
                    p += 4;
                    String name = new String(payload, p, nl, "UTF-8");
                    p += nl;
                    int len = Decryptor.readInt(payload, p);
                    p += 4;
                    byte[] blob = Arrays.copyOfRange(payload, p, p + len);
                    p += len;
                    byte[] key = DeriveKeys.keyFor(seed, "asset" + i);
                    byte[] comp = Decryptor.aesGcmDecrypt(key, blob);
                    byte[] data = Decryptor.inflate(comp);
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
            Log.w("JG", "AssetRestorer.restore failed", t);
            return null;
        }
    }
}

/** 密钥派生：seed = SHA256(签名证书)，per-dex key = HMAC-SHA256(seed, info) */
class DeriveKeys {
    static byte[] seed(Context ctx) throws Exception {
        byte[] cert = certDer(ctx);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(cert);
    }

    static byte[] keyFor(byte[] seed, String info) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(seed, "HmacSHA256"));
        mac.update(("JG|" + info).getBytes("UTF-8"));
        return mac.doFinal();
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

/** 轻量反调试 / 反注入特征扫描 */
class AntiDebug {
    static void check() {
        try {
            if (Debug.isDebuggerConnected()) {
                throw new SecurityException("debugger");
            }
            scanMaps();
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) { /* 容忍扫描失败 */ }
    }

    private static void scanMaps() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"));
        String line;
        while ((line = br.readLine()) != null) {
            String l = line.toLowerCase();
            if (l.contains("frida") || l.contains("substrate") || l.contains("xposed")
                    || l.contains("libsandhook") || l.contains("libmsaoaidsec")) {
                br.close();
                throw new SecurityException("hook framework: " + line.trim());
            }
        }
        br.close();
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
 * 说明：本版 Java 层已做 fileless 加载（DEX 不落盘、源缓冲区清零，见 Decryptor.decryptBuffers /
 *      Loader.injectDexFromBuffers），关闭了“磁盘明文文件 + 启动期整段明文大块”两个泄漏点。
 *      但 DEX 一旦被 ART 加载运行，优化代码仍存在于进程内存，无法仅靠 Java 层做到 100% 防内存
 *      dump（那需要 native 指令抽取，属 P3，高风险）。本层只屏蔽用于 dump 的主流框架
 *      （Frida/Substrate/Xposed 等）；native 层由 libjgguard.so 补充。
 */
class AntiTamper {
    private static final String TAG = "JG-AT";

    // 扩展特征库：覆盖改名后的 frida-gadget / magisk / 各类 hook 框架
    private static final String[] MAP_KEYWORDS = {
        "frida", "gadget", "libfrida", "frida-agent", "substrate",
        "xposed", "libsandhook", "libmsaoaidsec", "libnativehook",
        "cydia", "magisk", "re.frida", "frida-server"
    };

    // frida-server 默认监听端口
    private static final int[] FRIDA_PORTS = {27042, 27043};

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
        t.setName("jg-anti-tamper");
        t.setDaemon(true);
        t.start();
    }

    private static void loop() {
        // 启动即查一次；之后周期轮询
        if (detect()) respond();
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(ShieldApplication.ANTI_TAMPER_INTERVAL_MS);
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
        return scanMaps() || probeFridaPorts() || checkFridaServerFile() || checkTracerPid();
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

    private static boolean probeFridaPorts() {
        for (int port : FRIDA_PORTS) {
            Socket s = null;
            try {
                s = new Socket();
                s.connect(new InetSocketAddress("127.0.0.1", port), 200);
                Log.w(TAG, "tamper: frida port " + port + " open");
                return true;
            } catch (Throwable t) {
                // 连接失败 = 未监听，属正常
            } finally {
                if (s != null) try { s.close(); } catch (Throwable ignored) {}
            }
        }
        return false;
    }

    private static boolean checkFridaServerFile() {
        try {
            if (new File("/data/local/tmp/re.frida.server").exists()) {
                Log.w(TAG, "tamper: /data/local/tmp/re.frida.server exists");
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
        if ("none".equals(ShieldApplication.ANTI_TAMPER_RESPONSE)) {
            Log.w(TAG, "tamper detected but response=none (debug mode)");
            return;
        }
        // 默认静默退出进程（仅被篡改环境触发；干净设备永远走不到这里）
        Log.w(TAG, "tamper confirmed -> System.exit");
        try { System.exit(1); } catch (Throwable ignored) {}
    }
}

/** 运行期把真实 Application 与 ClassLoader 注入到系统 */
class Loader {
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

        // 逐文件加载 DexFile + 构造 Element（绕过 makePathElements 签名差异问题）
        Class<?> elementClass = existing.getClass().getComponentType(); // dalvik.system.DexPathList$Element
        java.util.List<Object> elementList = new ArrayList<>(); // 用 Object 列表兜底泛型推断

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
                Log.w("JG", "injectDexElements: failed " + f, t);
            }
        }

        if (elementList.isEmpty()) {
            throw new IOException("injectDexElements: all dex files failed to load");
        }

        Object[] newElements = elementList.toArray(
                (Object[]) java.lang.reflect.Array.newInstance(elementClass, elementList.size()));

        // 合并：解密 DEX 在前 → 壳 DEX 在后（原 App 类优先，壳在 com.jiagu.shield 不重名）
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
     * 隐藏类会让校验器拒绝整个 Loader 类。InMemoryDexClassLoader 是 API 26+ 公开标准 API，
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
