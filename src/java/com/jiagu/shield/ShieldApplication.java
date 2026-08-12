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
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.lang.ref.WeakReference;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

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
    }

    private void load(Context base) throws Exception {
        String origApp = readMeta(base, META_ORIG);
        File dexDir = new File(shellDir, "dex");
        if (!dexDir.exists()) dexDir.mkdirs();

        List<File> dexFiles = Decryptor.decrypt(base, dexDir);
        Log.i(TAG, "load: dexFiles=" + dexFiles.size());

        ClassLoader sysLoader = getClass().getClassLoader();
        Loader.injectDexElements(sysLoader, dexFiles);
        Log.i(TAG, "load: injectDexElements OK");

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

    private static byte[] readPayload(String apk) throws IOException {
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

    private static byte[] aesGcmDecrypt(byte[] key, byte[] blob) throws Exception {
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
