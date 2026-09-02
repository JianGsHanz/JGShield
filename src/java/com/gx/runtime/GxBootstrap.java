package com.gx.runtime;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * P8 引导壳（双壳方案）。
 *
 * 角色：作为 APK 的 android:name 入口 Application（系统直接实例化），
 * 但**极简**——只做三件事：
 *   1) 自举加载 lib<LIB_NAME>.so（字面量，早于任何 native 调用）；
 *   2) 从加密 zip 条目 __SHELL_DEX_ENTRY__ 读出 AES-GCM 加密的 GxApp 壳 DEX，
 *      解密后用 InMemoryDexClassLoader 注入 sysLoader（无磁盘明文）；
 *   3) 反射调用 GxApp.boot(base, this) 驱动真正的壳完成原 App 解密/启动，
 *      并把返回的 realApp 收下用于生命周期转发。
 *
 * 设计约束：
 *   - 绝不引用 GxApp 内的任何类/方法（编译期静态引用会让 GxApp 必须可见，
 *     破坏"壳 DEX 加密"的隔离）；所有对 GxApp 的调用均通过 Class.forName 反射。
 *   - lib 名 / shell dex 条目名 用字面量占位，由 build_stub 替换为随机名（抹特征）。
 *   - 本类自身代码量极小、无加固逻辑，逆向价值低；真正壳逻辑(GxApp 等 12 类)
 *     加密后不在 classes.dex，jadx 拖不到。
 */
public class GxBootstrap extends Application {
    private static final String TAG = "GX-BT";
    // 占位：build_stub 替换为随机 lib 名（与 GxApp.System.loadLibrary 一致）
    private static final String LIB_NAME = "__LIB_NAME__";
    // 占位：build_stub/harden 替换为随机 zip 条目名（加密的 GxApp 壳 DEX）
    private static final String SHELL_DEX_ENTRY = "__SHELL_DEX_ENTRY__";

    private Application realApp;
    private boolean realOnCreateCalled = false;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        // 1) 自举加载 native 库（必须在任何 native 调用前；字面量，不依赖 Obf）
        try {
            System.loadLibrary(LIB_NAME);
        } catch (Throwable t) {
            Log.w(TAG, "loadLibrary skipped", t);
        }

        try {
            bootShell(base);
        } catch (Throwable t) {
            Log.e(TAG, "bootShell failed", t);
            // 启动失败且没有 realApp -> 直接崩（与原壳行为一致）
            if (realApp == null) {
                throw new RuntimeException("GX bootstrap failed: " + t, t);
            }
        }
    }

    /** 解密加密壳 DEX 并注入，驱动 GxApp.boot。 */
    @SuppressWarnings("unchecked")
    private void bootShell(Context base) throws Exception {
        ClassLoader sysLoader = getClass().getClassLoader();

        // 读加密壳 DEX（从 APK 的随机 zip 条目）
        byte[] enc = readShellDex(base);
        if (enc == null || enc.length < 28) {
            throw new IllegalStateException("shell dex missing");
        }
        // AES-256-GCM 解密（与原 GxDecryptor.aesGcmDecrypt 同算法；壳 DEX 用与 APK 同证书派生，
        // 但此处独立实现以避免依赖 GxApp 类）。使用固定派生：与原壳 seed 派生一致。
        byte[] shellDex = aesGcmDecrypt(deriveShellKey(base), enc);

        // fileless 注入 sysLoader（复用系统公开 API，无磁盘明文）
        ByteBuffer buf = ByteBuffer.allocateDirect(shellDex.length);
        buf.put(shellDex);
        buf.position(0);
        android.util.Log.i(TAG, "bootShell: inject shell dex len=" + shellDex.length);

        Class<?> bdc = Class.forName("dalvik.system.BaseDexClassLoader");
        Field fPathList = bdc.getDeclaredField("pathList");
        fPathList.setAccessible(true);
        Object pathList = fPathList.get(sysLoader);
        Class<?> dpl = pathList.getClass();
        Field fDexElements = dpl.getDeclaredField("dexElements");
        fDexElements.setAccessible(true);
        Object[] existing = (Object[]) fDexElements.get(pathList);
        if (existing == null) existing = new Object[0];

        Class<?> imdcClass = Class.forName("dalvik.system.InMemoryDexClassLoader");
        Constructor<?> imdcCtor = imdcClass.getConstructor(ByteBuffer[].class, ClassLoader.class);
        ByteBuffer[] arr = new ByteBuffer[]{buf};
        Object imdc = imdcCtor.newInstance(arr, sysLoader);
        Object imPathList = fPathList.get(imdc);
        Object[] imElements = (Object[]) fDexElements.get(imPathList);
        if (imElements == null || imElements.length == 0) {
            throw new IOException("shell InMemoryDexClassLoader produced no elements");
        }
        Class<?> elementClass = existing.getClass().getComponentType();
        Object[] merged = (Object[]) java.lang.reflect.Array.newInstance(
                elementClass, imElements.length + existing.length);
        System.arraycopy(imElements, 0, merged, 0, imElements.length);
        System.arraycopy(existing, 0, merged, imElements.length, existing.length);
        fDexElements.set(pathList, merged);

        // 2) 反射驱动真正的壳 GxApp.boot(base, this)
        Class<?> gxAppClass = Class.forName("com.gx.runtime.GxApp", true, sysLoader);
        Method bootM = gxAppClass.getMethod("boot", Context.class, Application.class);
        Object ret = bootM.invoke(null, base, this);
        if (ret instanceof Application) {
            realApp = (Application) ret;
            Log.i(TAG, "bootShell: realApp=" + realApp.getClass().getName());
        } else {
            Log.i(TAG, "bootShell: realApp=null (default Application)");
        }
    }

    /** 从 APK 读加密壳 DEX（随机条目名）。 */
    private static byte[] readShellDex(Context ctx) throws Exception {
        String apk = ctx.getApplicationInfo().sourceDir;
        ZipFile zf = new ZipFile(apk);
        try {
            ZipEntry ze = zf.getEntry(SHELL_DEX_ENTRY);
            if (ze == null) return null;
            InputStream is = zf.getInputStream(ze);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[65536];
            int n;
            while ((n = is.read(b)) > 0) bos.write(b, 0, n);
            is.close();
            return bos.toByteArray();
        } finally {
            zf.close();
        }
    }

    /**
     * 派生壳 DEX 密钥（P0-A：下沉 native 白盒 KDF，配合 OLLVM 混淆关静态路线）。
     * 纯 Java 的 HmacSHA256 派生曾被逆向报告一字不差复现（攻击路径①），故逻辑移入
     * native（Java_com_gx_runtime_GxBootstrap_nativeDeriveShellKey，位于混淆后的壳 .so）。
     * salt 不再直接取 payload 末 32B 明文，改为 HMAC(trailer, head) 融合（见 native 端
     * 与 harden.py shell_salt，二者逐字节一致）。Java 侧只负责把证书 DER 与 payload 字节
     * 交给 native，不再出现任何密钥派生常量。
     */
    private static byte[] deriveShellKey(Context ctx) throws Exception {
        byte[] payload = readPayload(ctx, "__PAYLOAD_ENTRY__");
        byte[] cert = readCertDer(ctx);
        if (payload == null || payload.length < 32 || cert == null || cert.length == 0) {
            throw new IllegalStateException("shell key material missing");
        }
        return nativeDeriveShellKey(cert, payload);
    }

    /** native 白盒壳密钥派生（jg_guard.c，编译期经 OLLVM 混淆）。 */
    private static native byte[] nativeDeriveShellKey(byte[] certDer, byte[] payload);

    private static byte[] readPayload(Context ctx, String entry) throws Exception {
        String apk = ctx.getApplicationInfo().sourceDir;
        ZipFile zf = new ZipFile(apk);
        try {
            ZipEntry ze = zf.getEntry(entry);
            if (ze == null && "z9".equals(entry)) {
                // 兜底：若随机名未替换成功，尝试旧名（不应发生）
                ze = zf.getEntry("z9");
            }
            if (ze == null) return null;
            if (ze == null) return null;
            InputStream is = zf.getInputStream(ze);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[65536];
            int n;
            while ((n = is.read(b)) > 0) bos.write(b, 0, n);
            is.close();
            return bos.toByteArray();
        } finally {
            zf.close();
        }
    }

    private static byte[] readCertDer(Context ctx) {
        // 从 APK 内 META-INF/*.RSA/.DSA 读签名证书 DER（与原 GxKeys.seed 同来源）。
        // 简化：遍历 META-INF 找第一个 .RSA/.DSA，用系统 KeyStore 解析取证书。
        try {
            String apk = ctx.getApplicationInfo().sourceDir;
            ZipFile zf = new ZipFile(apk);
            try {
                for (java.util.Enumeration<? extends ZipEntry> e = zf.entries(); e.hasMoreElements(); ) {
                    ZipEntry ze = e.nextElement();
                    String nm = ze.getName();
                    if (nm.startsWith("META-INF/") && (nm.endsWith(".RSA") || nm.endsWith(".DSA"))) {
                        InputStream is = zf.getInputStream(ze);
                        java.security.cert.CertificateFactory cf =
                                java.security.cert.CertificateFactory.getInstance("X.509");
                        java.security.cert.X509Certificate c =
                                (java.security.cert.X509Certificate) cf.generateCertificate(is);
                        is.close();
                        return c.getEncoded();
                    }
                }
            } finally {
                zf.close();
            }
        } catch (Throwable t) {
            Log.w(TAG, "readCertDer failed", t);
        }
        return new byte[0];
    }

    private static byte[] aesGcmDecrypt(byte[] key, byte[] blob) throws Exception {
        if (blob.length < 28) throw new IllegalStateException("blob too short");
        byte[] iv = java.util.Arrays.copyOfRange(blob, 0, 12);
        byte[] rest = java.util.Arrays.copyOfRange(blob, 12, blob.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return c.doFinal(rest);
    }

    // ===== 生命周期转发给 realApp（系统只认 Bootstrap 为 Application）=====
    @Override
    public void onCreate() {
        super.onCreate();
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
    public void onConfigurationChanged(android.content.res.Configuration c) {
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
