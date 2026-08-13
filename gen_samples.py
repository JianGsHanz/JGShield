# -*- coding: utf-8 -*-
"""
gen_samples.py —— 生成约 10 个结构多样的测试 APK，用于端到端加固回测。

覆盖分支：
  - 是否含自定义 Application
  - 单 DEX / 多 DEX（classes2.dex，跨 DEX 引用 Helper）
  - 是否含 assets/ 与 lib/ 原生库（检验加固后不被丢弃）
样本统一用 aapt 打包 + dx 转 DEX + uber-apk-signer(common.jks) 签名。
"""
import os
import sys
import time
import shutil
import argparse

import config
from harden import run, env_with_android

SAMPLES = [
    dict(n=1,  custom=False, dexs=1, assets=False, native=False),
    dict(n=2,  custom=False, dexs=1, assets=False, native=False),
    dict(n=3,  custom=False, dexs=1, assets=True,  native=False),
    dict(n=4,  custom=True,  dexs=1, assets=False, native=False),
    dict(n=5,  custom=True,  dexs=1, assets=False, native=False),
    dict(n=6,  custom=True,  dexs=1, assets=True,  native=False),
    dict(n=7,  custom=False, dexs=2, assets=False, native=False),
    dict(n=8,  custom=True,  dexs=2, assets=False, native=False),
    dict(n=9,  custom=True,  dexs=2, assets=True,  native=True),
    dict(n=10, custom=False, dexs=1, assets=True,  native=True),
]

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{pkg}"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
    <application android:label="@string/app_name"{appattr}>
        <activity android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

STRINGS = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">JG Sample {n}</string>
</resources>
"""

def java_main(pkg, n, helper):
    hc = ' + " | " + Helper.greet()' if helper else ''
    return ("""package {pkg};

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        String msg = "Hello JG #" + {n}{hc};
        tv.setText(msg);
        setContentView(tv);
    }}
}}
""").format(pkg=pkg, n=n, hc=hc)

def java_app(pkg, n):
    return """package {pkg};

import android.app.Application;
import android.util.Log;

public class App{n} extends Application {{
    @Override
    public void onCreate() {{
        super.onCreate();
        Log.i("JG", "sample {n} custom Application started");
    }}
}}
""".format(pkg=pkg, n=n)

def java_helper(pkg):
    return """package {pkg};

public class Helper {{
    public static String greet() {{
        return "from helper dex";
    }}
}}
""".format(pkg=pkg)

def build_one(s, base_work, out_dir):
    n = s["n"]
    pkg = "com.jiagu.sample%d" % n
    w = os.path.join(base_work, "s%d_%d" % (n, int(time.time() * 1000)))
    config.rmtree_safe(w)
    os.makedirs(w, exist_ok=True)
    src = os.path.join(w, "src", "com", "jiagu", "sample%d" % n)
    os.makedirs(src, exist_ok=True)
    cls = os.path.join(w, "classes")
    os.makedirs(cls, exist_ok=True)

    # ---- 资源 ----
    res = os.path.join(w, "res", "values")
    os.makedirs(res, exist_ok=True)
    open(os.path.join(res, "strings.xml"), "w", encoding="utf-8").write(STRINGS.format(n=n))
    # ---- Manifest ----
    appattr = ""
    if s["custom"]:
        appattr = ' android:name=".App%d"' % n
    open(os.path.join(w, "AndroidManifest.xml"), "w", encoding="utf-8").write(
        MANIFEST.format(pkg=pkg, appattr=appattr))

    # ---- Java 源 ----
    open(os.path.join(src, "MainActivity.java"), "w", encoding="utf-8").write(
        java_main(pkg, n, helper=(s["dexs"] == 2)))
    if s["custom"]:
        open(os.path.join(src, "App%d.java" % n), "w", encoding="utf-8").write(java_app(pkg, n))
    if s["dexs"] == 2:
        open(os.path.join(src, "Helper.java"), "w", encoding="utf-8").write(java_helper(pkg))

    # ---- 编译 + dx ----
    javac_bin = config.JAVAC
    if s["dexs"] == 1:
        javac = [javac_bin, "--release", "8", "-cp", config.ANDROID_JAR,
                 "-d", cls, os.path.join(src, "MainActivity.java")]
        if s["custom"]:
            javac.append(os.path.join(src, "App%d.java" % n))
        run(javac, env=env_with_android())
        run([config.JAVA, "-jar", config.DX, "--dex",
             "--output=" + os.path.join(w, "classes.dex"), cls],
            env=env_with_android())
    else:
        # 多 DEX：Helper 单独编译，MainActivity(+App) 编译时仅把 Helper 作为 classpath，
        # 这样主 DEX 不含 Helper.class，避免重复定义。
        helper_cls = os.path.join(w, "classes_helper_src")
        main_cls = os.path.join(w, "classes_main_src")
        os.makedirs(helper_cls, exist_ok=True)
        os.makedirs(main_cls, exist_ok=True)
        run([javac_bin, "--release", "8", "-cp", config.ANDROID_JAR,
             "-d", helper_cls, os.path.join(src, "Helper.java")],
            env=env_with_android())
        javac = [javac_bin, "--release", "8",
                 "-cp", config.ANDROID_JAR + os.pathsep + helper_cls,
                 "-d", main_cls, os.path.join(src, "MainActivity.java")]
        if s["custom"]:
            javac.append(os.path.join(src, "App%d.java" % n))
        run(javac, env=env_with_android())
        run([config.JAVA, "-jar", config.DX, "--dex",
             "--output=" + os.path.join(w, "classes.dex"), main_cls],
            env=env_with_android())
        run([config.JAVA, "-jar", config.DX, "--dex",
             "--output=" + os.path.join(w, "classes2.dex"), helper_cls],
            env=env_with_android())

    # ---- aapt 打包 ----
    unsigned = os.path.join(w, "unsigned.apk")
    run([config.AAPT, "package", "-f", "-M", os.path.join(w, "AndroidManifest.xml"),
         "-S", os.path.join(w, "res"), "-I", config.ANDROID_JAR, "-F", unsigned],
        env=env_with_android())

    # ---- 加入 DEX（aapt add 以给定路径作为 zip 入口名，必须用相对路径）----
    add_files = ["classes.dex"]
    if s["dexs"] == 2:
        add_files.append("classes2.dex")
    # ---- assets / native ----
    if s["assets"]:
        adir = os.path.join(w, "assets")
        os.makedirs(adir, exist_ok=True)
        open(os.path.join(adir, "hello.txt"), "w", encoding="utf-8").write(
            "JG sample %d asset" % n)
        add_files.append("assets/hello.txt")
    if s["native"]:
        ldir = os.path.join(w, "lib", "arm64-v8a")
        os.makedirs(ldir, exist_ok=True)
        with open(os.path.join(ldir, "libjgtest.so"), "wb") as f:
            f.write(b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 64)
        add_files.append("lib/arm64-v8a/libjgtest.so")

    run([config.AAPT, "add", "-f", unsigned] + add_files, cwd=w, env=env_with_android())

    # ---- 签名 ----
    sign_dir = os.path.join(w, "signed")
    os.makedirs(sign_dir, exist_ok=True)
    for f in os.listdir(sign_dir):
        try: os.remove(os.path.join(sign_dir, f))
        except OSError: pass
    run([config.JAVA, "-jar", config.UBER, "--apks", unsigned,
         "--ks", config.KEYSTORE, "--ksAlias", config.KEY_ALIAS,
         "--ksPass", config.KEY_PASS, "--ksKeyPass", config.KEY_PASS,
         "--out", sign_dir], env=env_with_android())
    cands = [os.path.join(sign_dir, f) for f in os.listdir(sign_dir)
             if f.endswith((".apk")) and ("aligned-signed" in f or "signed" in f)]
    out_apk = os.path.join(out_dir, "sample%d.apk" % n)
    shutil.copyfile(cands[0], out_apk)
    print("  生成样本 sample%d.apk  -> %s" % (n, out_apk))
    return out_apk

def main():
    ap = argparse.ArgumentParser(description="生成测试 APK 样本")
    ap.add_argument("--count", type=int, default=len(SAMPLES), help="生成数量(默认全部)")
    args = ap.parse_args()
    out_dir = config.SAMPLES_DIR
    os.makedirs(out_dir, exist_ok=True)
    base_work = os.path.join(config.GEN_DIR, "build")
    os.makedirs(base_work, exist_ok=True)
    count = min(args.count, len(SAMPLES))
    print("生成 %d 个测试 APK 到 %s" % (count, out_dir))
    for s in SAMPLES[:count]:
        build_one(s, base_work, out_dir)
    print("完成。")

if __name__ == "__main__":
    main()
