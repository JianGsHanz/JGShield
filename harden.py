# -*- coding: utf-8 -*-
"""
JGShield 加固核心：对单个 APK 做差异化加壳。

流程（方向B，二进制 Manifest 编辑 + zip 直打包，不经过 apktool）：
  1. 抽取原始 classes*.dex
  2. 二进制编辑 AndroidManifest.xml（直接改 AXML，不解码/重编资源）
  3. 构建加密载荷：DEFLATE + AES-256-GCM（seed=SHA256(签名证书DER)）
  4. zip 直打包：原资源 + patched Manifest + stub.dex(classses.dex) + jg 载荷
  5. 签名对齐
  6. 内嵌回测
"""
import os
import time
import re
import sys
import struct
import shutil
import zipfile
import subprocess
import argparse
import traceback

import config
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from axml_editor import patch_manifest as _axml_patch
from axml_editor import get_orig_app_class as _axml_get_orig

# --------------------------------------------------------------------------
# 工具函数
# --------------------------------------------------------------------------
# 这些参数后面跟的“值”是密码，打印/回显时必须脱敏
_PASSWORD_KEYS = ("--ksPass", "--ksKeyPass", "--storepass", "--keypass")

def _format_args(cmd):
    """把命令列表格式化为可读字符串，密码值显示为 ***。"""
    out = []
    i = 0
    while i < len(cmd):
        c = cmd[i]
        if c in _PASSWORD_KEYS and i + 1 < len(cmd):
            out.append(c)
            out.append("***")
            i += 2
            continue
        out.append('"%s"' % c if " " in c else c)
        i += 1
    return " ".join(out)

class _RunResult:
    """兼容 subprocess.CompletedProcess：保留 returncode / stdout 供调用方检查。"""
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""

def run(cmd, cwd=None, env=None, check=True):
    """流式执行：子进程输出边产生边打印，保证 GUI 实时显示；
    同时累积 stdout 供调用方检查，并打印该命令耗时。"""
    print(">>", _format_args(cmd) if isinstance(cmd, list) else cmd, flush=True)
    t0 = time.time()
    p = subprocess.Popen(cmd, cwd=cwd, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace", bufsize=1)
    buf = []
    for line in p.stdout:
        line = line.rstrip("\r\n")
        buf.append(line)
        print(line, flush=True)   # 实时刷新（配合 PYTHONUNBUFFERED 生效）
    rc = p.wait()
    dt = time.time() - t0
    print("[耗时 %.2fs] %s" % (dt, cmd[0] if isinstance(cmd, list) else cmd), flush=True)
    if rc != 0 and check:
        raise RuntimeError("命令失败 (rc=%d): %s" % (rc, cmd[0]))
    return _RunResult(rc, "\n".join(buf))

def _lap(sw, label):
    """打印从上次 lap 到现在的用时（秒），并重置计时点。"""
    now = time.time()
    dt = now - sw["t"]
    sw["t"] = now
    print("[阶段 %-12s 用时 %.2fs]" % (label, dt), flush=True)
    return dt

def env_with_android():
    e = dict(os.environ)
    e["ANDROID_HOME"] = config.SIGN_FRAMEWORK
    e["ANDROID_SDK_ROOT"] = config.SIGN_FRAMEWORK
    return e

def _short_work(base):
    """生成短路径工作目录，规避 Windows 260 字符路径限制。

    apktool 解码大包时，解码后 res/ 目录的绝对路径若超过 260 字符，
    Java 的 File.listFiles() 会返回含 null 的数组，apktool 排序时抛
    NullPointerException 导致解码失败（与是否 --no-src 无关，是 apktool
    3.0.1 在长路径下的固有 bug）。用短 token 代替长 base 名即可规避。
    """
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_wk")
    os.makedirs(root, exist_ok=True)
    token = "h%d_%d" % (os.getpid(), int(time.time() * 1000) % 1000000)
    return os.path.join(root, token)

# --------------------------------------------------------------------------
# 密钥派生 & 加密（与 ShieldApplication.java 完全对应）
# --------------------------------------------------------------------------
def extract_cert_der(ks, alias, storepass):
    """从用户 keystore 提取签名证书 DER（keytool -exportcert）。
    种子 = SHA256(此证书)，必须与最终签名所用证书一致，否则设备端解密失败。"""
    import tempfile
    print("[*] 从密钥库提取签名证书: %s (alias=%s)" % (ks, alias), flush=True)
    fd, der = tempfile.mkstemp(suffix=".der")
    os.close(fd)
    try:
        base = [config.KEYTOOL, "-exportcert", "-keystore", ks,
                "-alias", alias, "-storepass", storepass, "-noprompt", "-file", der]
        if ks.lower().endswith((".p12", ".pfx")):
            base += ["-storetype", "PKCS12"]
        try:
            subprocess.run(base, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", check=True,
                           env=env_with_android())
        except subprocess.CalledProcessError:
            # 部分 keystore 需显式声明类型，重试
            subprocess.run(base + ["-storetype", "PKCS12"], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", check=True,
                           env=env_with_android())
        with open(der, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(der)
        except OSError:
            pass

def load_seed(ks=None, ks_alias=None, ks_pass=None):
    """派生种子：优先用用户指定的 keystore 证书，否则回退内置 common.cer。"""
    if ks and os.path.isfile(ks):
        cert = extract_cert_der(ks, ks_alias or config.KEY_ALIAS,
                                ks_pass or config.KEY_PASS)
    else:
        with open(config.CERT_DER, "rb") as f:
            cert = f.read()
    return SHA256.new(cert).digest()

def derive_key(seed, idx):
    mac = HMAC.new(seed, digestmod=SHA256)
    mac.update(b"JG|dex" + str(idx).encode("utf-8"))
    return mac.digest()  # 32 bytes -> AES-256

def encrypt_dex(seed, idx, dex_bytes):
    comp = zlib_compress(dex_bytes)          # zlib 格式，对应 Java Inflater() 无参
    key = derive_key(seed, idx)
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(comp)
    return iv + ct + tag

def build_payload(seed, dex_list):
    out = bytearray()
    out += config.MAGIC
    out += struct.pack("<I", len(dex_list))
    for i, d in enumerate(dex_list):
        blob = encrypt_dex(seed, i, d)
        out += struct.pack("<I", len(blob))
        out += blob
    return bytes(out)

def zlib_compress(data):
    import zlib
    return zlib.compress(data, 9)

# --------------------------------------------------------------------------
# 原始 DEX 收集
# --------------------------------------------------------------------------
def list_original_dexes(apk_path):
    with zipfile.ZipFile(apk_path) as z:
        names = [n for n in z.namelist() if re.match(r"classes(\d*)\.dex$", n)]
    def key(n):
        m = re.match(r"classes(\d*)\.dex$", n)
        num = m.group(1)
        return (0, 0) if num == "" else (1, int(num))
    names.sort(key=key)
    return names

def read_dexes(apk_path, names):
    out = []
    with zipfile.ZipFile(apk_path) as z:
        for n in names:
            out.append(z.read(n))
    return out

# --------------------------------------------------------------------------
# Manifest 改写（【已弃用】）
# 这是早期基于正则的文本流改写方案，已被 axml_editor.py 的二进制编辑取代。
# 二进制方案可绕开 apktool 解码/重编资源、避免大包长路径崩溃，且对原 App 的
# android:name 是资源引用（非字符串）时也能正确处理。保留仅供对照，harden() 不会调用。
# --------------------------------------------------------------------------
def edit_manifest(manifest_path, package):
    with open(manifest_path, "r", encoding="utf-8") as f:
        xml = f.read()

    # 1) 找到 <application ...> 起始标签，取出并移除其中原有 android:name
    m = re.search(r"<application\b[^>]*>", xml, re.S)
    if not m:
        raise RuntimeError("manifest 中未找到 <application> 标签")
    app_tag = m.group(0)
    orig_name = None
    nm = re.search(r'android:name="([^"]+)"', app_tag)
    if nm:
        orig_name = nm.group(1)
        # 去掉相对写法
        if orig_name.startswith(".") and package:
            orig_name = package + orig_name
        app_tag = app_tag.replace(nm.group(0), "")

    # 2) 注入壳 Application
    new_app_tag = app_tag[:-1] + ' android:name="%s">' % config.SHELL_APP
    xml = xml[:m.start()] + new_app_tag + xml[m.end():]

    # 3) 在 </application> 前插入 orig_app meta
    meta = ('\n        <meta-data android:name="%s" android:value="%s"/>'
            % (config.META_ORIG, orig_name if orig_name else ""))
    xml = xml.replace("</application>", meta + "\n    </application>", 1)

    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(xml)
    return orig_name

# --------------------------------------------------------------------------
# 重打包（【已弃用】）
# 早期基于 apktool 解码产物的重新打包方案，已被 repackage_direct() 取代。
# repackage_direct() 直接用 zipfile 重建 APK，确保 AndroidManifest.xml 为 ZIP 首条
# 且 STORED，避免安装器对压缩/乱序 Manifest 的排斥。保留仅供对照，harden() 不会调用。
# --------------------------------------------------------------------------
def repackage(unsigned_apk, stub_dex_bytes, payload, out_apk):
    with zipfile.ZipFile(unsigned_apk, "r") as zin:
        infos = zin.infolist()
        with zipfile.ZipFile(out_apk, "w", zipfile.ZIP_DEFLATED) as zout:
            for info in infos:
                fn = info.filename
                if re.match(r"classes(\d*)\.dex$", fn):
                    continue
                if fn.startswith("META-INF/"):
                    continue
                if fn == "jg":   # 剔除可能残留的旧载荷，避免重复条目
                    continue
                zout.writestr(info, zin.read(fn))
            zout.writestr("classes.dex", stub_dex_bytes)
            zout.writestr("jg", payload)

# --------------------------------------------------------------------------
# 签名（uber-apk-signer：v1+v2+v3）
# --------------------------------------------------------------------------
def sign(apk_path, sign_dir, ks=None, ks_alias=None, ks_pass=None, ks_keypass=None):
    ks = ks or config.KEYSTORE
    ks_alias = ks_alias or config.KEY_ALIAS
    ks_pass = ks_pass or config.KEY_PASS
    ks_keypass = ks_keypass or ks_pass
    os.makedirs(sign_dir, exist_ok=True)
    # 先清掉历史产出
    for f in os.listdir(sign_dir):
        try:
            os.remove(os.path.join(sign_dir, f))
        except OSError:
            pass
    which = "用户密钥库" if os.path.abspath(ks) != os.path.abspath(config.KEYSTORE) else "内置密钥库"
    print("[*] 使用 %s 签名: %s (alias=%s)" % (which, ks, ks_alias), flush=True)
    run([config.JAVA, "-jar", config.UBER,
         "--apks", apk_path,
         "--ks", ks,
         "--ksAlias", ks_alias,
         "--ksPass", ks_pass,
         "--ksKeyPass", ks_keypass,
         "--out", sign_dir],
        env=env_with_android())
    cands = [os.path.join(sign_dir, f) for f in os.listdir(sign_dir)
             if f.endswith("-aligned-signed.apk") or f.endswith("-signed.apk")]
    if not cands:
        raise RuntimeError("uber-apk-signer 未产出签名文件，目录=%s" % sign_dir)
    return cands[0]

# --------------------------------------------------------------------------
# 方向 B：zip 直打包（不经过 apktool）
# --------------------------------------------------------------------------
def _stored(name):
    """返回未压缩（STORED）的 ZipInfo，用于 AndroidManifest.xml 等必须不压缩的条目。"""
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_STORED
    return info


def repackage_direct(input_apk, patched_manifest, stub_dex, payload, output_path):
    """直接用 zipfile 重建 APK（Manifest 首条 + STORED，保持原资源+lib 顺序 + stub.dex + jg）。
    剔除原 classes*.dex、原 META-INF、原 AndroidManifest.xml。"""
    with zipfile.ZipFile(input_apk, 'r') as zin:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            # 1) 先写 Manifest（二进制 + STORED，首条保序）
            zout.writestr(_stored('AndroidManifest.xml'), patched_manifest)
            # 2) 复制原包其余条目（保留原序与压缩属性）
            for info in zin.infolist():
                fn = info.filename
                if fn == 'AndroidManifest.xml':
                    continue
                if re.match(r'classes(\d*)\.dex$', fn):
                    continue
                if fn.startswith('META-INF/'):
                    continue
                if fn == "jg":
                    continue
                zout.writestr(info, zin.read(fn))
            # 3) 壳 DEX + 载荷
            zout.writestr(zipfile.ZipInfo('classes.dex'), stub_dex)
            zout.writestr(zipfile.ZipInfo("jg"), payload)
    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        raise RuntimeError("zip 直打包失败")

# --------------------------------------------------------------------------
# 内嵌回测：解密载荷还原原始 DEX 并与输入比对
# --------------------------------------------------------------------------
def self_verify(out_apk, orig_dexes):
    import verify_payload
    # 直接用已签名产物的证书派生种子（与设备端一致），无需再传 keystore
    ok, detail = verify_payload.check_payload(out_apk, orig_dexes)
    if not ok:
        raise RuntimeError("内嵌回测失败: " + detail)
    print("[self-verify] 载荷解密还原与原始 DEX 一致: OK")
    return True

# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def harden(input_apk, output_apk=None, keep=False,
           ks=None, ks_alias=None, ks_pass=None, ks_keypass=None):
    _t0 = time.time()
    sw = {"t": _t0}
    input_apk = os.path.abspath(input_apk)
    if not os.path.exists(input_apk):
        raise FileNotFoundError(input_apk)
    base = os.path.splitext(os.path.basename(input_apk))[0]
    if output_apk is None:
        os.makedirs(config.OUTPUT_DIR, exist_ok=True)
        output_apk = os.path.join(config.OUTPUT_DIR, "hardened_" + base + ".apk")
    output_apk = os.path.abspath(output_apk)

    work = _short_work(base)
    config.rmtree_safe(work)
    os.makedirs(work, exist_ok=True)

    print("=" * 60)
    print("加固:", input_apk)
    print("输出:", output_apk)
    print("工作:", work)
    print("=" * 60)

    # 1) 原始 DEX
    dex_names = list_original_dexes(input_apk)
    print("[1] 原始 DEX:", dex_names)
    if not dex_names:
        raise RuntimeError("APK 中未找到任何 classes*.dex")
    orig_dexes = read_dexes(input_apk, dex_names)
    _lap(sw, "收集DEX")

    # 2) 二进制编辑 Manifest（跳过 apktool 解码/重编资源，大包从 ~10 分钟降到秒级）
    with zipfile.ZipFile(input_apk, 'r') as z:
        manifest_data = z.read('AndroidManifest.xml')
    orig_app = _axml_get_orig(manifest_data)
    if not orig_app:
        raise RuntimeError("无法从二进制 Manifest 提取原始 Application 类名（"
                           "android:name 是资源引用而非字符串），请用 apktool 文本流")
    patched_manifest = _axml_patch(manifest_data, orig_app)
    print("[2] 原 Application:", orig_app)
    _lap(sw, "改Manifest(二进制)")

    # 3) 构造载荷（魔数 JGS1），classes.dex 保持为干净壳 DEX
    seed = load_seed(ks, ks_alias, ks_pass)
    print("[*] 种子已按签名证书派生（证书绑定密钥，换签即解密失败）", flush=True)
    payload = build_payload(seed, orig_dexes)
    with open(config.STUB_DEX, "rb") as f:
        stub = f.read()
    print("[3] stub.dex(%d) + 载荷(%d) -> 注入为 jg 条目" % (len(stub), len(payload)))
    _lap(sw, "加密载荷")

    # 4) zip 直打包（原资源 + patched Manifest + stub.dex + jg，跳过 apktool b）
    unsigned = os.path.join(work, "unsigned.apk")
    repackage_direct(input_apk, patched_manifest, stub, payload, unsigned)
    _lap(sw, "zip打包")

    # 5) 签名
    sign_dir = os.path.join(work, "signed")
    signed = sign(unsigned, sign_dir, ks, ks_alias, ks_pass, ks_keypass)
    _lap(sw, "签名")
    shutil.copyfile(signed, output_apk)

    # 6) 内嵌回测
    self_verify(output_apk, orig_dexes)
    _lap(sw, "自检")
    print("[总耗时 %.2fs]" % (time.time() - _t0), flush=True)

    if not keep:
        config.rmtree_safe(work)
    print("[完成] 已生成加固 APK:", output_apk)
    return output_apk

def main():
    ap = argparse.ArgumentParser(description="JGShield 单 APK 加固")
    ap.add_argument("input", help="输入 APK 路径")
    ap.add_argument("-o", "--output", help="输出 APK 路径")
    ap.add_argument("--keep", action="store_true", help="保留工作目录")
    ap.add_argument("--ks", help="签名密钥库(jks/keystore/p12)，默认用内置")
    ap.add_argument("--ksAlias", help="密钥别名（默认 common）")
    ap.add_argument("--ksPass", help="密钥库密码（默认内置）")
    ap.add_argument("--ksKeyPass", help="密钥密码（默认同密钥库密码）")
    args = ap.parse_args()
    try:
        harden(args.input, args.output, args.keep,
               ks=args.ks, ks_alias=args.ksAlias,
               ks_pass=args.ksPass, ks_keypass=args.ksKeyPass)
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
