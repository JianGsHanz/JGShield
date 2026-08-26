# -*- coding: utf-8 -*-
"""
JGShield 加固核心：对单个 APK 做差异化加壳。

流程（方向B，二进制 Manifest 编辑 + zip 直打包，不经过 apktool）：
  1. 抽取原始 classes*.dex
  2. 二进制编辑 AndroidManifest.xml（直接改 AXML，不解码/重编资源）
  3. 构建加密载荷：DEFLATE + AES-256-GCM
  4. zip 直打包：原资源 + patched Manifest + stub.dex(classses.dex) + jg 载荷
  5. 签名对齐
  6. 内嵌回测

密钥派生（HKDF-Extract 加盐，抗跨构建密钥比对）：
  cert_hash = SHA256(签名证书DER)         # 证书绑定材料（换签即变→GCM 认证失败）
  build_salt = os.urandom(32)             # 每次构建随机（存 jg 载荷末 32B trailer）
  seed = HMAC-SHA256(key=build_salt, msg=cert_hash)   # RFC5869 HKDF-Extract
  per-dex/asset key = HMAC-SHA256(seed, "JG|"+label+idx)
  per-method key     = HMAC-SHA256(seed, "JG|m"+dexIdx+"."+methodIdx)
兼具「证书绑定」（cert_hash 作 IKM）与「每次构建密文不同」（随机 salt），
使逆向者无法通过对比两次构建的密文/密钥定位加密结构。下游 HMAC 链与 native
（只消费最终 seed）均不受影响；壳/回测须先从载荷末 32B 取 salt 再派生 seed。
"""
import os
import time
import re
import sys
import zlib
import struct
import shutil
import zipfile
import subprocess
import argparse
import traceback

import config
import verify_payload

# Windows 下 --windowed exe 调起 console 子进程（java/aapt/adb/zipalign/keytool
# 均为 console 子系统）会为其单独分配控制台窗口 → 加固时黑窗频闪。加此 flag
# 抑制；非 Windows 降级为 0，无副作用。
_SUBPROC_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from axml_editor import patch_manifest as _axml_patch
from axml_editor import get_orig_app_class as _axml_get_orig

# --------------------------------------------------------------------------
# 工具函数
# --------------------------------------------------------------------------
# 这些参数后面跟的“值”是密码，打印/回显时必须脱敏
_PASSWORD_KEYS = ("--ksPass", "--ksKeyPass", "--storepass", "--keypass")

# 外部工具(aapt/adb/java)输出按系统代码页(GBK)时，用本函数容错解码，避免日志乱码
from config import _decode_bytes

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
    同时累积 stdout 供调用方检查，并打印该命令耗时。

    外部工具（aapt/adb/java）在中文 Windows 下按 GBK 输出，故读字节后用
    _decode_bytes 容错解码，避免日志中文乱码。
    """
    print(">>", _format_args(cmd) if isinstance(cmd, list) else cmd, flush=True)
    t0 = time.time()
    p = subprocess.Popen(cmd, cwd=cwd, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         bufsize=0, creationflags=_SUBPROC_FLAGS)
    buf = []
    while True:
        raw = p.stdout.readline()
        if not raw:
            break
        line = _decode_bytes(raw).rstrip("\r\n")
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
    root = os.path.join(config.BUILD_DIR, "_wk")
    os.makedirs(root, exist_ok=True)
    token = "h%d_%d" % (os.getpid(), int(time.time() * 1000) % 1000000)
    return os.path.join(root, token)

# --------------------------------------------------------------------------
# 密钥派生 & 加密（与 GxApp.java 完全对应）
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
            r = subprocess.run(base, capture_output=True, check=True,
                               env=env_with_android(),
                               creationflags=_SUBPROC_FLAGS)
            _ = _decode_bytes(r.stdout or b"")
        except subprocess.CalledProcessError:
            # 部分 keystore 需显式声明类型，重试
            r = subprocess.run(base + ["-storetype", "PKCS12"], capture_output=True,
                               check=True, env=env_with_android(),
                               creationflags=_SUBPROC_FLAGS)
            _ = _decode_bytes(r.stdout or b"")
        with open(der, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(der)
        except OSError:
            pass

def load_cert_hash(ks=None, ks_alias=None, ks_pass=None):
    """证书绑定材料 cert_hash = SHA256(证书DER)。
    优先用用户指定的 keystore 证书，否则回退内置 common.cer。
    这是 HKDF-Extract 的 IKM（信息密钥材料）：换签→证书变→cert_hash 变→seed 变。"""
    if ks and os.path.isfile(ks):
        cert = extract_cert_der(ks, ks_alias or config.KEY_ALIAS,
                                ks_pass or config.KEY_PASS)
    else:
        with open(config.CERT_DER, "rb") as f:
            cert = f.read()
    return SHA256.new(cert).digest()

# 兼容旧调用名（如有外部引用），语义即 cert_hash
load_seed = load_cert_hash

def derive_seed(cert_hash, salt):
    """RFC5869 HKDF-Extract：seed = HMAC-SHA256(key=salt, msg=cert_hash)。
    salt=每次构建随机 32B（存载荷末尾）；cert_hash=证书绑定材料。
    → 每次构建 seed 不同（抗跨构建密钥/密文比对），同时保留证书绑定
    （salt 相同而证书变→cert_hash 变→seed 仍变；证书相同而 salt 变→seed 变）。"""
    mac = HMAC.new(salt, digestmod=SHA256)
    mac.update(cert_hash)
    return mac.digest()

def derive_key(seed, idx, label=b"dex"):
    msg = config.KEY_PREFIX + label + str(idx).encode("utf-8")
    if config.WB_KDF:
        import whitebox_kdf
        return whitebox_kdf.wb_derive(seed, msg, config.WB_SECRET)
    mac = HMAC.new(seed, digestmod=SHA256)
    mac.update(msg)
    return mac.digest()  # 32 bytes -> AES-256

def encrypt_asset(seed, idx, data):
    """加密单个 assets 条目（与 encrypt_dex 同算法，label=asset 区分密钥）。"""
    comp = zlib_compress(data)
    key = derive_key(seed, idx, b"asset")
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(comp)
    return iv + ct + tag

def encrypt_dex(seed, idx, dex_bytes):
    comp = zlib_compress(dex_bytes)          # zlib 格式，对应 Java Inflater() 无参
    key = derive_key(seed, idx)
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(comp)
    return iv + ct + tag

def encrypt_shell_dex(seed, dex_bytes):
    """P8：加密壳自身 DEX（GxApp 等 12 类），密钥派生与原载荷同源同 salt，
    但 label 用 "JG|shell" 区分，使壳 DEX 与原 App DEX 使用不同密钥。
    Bootstrap 端 deriveShellKey 必须用完全相同派生（见 GxBootstrap.java）。
    注意：此处对原始 DEX 字节直接加密（不 zlib 压缩），使解密结果就是合法 DEX
    文件，InMemoryDexClassLoader 可直接加载；否则 Bootstrap 端需额外 inflate，
    违背"壳 DEX 即 DEX 文件"的语义且增加失败面。"""
    key = derive_key(seed, 0, label=b"shell")
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(dex_bytes)
    return iv + ct + tag

def build_payload(seed, dex_list, asset_list=None, method_sections=None, salt=None):
    out = bytearray()
    out += config.MAGIC
    out += struct.pack("<I", len(dex_list))
    for i, d in enumerate(dex_list):
        blob = encrypt_dex(seed, i, d)
        out += struct.pack("<I", len(blob))
        out += blob
    # 资产区段：加密原始 assets/ 条目，运行时由壳解密还原进 AssetManager。
    # 末尾追加 asset_count + 若干 (name_len,name,len,blob)；无资产时为 0。
    # 该区段位于 dex 区段之后，旧壳/旧校验逻辑读 dex 后自然停在末尾、不受影响。
    assets = asset_list or []
    out += struct.pack("<I", len(assets))
    for i, (name, data) in enumerate(assets):
        nb = name.encode("utf-8")
        out += struct.pack("<I", len(nb))
        out += nb
        blob = encrypt_asset(seed, i, data)
        out += struct.pack("<I", len(blob))
        out += blob
    # P3.1 方法区段：每个被抽取 DEX 一条 (dex_idx, stream_blob, entries)。
    # 整 dex 方法码拼成一条流、整体压缩+整体加密为 stream_blob(一次 GCM)；
    # entries 记录每个方法在流内的 (method_idx, code_off, insns_size, offset_in_stream, len_in_stream)。
    # 位于资产区段之后；解析器读完 dex+asset 后自然停在末尾，不受影响。
    msecs = method_sections or []
    out += struct.pack("<I", len(msecs))
    for (dex_idx, blob, entries) in msecs:
        out += struct.pack("<I", dex_idx)
        out += struct.pack("<I", len(entries))
        out += struct.pack("<I", len(blob))
        out += blob
        # P6：方法元数据表整体 zlib 压缩，避免 21 万方法 × 20B 裸 u32 占 ~4MB。
        # 仅存 (method_idx, code_off, insns_size) 三项；offset_in_stream / len_in_stream
        # 可由 insns_size 在还原端按序累加推得，无需存储。整体压缩后 212993×12B → ~1MB。
        if entries:
            meta = b"".join(struct.pack("<III", m[0], m[1], m[2]) for m in entries)
        else:
            meta = b""
        meta_blob = zlib_compress(meta)
        out += struct.pack("<I", len(meta_blob))
        out += meta_blob
    # 盐 trailer：每次构建随机 32B，追加在所有区段之后（载荷最末）。
    # 所有解析器（native / verify / 壳）读完 dex+asset+method 区段后自然停住，
    # 从不读到这 32B；仅需「读末 32B 取 salt」即可还原派生种子。向后兼容旧解析逻辑。
    if salt is not None:
        if len(salt) != 32:
            raise ValueError("build_payload: salt must be 32 bytes, got %d" % len(salt))
        out += salt
    return bytes(out)

# --------------------------------------------------------------------------
# P3.1 DEX 方法级指令抽取（离线，防内存 dump 的核心）
# --------------------------------------------------------------------------
def _read_uleb128(b, off):
    """从 DEX 字节流读 LEB128 无符号整数，返回 (value, 新偏移)。"""
    result = 0
    shift = 0
    idx = off
    while True:
        x = b[idx]
        idx += 1
        result |= (x & 0x7f) << shift
        if not (x & 0x80):
            break
        shift += 7
    return result, idx

def _u32(b, off):
    return (b[off] & 0xff) | ((b[off+1] & 0xff) << 8) \
        | ((b[off+2] & 0xff) << 16) | ((b[off+3] & 0xff) << 24)

def derive_method_key(seed, dex_idx):
    """P3 方法段 per-dex 密钥：HMAC(seed, "JG|m"+dexIdx)。

    整 dex 的方法码拼成一条流、整体压缩后整体用此密钥加密（一次 GCM）。
    相比旧版「逐方法压缩+逐方法加密」：明文方法码 12.58MB 由压缩比 ~1.08x
    (≈11.65MB) 提升到 ~3x(≈4MB)，且 21 万方法的 28B IV/tag 固定开销(≈5.7MB)
    降为每 dex 一次(≈0.5KB)。包体由 +15MB 降为近零增长，安全性不变
    （方法抽取反脱壳层原样保留）。沿用整包种子体系，换签即失败。"""
    msg = config.KEY_PREFIX + b"m" + str(dex_idx).encode("utf-8")
    if config.WB_KDF:
        import whitebox_kdf
        return whitebox_kdf.wb_derive(seed, msg, config.WB_SECRET)
    mac = HMAC.new(seed, digestmod=SHA256)
    mac.update(msg)
    return mac.digest()

def extract_methods(seed, dex_idx, dex_bytes):
    """抽取单个 DEX 每个方法的 CodeItem.insns，整 dex 拼成一条流、整体 zlib 压缩后
    整体 AES-256-GCM 加密（per-dex 密钥，一次 GCM），并记录每个方法在流内的偏移/长度；
    原位把 insns 回填 NOP（保留 insns_size 使 ART 仍可解析验证）。

    返回 (NOP 化后的 dex 字节, stream_blob, [(method_idx, code_off, insns_size,
    offset_in_stream, len_in_stream), ...])。
    - stream_blob = iv(12) + AES-256-GCM(ct+tag)，ct = zlib(concat_insns)。
    - 运行时 native 整体解密+inflate 一次，再按 offset/len 逐方法 memcpy 回写。

    相比旧版「逐方法压缩+逐方法加密」：明文方法码 12.58MB 由压缩比 ~1.08x(≈11.65MB)
    提升到 ~3x(≈4MB)，且 21 万方法的 28B IV/tag 开销(≈5.7MB) 降为每 dex 一次(≈0.5KB)。
    包体由 +15MB 降为近零增长，安全性不变（方法抽取反脱壳层原样保留）。"""
    dex = bytearray(dex_bytes)
    entries = []          # (method_idx, code_off, insns_size, offset_in_stream, len_in_stream)
    stream = bytearray()  # 按 entries 顺序拼接的 insns
    class_defs_off = _u32(dex, 0x64)
    class_defs_size = _u32(dex, 0x60)
    for ci in range(class_defs_size):
        cd_off = class_defs_off + ci * 32
        class_data_off = _u32(dex, cd_off + 0x18)
        if class_data_off == 0:
            continue
        p = class_data_off
        static_fields_size, p = _read_uleb128(dex, p)
        instance_fields_size, p = _read_uleb128(dex, p)
        direct_methods_size, p = _read_uleb128(dex, p)
        virtual_methods_size, p = _read_uleb128(dex, p)
        # 跳过字段
        for _ in range(static_fields_size + instance_fields_size):
            _, p = _read_uleb128(dex, p)
            _, p = _read_uleb128(dex, p)
        running = 0
        for _ in range(direct_methods_size + virtual_methods_size):
            diff, p = _read_uleb128(dex, p)
            running += diff
            _, p = _read_uleb128(dex, p)          # access_flags
            code_off, p = _read_uleb128(dex, p)
            if code_off == 0:
                continue
            insns_size = _u32(dex, code_off + 12)
            if insns_size == 0:
                continue
            insns_off = code_off + 16
            insns = bytes(dex[insns_off:insns_off + insns_size * 2])
            offset = len(stream)
            stream += insns
            entries.append((running, code_off, insns_size, offset, insns_size * 2))
            for k in range(insns_size * 2):       # 原位回填 NOP
                dex[insns_off + k] = 0
    # 整 dex 方法码拼流，整体压缩 + 整体加密（一次 GCM）
    blob = b""
    if stream:
        comp = zlib_compress(bytes(stream))       # 整体 deflate
        key = derive_method_key(seed, dex_idx)    # per-dex 密钥
        iv = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ct, tag = cipher.encrypt_and_digest(comp)
        blob = iv + ct + tag
    return bytes(dex), blob, entries

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

def collect_assets(apk_path):
    """收集原始 APK 的 assets/ 文件条目，用于加密后从 APK 剥离（关闭资源明文泄漏）。

    仅覆盖 assets/（不含 res/）：res/ 由资源表 resources.arsc 索引，剥离后即使运行时
    合并 AssetManager 也常无法正确还原 res/raw 等资源解析，风险高，故 res/ 保持原样。
    """
    items = []
    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            fn = info.filename
            if fn.startswith("assets/") and not fn.endswith("/"):
                items.append((fn, z.read(fn)))
    return items

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
                if fn == "z9":   # 剔除可能残留的旧载荷，避免重复条目
                    continue
                zout.writestr(info, zin.read(fn))
            zout.writestr("classes.dex", stub_dex_bytes)
            zout.writestr("z9", payload)

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


def repackage_direct(input_apk, patched_manifest, stub_dex, payload, output_path,
                     native_libs_dir=None, strip_assets=False,
                     shell_dex_enc=None, shell_dex_entry=None):
    """直接用 zipfile 重建 APK（Manifest 首条 + STORED，保持原资源+lib 顺序 + 入口壳 DEX + 加密壳 DEX + jg）。
    剔除原 classes*.dex、原 META-INF、原 AndroidManifest.xml。

    P8：stub_dex 参数此处接收的是 bootstrap.dex（明文入口 Application）；
    加密的壳 DEX（GxApp 等）通过 shell_dex_enc / shell_dex_entry 注入随机条目，
    由 Bootstrap 运行期解密并加载。

    native_libs_dir：若提供，则把其中的 lib<LIB_NAME>.so 注入到输出 APK 的 lib/<abi>/，
    与原 App 自身的 .so 并列（ZIP_STORED 不压缩，Android 要求）。
    """
    # 确定要注入的 ABI 集合：优先取原包已有的 lib/<abi>/，没有则补 arm64-v8a/armeabi-v7a
    abis = set()
    with zipfile.ZipFile(input_apk, 'r') as z:
        for n in z.namelist():
            m = re.match(r'lib/([^/]+)/', n)
            if m:
                abis.add(m.group(1))
    if not abis:
        abis = {'arm64-v8a', 'armeabi-v7a'}

    have_native = bool(native_libs_dir) and os.path.isdir(native_libs_dir)

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
                if fn == config.PAYLOAD_ENTRY:
                    continue
                if strip_assets and fn.startswith("assets/"):
                    continue
                zout.writestr(info, zin.read(fn))
            # 3) 壳 DEX（入口 bootstrap，明文）+ 加密壳 DEX + 载荷
            zout.writestr(zipfile.ZipInfo('classes.dex'), stub_dex)
            if shell_dex_enc is not None and shell_dex_entry is not None:
                zi = zipfile.ZipInfo(shell_dex_entry)
                zi.compress_type = zipfile.ZIP_STORED
                zout.writestr(zi, shell_dex_enc)
            zout.writestr(zipfile.ZipInfo(config.PAYLOAD_ENTRY), payload)
            # 4) 注入 native 反篡改库（与原 App .so 并列；STORED 不压缩）
            #    注意：APK 内文件名随机化（lib<LIB_NAME>.so），但 .so 内部 JNI 符号与
            #    文件名无关，壳 System.loadLibrary("<LIB_NAME>") 按文件名加载、按类名解析。
            if have_native:
                injected = 0
                for abi in sorted(abis):
                    src = os.path.join(native_libs_dir, abi,
                                       'lib%s.so' % config.LIB_NAME)
                    if not os.path.isfile(src):
                        continue
                    with open(src, 'rb') as f:
                        data = f.read()
                    zi = zipfile.ZipInfo('lib/%s/lib%s.so' % (abi, config.LIB_NAME))
                    zi.compress_type = zipfile.ZIP_STORED
                    zout.writestr(zi, data)
                    injected += 1
                if injected:
                    print("[*] 注入 native 反篡改库 lib%s.so 到 %d 个 ABI: %s"
                          % (config.LIB_NAME, injected, ', '.join(sorted(abis))), flush=True)
                else:
                    print("[!] 未找到任何 ABI 的 libjgguard.so，跳过 native 注入（需先 build_stub）",
                          flush=True)
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
           ks=None, ks_alias=None, ks_pass=None, ks_keypass=None,
           assets_encrypt=False, method_extract=False,
           ssl_pins=None, strengthen="exit", rebuild_stub=True,
           wb_kdf=False, antidump=False):
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

    # 0) 壳指纹随机化（抹壳特征）：按构建唯一化包名/类名/meta 键/TAG/payload 条目/
    #     魔数/lib 名/Obf 密钥，重建 stub.dex 与 4 ABI native，并把随机参数应用到 config
    #     （写端 manifest/payload 与壳读端 stub.dex/.so 完全一致）。
    #     rebuild_stub=False 时跳过重建、直接复用已有 build/stamp.json + 产物（快速迭代用）。
    if rebuild_stub:
        import build_stub
        build_stub.main(wb_kdf=wb_kdf)
    config.apply_stamp_from_file()

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

    # 1.5) 原始 assets（可选加密剥离；默认关闭，避免运行时还原失败导致 App 缺资源）
    assets = []
    if assets_encrypt:
        assets = collect_assets(input_apk)
        print("[1.5] 待加密 assets 条目数:", len(assets))

    # 2) 二进制编辑 Manifest（跳过 apktool 解码/重编资源，大包从 ~10 分钟降到秒级）
    with zipfile.ZipFile(input_apk, 'r') as z:
        manifest_data = z.read('AndroidManifest.xml')
    orig_app = _axml_get_orig(manifest_data)
    if not orig_app:
        raise RuntimeError("无法从二进制 Manifest 提取原始 Application 类名（"
                           "android:name 是资源引用而非字符串），请用 apktool 文本流")
    patched_manifest = _axml_patch(manifest_data, orig_app,
                                   shell_app_class=config.BOOTSTRAP_APP,
                                   ssl_pins=ssl_pins, strengthen=strengthen, antidump=antidump,
                                   meta_orig=config.META_ORIG,
                                   meta_ssl=config.META_SSL_PINS,
                                   meta_strengthen=config.META_STRENGTHEN,
                                   meta_antidump=config.META_ANTIDUMP)
    if ssl_pins:
        print("[2*] 注入 SSL pinning meta: %s (%d host(s))"
              % (config.META_SSL_PINS, ssl_pins.count(';') + 1))
    if strengthen:
        print("[2*] 注入统一响应姿态 meta: %s = %s" % (config.META_STRENGTHEN, strengthen))
        if strengthen == "exit":
            print("[!] 警告: exit 模式会误杀正常 VPN/海外用户，不推荐用于面向海外用户的 app。")
    if antidump:
        print("[2*] 注入 P0-C 内存级 anti-dump 开关 meta: %s = 1 (默认关,opt-in)" % config.META_ANTIDUMP)
        print("[!] 警告: 内存扫描可能误命中 ART 另拷的匿名 DEX 区，需真机验证后再用于生产。")
    print("[2] 原 Application:", orig_app)
    _lap(sw, "改Manifest(二进制)")

    # 3) 构造载荷（魔数 JGS1），classes.dex 保持为干净壳 DEX
    # HKDF-Extract 加盐派生：cert_hash 绑证书，build_salt 每次构建随机 → 抗跨构建密钥比对。
    cert_hash = load_cert_hash(ks, ks_alias, ks_pass)
    build_salt = os.urandom(32)
    seed = derive_seed(cert_hash, build_salt)
    if ks and os.path.isfile(ks):
        print("[*] 种子=HKDF-Extract(salt=随机32B, ikm=SHA256(你的签名证书 alias=%s))："
              "证书绑定+每次构建随机，加固/上架须用同一证书，换签即解密失败"
              % (ks_alias or config.KEY_ALIAS), flush=True)
    else:
        print("[*] 种子=HKDF-Extract(salt=随机32B, ikm=SHA256(内置证书 common))："
              "证书绑定+每次构建随机，换签即解密失败", flush=True)
    # P3.1 方法级指令抽取（默认关闭）：把每个方法的 insns 抽走加密、DEX 内原位回填 NOP。
    # 抽取后的 DEX 存入载荷（运行时加载的是 NOP 版），密文单独存方法区段，待 P3.3 运行时还原。
    # 注意：开启后产物在 P3.3 之前不可独立运行（方法体为空），仅用于验证抽取链路。
    extracted_dexes = orig_dexes
    method_sections = None
    if method_extract:
        extracted_dexes = []
        method_sections = []
        total_methods = 0
        for i, d in enumerate(orig_dexes):
            ex, blob, entries = extract_methods(seed, i, d)
            extracted_dexes.append(ex)
            method_sections.append((i, blob, entries))
            total_methods += len(entries)
        print("[3.1] 抽取方法指令数: %d（需 P3.3 运行时还原，当前产物不可独立运行）" % total_methods,
              flush=True)
    payload = build_payload(seed, extracted_dexes, assets if assets else None,
                            method_sections, salt=build_salt)
    with open(config.STUB_DEX, "rb") as f:
        stub = f.read()
    # P8：加密壳自身 DEX（GxApp 等 12 类），与原载荷同 salt 同 seed，
    # 但 label "JG|shell" 区分密钥；Bootstrap 端用同派生解密。
    shell_dex_enc = encrypt_shell_dex(seed, stub)
    print("[3] stub.dex(%d) + 载荷(%d) -> 注入为 %s 条目；壳 DEX 加密(%d) -> %s 条目"
          % (len(stub), len(payload), config.PAYLOAD_ENTRY,
             len(shell_dex_enc), config.SHELL_DEX_ENTRY))
    _lap(sw, "加密载荷")

    # 4) zip 直打包（原资源 + patched Manifest + bootstrap.dex(明文入口) +
    #    加密壳 DEX + 载荷，跳过 apktool b）
    with open(config.BOOTSTRAP_DEX, "rb") as f:
        bootstrap = f.read()
    unsigned = os.path.join(work, "unsigned.apk")
    repackage_direct(input_apk, patched_manifest, bootstrap, payload, unsigned,
                     native_libs_dir=config.LIBJGGUARD_DIR, strip_assets=bool(assets),
                     shell_dex_enc=shell_dex_enc, shell_dex_entry=config.SHELL_DEX_ENTRY)
    _lap(sw, "zip打包")

    # 5) 签名
    sign_dir = os.path.join(work, "signed")
    signed = sign(unsigned, sign_dir, ks, ks_alias, ks_pass, ks_keypass)
    _lap(sw, "签名")
    shutil.copyfile(signed, output_apk)

    # 6) 内嵌回测
    self_verify(output_apk, orig_dexes)
    # 6.5) assets 自检：解密还原后与原 assets 逐一比对
    if assets:
        ok, detail = verify_payload.check_assets(output_apk, assets)
        if not ok:
            raise RuntimeError("内嵌 assets 回测失败: " + detail)
        print("[self-verify] 资产解密还原与原始一致: OK")
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
    ap.add_argument("--assets-encrypt", action="store_true",
                    help="加密并剥离原始 assets/（实验性）：关闭资源明文泄漏，运行时由壳还原；"
                         "部分 ROM/高版本可能因隐藏 API 限制导致还原失败（App 缺资源），"
                         "遇此情况请去掉本参数重新加固")
    ap.add_argument("--method-extract", action="store_true",
                    help="P3.1 方法级指令抽取（实验性）：抽取每个方法的指令并加密，DEX 内原位回填 NOP，"
                         "运行时需 P3.3 native 还原才能执行；当前产物不可独立运行，仅用于验证抽取链路。默认关闭。")
    ap.add_argument("--pins", help="SSL 证书固定：host=sha256/Base64;host2=sha256/Base64（与 OkHttp "
                                    "CertificatePinner 同构）。例：api.example.com=sha256/ABCD... 。"
                                    "配置后壳在运行期做按主机证书固定，挡 root+系统证书 MITM。不指定则不启用。")
    ap.add_argument("--strengthen", choices=["log", "exit"], default="exit",
                    help="P0-A 统一响应姿态（覆盖壳默认 'log'）：exit=检测命中（root/模拟器/frida/"
                         "代理/VPN/自校验失败）即退出进程；log=仅记日志不阻断（调试用）。"
                         "⚠ exit 可能误杀部分正常设备（反调试/自校验 OEM 误报），生产发布前务必在"
                         "目标机型（如华为 A10 / 小米 A9）真机验证；如需关闭用 --strengthen log。"
                         "经 manifest meta 注入，运行期生效，无需重编 stub.dex。")
    ap.add_argument("--wb-kdf", action="store_true",
                    help="P0-B 真白盒密钥派生（opt-in，默认关闭）：把 HMAC(seed,msg) 再经一次以每构建"
                         "随机 wb_secret 预处理态为起点的 SHA256 融合，去除 .so 内连续 seed 字面量与可被"
                         "一行 HMAC() 直接复用的干净派生。⚠ 诚实边界：离线无服务端，seed 仍可由 APK 证书"
                         "+salt 重建，白盒仅提逆向成本、不补保密性（真墙是 VMP/服务端密钥，不在本次范围）。"
                         "开启后 native 走 WB_KDF 烘焙路径，需 build_stub 重编 4 ABI。沙箱仅能验数学等价"
                         "（白盒≠clean 且确定），运行期一致性需真机+frida 反向验证后才可默认开启。")
    ap.add_argument("--antidump", action="store_true",
                    help="P0-C 内存级 anti-dump（opt-in，默认关闭）：壳运行期扫 /proc/self/maps，对匿名/"
                         "memfd 区域读首 4 字节是否 DEX 魔数（frida-dexdump / memfd 内存 dump 特征），"
                         "命中且 --strengthen exit 则退出进程，否则仅记日志。⚠ 诚实边界：这是「检测」不是"
                         "「杜绝」——DEX 必被 ART 明文执行，内存里永远有明文副本，只提 dump 成本、给运行期"
                         "信号。且可能误命中 ART 另拷的匿名 DEX 区导致自爆，已排除自家 direct-buffer 区间但"
                         "残留未覆盖风险；开关默认关，需真机+frida 反向验证后才用于生产。")
    args = ap.parse_args()
    try:
        harden(args.input, args.output, args.keep,
               ks=args.ks, ks_alias=args.ksAlias,
               ks_pass=args.ksPass, ks_keypass=args.ksKeyPass,
               assets_encrypt=args.assets_encrypt,
               method_extract=args.method_extract,
               ssl_pins=args.pins,
               strengthen=args.strengthen,
               wb_kdf=args.wb_kdf,
               antidump=args.antidump)
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
