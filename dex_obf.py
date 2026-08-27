"""DEX 字符串加密 + 标识符重命名 + 弱控制流混淆（抗 AI 静态逆向）。

策略（三层，全部 opt-in，默认关）
------------------------------
L1 字符串加密（--dex-obf）：
  把每个 `const-string` 改写为 `const-string <密文>` + `invoke ObfStr.d` + `move-result`，
  打掉 "JADX + LLM" 的语义来源。解密器 ObfStr.d 在独立 obf.dex（B3' 每次加固随机类名）。

L3 标识符重命名（--dex-rename）：
  把 App 自有包的类/方法/字段名改成无意义短名（a/b/c...）。keep 集合 = manifest 四大组件
  + Application 及其生命周期回调 + native 方法（JNI 符号名绑定）+ 布局里的自定义 View。
  其余内部符号全改，全局重写描述符引用并移动 .smali 路径。

L2 弱控制流（--dex-cfg）：
  verifier 安全的弱版——给方法分配新寄存器并插入「无用条件分支 + 死块」，改变 CFG 形状、
  干扰线性反编译，但不影响语义、不影响 ART 校验。真正的 CFG 平坦化留给 B2（native/OLLVM）。

实现：apktool 解码整包（含 res/，aapt2 才能正确回编 manifest）→ 单个 decode 目录内串行跑
L1/L3/L2 pass → apktool 回编整包 → 只抽取回编后的 classes*.dex。最终加固产物资源来自原包
（harden 走 zip 直打包），这里仅借用回编后的 DEX。

约束 / 边界（诚实）
----------------
- 全是「混淆」不是「加密」：DEX 加载后明文常驻，跑起来即可抽；价值在抬高静态 AI 成本。
- L1 跳过含反斜杠 `\\` 的字符串（smali 转义安全）。解密器类名 B3' 随机化。
- L3 keep 集合是「误杀」生死线：组件/生命周期/native/布局 View 必须保留原名，否则崩溃或
  framework 找不到类。反射按字符串动态拼类名等情况不在 keep 范围，属 opt-in 已知风险。
- L2 是弱版，强度远低于 OLLVM，但绝不崩正常 App（key 是 verifier 安全）。
- 所有 pass 默认关，符合「脆弱特性绝不默认开 + 声明安全前必真机验证」铁律。
"""
import os
import re
import base64
import zipfile
import shutil
import subprocess

import random

import config

OBF_KEY = b"JGShieldDEXobf01"
DEC_CLASS = "Lcom/jiagu/obf/ObfStr;"   # 固定回退名（随机编译失败时用，与 tools/obf.dex 一致）
DEC_METHOD = DEC_CLASS + "->d(Ljava/lang/String;)Ljava/lang/String;"
OBF_DEX = os.path.join(config.TOOLS, "obf.dex")
OBF_SRC_TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "src", "java", "com", "jiagu", "obf", "ObfStr.java")
D8_JAR = os.path.join(config.TOOLS, "d8.jar")


def _javac_path():
    """从 config.JAVA(java.exe) 派生同目录 javac.exe。"""
    j = config.JAVA
    if j and os.path.basename(j).lower().startswith("java"):
        return os.path.join(os.path.dirname(j), "javac.exe")
    return "javac"  # PATH 回退


JAVAC = _javac_path()

# const-string vN, "LIT"   /   const-string/jumbo vN, "LIT"
_CS_RE = re.compile(
    r'^(?P<ind>\s*)const-string(/jumbo)?\s+(?P<reg>v[0-9a-fA-F]+),\s*"(?P<lit>.*)"\s*$'
)

_SUBPROC_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run_java(args):
    subprocess.check_call([config.JAVA, "-jar"] + args,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          creationflags=_SUBPROC_FLAGS)


def encrypt_string(s):
    ct = bytes(c ^ OBF_KEY[i % len(OBF_KEY)] for i, c in enumerate(s.encode("utf-8")))
    return base64.b64encode(ct).decode("ascii")


def obf_dec_method(dec_class):
    """解密器静态方法引用，随 dec_class 变化（B3' 随机化）。"""
    return dec_class + "->d(Ljava/lang/String;)Ljava/lang/String;"


def gen_dec_class():
    """生成随机解密器类描述符，如 `La7F3k/pQ2xZ;`（包名+类名均随机，无 com/jiagu/obf 前缀）。"""
    alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    alnum = alpha + "0123456789"
    pkg = random.choice(alpha) + "".join(random.choice(alnum) for _ in range(random.randint(4, 9)))
    cls = random.choice(alpha) + "".join(random.choice(alnum) for _ in range(random.randint(4, 9)))
    return "L%s/%s;" % (pkg, cls)


def compile_obf_dex(dec_class, workdir):
    """从模板生成随机类名的解密器，javac --release 8 -> d8 --min-api 21 -> classes.dex。"""
    if not os.path.isfile(OBF_SRC_TEMPLATE):
        raise RuntimeError("缺少解密器模板 %s" % OBF_SRC_TEMPLATE)
    desc = dec_class.strip("L").rstrip(";")
    pkg, cls = desc.split("/")
    srcdir = os.path.join(workdir, "_obfsrc")
    pkgdir = os.path.join(srcdir, pkg)
    os.makedirs(pkgdir, exist_ok=True)
    jpath = os.path.join(pkgdir, cls + ".java")
    tmpl = open(OBF_SRC_TEMPLATE, "r", encoding="utf-8").read()
    tmpl = tmpl.replace("package com.jiagu.obf;", "package %s;" % pkg)
    tmpl = tmpl.replace("public class ObfStr", "public class %s" % cls)
    with open(jpath, "w", encoding="utf-8") as f:
        f.write(tmpl)

    outdir = os.path.join(workdir, "_obfcls")
    shutil.rmtree(outdir, ignore_errors=True)
    os.makedirs(outdir, exist_ok=True)
    try:
        subprocess.check_call([JAVAC, "-encoding", "UTF-8", "--release", "8", "-d", outdir, jpath],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             creationflags=_SUBPROC_FLAGS)
    except subprocess.CalledProcessError as e:
        raise RuntimeError("javac 失败: " + (e.stderr or b"").decode("utf-8", "replace"))
    classfile = os.path.join(outdir, pkg, cls + ".class")

    zippath = os.path.join(workdir, "_obf_tmp.zip")
    if os.path.isfile(zippath):
        os.remove(zippath)
    try:
        subprocess.check_call([config.JAVA, "-cp", D8_JAR, "com.android.tools.r8.D8",
                              "--min-api", "21", "--lib", config.ANDROID_JAR,
                              "--output", zippath, classfile],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             creationflags=_SUBPROC_FLAGS)
    except subprocess.CalledProcessError as e:
        raise RuntimeError("d8 失败: " + (e.stderr or b"").decode("utf-8", "replace"))
    with zipfile.ZipFile(zippath) as z:
        return z.read("classes.dex")


# ===========================================================================
# L1 字符串加密
# ===========================================================================
def _transform_smali(path, dec_class):
    changed = 0
    dec_method = obf_dec_method(dec_class)
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = _CS_RE.match(line.rstrip("\n"))
            if m and m.group("lit") != "" and "\\" not in m.group("lit"):
                reg = m.group("reg")
                b64 = encrypt_string(m.group("lit"))
                ind = m.group("ind")
                out.append('%sconst-string %s, "%s"\n' % (ind, reg, b64))
                out.append("%sinvoke-static {%s}, %s\n" % (ind, reg, dec_method))
                out.append("%smove-result-object %s\n" % (ind, reg))
                changed += 1
            else:
                out.append(line)
    if changed:
        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(out))
    return changed


# ===========================================================================
# L3 标识符重命名（B1）
# ===========================================================================
_LIFECYCLE = {
    "onCreate", "onStart", "onRestart", "onResume", "onPause", "onStop", "onDestroy",
    "onPostCreate", "onPostResume", "onAttachedToWindow", "onDetachedFromWindow",
    "onAttach", "onActivityCreated", "onViewCreated", "onDestroyView", "onDetach",
    "onBind", "onUnbind", "onRebind", "onRecreate", "onReceive", "onHandleIntent",
    "onConfigurationChanged", "onLowMemory", "onTrimMemory", "attachBaseContext",
    "onCreateOptionsMenu", "onPrepareOptionsMenu", "onOptionsItemSelected",
    "onOptionsMenuClosed", "onContextItemSelected", "onSearchRequested",
    "onRequestPermissionsResult", "onActivityResult", "onNewIntent",
    "onSaveInstanceState", "onRestoreInstanceState", "onBackPressed",
    "onKeyDown", "onKeyUp", "onKeyLongPress", "onKeyMultiple", "onTouchEvent",
    "onTrackballEvent", "onUserInteraction", "onWindowFocusChanged",
    "onContentChanged", "onFinishInflate", "onApplyWindowInsets", "onStateChanged",
    "onClick", "onItemClick", "onItemSelected", "onPageSelected", "onPageScrolled",
}
_RESERVED_METHOD = {"<init>", "<clinit>"}

_CLASS_RE = re.compile(r'\.class\s+(?:.*?\s)?(L[\w/$]+;)')
# 重写 .class 行时保留访问标志（public/final 等）。若直接 ".class "+新描述符 会丢掉 public，
# 导致类被降为包私有 → 外壳反射 newInstance 抛 IllegalAccessException（App 启动即崩）。见 _apply_rename。
_CLASS_REWRITE_RE = re.compile(r'\.class\s+(.*?)(L[\w/$]+;)')
_SUPER_RE = re.compile(r'\.super\s+(L[\w/$]+;)')
_IMPL_RE = re.compile(r'\.implements\s+(L[\w/$]+;)')
_TYPE_TOKEN_RE = re.compile(r'L[\w/$]+;')
_METHOD_HDR_RE = re.compile(r'^(\s*)\.method\s+(?P<acc>.*?)\s+(?P<name>[^\s(]+)\((?P<desc>[^)]*)\)\s*$')
_FIELD_HDR_RE = re.compile(r'^(\s*)\.field\s+(?P<acc>.*?)\s+(?P<name>[^\s:]+):(?P<type>.*)$')
# Lcls;->name(desc) 或 Lcls;->name:type
_REF_RE = re.compile(r'(L[\w/$]+;)->([\w$]+)((?:\(\S*\))|(?::\S+))')


def _gen_id(gen):
    """生成短标识符 a..z, aa..az, ba..（纯字母，避开 <init>/<clinit> 等）。"""
    n = gen[0]
    gen[0] += 1
    s = ""
    n += 1
    while n > 0:
        n -= 1
        s = chr(ord('a') + (n % 26)) + s
        n //= 26
    return s


def _parse_manifest(dec_dir):
    """返回 (package, keep_classes 集合 of L...;)。组件名可能以 '.' 相对包。"""
    mpath = os.path.join(dec_dir, "AndroidManifest.xml")
    pkg = ""
    keep = set()
    if not os.path.isfile(mpath):
        return pkg, keep
    txt = open(mpath, "r", encoding="utf-8", errors="ignore").read()
    m = re.search(r'package="([^"]+)"', txt)
    if m:
        pkg = m.group(1).replace(".", "/")
    tag_comp = re.compile(
        r'<(application|activity|activity-alias|service|receiver|provider|instrumentation)\b[^>]*>',
        re.I)
    name_re = re.compile(r'(?:android:name|name)="([^"]+)"')
    # 注意：tag_comp 含捕获组，必须用 finditer(.group(0)) 取整段标签；
    # 用 findall 只会返回组内容("application"/"activity"…)，导致 keep 集合为空 → 组件被改名 → 崩溃。
    for m in tag_comp.finditer(txt):
        tag = m.group(0)
        for nm in name_re.findall(tag):
            if nm.startswith("."):
                # 相对名 .App4：pkg 已是斜杠形式(com/jiagu/sample4)，补点号后整体转斜杠
                full = "L" + (pkg + nm).replace(".", "/") + ";"
            elif "." in nm and not nm.startswith("android"):
                full = "L" + nm.replace(".", "/") + ";"
            else:
                continue
            keep.add(full)
    return pkg, keep


def _parse_layout_views(dec_dir):
    """布局 XML 里出现的自定义 View 类名（<com.foo.Bar 或 android:name="com.foo.Bar"）。"""
    views = set()
    res = os.path.join(dec_dir, "res")
    if not os.path.isdir(res):
        return views
    for root, _, files in os.walk(res):
        for fn in files:
            if not fn.endswith(".xml"):
                continue
            txt = open(os.path.join(root, fn), "r", encoding="utf-8", errors="ignore").read()
            for m in re.finditer(r'<([A-Za-z][\w.]*(?:\.[A-Z]\w+)+)', txt):
                cls = m.group(1)
                if cls.startswith(("android.", "androidx.", "java.", "org.", "java.")):
                    continue
                views.add("L" + cls.replace(".", "/") + ";")
            for m in re.finditer(r'(?:android:name|name)="([\w.]+)"', txt):
                cls = m.group(1)
                if "." in cls and not cls.startswith("android"):
                    views.add("L" + cls.replace(".", "/") + ";")
    return views


def _collect_defs(dec_dir):
    """返回 {(class_desc): smali_path} 所有已定义类。"""
    defs = {}
    for root, _, files in os.walk(dec_dir):
        for fn in files:
            if not fn.endswith(".smali"):
                continue
            p = os.path.join(root, fn)
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    m = _CLASS_RE.match(line.strip())
                    if m:
                        defs[m.group(1)] = p
                        break
    return defs


def _is_external(desc, pkg):
    """非 App 自有包 → 不重命名（框架/第三方库）。"""
    if not pkg:
        return False
    d = desc.strip("L").rstrip(";")
    return not (d == pkg or d.startswith(pkg + "/"))


def _build_keep_native(defs):
    """有 native 方法的类，其类名与 native 方法名保留（JNI 符号绑定）。"""
    keep_classes = set()
    keep_meth = set()
    for cls, path in defs.items():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if ".method" in line and " native " in (" " + line + " "):
                    m = _METHOD_HDR_RE.match(line.strip())
                    if m and m.group("name") not in _RESERVED_METHOD:
                        keep_meth.add((cls, m.group("name")))
                        keep_classes.add(cls)
    return keep_classes, keep_meth


def _build_rename_maps(defs, dec_dir):
    """构造 class/method/field 重命名映射。返回 (class_map, method_map, field_map)。"""
    pkg, manifest_keep = _parse_manifest(dec_dir)
    layout_views = _parse_layout_views(dec_dir)
    native_cls, native_meth = _build_keep_native(defs)

    keep_classes = set()
    keep_classes |= manifest_keep
    keep_classes |= layout_views
    keep_classes |= native_cls

    keep_methods = set()
    for cls in keep_classes:
        if cls in defs:
            keep_methods.add((cls, "*"))   # 组件类所有方法名保留（防漏生命周期）
    keep_methods |= native_meth

    class_map = {}
    method_map = {}
    field_map = {}

    gen = [0]
    used_class = set()
    # 重命名类统一挂到一个随机短包名下（如 Lx9b/），保证文件落在 dec/smali/<pkg>/ 内，
    # 否则单段描述符(如 La;)会被 apktool 放到 smali/ 之外导致回编成空 DEX。
    alpha = "abcdefghijklmnopqrstuvwxyz"
    randpkg = "".join(random.choice(alpha) for _ in range(random.randint(3, 6)))

    for cls in sorted(defs):
        if cls in keep_classes or _is_external(cls, pkg):
            class_map[cls] = cls
            continue
        while True:
            nid = _gen_id(gen)
            cand = "L%s/%s;" % (randpkg, nid)
            if cand not in used_class and cand not in class_map.values():
                used_class.add(cand)
                class_map[cls] = cand
                break

    for cls, path in defs.items():
        if class_map.get(cls) != cls:
            used_m = set()
            used_f = set()
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    mh = _METHOD_HDR_RE.match(line.strip())
                    if mh:
                        name = mh.group("name")
                        if name in _RESERVED_METHOD or (cls, "*") in keep_methods \
                                or (cls, name) in keep_methods:
                            continue
                        newn = _unique(gen, used_m)
                        method_map[(cls, name, "(" + mh.group("desc") + ")")] = newn
                        used_m.add(newn)
                        continue
                    fh = _FIELD_HDR_RE.match(line.strip())
                    if fh:
                        name = fh.group("name")
                        if (cls, "*") in keep_methods or (cls, name) in keep_methods:
                            continue
                        newn = _unique(gen, used_f)
                        field_map[(cls, name)] = newn
                        used_f.add(newn)
    return class_map, method_map, field_map


def _unique(gen, used):
    while True:
        nid = _gen_id(gen)
        if nid not in used:
            return nid


def _tr_text(text, class_map, method_map, field_map):
    """对单行做引用/描述符/名称重写（引用查表用其自身 old cls，不依赖 cur_class）。"""

    def tr_type(tok):
        return class_map.get(tok, tok)

    def tr_ref(m):
        cls, name, tail = m.group(1), m.group(2), m.group(3)
        new_cls = class_map.get(cls, cls)
        if tail.startswith("("):
            key = (cls, name, tail)
            new_name = method_map.get(key, name)
        else:
            key = (cls, name)
            new_name = field_map.get(key, name)
        return "%s->%s%s" % (new_cls, new_name, tail)

    out = _REF_RE.sub(tr_ref, text)
    out = _TYPE_TOKEN_RE.sub(lambda m: tr_type(m.group(0)), out)
    return out


def _apply_rename(dec_dir, class_map, method_map, field_map):
    """重写所有 smali 内容并移动文件到新路径。返回改动文件数。"""
    moves = []
    for cls, old_path in list(_collect_defs(dec_dir).items()):
        with open(old_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        cur_class = cls
        new_lines = []
        for line in lines:
            stripped = line.strip()
            mc = _CLASS_RE.match(stripped)
            if mc:
                new_cls = class_map.get(mc.group(1), mc.group(1))
                # 关键：保留 .class 的访问标志（public 等）。否则类被降为包私有，
                # 外壳反射 Class.forName(...).newInstance() 抛 IllegalAccessException（App 启动即崩）。
                line = _CLASS_REWRITE_RE.sub(lambda m: ".class " + m.group(1) + new_cls, line, count=1)
                # cur_class 保持旧值用于引用查表（下方 body 仍是旧描述符）
            ms = _SUPER_RE.match(stripped)
            if ms:
                line = re.sub(_SUPER_RE,
                             lambda m: ".super " + class_map.get(m.group(1), m.group(1)),
                             line, count=1)
            mi = _IMPL_RE.match(stripped)
            if mi:
                line = re.sub(_IMPL_RE,
                             lambda m: ".implements " + class_map.get(m.group(1), m.group(1)),
                             line, count=1)
            mh = _METHOD_HDR_RE.match(stripped)
            if mh:
                name = mh.group("name")
                key = (cur_class, name, "(" + mh.group("desc") + ")")
                if key in method_map:
                    newn = method_map[key]
                    line = re.sub(_METHOD_HDR_RE,
                                 lambda m: "%s.method %s %s(%s)" % (
                                     m.group(1), m.group("acc"), newn, m.group("desc")),
                                 line, count=1)
            fh = _FIELD_HDR_RE.match(stripped)
            if fh:
                name = fh.group("name")
                key = (cur_class, name)
                if key in field_map:
                    newn = field_map[key]
                    line = re.sub(_FIELD_HDR_RE,
                                 lambda m: "%s.field %s %s:%s" % (
                                     m.group(1), m.group("acc"), newn, m.group("type")),
                                 line, count=1)
            line = _tr_text(line, class_map, method_map, field_map)
            new_lines.append(line)
        with open(old_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        new_cls = class_map.get(cls, cls)
        if new_cls != cls:
            rel = new_cls.strip("L").rstrip(";") + ".smali"   # e.g. x9b/a.smali
            new_path = os.path.join(dec_dir, "smali", *rel.split("/"))
            moves.append((old_path, new_path))
    for old_path, new_path in moves:
        if os.path.abspath(old_path) == os.path.abspath(new_path):
            continue
        os.makedirs(os.path.dirname(new_path), exist_ok=True)
        shutil.move(old_path, new_path)
    return len(moves)


# ===========================================================================
# L2 弱控制流（B1）
# ===========================================================================
_REGISTERS_RE = re.compile(r'^\s*\.registers\s+(\d+)\s*$')
_LOCALS_RE = re.compile(r'^\s*\.locals\s+(\d+)\s*$')
_CODE_START_RE = re.compile(r'^\s*\.method\b')
_CODE_END_RE = re.compile(r'^\s*\.end method\s*$')


def _obfuscate_cfg_file(path):
    """verifier 安全的弱控制流：方法头插入「无用条件分支 + 死块」。返回改动方法数。

    关键：扫描 .registers/.locals 时用独立索引 j，绝不动 i（i 始终停在方法首条 body 行），
    否则会把整个方法体吞掉导致 .end method 丢失、回编失败。
    """
    changed = 0
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    out = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if _CODE_START_RE.match(line) and not _CODE_END_RE.match(line):
            mh = _METHOD_HDR_RE.match(line.strip())
            name = mh.group("name") if mh else ""
            acc = mh.group("acc") if mh else ""
            # 构造器/类初始化器/同步方法禁止插桩：
            #  - <init> 第一条指令必须是 super 调用，插桩会触发 ART 校验拒绝 → 类无法实例化
            #    （表现为外壳反射 newInstance 抛 IllegalAccessException，App 启动即崩）
            #  - <clinit> 有线程安全与首指令约束
            #  - synchronized 方法首指令是 monitor-enter，插桩会破坏 monitor 配对语义
            skip = (name in _RESERVED_METHOD) or ("synchronized" in acc)
            out.append(line)
            i += 1  # i 停在第一条 body 行
            if skip:
                while i < n and not _CODE_END_RE.match(lines[i]):
                    out.append(lines[i]); i += 1
                if i < n:
                    out.append(lines[i]); i += 1  # .end method
                continue
            # 用 j 扫描 reg 行与 .prologue（i 不动）
            reg_idx = None
            prologue_idx = None
            j = i
            while j < n and not _CODE_END_RE.match(lines[j]):
                if reg_idx is None and (_REGISTERS_RE.match(lines[j]) or _LOCALS_RE.match(lines[j])):
                    reg_idx = j
                if prologue_idx is None and lines[j].strip() == ".prologue":
                    prologue_idx = j
                j += 1
            if reg_idx is None:
                while i < n and not _CODE_END_RE.match(lines[i]):
                    out.append(lines[i]); i += 1
                if i < n:
                    out.append(lines[i]); i += 1  # .end method
                continue
            m = _REGISTERS_RE.match(lines[reg_idx])
            m2 = _LOCALS_RE.match(lines[reg_idx])
            is_locals = bool(m2) and not bool(m)
            reg_count = int((m or m2).group(1))
            # 原寄存器数 >= 255 时 if-nez 寻址越界，跳过本方法（保真优先于覆盖）
            if reg_count < 1 or reg_count >= 255:
                while i < n and not _CODE_END_RE.match(lines[i]):
                    out.append(lines[i]); i += 1
                if i < n:
                    out.append(lines[i]); i += 1
                continue
            # 1) 方法头到 reg 行（不含 reg 行本身，避免重复 .registers/.locals 指令）
            while i < reg_idx:
                out.append(lines[i]); i += 1
            # 2) 修改后的 reg 行（寄存器 +1）取代原行
            new_reg = reg_count + 1
            out.append((".locals %d\n" % new_reg) if is_locals else (".registers %d\n" % new_reg))
            i += 1  # 越过原 reg 行，避免旧 .locals/.registers 被后续拷贝重复
            vr = new_reg - 1  # 0-based 最后一根寄存器，在 new_reg 范围内合法
            lbl = "zz_obf_%d" % changed
            # 3) 若存在 .prologue，先原样输出到 .prologue（含），把死块插在它之后
            if prologue_idx is not None:
                while i <= prologue_idx:
                    out.append(lines[i]); i += 1
            # 4) 插入死块（const/16 覆盖到 v255，避免大寄存器方法产生非法字节码）
            out.append("    const/16 v%d, 0x1\n" % vr)
            out.append("    if-nez v%d, :%s\n" % (vr, lbl))
            out.append("    const/16 v%d, 0x0\n" % vr)
            out.append("    :%s\n" % lbl)
            changed += 1
            # 5) 输出剩余方法体
            while i < n and not _CODE_END_RE.match(lines[i]):
                out.append(lines[i]); i += 1
            if i < n:
                out.append(lines[i]); i += 1  # .end method
            continue
        else:
            out.append(line)
            i += 1
    if changed:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(out)
    return changed


def obfuscate_apk(input_apk, workdir, dec_class,
                  do_str=False, do_rename=False, do_cfg=False):
    """对整个 APK 做 DEX 混淆组合，返回 (dex 字节列表[按 classes.dex, classes2.dex... 排序], stats)。

    do_str/do_rename/do_cfg 对应 L1/L3/L2，默认全关。顺序：先 rename 后 str（str 插入的
    解密器引用在外部随机包，不被 rename 影响）。单个 apktool decode 目录内串行跑所有 pass。
    """
    os.makedirs(workdir, exist_ok=True)
    dec = os.path.join(workdir, "dec")
    reb = os.path.join(workdir, "reb.apk")
    shutil.rmtree(dec, ignore_errors=True)
    _run_java([config.APKTOOL, "d", input_apk, "-o", dec, "-f"])

    stats = {"str": 0, "rename_files": 0, "rename_classes": 0, "cfg_methods": 0}

    if do_rename:
        defs = _collect_defs(dec)
        class_map, method_map, field_map = _build_rename_maps(defs, dec)
        stats["rename_classes"] = sum(1 for k, v in class_map.items() if v != k)
        stats["rename_files"] = _apply_rename(dec, class_map, method_map, field_map)

    if do_str:
        total = 0
        for root, _, files in os.walk(dec):
            for fn in files:
                if fn.endswith(".smali"):
                    total += _transform_smali(os.path.join(root, fn), dec_class)
        stats["str"] = total

    if do_cfg:
        total = 0
        for root, _, files in os.walk(dec):
            for fn in files:
                if fn.endswith(".smali"):
                    total += _obfuscate_cfg_file(os.path.join(root, fn))
        stats["cfg_methods"] = total

    _run_java([config.APKTOOL, "b", dec, "-o", reb])

    out = []
    with zipfile.ZipFile(reb) as z:
        for name in z.namelist():
            m = re.match(r"classes(\d*)\.dex$", name)
            if m:
                num = m.group(1)
                out.append(((0, 0) if num == "" else (1, int(num)), z.read(name)))
    out.sort(key=lambda kv: kv[0])
    return [b for _, b in out], stats


def load_obf_dex():
    if not os.path.isfile(OBF_DEX):
        raise RuntimeError("缺少解密器 %s（请先 d8 编译 ObfStr -> obf.dex）" % OBF_DEX)
    with open(OBF_DEX, "rb") as f:
        return f.read()
