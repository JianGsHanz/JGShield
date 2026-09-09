# vmp_protect.py -- T4-lite VMP "进壳" 集成核心。
#
# 对「任意 App」通用：勾选 VMP 后自动扫描全部 DEX 的全部方法，用 vmp_compile 的
# 安全子集闸门筛选（纯 int/long 计算、regs<=15、无 invoke/字段/数组/对象/字符串/
# float/double/异常表），命中的方法在构建期现场编译成私有字节码：
#   1) 私有字节码(blob, 魔数 FD C2 + per-method XOR key) 由 vmp_compile.compile 现场生成，
#      零 androguard 依赖（打包 exe 也能跑）；
#   2) 在原始 app DEX 里把该方法翻转为 native (access_flags|=ACC_NATIVE, code_off=0) 并清零原 insns;
#   3) 生成 jg_vmp_shim.c: 把 blob 编进 .so .rodata, 并为每个方法导出 JNI 符号 Java_<cls>_<name>,
#      运行时由 libjgguard.so 里的解释器(jg_vmp.c)执行私有字节码。
#
# 诚实边界: 这只是抬高逆向成本。私有指令执行时仍是明文; 真机内存 dd 抽到的将是私有指令而非 dalvik。
# 解释器本身需 OLLVM 混淆才更抗逆。

import os
import sys
import struct
import zlib
import hashlib

# 通用自动发现：不再有硬编码包名白名单/预编译 blob。
# 唯一可调旋钮是「单包最多虚拟化多少方法」——防止 .so / shim C 体积爆炸。
# ylyk 实测安全子集约 5900 个方法；上限 300 时 shim C 约 1MB、编译耗时可控。
MAX_VMP_METHODS = int(os.environ.get("JG_VMP_MAX_METHODS", "300"))
# 过于短小的方法（几条指令）虚拟化收益低、风险不低，设下限。
MIN_VMP_INSNS = int(os.environ.get("JG_VMP_MIN_INSNS", "4"))

ACC_NATIVE = 0x100
ACC_ABSTRACT = 0x400
ACC_CONSTRUCTOR = 0x200  # 顺手清掉, 避免 native+constructor 冲突

TYPE_CLASS_DATA_ITEM = 0x2000  # 注意：0x1000 是 MAP_LIST，CLASS_DATA_ITEM 是 0x2000（踩过坑）


# ---------- VMP 编译器（懒加载，零 androguard 依赖） ----------
def _ensure_vmp_compiler():
    """返回 vmp_compile 模块。vmp_compile 依赖 vmp_arch2（纯 Python，位于
    experiments/vmp_lite/），这里做 sys.path 兜底，打包 exe 也能 import。"""
    try:
        import vmp_compile
        return vmp_compile
    except ImportError:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "experiments", "vmp_lite"), here):
        if cand not in sys.path:
            sys.path.insert(0, cand)
    try:
        import vmp_compile
        return vmp_compile
    except ImportError as e:
        raise RuntimeError(
            "VMP 编译依赖 vmp_compile.py + vmp_arch2.py（两者均为纯 Python，无 androguard 依赖）。"
            "当前运行环境找不到这两个模块，无法启用 VMP——请在 GUI/CLI 中关闭 VMP 选项，"
            "或确认打包时已包含 experiments/vmp_lite/vmp_arch2.py。原始错误: %s" % e
        ) from e


# ---------- DEX 基础读写 ----------
def _u16(b, off):
    return b[off] | (b[off + 1] << 8)


def _u32(b, off):
    return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24))


def _w16(b, off, v):
    b[off] = v & 0xff
    b[off + 1] = (v >> 8) & 0xff


def _w32(b, off, v):
    b[off] = v & 0xff
    b[off + 1] = (v >> 8) & 0xff
    b[off + 2] = (v >> 16) & 0xff
    b[off + 3] = (v >> 24) & 0xff


def _read_uleb(b, off):
    r = 0
    s = 0
    i = off
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7f) << s
        if not (x & 0x80):
            break
        s += 7
    return r, i


def _write_uleb(v):
    out = bytearray()
    x = v
    while True:
        b = x & 0x7f
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return out


def _str_off(dex):
    return _u32(dex, 0x3C)


def _type_off(dex):
    return _u32(dex, 0x44)


def _proto_off(dex):
    return _u32(dex, 0x4C)


def _method_off(dex):
    return _u32(dex, 0x5C)


def _classdef_off(dex):
    return _u32(dex, 0x64)


def _classdef_size(dex):
    return _u32(dex, 0x60)


def _read_string(dex, idx):
    off = _u32(dex, _str_off(dex) + idx * 4)
    _, p = _read_uleb(dex, off)  # skip utf16_size
    start = p
    end = p
    while dex[end] != 0:
        end += 1
    return bytes(dex[start:end]).decode("utf-8", "replace")


def _type_name(dex, type_idx):
    so = _type_off(dex)
    str_idx = _u32(dex, so + type_idx * 4)
    return _read_string(dex, str_idx)


def _method_descriptor(dex, proto_idx):
    base = _proto_off(dex) + proto_idx * 12
    ret_idx = _u32(dex, base + 4)
    params_off = _u32(dex, base + 8)
    ret = _type_name(dex, ret_idx)
    params = ""
    if params_off != 0:
        size = _u32(dex, params_off)
        p = params_off + 4
        for _ in range(size):
            tidx = _u16(dex, p)
            p += 2
            params += _type_name(dex, tidx)
    return "(" + params + ")" + ret


def _method_name_desc(dex, midx):
    mb = _method_off(dex) + midx * 8
    name_idx = _u32(dex, mb + 4)
    proto_idx = _u16(dex, mb + 2)
    return _read_string(dex, name_idx), _method_descriptor(dex, proto_idx)


def _fix_dex(dex):
    """重算 DEX 校验和(adler32)与签名(sha1), 否则 ART 会拒载。"""
    sig = hashlib.sha1(bytes(dex[32:])).digest()
    for i in range(20):
        dex[12 + i] = sig[i]
    c = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    _w32(dex, 8, c)


# ---------- class_data 解析 / 序列化 ----------
def _parse_class_data(dex, cd_off):
    p = cd_off
    sf_size, p = _read_uleb(dex, p)
    if_size, p = _read_uleb(dex, p)
    dm_size, p = _read_uleb(dex, p)
    vm_size, p = _read_uleb(dex, p)
    sf = []
    last = 0
    for _ in range(sf_size):
        diff, p = _read_uleb(dex, p)
        last += diff
        af, p = _read_uleb(dex, p)
        sf.append((last, af))
    inf = []
    last = 0
    for _ in range(if_size):
        diff, p = _read_uleb(dex, p)
        last += diff
        af, p = _read_uleb(dex, p)
        inf.append((last, af))
    dm = []
    last = 0
    for _ in range(dm_size):
        diff, p = _read_uleb(dex, p)
        last += diff
        af, p = _read_uleb(dex, p)
        co, p = _read_uleb(dex, p)
        dm.append((last, af, co))
    vm = []
    last = 0
    for _ in range(vm_size):
        diff, p = _read_uleb(dex, p)
        last += diff
        af, p = _read_uleb(dex, p)
        co, p = _read_uleb(dex, p)
        vm.append((last, af, co))
    st = {"sf": sf, "if": inf, "dm": dm, "vm": vm}
    return st, p


def _serialize_class_data(st):
    out = bytearray()
    out += _write_uleb(len(st["sf"]))
    out += _write_uleb(len(st["if"]))
    out += _write_uleb(len(st["dm"]))
    out += _write_uleb(len(st["vm"]))
    prev = 0
    for (idx, af) in st["sf"]:
        out += _write_uleb(idx - prev); prev = idx
        out += _write_uleb(af)
    prev = 0
    for (idx, af) in st["if"]:
        out += _write_uleb(idx - prev); prev = idx
        out += _write_uleb(af)
    prev = 0
    for (idx, af, co) in st["dm"]:
        out += _write_uleb(idx - prev); prev = idx
        out += _write_uleb(af)
        out += _write_uleb(co)
    prev = 0
    for (idx, af, co) in st["vm"]:
        out += _write_uleb(idx - prev); prev = idx
        out += _write_uleb(af)
        out += _write_uleb(co)
    return out


def _patch_class_data(dex, cd_off, targets_in_class):
    """翻转 targets_in_class({(name,desc),...}) 里的方法为 native, 清零原 insns。
    返回 (new_class_data_bytes_or_None, [(insns_off, insns_size), ...])。"""
    st, end_off = _parse_class_data(dex, cd_off)
    zero_tasks = []
    changed = False
    for lst in (st["dm"], st["vm"]):
        for i, (midx, af, co) in enumerate(lst):
            if co == 0:
                continue
            nm, ds = _method_name_desc(dex, midx)
            if (nm, ds) in targets_in_class:
                insns_size = _u32(dex, co + 12)
                insns_off = co + 16
                if insns_size > 0:
                    zero_tasks.append((insns_off, insns_size))
                new_af = (af | ACC_NATIVE) & (~ACC_ABSTRACT) & (~ACC_CONSTRUCTOR) & 0xFFFF
                lst[i] = (midx, new_af, 0)
                changed = True
    if not changed:
        return None, []
    return _serialize_class_data(st), zero_tasks


def _update_map_class_data_section(dex, new_off, count):
    """整段重建后同步 map_list：更新 class_data 条目的 offset/size，并把整张 map 按
    offset 升序重排（DEX 规范强制不变式）。class_data 被移到文件尾后其 offset 最大，
    必须排到末尾，否则 dexdump/ART 报 'Map is missing header entry'。"""
    map_off = _u32(dex, 0x34)
    if map_off == 0:
        return
    size = _u32(dex, map_off)
    e = map_off + 4
    entries = []
    for _ in range(size):
        typ = _u16(dex, e)
        sz = _u32(dex, e + 4)
        off = _u32(dex, e + 8)
        entries.append([typ, sz, off])
        e += 12
    for ent in entries:
        if ent[0] == TYPE_CLASS_DATA_ITEM:
            ent[1] = count
            ent[2] = new_off
    # 按 offset 升序重排（header 在 offset 0，必排首位）
    entries.sort(key=lambda x: x[2])
    e = map_off + 4
    for (typ, sz, off) in entries:
        _w16(dex, e, typ)
        _w16(dex, e + 2, 0)
        _w32(dex, e + 4, sz)
        _w32(dex, e + 8, off)
        e += 12


def _map_entries(dex):
    """返回 [(type, size, offset), ...]，按 map_list 中的记录顺序。"""
    map_off = _u32(dex, 0x34)
    if map_off == 0:
        return []
    size = _u32(dex, map_off)
    out = []
    e = map_off + 4
    for _ in range(size):
        out.append((_u16(dex, e), _u32(dex, e + 4), _u32(dex, e + 8)))
        e += 12
    return out


def _section_bounds(dex, type_code):
    """返回该类型 section 的 [start, limit)：start 为 map 记录偏移，limit 为 map 中
    下一个 offset 更大的 section 起点（没有则取 file_size）。"""
    ents = _map_entries(dex)
    mine = [e for e in ents if e[0] == type_code]
    if not mine:
        return None
    start = min(e[2] for e in mine)
    later = sorted(e[2] for e in ents if e[2] > start)
    limit = later[0] if later else _u32(dex, 0x20)
    return (start, limit)


def patch_single_dex(dex_bytes, targets):
    """targets: 属于该 dex 的白名单 [(cls,name,desc), ...]。返回修补后的 dex 字节。

    ⚠ 关键（踩过的坑）：ART/libdexfile 校验 class_data_item 时，是从 map 记录的 section
    起点开始【逐个连续】遍历的（offset += 当前 item 长度，共 size 个）。因此**任何单个
    class_data_item 变短都会让后面所有条目在错误偏移上被解析** → 整个 DEX 校验失败 →
    该 dex 所有类都 ClassNotFoundException（真实现象：App 的 Application 类找不到）。
    所以不能"原地改写+补零"，必须把整段 class_data 重新紧凑排布，并同步更新每个
    class_def 的 class_data_off。段尾多出来的空间补零（零 padding 是合法的）。
    """
    dex = bytearray(dex_bytes)
    by_class = {}
    for (cls, name, desc) in targets:
        by_class.setdefault(cls, set()).add((name, desc))

    cdo = _classdef_off(dex)
    cds = _classdef_size(dex)

    # 1) 按 class_def 顺序收集全部 class_data（顺序必须与 map 遍历顺序一致）
    entries = []          # [(cd_pos, class_name_or_None, cd_off, st_or_None, old_len)]
    for ci in range(cds):
        cd_pos = cdo + ci * 32
        cd_off = _u32(dex, cd_pos + 0x18)
        if cd_off == 0:
            entries.append((cd_pos, None, 0, None, 0))
            continue
        class_name = _type_name(dex, _u32(dex, cd_pos))
        st, end = _parse_class_data(dex, cd_off)
        entries.append((cd_pos, class_name, cd_off, st, end - cd_off))

    # 2) 施加修改（只改内存里的结构，暂不落盘）
    zero_tasks = []
    changed = False
    for (_pos, cname, _off, st, _old_len) in entries:
        if st is None or cname not in by_class:
            continue
        for lst in (st["dm"], st["vm"]):
            for i, (midx, af, co) in enumerate(lst):
                if co == 0:
                    continue
                nm, ds = _method_name_desc(dex, midx)
                if (nm, ds) not in by_class[cname]:
                    continue
                if _u32(dex, co + 12):
                    zero_tasks.append((co + 16, _u32(dex, co + 12)))
                new_af = (af | ACC_NATIVE) & (~ACC_ABSTRACT) & (~ACC_CONSTRUCTOR) & 0xFFFF
                lst[i] = (midx, new_af, 0)
                changed = True
    if not changed:
        return bytes(dex_bytes)

    # 3) 清零被虚拟化方法的原 dalvik 指令区
    for (io, isz) in zero_tasks:
        for k in range(isz * 2):
            dex[io + k] = 0

    # 4) 整段重建：所有 class_data 紧凑连续重排回【原 class_data section 起点】，
    #    同步更新每个 class_def.class_data_off。段尾多余空间清零(零 padding 合法)。
    #    原地重写不移动段位置，map_list 无需重排，dexdump/ART 校验稳定通过。
    bounds = _section_bounds(dex, TYPE_CLASS_DATA_ITEM)
    live = [e for e in entries if e[2] != 0]
    if bounds is None:
        print("[VMP] 警告: map_list 无 class_data section，放弃修补该 dex")
        return bytes(dex_bytes)
    sec_start, sec_limit = bounds

    blob = bytearray()
    offsets = []          # 与 entries 对齐：每个可写 class_data 在新块内的起始偏移
    for (_pos, _cn, _off, st, _old_len) in entries:
        if st is None:
            offsets.append(None)
            continue
        offsets.append(len(blob))
        blob += _serialize_class_data(st)

    if sec_start + len(blob) > sec_limit:
        print("[VMP] 警告: 重建后 class_data 段放不下(%d > %d)，放弃修补该 dex"
              % (sec_start + len(blob), sec_limit))
        return bytes(dex_bytes)

    dex[sec_start:sec_start + len(blob)] = blob
    for k in range(sec_start + len(blob), sec_limit):
        dex[k] = 0
    for (cd_pos, _cn, _off, st, _old_len), off in zip(entries, offsets):
        if st is None:
            continue
        _w32(dex, cd_pos + 0x18, sec_start + off)
    _update_map_class_data_section(dex, sec_start, len(live))

    _fix_dex(dex)
    return bytes(dex)


# ---------- 目标发现 + 编译 ----------
ACC_STATIC = 0x8


def _desc_safe(desc):
    """描述符闸门：拒绝 float/double 的返回或参数。

    F/D 无法用 int64 私有寄存器位精确表示 —— shim 里 (int64_t)p 是「值转换」而非
    「位重解释」，虚拟化后会静默算出错误结果。对象/数组参数是纯指针，位精确，允许。
    """
    try:
        rp = desc.rindex(')')
        ret = desc[rp + 1:]
        body = desc[desc.index('(') + 1:rp]
    except ValueError:
        return False
    if 'F' in ret or 'D' in ret:
        return False
    i = 0
    while i < len(body):
        c = body[i]
        if c == '[':
            i += 1
            continue
        if c == 'L':
            j = body.find(';', i)
            if j < 0:
                return False
            i = j + 1
            continue
        if c in 'FD':
            return False
        i += 1
    return True


def _discover_auto(dex_names, orig_dexes, max_methods=None, only=None):
    """通用自动发现：扫描全部 DEX 的全部方法，用 vmp_compile 的安全子集闸门筛选。

    与包名无关（不再有 zhuomogroup 之类硬编码），任意 App 勾选 VMP 都生效。
    返回 [{dex_idx,cls,name,desc,code_off,static,overloaded}]。
    """
    if max_methods is None:
        max_methods = MAX_VMP_METHODS
    vc = _ensure_vmp_compiler()

    # 一遍遍历：统计同名重载(JNI 符号需要) + 收集「有方法体」的候选
    name_count = {}
    cands = []
    dex_cache = {}
    for di, db in enumerate(orig_dexes):
        dex = bytearray(db)
        dex_cache[di] = dex
        try:
            cdo, cds = _classdef_off(dex), _classdef_size(dex)
        except Exception:
            continue
        for ci in range(cds):
            cd_pos = cdo + ci * 32
            try:
                cls_name = _type_name(dex, _u32(dex, cd_pos))
                cd_off = _u32(dex, cd_pos + 0x18)
            except Exception:
                continue
            if cd_off == 0:
                continue
            try:
                st, _ = _parse_class_data(dex, cd_off)
            except Exception:
                continue
            for lst in (st["dm"], st["vm"]):
                for (midx, af, co) in lst:
                    try:
                        nm, ds = _method_name_desc(dex, midx)
                    except Exception:
                        continue
                    name_count[(cls_name, nm)] = name_count.get((cls_name, nm), 0) + 1
                    if co == 0 or (af & ACC_ABSTRACT):
                        continue
                    if only is not None and (cls_name, nm, ds) not in only:
                        continue
                    cands.append((di, cls_name, nm, ds, af, co))

    found = []
    skipped = {}
    for (di, cls_name, nm, ds, af, co) in cands:
        if len(found) >= max_methods:
            break
        dex = dex_cache[di]
        if not _desc_safe(ds):
            skipped['float/double 描述符'] = skipped.get('float/double 描述符', 0) + 1
            continue
        try:
            if _u16(dex, co + 6) != 0:      # tries_size != 0 -> 带 try/catch，异常语义无法还原
                skipped['try/catch'] = skipped.get('try/catch', 0) + 1
                continue
            ok, reason = vc.classify(dex, co)
        except Exception as e:
            ok, reason = False, 'exc:%s' % e
        if not ok:
            key = str(reason).split(':')[0]
            skipped[key] = skipped.get(key, 0) + 1
            continue
        try:
            _r, insns, _isz = vc.decode_method(dex, co)
        except Exception as e:
            skipped['decode:%s' % type(e).__name__] = skipped.get('decode:%s' % type(e).__name__, 0) + 1
            continue
        if len(insns) < MIN_VMP_INSNS:
            skipped['过短(<insns)'] = skipped.get('过短(<insns)', 0) + 1
            continue
        found.append({"dex_idx": di, "cls": cls_name, "name": nm, "desc": ds,
                      "code_off": co,
                      "static": bool(af & ACC_STATIC),
                      "overloaded": name_count.get((cls_name, nm), 1) > 1})

    print("[VMP] 自动扫描完成: 有体方法 %d, 安全子集命中 %d (上限 %d, 最短 %d 指令)"
          % (len(cands), len(found), max_methods, MIN_VMP_INSNS))
    if skipped:
        top = sorted(skipped.items(), key=lambda kv: -kv[1])[:6]
        print("[VMP] 未命中原因 top: " + ", ".join("%s=%d" % kv for kv in top))
    return found


def discover_targets(dex_names, orig_dexes, whitelist=None, max_methods=None):
    """在 orig_dexes 里找到可虚拟化方法, 返回 [{dex_idx,cls,name,desc,code_off,static,overloaded}]。

    默认（whitelist=None）= 通用自动发现：任意 App 都生效，无需硬编码包名。
    whitelist 仅作调试/回归用：显式指定时只考虑这些 (cls,name,desc)。
    """
    if whitelist:
        return _discover_auto(dex_names, orig_dexes, max_methods=max_methods,
                              only=set(whitelist))
    return _discover_auto(dex_names, orig_dexes, max_methods=max_methods)


def compile_targets(targets, keys, orig_dexes):
    """把目标方法现场编译成私有 blob。keys[i] = 第 i 个方法的 per-build XOR key。

    返回 [{cls,name,desc,blob,param_reg,static,overloaded}]。
    注: key 必须 per-method 且 per-build 不同 —— 固定 0xC2 会让所有构建产物
    的 .rodata 出现同一字节流, 成为跨版本 diff 的锚点。
    """
    vc = _ensure_vmp_compiler()
    out = []
    dex_cache = {}
    for i, t in enumerate(targets):
        key = keys[i] & 0xFF
        di = t["dex_idx"]
        if di not in dex_cache:
            dex_cache[di] = bytearray(orig_dexes[di])
        try:
            blob, preg = vc.compile(dex_cache[di], t["code_off"], t["desc"], key)
        except Exception as e:
            print("[VMP] 跳过 %s.%s%s: 编译失败 (%s: %s)"
                  % (t["cls"], t["name"], t["desc"], type(e).__name__, e))
            continue
        out.append({"cls": t["cls"], "name": t["name"], "desc": t["desc"],
                    "blob": blob, "param_reg": preg,
                    "static": t["static"], "overloaded": t["overloaded"]})
    print("[VMP] 编译完成: %d/%d 个方法 -> 私有字节码 (总 %d 字节)"
          % (len(out), len(targets), sum(len(m["blob"]) for m in out)))
    return out


def patch_dexes(orig_dexes, targets):
    """按 dex 分组修补。返回修补后的 orig_dexes 列表。"""
    by_dex = {}
    for t in targets:
        by_dex.setdefault(t["dex_idx"], []).append((t["cls"], t["name"], t["desc"]))
    patched = list(orig_dexes)
    for di, tg in by_dex.items():
        patched[di] = patch_single_dex(orig_dexes[di], tg)
    return patched


# ---------- shim 生成 ----------
def _dalvik_to_c(t):
    return {
        "Z": "jboolean", "B": "jbyte", "S": "jshort", "C": "jchar",
        "I": "jint", "J": "jlong", "F": "jfloat", "D": "jdouble",
    }.get(t, "jobject")


def _param_regs(desc):
    """返回 [(ctype, dalvik_reg_start, width_in_regs), ...]，按 dalvik 参数顺序。"""
    params = desc[desc.index("(") + 1:desc.index(")")]
    res = []
    i = 0
    while i < len(params):
        if params[i] == "L":
            i = params.index(";", i) + 1
            res.append(("jobject", 1))
            continue
        if params[i] == "[":
            while params[i] == "[":
                i += 1
            if params[i] == "L":
                i = params.index(";", i) + 1
            else:
                i += 1
            res.append(("jobject", 1))
            continue
        c = params[i]
        w = 2 if c in "JD" else 1
        res.append((_dalvik_to_c(c), w))
        i += 1
    # 计算实际寄存器起点(相对 param_reg)
    layout = []
    cursor = 0
    for (ct, w) in res:
        layout.append((ct, cursor, w))
        cursor += w
    return layout


def _ret_cast(desc):
    r = desc[desc.rindex(")") + 1]
    if r == "I":
        return "(jint)(r & 0xFFFFFFFF)"
    # dalvik 布尔是 0/1，但用 (r != 0) 比 (r & 1) 稳：万一返回寄存器里是其它非零值
    # 也不会把 true 误判成 false（&(1) 会让 2 变 0）。
    if r == "Z":
        return "(jboolean)((r != 0) ? 1 : 0)"
    if r == "J":
        return "(jlong)r"
    if r == "C":
        return "(jchar)(r & 0xFFFF)"
    if r == "B":
        return "(jbyte)(r & 0xFF)"
    if r == "S":
        return "(jshort)(r & 0xFFFF)"
    return "(jint)(r & 0xFFFFFFFF)"


def _jni_mangle(s):
    """JNI 全名修饰（JNI spec 同名规则）。

    ⚠ 踩过的坑: 之前只处理 _ / ; [ / ，漏了内部类的 '$'。
    ART 查找 native 实现时用的是 Java_androidx_..._ItemTouchHelper_00024Callback_xxx，
    若符号里保留裸 '$' 则注册/查找不到 -> 运行期 UnsatisfiedLinkError 崩溃。
    规则: 字母数字保留；'/' '.' -> '_'；'_'->'_1' ';'->'_2' '['->'_3'；
    其它字符 -> '_0' + UTF-16 码元的 4 位十六进制（如 '$' -> _00024）。
    """
    out = []
    for ch in s:
        if ch.isascii() and ch.isalnum():
            out.append(ch)
        elif ch in "/.":
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        else:
            b = ch.encode("utf-16-be")
            for i in range(0, len(b), 2):
                out.append("_0%04x" % ((b[i] << 8) | b[i + 1]))
    return "".join(out)


def _jni_name(cls, name, desc=None, overloaded=False):
    """JNI 符号名。overloaded 时按 JNI 规范追加 __<mangled params> 后缀。"""
    s = cls.strip(";")[1:]  # Lcom/.../a -> com/.../a
    base = "Java_" + _jni_mangle(s) + "_" + _jni_mangle(name)
    if overloaded and desc:
        params = desc[desc.index("(") + 1:desc.index(")")]
        base += "__" + _jni_mangle(params)
    return base


def gen_shim_c(compiled, out_path):
    lines = []
    lines.append("/* AUTO-GENERATED by vmp_protect.py -- T4-lite VMP JNI shims.")
    lines.append(" * 被保护方法的 dalvik 体已在构建期从 DEX 移除并翻转为 native；")
    lines.append(" * 这里导出的 JNI 符号在运行时由 jg_vmp.c 的解释器执行私有字节码。 */")
    lines.append("#include <jni.h>")
    lines.append("#include <stdint.h>")
    lines.append("#include <string.h>")
    lines.append("#include <stdlib.h>")
    lines.append('#include "jg_vmp.h"')
    lines.append("")
    for i, m in enumerate(compiled):
        blob = m["blob"]
        arr = ", ".join("0x%02x" % b for b in blob)
        lines.append("/* %s.%s%s  param_reg=%d  key=0x%02x */"
                     % (m["cls"], m["name"], m["desc"], m["param_reg"], blob[2]))
        lines.append("static const uint8_t kJG_VMP_BLOB_%d[] = { %s };" % (i, arr))
    lines.append("")
    for i, m in enumerate(compiled):
        desc = m["desc"]
        layout = _param_regs(desc)
        params = ", ".join("%s p%d" % (ct, j) for j, (ct, _rs, _w) in enumerate(layout))
        jni = _jni_name(m["cls"], m["name"], desc, m.get("overloaded", False))
        # static -> jclass; 非 static -> jobject(this)
        second = "jclass cls" if m.get("static", True) else "jobject thiz"
        lines.append("JNIEXPORT %s JNICALL %s(JNIEnv* env, %s%s%s) {"
                     % (_dalvik_to_c(desc[desc.rindex(")") + 1]), jni, second,
                        ", " if params else "", params))
        lines.append("    int64_t seed[16]; memset(seed, 0, sizeof(seed));")
        nargs = 0
        if not m.get("static", True):
            # dalvik 参数寄存器位于帧尾, `this` 是第一个参数 -> 占 param_reg-1 号寄存器
            lines.append("    seed[%d] = (int64_t)(intptr_t)thiz;" % (m["param_reg"] - 1))
            nargs = max(nargs, m["param_reg"])
        for j, (ct, rs, w) in enumerate(layout):
            # 对象/数组参数是纯指针：先转 intptr_t 再转 int64_t，避免 32 位 ABI 上
            # 指针直接转 int64_t 的符号扩展差异（真机会拿到错误的寄存器种子值）。
            cast = "(int64_t)(intptr_t)p%d" if ct == "jobject" else "(int64_t)p%d"
            lines.append("    seed[%d] = %s;" % (m["param_reg"] + rs, cast % j))
            nargs = max(nargs, m["param_reg"] + rs + w)
        lines.append("    size_t n; uint8_t* code = jg_vmp_deobfuscate("
                     "kJG_VMP_BLOB_%d, sizeof(kJG_VMP_BLOB_%d), &n);" % (i, i))
        lines.append("    int64_t r = jg_vmp_run(code, n, seed, %d);" % nargs)
        lines.append("    free(code);")
        lines.append("    return %s;" % _ret_cast(desc))
        lines.append("}")
        lines.append("")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("[VMP] shim 已生成: %s (%d 个方法)" % (out_path, len(compiled)))
    return out_path


def apply_vmp(dex_names, orig_dexes, key_fn, work_dir, whitelist=None):
    """进壳编排：发现目标 -> 编译私有 blob -> 修补 DEX -> 生成 JNI shim。

    key_fn(i) -> 第 i 个方法的 XOR key（调用方传入以保证与 harden 同一次 HKDF 派生）。
    返回 None（无可虚拟化方法）或 {"dexes","shim","methods","count"}。
    """
    tg = discover_targets(dex_names, orig_dexes, whitelist)
    if not tg:
        print("[VMP] 当前 APK 未发现可虚拟化的安全子集方法，跳过")
        return None
    keys = [key_fn(i) & 0xFF for i in range(len(tg))]
    compiled = compile_targets(tg, keys, orig_dexes)
    if not compiled:
        print("[VMP] 全部目标编译失败，跳过 VMP")
        return None
    # ⚠ 关键：只翻转「真正编译成功」的方法为 native。
    # 若把编译失败的方法也翻成 native，运行时会找不到 JNI 实现 -> UnsatisfiedLinkError 崩溃。
    ok_keys = {(m["cls"], m["name"], m["desc"]) for m in compiled}
    patch_tg = [t for t in tg if (t["cls"], t["name"], t["desc"]) in ok_keys]
    patched = patch_dexes(orig_dexes, patch_tg)
    os.makedirs(work_dir, exist_ok=True)
    shim = os.path.join(work_dir, "jg_vmp_shim.c")
    gen_shim_c(compiled, shim)
    methods = [(m["cls"], m["name"], m["desc"], len(m["blob"]), m["blob"][2])
               for m in compiled]
    return {"dexes": patched, "shim": shim, "methods": methods, "count": len(compiled)}


if __name__ == "__main__":
    # 独立自测: 直接在 APK 原始 DEX 上跑「自动发现 -> 编译 -> 修补 -> 生成 shim」全链路。
    import zipfile
    APK = "D:/APK/ylyk_5.9.4/app-Ptest-5.9.4-2026-08-04.apk"
    apk = os.environ.get("VMP_APK", APK)
    z = zipfile.ZipFile(apk)
    names = sorted(n for n in z.namelist() if n.endswith(".dex"))
    orig = [z.read(n) for n in names]
    HERE = os.path.dirname(os.path.abspath(__file__))

    res = apply_vmp(names, orig, (lambda i: (0x5A + i * 37) & 0xFF),
                    os.path.join(HERE, "experiments", "vmp_lite"))
    if not res:
        print("[FAIL] 未发现任何可虚拟化方法")
        raise SystemExit(1)
    print("[VMP] 虚拟化 %d 个方法:" % res["count"])
    for (cls, nm, ds, blen, key) in res["methods"][:10]:
        print("    %s.%s%s  blob=%dB key=0x%02x" % (cls, nm, ds, blen, key))
    for di, (o, p) in enumerate(zip(orig, res["dexes"])):
        print("dex[%d] orig=%d patched=%d changed=%s" % (di, len(o), len(p), o != p))
    print("[OK] 自测完成 -> %s" % res["shim"])
