#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A·强反 Frida 沙箱逻辑门禁（纯谓词，不依赖设备 /proc 或 frida 运行期）。

覆盖两段可沙箱验证的逻辑：
  1) 写端（Python）— harden.py 经 patch_manifest(antifrida=True) 注入的 manifest meta
     (随机名 config.META_ANTIFRIDA="1") 必须被正确写入，且原 Application 类名解析不受影响；
     关闭时不注入。这使 Java 读端 GxAntiFrida 经 mb.getString(meta) 能拿到开关。
  2) 读端判定镜像（Python 镜像 jg_anti_frida.c）— maps 路径 frida 签名匹配（大小写不敏感）、
     TracerPid 解析、端口探测 -> 位掩码。证明检测谓词正确（语法/边界/误报红线）。

真实 /proc/self/maps 读取、端口 connect、native 位掩码收口属真机运行期行为，沙箱无法执行；
本门禁只证明：① 写读两端以同一随机 meta 键对齐（开关注入正确）、② 检测谓词边界正确。
运行期「真机+frida 反向验证」仍由用户在本机完成（沙箱无设备/无 frida）。
"""
import os
import struct
import sys
import zipfile

import config
import axml_editor as ax


# ── 1) 写端：manifest 注入正确性 ───────────────────────────────────────────────

def _collect_meta(manifest_data):
    """解析 patched manifest，返回 [(meta_name, meta_value), ...]，仅 meta-data 子元素。"""
    data = manifest_data
    pool = ax._parse_string_pool(data, 8)
    strings = pool['strings']
    android_uri_idx = ax._find_string_index(strings, ax.ANDROID_NS_URI)
    name_attr_idx   = ax._find_string_index(strings, 'name')
    value_attr_idx  = ax._find_string_index(strings, 'value')
    meta_data_idx   = ax._find_string_index(strings, 'meta-data')
    xml_start = ax._find_xml_start(data, 8)
    pairs = []
    for chunk_type, cs, csz in ax._iter_chunks(data, xml_start):
        if chunk_type != ax.CHUNK_START_ELEMENT:
            continue
        nm = struct.unpack_from('<I', data, cs + 20)[0]
        if nm != meta_data_idx:
            continue
        elem = ax._parse_start_element(data, cs)
        kname = kval = None
        for a in elem['attributes']:
            if a['ns'] == android_uri_idx and a['name'] == name_attr_idx:
                if a['data_type'] == ax.TYPE_STRING and a['data'] < len(strings):
                    kname = strings[a['data']]
            if a['ns'] == android_uri_idx and a['name'] == value_attr_idx:
                if a['data_type'] == ax.TYPE_STRING and a['data'] < len(strings):
                    kval = strings[a['data']]
        if kname is not None:
            pairs.append((kname, kval))
    return pairs


def _sample_manifest():
    """选第一个能解析出字符串 Application 类名的 sample APK 作为测例（壳引导依赖此值）。"""
    import glob
    base = os.path.join(os.path.dirname(__file__), "test_apks", "*.apk")
    for apk in sorted(glob.glob(base)):
        try:
            with zipfile.ZipFile(apk, 'r') as z:
                m = z.read('AndroidManifest.xml')
            if ax.get_orig_app_class(m):
                return m
        except Exception:
            continue
    raise RuntimeError("test_apks 中无可用 sample（需 android:name 为字符串）")


# ── 2) 读端判定镜像（jg_anti_frida.c）──────────────────────────────────────────

FRIDA_SIGS = ["frida", "frida-agent", "frida-gadget", "libfrida",
              "gum-js-loop", "linjector", "re.frida.server"]


def _strcasestr(hay, needle):
    if not hay or not needle:
        return False
    return needle.lower() in hay.lower()


def _maps_path(line):
    p = line.rfind(' ')
    return line[p + 1:] if p >= 0 else ""


def _maps_frida(line):
    return any(_strcasestr(_maps_path(line), s) for s in FRIDA_SIGS)


def _tracerpid_hit(status_line):
    if status_line.startswith("TracerPid:"):
        try:
            return int(status_line.split(':', 1)[1].strip()) != 0
        except ValueError:
            return False
    return False


def _mask(maps, tracerpid, port):
    m = 0
    if maps:      m |= 1
    if tracerpid: m |= 2
    if port:      m |= 4
    return m


# ── 主流程 ────────────────────────────────────────────────────────────────────

def _main():
    manifest = _sample_manifest()
    orig_app = ax.get_orig_app_class(manifest)
    assert orig_app, "sample1.apk 应能从二进制 Manifest 解析出原 Application 类名"

    # 2.1 写端：antifrida=True 必须注入 (META_ANTIFRIDA, "1")，且不影响原类名解析
    patched_on = ax.patch_manifest(manifest, orig_app,
                                   shell_app_class=config.SHELL_APP,
                                   antidump=False, antifrida=True,
                                   meta_antifrida=config.META_ANTIFRIDA)
    pairs_on = _collect_meta(patched_on)
    assert (config.META_ANTIFRIDA, "1") in pairs_on, \
        "antifrida=True 必须注入 meta %s=1，实际: %s" % (config.META_ANTIFRIDA, pairs_on)
    # 原 Application 类名经 gx.orig_app meta 保留（壳引导依赖）；注入后 android:name 已是壳类
    assert (config.META_ORIG, orig_app) in pairs_on, \
        "注入后原 Application 必须仍以 %s meta 保留，实际: %s" % (config.META_ORIG, pairs_on)
    assert ax.get_orig_app_class(patched_on) == config.SHELL_APP, \
        "注入后 <application android:name> 必须改写为壳入口（引导依赖）"

    # 2.2 写端：antifrida=False 不得注入该 meta（默认关，零副作用）
    patched_off = ax.patch_manifest(manifest, orig_app,
                                    shell_app_class=config.SHELL_APP,
                                    antidump=False, antifrida=False,
                                    meta_antifrida=config.META_ANTIFRIDA)
    pairs_off = _collect_meta(patched_off)
    assert (config.META_ANTIFRIDA, "1") not in pairs_off, \
        "antifrida=False 不得注入 meta（默认关闭），实际: %s" % (pairs_off,)

    # 2.3 读端判定镜像：maps frida 签名（大小写不敏感、误报红线）。
    # 路径列 = maps 行最后一个空格之后（与 native _scan_maps_frida 一致）。
    assert _maps_frida("7b8c000000-7b8c001000 rw-p 00000000 00:00 0 /data/app/com.x/lib/libfrida-agent.so") is True
    assert _maps_frida("7b8c000000-7b8c001000 rw-p 00000000 00:00 0 re.frida.server") is True
    assert _maps_frida("7b8c000000-7b8c001000 r-xp 00000000 08:01 456 /data/app/com.x/base.apk") is False  # 正常 APK 不误报
    assert _maps_frida("7b8c000000-7b8c001000 rw-p 00000000 00:00 0 [anon:gmain]") is False  # 排除泛化串

    # 2.4 TracerPid 解析
    assert _tracerpid_hit("TracerPid:\t0") is False
    assert _tracerpid_hit("TracerPid:\t12345") is True
    assert _tracerpid_hit("Name:\tcom.x") is False

    # 2.5 位掩码组合（与 GxAntiFrida.detect mask!=0 对应）
    assert _mask(False, False, False) == 0
    assert _mask(True,  False, False) == 1
    assert _mask(False, True,  False) == 2
    assert _mask(False, False, True)  == 4
    assert _mask(True,  True,  True)  == 7

    print("[gate] A·强反 Frida 写端 manifest 注入 (开/关): OK")
    print("[gate] A·强反 Frida 读端判定镜像 (maps/TracerPid/port -> mask): OK")
    print("[gate]   注: native scanJNI 运行期一致性 + 真机+frida 反向验证 = 用户本机范畴，沙箱不执行")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
