#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P0-C anti-dump 沙箱逻辑门禁（纯谓词，不依赖设备 /proc）。

镜像 GxAntiDump 的检测逻辑：
  - parse_maps_start : 解析 /proc/self/maps 行起始地址
  - is_dex_magic     : 4 字节是否 DEX 魔数 (dex\n / dey\n)
  - classify_region  : 匿名 / memfd / 文件映射 分类
  - in_self_dex      : 地址是否落在已登记的自家 DEX 区间（排除自检误报）
  - detect           : 组合判定（含排除）

真实 /proc/self/maps 读取与 /proc/self/mem seek 属真机运行期行为，沙箱无法执行；
本门禁只证明判定逻辑正确（语法/边界/排除），运行期一致性仍需真机+frida 反向验证。
"""
import sys


def parse_maps_start(line):
    sp = line.find('-')
    if sp <= 0:
        return -1
    try:
        return int(line[:sp].strip(), 16)
    except ValueError:
        return -1


def is_dex_magic(head):
    if len(head) != 4:
        return False
    return (head[0] == 0x64 and head[1] == 0x65 and head[3] == 0x0a
            and (head[2] == 0x78 or head[2] == 0x79))


def classify_region(line):
    sp = line.find('-')
    if sp <= 0:
        return "skip"
    idx = line.find('/', sp)
    path = line[idx:].strip() if idx >= 0 else ""
    anon = (path == "")
    memfd = path.startswith("/memfd:") or ("memfd" in path)
    if anon or memfd:
        return "<scan>"
    return "skip"   # 文件映射（含 APK 自身）跳过


def in_self_dex(addr, ranges):
    for r in ranges:
        if r[0] <= addr < r[1]:
            return True
    return False


def detect(lines, self_dex):
    """lines: list of /proc/self/maps 行；self_dex: [[start,end),...]。
    返回 (hit_bool, hit_detail_or_None)。扫描仅对匿名/memfd 区域、且排除 self_dex。"""
    if not self_dex:
        return False, None   # 启动竞态保护：自家 DEX 未登记不扫描
    for line in lines:
        if classify_region(line) != "<scan>":
            continue
        start = parse_maps_start(line)
        if start < 0:
            continue
        if in_self_dex(start, self_dex):
            continue
        # 真实环境此处读 /proc/self/mem[start:start+4]；沙箱用行内注入的 magic 模拟
        magic = _SIM_MAGIC.get(start)
        if magic is not None and is_dex_magic(magic):
            return True, "0x%x" % start
    return False, None


# 沙箱模拟：地址 -> 该区域首 4 字节（真实环境由 /proc/self/mem 读出）
_SIM_MAGIC = {}


def _main():
    ok = True

    # 1) parse_maps_start
    assert parse_maps_start("00400000-00401000 r-xp 00000000 08:01 123 /bin/foo") == 0x400000
    assert parse_maps_start("7b8c2a0000-7b8c2b0000 rw-p 00000000 00:00 0") == 0x7b8c2a0000
    assert parse_maps_start("not-a-map-line") == -1

    # 2) is_dex_magic
    assert is_dex_magic(b"dex\n") is True
    assert is_dex_magic(b"dey\n") is True
    assert is_dex_magic(b"zip\n") is False
    assert is_dex_magic(b"dex\x00") is False
    assert is_dex_magic(b"dexx") is False

    # 3) classify_region
    assert classify_region("00400000-00401000 r-xp 00000000 08:01 123 /bin/foo") == "skip"   # 文件
    assert classify_region("7b8c000000-7b8c001000 rw-p 00000000 00:00 0") == "<scan>"          # 匿名
    assert classify_region("7b8c001000-7b8c002000 rw-p 00000000 00:00 0 /memfd:foo (deleted)") == "<scan>"  # memfd

    # 4) in_self_dex
    ranges = [[0x1000, 0x5000], [0x9000, 0xB000]]
    assert in_self_dex(0x2000, ranges) is True
    assert in_self_dex(0x8000, ranges) is False
    assert in_self_dex(0xB000, ranges) is False   # 半开区间

    # 5) detect 组合
    # 场景 A：匿名区含 DEX 魔数、不在 self 区间 -> 命中
    _SIM_MAGIC.clear()
    _SIM_MAGIC[0x70000] = b"dex\n"
    lines = [
        "00400000-00401000 r-xp 00000000 08:01 123 /bin/foo",
        "00070000-00071000 rw-p 00000000 00:00 0",   # 匿名，含 DEX 魔数
    ]
    hit, detail = detect(lines, [[0x1000, 0x5000]])
    assert hit is True and detail == "0x70000", (hit, detail)

    # 场景 B：DEX 魔数落在 self 区间 -> 排除，不命中
    _SIM_MAGIC.clear()
    _SIM_MAGIC[0x2000] = b"dex\n"
    lines_b = [
        "00001000-00005000 rw-p 00000000 00:00 0",   # 匿名，但属 self
    ]
    hit, detail = detect(lines_b, [[0x1000, 0x5000]])
    assert hit is False, (hit, detail)

    # 场景 C：DEX 魔数在文件映射区（APK 自身）-> 跳过，不命中
    _SIM_MAGIC.clear()
    _SIM_MAGIC[0x30000] = b"dex\n"
    lines_c = [
        "00030000-00031000 r--p 00000000 08:01 456 /data/app/foo/base.apk",
    ]
    hit, detail = detect(lines_c, [[0x1000, 0x5000]])
    assert hit is False, (hit, detail)

    # 场景 D：self 区间为空（启动竞态）-> 不扫描，不命中
    _SIM_MAGIC.clear()
    _SIM_MAGIC[0x70000] = b"dex\n"
    lines_d = ["00070000-00071000 rw-p 00000000 00:00 0"]
    hit, detail = detect(lines_d, [])
    assert hit is False, (hit, detail)

    print("[gate] P0-C anti-dump 谓词逻辑: OK (5 组用例全过)")
    print("[gate]   注: 真实 /proc/self/mem 读取与 ART 匿名拷贝误报残留=真机+frida 验证范畴")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
