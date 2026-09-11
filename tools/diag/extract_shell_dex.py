# -*- coding: utf-8 -*-
"""从「合法外形 + 尾部 overlay」的商业壳 APK 里切出壳 DEX 并反编译。

适用对象：梆梆(SecShell) 这类壳 —— classes.dex 的 magic 是 `dex\n035`、adler32 覆盖全文件
自洽（所以 ART 认它是合法 dex、愿意在安装期做 dex2oat），但 `map_list` 只覆盖前面一小段
（壳类），声明出来的 `file_size` 后面挂着一大块「不被 dex 结构引用」的 blob（真实业务 DEX
密文/私有格式，起点常带 `dexdata0` 之类标记）。

做法（三步，全部可验证）：
  1) 用 map_list 自洽性求「结构区末尾」= map_off + 4 + map_size*12；
  2) 取 [:末尾] 做壳 DEX，把 header 的 file_size 改成该长度、重算 adler32 + SHA-1；
  3) 交给 baksmali 反编译成 smali（默认命令见 --baksmali）。

边界与诚实说明：
  * 这只对「壳 dex 结构自洽」的壳有效（梆梆符合）。若 header 被刻意破坏（魔数/长度撒谎），
    本脚本会明确报错而不是猜。
  * 切出来的只是**壳自己的类**（梆梆实测 683 个 `com.SecShell.SecShell.*`），
    业务类不在其中 —— 本脚本不给业务代码。

用法：
  python tools/diag/extract_shell_dex.py <apk或dex> [-o out.dex] [--entry classes.dex]
                                        [--smali-dir DIR] [--baksmali JAR] [--no-baksmali]
示例：
  python tools/diag/extract_shell_dex.py \
      "D:/APK/ylyk_5.9.5/app-huawei-5.9.5-2026-09-07_protected_sign.apk" \
      -o _wk_diag/secshell_shell_only.dex --smali-dir _wk_diag/secshell_smali
"""
import argparse
import hashlib
import os
import struct
import subprocess
import sys
import zipfile
import zlib

DEFAULT_BAKSMALI = r'D:/Android/baksmali-2.5.2.jar'

MAP_NAMES = {
    0x0000: 'header', 0x0001: 'string_id', 0x0002: 'type_id', 0x0003: 'proto_id',
    0x0004: 'field_id', 0x0005: 'method_id', 0x0006: 'class_def', 0x1000: 'map_list',
    0x1001: 'type_list', 0x1002: 'annotation_set_ref', 0x1003: 'annotation_set',
    0x2000: 'class_data', 0x2001: 'code_item', 0x2002: 'string_data',
    0x2003: 'debug_info', 0x2004: 'annotation', 0x2005: 'encoded_array',
    0x2006: 'annotations_directory',
}


def read_source(path, entry):
    """返回 (字节, 来源描述)。APK 取指定 entry；裸 dex 直接读。"""
    if path.lower().endswith('.apk'):
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if entry not in names:
                raise SystemExit('APK 内没有 %s（现有 dex: %s）'
                                 % (entry, [n for n in names if n.endswith('.dex')]))
            info = z.getinfo(entry)
            return z.read(entry), '%s!%s (compress=%d raw=%d)' % (
                os.path.basename(path), entry, info.compress_size, info.file_size)
    with open(path, 'rb') as f:
        return f.read(), os.path.basename(path)


def parse_header(d):
    U = lambda off: struct.unpack_from('<I', d, off)[0]
    return {
        'checksum': U(0x08), 'signature': d[12:32].hex(),
        'file_size': U(0x20), 'header_size': U(0x24), 'endian': U(0x28),
        'map_off': U(0x34), 'string_ids_size': U(0x38), 'type_ids_size': U(0x40),
        'method_ids_size': U(0x58), 'class_defs_size': U(0x60),
        'data_size': U(0x68),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('apk')
    ap.add_argument('-o', '--output', default=None, help='切出的壳 dex 输出路径')
    ap.add_argument('--entry', default='classes.dex')
    ap.add_argument('--smali-dir', default=None)
    ap.add_argument('--baksmali', default=DEFAULT_BAKSMALI)
    ap.add_argument('--no-baksmali', action='store_true')
    args = ap.parse_args()

    data, src = read_source(args.apk, args.entry)
    print('来源: %s' % src)
    print('字节数: %d' % len(data))

    if data[:4] != b'dex\n':
        raise SystemExit('魔数不是 dex\\n —— 该 dex 被整体加密/变形，本脚本不适用')

    h = parse_header(data)
    print('header: version=%s file_size=%d header_size=%d endian=%08x map_off=%d'
          % (data[4:7].decode('ascii', 'replace'), h['file_size'], h['header_size'],
             h['endian'], h['map_off']))
    print('        string_ids=%d type_ids=%d method_ids=%d class_defs=%d data_size=%d'
          % (h['string_ids_size'], h['type_ids_size'], h['method_ids_size'],
             h['class_defs_size'], h['data_size']))

    if zlib.adler32(data[12:h['file_size']]) & 0xffffffff != h['checksum']:
        raise SystemExit('adler32 不自洽 —— header 在撒谎，本脚本不猜，请人工分析')

    mo = h['map_off']
    if not (0 < mo < len(data) - 4):
        raise SystemExit('map_off 越界')
    n = struct.unpack_from('<I', data, mo)[0]
    end = mo + 4 + n * 12
    print('map_list @%d: %d 项（结构区末尾 = %d）' % (mo, n, end))

    # 展示 map 表，便于确认「尾部不被引用」
    for i in range(min(n, 20)):
        t, _, sz, off = struct.unpack_from('<HHII', data, mo + 4 + i * 12)
        print('   type=0x%04x %-18s size=%-8d off=%d' % (t, MAP_NAMES.get(t, '?'), sz, off))

    overlay = len(data) - end
    print()
    print('overlay（不被 dex 结构引用的尾部）: %d 字节' % overlay)
    if overlay > 0:
        print('  起点标记样例: %r' % data[end:end + 16])

    # 切壳 dex 并修头
    end = min(end, len(data))
    shell = bytearray(data[:end])
    struct.pack_into('<I', shell, 0x20, end)            # file_size
    struct.pack_into('<I', shell, 0x08, 0)              # checksum 占位
    shell[12:32] = hashlib.sha1(bytes(shell[32:])).digest()      # SHA-1 覆盖 [32, end)
    struct.pack_into('<I', shell, 0x08,
                     zlib.adler32(bytes(shell[12:])) & 0xffffffff)  # adler32 覆盖 [12, end)

    out = args.output or (os.path.splitext(args.apk)[0] + '_shell_only.dex')
    with open(out, 'wb') as f:
        f.write(bytes(shell))
    print()
    print('写出 %s  %d 字节' % (out, len(shell)))
    print('自检: magic=%r file_size=%d adler32 自洽=%s'
          % (bytes(shell[:8]), struct.unpack_from('<I', shell, 0x20)[0],
             'YES' if (zlib.adler32(bytes(shell[12:])) & 0xffffffff)
             == struct.unpack_from('<I', shell, 0x08)[0] else 'NO'))

    if args.no_baksmali:
        return 0
    smali = args.smali_dir or (os.path.splitext(out)[0] + '_smali')
    if not os.path.exists(args.baksmali):
        print('未找到 baksmali: %s（用 --no-baksmali 关掉这一步，或 --baksmali 指定路径）'
              % args.baksmali)
        return 0
    if os.path.isdir(smali):
        print('smali 目录已存在，跳过反编译: %s' % smali)
        return 0
    cmd = ['java', '-jar', args.baksmali, 'd', os.path.abspath(out), '-o', os.path.abspath(smali)]
    print('反编译: %s' % ' '.join(cmd))
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        print(r.stdout.decode('utf-8', 'replace'))
        return r.returncode
    cnt = sum(1 for _, _, fs in os.walk(smali) for x in fs if x.endswith('.smali'))
    print('反编译完成: %s（%d 个 .smali）' % (smali, cnt))
    return 0


if __name__ == '__main__':
    sys.exit(main())
