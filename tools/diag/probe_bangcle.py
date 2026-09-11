"""剖析梆梆/SecShell 加固包的结构：DEX 是否明文、壳入口在哪、有没有落地 dex。"""
import zipfile, struct, hashlib, zlib, sys

P = sys.argv[1] if len(sys.argv) > 1 else r'D:/APK/ylyk_5.9.5/app-huawei-5.9.5-2026-09-07_protected_sign.apk'
z = zipfile.ZipFile(P)


def dex_names(z):
    return [i.filename for i in z.infolist() if i.filename.lower().endswith('.dex')]


print("=== APK: %s" % P)
print("=== dex 条目 ===")
for i in z.infolist():
    if i.filename.lower().endswith('.dex'):
        print("   %-20s comp=%-9d raw=%-9d" % (i.filename, i.compress_size, i.file_size))

print()
print("=== assets/ 下 >64KB 的条目（可能的加密载荷）===")
for i in z.infolist():
    if i.filename.startswith('assets/') and i.file_size > 65536:
        print("   %-60s raw=%-10d" % (i.filename, i.file_size))

name = dex_names(z)[0]
data = z.read(name)
print()
print("=== %s 头解析 ===" % name)
F = lambda off: struct.unpack_from('<I', data, off)[0]
hdr = {
    'checksum': F(0x08), 'file_size': F(0x20), 'header_size': F(0x24), 'endian': F(0x28),
    'link_size': F(0x2C), 'link_off': F(0x30), 'map_off': F(0x34),
    'string_ids_size': F(0x38), 'string_ids_off': F(0x3C),
    'type_ids_size': F(0x40), 'type_ids_off': F(0x44),
    'proto_ids_size': F(0x48), 'proto_ids_off': F(0x4C),
    'field_ids_size': F(0x50), 'field_ids_off': F(0x54),
    'method_ids_size': F(0x58), 'method_ids_off': F(0x5C),
    'class_defs_size': F(0x60), 'class_defs_off': F(0x64),
    'data_size': F(0x68), 'data_off': F(0x6C),
}
for k, v in hdr.items():
    print("   %-16s = %-12d" % (k, v))
fsz = hdr['file_size']
print("   magic=%r" % data[:8])
print("   实际字节=%d vs file_size=%d → %s" % (len(data), fsz, "一致" if len(data) == fsz else "不一致"))
print("   adler32 自洽: %s" % ("YES" if (zlib.adler32(data[12:fsz]) & 0xffffffff) == hdr['checksum'] else "NO"))
print("   SHA-1 自洽:   %s" % ("YES" if hashlib.sha1(data[32:fsz]).hexdigest() == data[12:32].hex() else "NO"))

mo = hdr['map_off']
names = {0x0000: 'header', 0x0001: 'string_id', 0x0002: 'type_id', 0x0003: 'proto_id',
         0x0004: 'field_id', 0x0005: 'method_id', 0x0006: 'class_def', 0x1000: 'map_list',
         0x1001: 'type_list', 0x1002: 'annotation_set_ref', 0x1003: 'annotation_set',
         0x2000: 'class_data', 0x2001: 'code_item', 0x2002: 'string_data',
         0x2003: 'debug_info', 0x2004: 'annotation', 0x2005: 'encoded_array'}
if 0 < mo < len(data) - 4:
    n = F(mo)
    print("   map_list @%d: %d 项" % (mo, n))
    for i in range(min(n, 20)):
        t, _u, sz, off = struct.unpack_from('<HHII', data, mo + 4 + i * 12)
        print("      0x%04x %-18s size=%-8d off=%d" % (t, names.get(t, '?'), sz, off))

soff, ssz = hdr['string_ids_off'], hdr['string_ids_size']


def read_str(idx):
    o = struct.unpack_from('<I', data, soff + idx * 4)[0]
    n = data[o]
    if n & 0x80:
        n = ((n & 0x7f) << 8) | data[o + 1]
        o += 2
    else:
        o += 1
    e = o
    while data[e] != 0:
        e += 1
    return data[o:e].decode('utf-8', 'replace')


print()
print("=== 字符串命中（判断谁是入口/壳）===")
keys = ['zhuomogroup', 'SecShell', 'StubApp', 'attachBaseContext', 'Application', 'ProxyApplication']
hits = {k: [] for k in keys}
for i in range(ssz):
    try:
        s = read_str(i)
    except Exception:
        continue
    for k in keys:
        if k.lower() in s.lower() and len(hits[k]) < 8:
            hits[k].append(s)
for k in keys:
    print("   [%-18s] %s" % (k, hits[k][:8]))
