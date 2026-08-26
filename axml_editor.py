# -*- coding: utf-8 -*-
"""
二进制 AndroidManifest.xml (AXML 格式) 编辑器。

对外接口：
    get_orig_app_class(manifest_data: bytes) -> str | None
    patch_manifest(manifest_data: bytes, orig_app_class: str,
                   shell_app_class: str = "com.gx.runtime.GxApp") -> bytes
"""

import struct

import config


# ─── 常量 ──────────────────────────────────────────────────────────────────────

# Chunk 类型
CHUNK_STRING_POOL     = 0x001C0001
CHUNK_RESOURCE_MAP    = 0x00080180
CHUNK_START_NAMESPACE = 0x00100100
CHUNK_END_NAMESPACE   = 0x00100101
CHUNK_START_ELEMENT   = 0x00100102
CHUNK_END_ELEMENT     = 0x00100103

# Res_value dataType
TYPE_NULL       = 0x00
TYPE_REFERENCE  = 0x01
TYPE_STRING     = 0x03
TYPE_INT_HEX    = 0x10

# 文件头 magic
AXML_MAGIC = 0x00080003  # bytes: 03 00 08 00

# 命名空间 URI
ANDROID_NS_URI = "http://schemas.android.com/apk/res/android"

# Sentinel 值
NO_ENTRY = 0xFFFFFFFF  # -1 的无符号表示

# android: 标准属性资源 ID（PackageParser 按资源 ID 匹配，不能写成字符串索引！）
# 写成字符串 "name"/"value" 时 aapt dump 能显示，但设备安装器严格按 0x0101xxxx 匹配会找不到 -> 报缺 value。
RES_ANDROID_NAME  = 0x01010003  # android:name
RES_ANDROID_VALUE = 0x01010024  # android:value


# ─── 字符串池工具 ─────────────────────────────────────────────────────────────

def _parse_string_pool(data, pool_start):
    """
    解析字符串池 chunk。

    参数:
        data: 完整文件数据 (bytes/bytearray)
        pool_start: pool chunk 在 data 中的绝对偏移

    返回:
        dict: {
            'strings':          [str, ...],          # 解码后的字符串列表
            'is_utf8':          bool,                # True=UTF-8, False=UTF-16
            'string_count':     int,
            'style_count':      int,
            'strings_start':    int,                 # stringsStart 字段值
            'styles_start':     int,                 # stylesStart 字段值
            'chunk_size':       int,                 # pool 总大小
            'flag':             int,                 # flags 原始值
            'string_data_offset': int,               # 字符串数据区在 data 中的绝对偏移
            'string_ends':      [int, ...],           # 每个字符串在 data 中的绝对结束偏移(NUL 之后)
        }
    """
    chunk_type = struct.unpack_from('<I', data, pool_start)[0]
    if chunk_type != CHUNK_STRING_POOL:
        raise ValueError(f"期望 STRING_POOL (0x001C0001)，得到 0x{chunk_type:08X}")

    chunk_size     = struct.unpack_from('<I', data, pool_start + 4)[0]
    string_count   = struct.unpack_from('<I', data, pool_start + 8)[0]
    style_count    = struct.unpack_from('<I', data, pool_start + 12)[0]
    flag           = struct.unpack_from('<I', data, pool_start + 16)[0]
    strings_start  = struct.unpack_from('<I', data, pool_start + 20)[0]
    styles_start   = struct.unpack_from('<I', data, pool_start + 24)[0]

    is_utf8 = bool(flag & 0x0100)

    # 偏移数组地址
    offsets_start = pool_start + 28  # 8(hdr: type+size) + 5*4(stringCount..stylesStart)
    string_data_abs = pool_start + strings_start

    strings = []
    string_ends_cache = []  # 每个字符串数据的结束绝对位置 (含 NUL 终止符之后的位置)

    for i in range(string_count):
        offset_in_pool = struct.unpack_from('<I', data, offsets_start + i * 4)[0]
        abs_pos = pool_start + strings_start + offset_in_pool

        if is_utf8:
            decoded, next_pos = _decode_utf8_string(data, abs_pos)
        else:
            decoded, next_pos = _decode_utf16_string(data, abs_pos)

        strings.append(decoded)
        string_ends_cache.append(next_pos)

    return {
        'strings':            strings,
        'is_utf8':            is_utf8,
        'string_count':       string_count,
        'style_count':        style_count,
        'strings_start':      strings_start,
        'styles_start':       styles_start,
        'chunk_size':         chunk_size,
        'flag':               flag,
        'string_data_offset': string_data_abs,
        'string_ends':        string_ends_cache,
    }


def _decode_utf8_string(data, abs_pos):
    """解码 UTF-8 编码的字符串。返回 (str, 下一个字符串起始位置)。"""
    b0 = data[abs_pos]
    if b0 >= 0x80:
        b1 = data[abs_pos + 1]
        length = ((b0 & 0x7F) << 8) | b1
        str_start = abs_pos + 2
    else:
        length = b0
        str_start = abs_pos + 1
    # 末尾有 NUL 终止符
    end = str_start + length
    return data[str_start:end].decode('utf-8'), end + 1


def _decode_utf16_string(data, abs_pos):
    """解码 UTF-16 编码的字符串。返回 (str, 下一个字符串起始位置)。"""
    length = struct.unpack_from('<H', data, abs_pos)[0]
    str_start = abs_pos + 2
    utf16_data = data[str_start:str_start + length * 2]
    # 末尾有 2 字节 NUL 终止符
    return utf16_data.decode('utf-16-le'), str_start + length * 2 + 2


def _encode_utf8_string(s):
    """将 Python 字符串编码为字符串池的 UTF-8 格式。"""
    utf8_bytes = s.encode('utf-8')
    utf8_len = len(utf8_bytes)
    if utf8_len > 0x7F:
        length_bytes = bytes([(utf8_len >> 8) | 0x80, utf8_len & 0xFF])
    else:
        length_bytes = bytes([utf8_len])
    return length_bytes + utf8_bytes + b'\x00'


def _encode_utf16_string(s):
    """将 Python 字符串编码为字符串池的 UTF-16 格式。"""
    utf16_bytes = s.encode('utf-16-le')
    char_count = len(s)  # 字符数，不是字节数
    return struct.pack('<H', char_count) + utf16_bytes + b'\x00\x00'


def _add_string_to_pool(data, pool_start, new_str, strings, is_utf8):
    """
    向字符串池追加新字符串。修改 data bytearray。

    参数:
        data:       bytearray，完整文件数据（原地修改）
        pool_start: pool chunk 在 data 中的绝对偏移
        new_str:    要添加的新字符串
        strings:    当前已知的字符串列表（函数调用后会更新）
        is_utf8:    pool 编码标志

    返回:
        int: 新字符串在池中的索引
    """
    # 检查是否已存在
    for i, s in enumerate(strings):
        if s == new_str:
            return i

    string_count = struct.unpack_from('<I', data, pool_start + 8)[0]
    style_count  = struct.unpack_from('<I', data, pool_start + 12)[0]
    strings_start = struct.unpack_from('<I', data, pool_start + 20)[0]
    styles_start  = struct.unpack_from('<I', data, pool_start + 24)[0]

    # 编码新字符串
    if is_utf8:
        encoded = _encode_utf8_string(new_str)
    else:
        encoded = _encode_utf16_string(new_str)

    # 计算当前字符串数据区长度
    if style_count > 0:
        str_data_end = styles_start
    else:
        str_data_end = struct.unpack_from('<I', data, pool_start + 4)[0]  # chunkSize

    str_data_len = str_data_end - strings_start
    new_offset = str_data_len

    # 插入新 offset 条目到 offset 数组末尾
    insert_pos = pool_start + 28 + string_count * 4
    data[insert_pos:insert_pos] = struct.pack('<I', new_offset)

    # 偏移数组多 4 字节 → stringsStart / stylesStart 各 +4
    struct.pack_into('<I', data, pool_start + 20, strings_start + 4)
    struct.pack_into('<I', data, pool_start + 24, styles_start + 4)

    # 在字符串数据区末尾追加编码数据
    str_data_insert = pool_start + strings_start + 4 + str_data_len
    data[str_data_insert:str_data_insert] = encoded

    # stylesStart 因尾部追加再后移
    struct.pack_into('<I', data, pool_start + 24, styles_start + 4 + len(encoded))

    # 更新 string_count
    struct.pack_into('<I', data, pool_start + 8, string_count + 1)

    # 更新 chunk_size
    old_chunk_size = struct.unpack_from('<I', data, pool_start + 4)[0]
    new_chunk_size = old_chunk_size + 4 + len(encoded)
    struct.pack_into('<I', data, pool_start + 4, new_chunk_size)

    strings.append(new_str)
    return string_count


def _find_string_index(strings, target):
    """在字符串列表中查找目标字符串，返回索引或 -1。"""
    for i, s in enumerate(strings):
        if s == target:
            return i
    return -1


# ─── XML 块扫描 ───────────────────────────────────────────────────────────────

def _iter_chunks(data, start_offset, end_offset=None):
    """
    遍历 data 中的 chunk。每个 chunk 必须从 start_offset 开始连续排列。

    Yields: (chunk_type, chunk_start, chunk_size)
    """
    if end_offset is None:
        end_offset = len(data)

    pos = start_offset
    while pos + 8 <= end_offset:
        chunk_type = struct.unpack_from('<I', data, pos)[0]
        chunk_size = struct.unpack_from('<I', data, pos + 4)[0]
        if chunk_size < 8:
            break
        yield chunk_type, pos, chunk_size
        pos += chunk_size


def _find_xml_start(data, pool_start):
    """找到 XML 树起始位置（跳过 StringPool 和可选的 ResourceMap）。"""
    pool_chunk_size = struct.unpack_from('<I', data, pool_start + 4)[0]
    pos = pool_start + pool_chunk_size

    # 跳过可选的 ResourceMap chunk
    if pos + 8 <= len(data):
        chunk_type = struct.unpack_from('<I', data, pos)[0]
        if chunk_type == CHUNK_RESOURCE_MAP:
            chunk_size = struct.unpack_from('<I', data, pos + 4)[0]
            pos += chunk_size
    return pos


# 框架属性名 -> 资源 ID（用于按文档顺序重建 ResourceMap）。
# 仅 meta-data 的 name/value 被严格解析，必须精确；其余属性即便填错框架 ID
# 也不影响安装（原包 ResourceMap 错位仍能装即证明非严格属性容忍错位）。
_ANDROID_ATTR_RES = {
    'name': 0x01010003, 'value': 0x01010024, 'label': 0x01010001,
    'icon': 0x01010002, 'theme': 0x01010000, 'exported': 0x01010010,
    'enabled': 0x0101000E, 'permission': 0x01010006, 'process': 0x01010009,
    'multiprocess': 0x0101000A, 'taskAffinity': 0x0101000B,
    'minSdkVersion': 0x0101000C, 'targetSdkVersion': 0x01010010,
    'maxSdkVersion': 0x01010011, 'debuggable': 0x0101000F,
    'versionCode': 0x0101021B, 'versionName': 0x0101021C,
    'package': 0x0101020C, 'platformBuildVersionCode': 0x01010270,
    'platformBuildVersionName': 0x01010001, 'allowBackup': 0x01010280,
    'roundIcon': 0x01010536, 'supportsRtl': 0x010103F1,
    'launchMode': 0x0101001D, 'screenOrientation': 0x0101001E,
    'configChanges': 0x0101001F, 'windowSoftInputMode': 0x0101022B,
    'category': 0x01010003, 'action': 0x01010003, 'data': 0x01010004,
    'host': 0x01010005, 'scheme': 0x01010007, 'mimeType': 0x01010026,
    'authorities': 0x01010018, 'resource': 0x01010025, 'initOrder': 0x01010021,
    'description': 0x01010008, 'parentActivityName': 0x0101037A,
    'hardwareAccelerated': 0x010102E1, 'uiOptions': 0x010102D9,
    'required': 0x0101038D, 'protectionLevel': 0x01010029,
}


def _rebuild_resource_map(data, pool_start, strings):
    """
    重建 ResourceMap：按「属性名的字符串池索引」建立 资源ID 映射。

    真机实测定位的根因（关键修正）：
      Android `ResXMLTree::getAttributeNameResource(i)` 返回
      `mResIds[attr->name.index]`，即 ResourceMap 按「属性名在字符串池中的索引」
      寻址，而非按文档属性顺序。aapt 编译的清单正是这种布局
      （见 _ref/ref.apk：RM=[0x01010003,0x01010001,0x01010024]，
       分别落在 name/label/value 三个字符串索引 0/1/2 处）。

      旧实现按文档属性顺序 1:1 生成 RM，导致 meta-data 的 android:name
      属性（name 字符串索引=5）被映射到 RM[5]（恰好是 minSdkVersion 的资源 ID），
      getAttributeNameResource 返回 0x0101000C 而非 0x01010003，
      PackageParser.parseMetaData 判定「缺少 android:name」→
      INSTALL_PARSE_FAILED_MANIFEST_MALFORMED。

      修正：遍历最终文档，为每个属性按其「name 字段的字符串索引」填入框架
      资源 ID（name→0x01010003 / value→0x01010024 / label→0x01010001 …），
      RM 数组长度 = (最大 name 字符串索引 + 1)，位置严格对齐字符串索引。
      这样 meta-data 的 android:name 必被正确解析。
    """
    # 1. 收集 name 字符串索引 -> 资源 ID
    res_by_name_idx = {}
    p = _find_xml_start(data, pool_start)
    while p + 8 <= len(data):
        ct = struct.unpack_from('<I', data, p)[0]
        cs = struct.unpack_from('<I', data, p + 4)[0]
        if cs < 8:
            break
        if ct == CHUNK_START_ELEMENT:
            e = _parse_start_element(data, p)
            for a in e['attributes']:
                nm = a['name']
                if nm >= 0x01000000:
                    # 已是资源 ID（aapt 实际不这么写，防御性跳过，不占 RM 位置）
                    continue
                if nm < len(strings):
                    rid = _ANDROID_ATTR_RES.get(strings[nm], 0)
                else:
                    rid = 0
                res_by_name_idx[nm] = rid
        p += cs

    if not res_by_name_idx:
        return False

    max_idx = max(res_by_name_idx.keys())
    new_len = max_idx + 1
    rm_body = [0] * new_len
    for idx, rid in res_by_name_idx.items():
        if idx < new_len:
            rm_body[idx] = rid

    new_rm = struct.pack('<II', CHUNK_RESOURCE_MAP, 8 + new_len * 4)
    new_rm += b"".join(struct.pack('<I', x) for x in rm_body)

    # 2. 替换（或新建）RM chunk，位置在原 RM 处
    pool_chunk_size = struct.unpack_from('<I', data, pool_start + 4)[0]
    rm_pos = pool_start + pool_chunk_size
    had_rm = (rm_pos + 8 <= len(data) and
              struct.unpack_from('<I', data, rm_pos)[0] == CHUNK_RESOURCE_MAP)
    if had_rm:
        rm_size = struct.unpack_from('<I', data, rm_pos + 4)[0]
        data[rm_pos:rm_pos + rm_size] = new_rm
    else:
        data[rm_pos:rm_pos] = new_rm
    return True


# ─── StartElement 解析 / 构造 ─────────────────────────────────────────────────

def _parse_start_element(data, chunk_start):
    """
    解析一个 StartElement chunk。

    chunk_start 指向 chunk 的 type 字段。

    返回:
        dict: {
            'ns': int,                # 元素命名空间索引
            'name': int,              # 元素名索引
            'attribute_count': int,
            'attributes': [
                {
                    'ns': int,        # 属性命名空间索引
                    'name': int,      # 属性名索引
                    'raw_value': int, # 原始字符串值索引
                    'data_type': int, # Res_value dataType
                    'data': int,      # Res_value data
                }, ...
            ],
            'chunk_size': int,
            'line': int,
        }
    """
    chunk_size = struct.unpack_from('<I', data, chunk_start + 4)[0]
    line       = struct.unpack_from('<I', data, chunk_start + 8)[0]
    # comment 在 offset 12
    ns_val   = struct.unpack_from('<I', data, chunk_start + 16)[0]
    name_val = struct.unpack_from('<I', data, chunk_start + 20)[0]
    attr_start = struct.unpack_from('<H', data, chunk_start + 24)[0]
    attr_size  = struct.unpack_from('<H', data, chunk_start + 26)[0]
    attr_count = struct.unpack_from('<H', data, chunk_start + 28)[0]

    attributes = []

    # attr_start 是从 ns 字段开始的偏移
    # ns 字段在 chunk_start + 16
    # 所以属性从 chunk_start + 16 + attr_start 开始
    attr_pos = chunk_start + 16 + attr_start

    for _ in range(attr_count):
        attr_ns   = struct.unpack_from('<I', data, attr_pos)[0]
        attr_name = struct.unpack_from('<I', data, attr_pos + 4)[0]
        raw_value = struct.unpack_from('<I', data, attr_pos + 8)[0]
        # Res_value: size(uint16) + res0(uint8) + dataType(uint8) + data(uint32)
        rv_size, rv_res0, data_type, rv_data = struct.unpack_from('<HBB I', data, attr_pos + 12)

        attributes.append({
            'ns':        attr_ns,
            'name':      attr_name,
            'raw_value': raw_value,
            'data_type': data_type,
            'data':      rv_data,
        })
        attr_pos += attr_size

    return {
        'ns':              ns_val,
        'name':            name_val,
        'attribute_count': attr_count,
        'attributes':      attributes,
        'chunk_size':      chunk_size,
        'line':            line,
    }


def _pack_start_element_chunk(elem_ns, elem_name, attributes, line=0):
    """
    构造一个完整的 StartElement chunk（含 8 字节 chunk header）。

    参数:
        elem_ns:    元素命名空间索引（-1 = NO_ENTRY）
        elem_name:  元素名索引
        attributes: [{ns, name, raw_value, data_type, data}, ...]
        line:       行号

    返回:
        bytes: 完整的 chunk 数据
    """
    attr_count = len(attributes)
    attr_size = 20
    attr_start = 20  # 从 ns 字段算起的偏移（标准值）

    # chunk body 大小: 28 字节头 + 属性区
    body_size = 28 + attr_count * attr_size
    chunk_size = 8 + body_size

    buf = bytearray()
    # Chunk header
    buf += struct.pack('<II', CHUNK_START_ELEMENT, chunk_size)
    # line, comment
    buf += struct.pack('<II', line, NO_ENTRY)
    # ns, name
    buf += struct.pack('<II', elem_ns, elem_name)
    # attributeStart, attributeSize, attributeCount, idIndex, classIndex, styleIndex
    # idIndex/classIndex/styleIndex：属性数组内 android:id/class/style 的 0 基索引，
    # 无对应属性时写 0（与 aapt 一致）。写成 0xFFFF 会越界破坏属性解析 →
    # 严格安装器报 INSTALL_PARSE_FAILED_MANIFEST_MALFORMED「requires android:name」。
    buf += struct.pack('<HHHHHH', attr_start, attr_size, attr_count, 0, 0, 0)

    for attr in attributes:
        buf += struct.pack('<III', attr['ns'], attr['name'], attr['raw_value'])
        buf += struct.pack('<HBB I', 8, 0, attr['data_type'], attr['data'])

    return bytes(buf)


def _pack_end_element_chunk(elem_ns, elem_name, line=0):
    """
    构造 EndElement chunk。

    返回:
        bytes: 完整的 chunk 数据
    """
    chunk_size = 8 + 16  # header(8) + 4*uint32(16)
    buf = bytearray()
    buf += struct.pack('<II', CHUNK_END_ELEMENT, chunk_size)
    buf += struct.pack('<II', line, NO_ENTRY)
    buf += struct.pack('<II', elem_ns, elem_name)
    return bytes(buf)


# ─── 查找 application 元素 ────────────────────────────────────────────────────

def _find_application_in_chunks(data, xml_start, strings):
    """
    扫描 XML 块，查找名称 == 'application' 的 StartElement。

    返回:
        (chunk_start, parsed_element_dict) 或 (None, None)
    """
    for chunk_type, chunk_start, chunk_size in _iter_chunks(data, xml_start):
        if chunk_type == CHUNK_START_ELEMENT:
            name_idx = struct.unpack_from('<I', data, chunk_start + 20)[0]
            if name_idx < len(strings) and strings[name_idx] == 'application':
                elem = _parse_start_element(data, chunk_start)
                return chunk_start, elem
    return None, None


# ─── 工具 ─────────────────────────────────────────────────────────────────────

def _update_file_size(data, new_size):
    """更新文件头中的 file_size 字段（offset 4）。"""
    struct.pack_into('<I', data, 4, new_size)


def _update_chunk_size(data, chunk_start, new_size):
    """更新某个 chunk 的 chunkSize 字段（offset +4 相对 chunk 头）。"""
    struct.pack_into('<I', data, chunk_start + 4, new_size)


def _validate_axml(data):
    """验证文件头是否为 AXML 格式。"""
    if len(data) < 8:
        raise ValueError("文件过小，不是有效的 AXML 文件")
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != AXML_MAGIC:
        raise ValueError(f"AXML magic 不匹配: 期望 0x00080003, 得到 0x{magic:08X}")


# ─── 公开接口 ─────────────────────────────────────────────────────────────────

def get_orig_app_class(manifest_data):
    """
    从二进制 AndroidManifest.xml 中提取原始 application 类的 android:name。

    参数:
        manifest_data: APK 中读取的原始二进制 Manifest 数据 (bytes)

    返回:
        str | None: application 类名，如果未找到 attribute 则返回 None
    """
    _validate_axml(manifest_data)
    data = manifest_data  # 不修改，用 bytes 即可

    pool_info = _parse_string_pool(data, 8)
    strings = pool_info['strings']

    android_uri_idx = _find_string_index(strings, ANDROID_NS_URI)
    name_attr_idx   = _find_string_index(strings, 'name')

    xml_start = _find_xml_start(data, 8)
    _, app_elem = _find_application_in_chunks(data, xml_start, strings)

    if app_elem is None:
        return None

    for attr in app_elem['attributes']:
        # 检查属性是否为 android:name
        is_android_name = (
            attr['ns'] == android_uri_idx and
            attr['name'] == name_attr_idx
        )
        if is_android_name:
            if attr['data_type'] == TYPE_STRING and attr['data'] < len(strings):
                return strings[attr['data']]
            elif attr['data_type'] == TYPE_REFERENCE:
                # 资源引用 → 无法直接获取类名，返回 None
                return None
            elif attr['raw_value'] != NO_ENTRY and attr['raw_value'] < len(strings):
                return strings[attr['raw_value']]
            return None

    return None


def patch_manifest(manifest_data, orig_app_class, shell_app_class=config.SHELL_APP,
                   ssl_pins=None, strengthen=None, antidump=None, antifrida=None,
                   meta_orig=config.META_ORIG, meta_ssl=config.META_SSL_PINS,
                   meta_strengthen=config.META_STRENGTHEN, meta_antidump=config.META_ANTIDUMP,
                   meta_antifrida=config.META_ANTIFRIDA):
    """
    修改二进制 AndroidManifest.xml：

    1. 将 <application android:name="原始类名"> 改为 shell_app_class
    2. 在 <application> 内注入 <meta-data android:name="JG_ORIG_APP"
       android:value="原始类名"/>
    3. 删除 <application> 的 android:appComponentFactory 属性（而非设为空串）。
       华为等定制 ROM 的 PackageParser 对空串 appComponentFactory 报 "Empty class name"
       → INSTALL_PARSE_FAILED_MANIFORMED 硬失败；直接删除该属性后，框架读到
       ai.appComponentFactory == null 即用默认 AppComponentFactory，运行时行为与之前的
       "回退 DEFAULT" 完全一致（零回归），且不再产生 ClassNotFoundException 的 E 级日志。

    参数:
        manifest_data:  原始二进制 Manifest 数据 (bytes)
        orig_app_class: 原始 Application 类名 (字符串)
        shell_app_class: 要替换为的壳 Application 类名

    返回:
        bytes: 修改后的 Manifest 数据
    """
    _validate_axml(manifest_data)

    data = bytearray(manifest_data)

    # 1. 解析字符串池 (总是在 offset 8)
    pool_start = 8
    # 确认 offset 8 处确实是字符串池
    if struct.unpack_from('<I', data, pool_start)[0] != CHUNK_STRING_POOL:
        raise ValueError(f"偏移 8 处不是字符串池 chunk")
    pool_info = _parse_string_pool(data, pool_start)
    strings = pool_info['strings']
    is_utf8 = pool_info['is_utf8']

    # 1.5 ResourceMap 按「最终文档顺序」重建，须在全部 meta-data 注入后执行
    #     （见末尾调用），此处仅占位说明。


    android_uri_idx = _find_string_index(strings, ANDROID_NS_URI)
    name_attr_idx   = _find_string_index(strings, 'name')
    value_attr_idx  = _find_string_index(strings, 'value')
    meta_data_idx   = _find_string_index(strings, 'meta-data')

    # 2. 找到 application 元素
    xml_start = _find_xml_start(data, 8)
    app_chunk_start, app_elem = _find_application_in_chunks(data, xml_start, strings)

    if app_elem is None:
        raise ValueError("未找到 <application> 元素")

    # 3. 确定需要新增的字符串
    new_strings_needed = []
    for s in [shell_app_class, orig_app_class, meta_orig]:
        if _find_string_index(strings, s) == -1:
            new_strings_needed.append(s)
    if _find_string_index(strings, 'name') == -1:
        new_strings_needed.append('name')
    if _find_string_index(strings, 'value') == -1:
        new_strings_needed.append('value')
    if _find_string_index(strings, 'meta-data') == -1:
        new_strings_needed.append('meta-data')
    # SSL pinning meta（P-CAPTURE）：加固期注入 gx.ssl_pins，壳运行期读取
    if ssl_pins:
        for s in [meta_ssl, ssl_pins]:
            if _find_string_index(strings, s) == -1:
                new_strings_needed.append(s)
    # 统一响应姿态 meta（P-CAPTURE）：加固期注入 gx.strengthen，壳运行期读取覆盖默认 "log"
    if strengthen:
        for s in [meta_strengthen, strengthen]:
            if _find_string_index(strings, s) == -1:
                new_strings_needed.append(s)
    # P0-C 内存级 anti-dump 开关 meta：仅 --antidump 时注入 meta_antidump="1"，壳运行期读取启用扫描
    if antidump:
        for s in [meta_antidump, "1"]:
            if _find_string_index(strings, s) == -1:
                new_strings_needed.append(s)
    # A·强反 Frida 开关 meta：仅 --antifrida 时注入 meta_antifrida="1"，壳运行期读取启用检测
    if antifrida:
        for s in [meta_antifrida, "1"]:
            if _find_string_index(strings, s) == -1:
                new_strings_needed.append(s)
    # 注：删除 appComponentFactory 属性时无需把 appComponentFactory / 空串 加入字符串池

    # 4. 向字符串池追加新字符串（在 XML 修改前完成，避免偏移追踪困扰）
    for s in new_strings_needed:
        _add_string_to_pool(data, pool_start, s, strings, is_utf8)

    # 4.5 一次性补齐字符串池 chunk 到 4 字节对齐（AXML 要求）
    sp_chunk_size = struct.unpack_from('<I', data, pool_start + 4)[0]
    while sp_chunk_size % 4 != 0:
        data.insert(pool_start + sp_chunk_size, 0)
        sp_chunk_size += 1
    struct.pack_into('<I', data, pool_start + 4, sp_chunk_size)

    # 重新获取更新后的字符串索引
    android_uri_idx = _find_string_index(strings, ANDROID_NS_URI)
    name_attr_idx   = _find_string_index(strings, 'name')
    value_attr_idx  = _find_string_index(strings, 'value')
    meta_data_idx   = _find_string_index(strings, 'meta-data')
    shell_class_idx = _find_string_index(strings, shell_app_class)
    orig_class_idx  = _find_string_index(strings, orig_app_class)
    jg_orig_idx     = _find_string_index(strings, meta_orig)
    ssl_pins_idx     = _find_string_index(strings, meta_ssl) if ssl_pins else -1
    ssl_pins_val_idx = _find_string_index(strings, ssl_pins) if ssl_pins else -1
    strengthen_idx     = _find_string_index(strings, meta_strengthen) if strengthen else -1
    strengthen_val_idx = _find_string_index(strings, strengthen) if strengthen else -1
    antidump_idx     = _find_string_index(strings, meta_antidump) if antidump else -1
    antidump_val_idx = _find_string_index(strings, "1") if antidump else -1
    # A·强反 Frida 开关 meta 索引：仅 --antifrida 时有效
    antifrida_idx     = _find_string_index(strings, meta_antifrida) if antifrida else -1
    antifrida_val_idx = _find_string_index(strings, "1") if antifrida else -1

    # 重新定位 application（字符串池修改后位置可能后移）
    xml_start = _find_xml_start(data, 8)
    app_chunk_start, app_elem = _find_application_in_chunks(data, xml_start, strings)
    if app_elem is None:
        raise ValueError("字符串池修改后未找到 <application> 元素")

    # 5. 修改 application 的 android:name 属性
    attr_pos = app_chunk_start + 16 + 20  # ns(offset 16) + attrStart(20)
    modified = False

    for i in range(app_elem['attribute_count']):
        attr_ns   = struct.unpack_from('<I', data, attr_pos)[0]
        attr_name = struct.unpack_from('<I', data, attr_pos + 4)[0]

        if attr_ns == android_uri_idx and attr_name == name_attr_idx:
            # 修改 raw_value（原始字符串值索引）
            struct.pack_into('<I', data, attr_pos + 8, shell_class_idx)
            # 修改 Res_value: dataType=TYPE_STRING, data=shell_class_idx
            struct.pack_into('<HBB I', data, attr_pos + 12, 8, 0, TYPE_STRING, shell_class_idx)
            modified = True
            break

        attr_pos += 20

    # 记录 application chunk 的增长量，用于后续更新 chunkSize
    app_size_growth = 0

    if not modified:
        # 没有 android:name 属性 → 需要新建该属性并添加到元素中
        new_attr = struct.pack('<III', android_uri_idx, name_attr_idx, shell_class_idx)
        new_attr += struct.pack('<HBB I', 8, 0, TYPE_STRING, shell_class_idx)

        # 插入位置：最后一个属性之后
        insert_pos = app_chunk_start + 16 + 20 + app_elem['attribute_count'] * 20
        data[insert_pos:insert_pos] = new_attr

        # 更新 attribute_count
        struct.pack_into('<H', data, app_chunk_start + 28, app_elem['attribute_count'] + 1)
        app_elem['attribute_count'] += 1
        app_size_growth += 20

    # 5.5 删除 android:appComponentFactory 属性（消除硬失败 + 难看 E 日志）
    # 壳把 classes.dex 整体替换为 stub.dex 后，原 AppComponentFactory(通常 androidx.core.app.CoreComponentFactory)
    # 位于被加密、运行时才注入 sysLoader 的原始 DEX。系统在 LoadedApk 构造期用 base classloader 查找它失败 →
    # 若其值为空串，华为等 ROM 的 PackageParser 会报 "Empty class name" →
    # INSTALL_PARSE_FAILED_MANIFEST_MALFORMED 硬失败(之前误判为无害)。
    # 干净做法：直接删除该属性。框架读到 ai.appComponentFactory == null 即用 AppComponentFactory.DEFAULT，
    # 运行时行为等价于之前的"回退 DEFAULT"(零回归)，无 ClassNotFoundException 日志、可正常安装。
    _acf_idx = _find_string_index(strings, 'appComponentFactory')
    if _acf_idx != -1:
        _ap = app_chunk_start + 16 + 20  # ns(offset 16) + attrStart(20)
        for _i in range(app_elem['attribute_count']):
            _ans = struct.unpack_from('<I', data, _ap)[0]
            _anm = struct.unpack_from('<I', data, _ap + 4)[0]
            if _ans == android_uri_idx and _anm == _acf_idx:
                # 删除该 20 字节属性项（后续所有数据整体前移 20 字节）
                del data[_ap:_ap + 20]
                # 更新 attribute_count
                struct.pack_into('<H', data, app_chunk_start + 28,
                                 app_elem['attribute_count'] - 1)
                app_elem['attribute_count'] -= 1
                app_size_growth -= 20
                break
            _ap += 20

    # 6. 构造 meta-data 子元素
    meta_attrs = [
        {
            'ns':        android_uri_idx,
            'name':      name_attr_idx,
            'raw_value': jg_orig_idx,
            'data_type': TYPE_STRING,
            'data':      jg_orig_idx,
        },
        {
            'ns':        android_uri_idx,
            'name':      value_attr_idx,
            'raw_value': orig_class_idx,
            'data_type': TYPE_STRING,
            'data':      orig_class_idx,
        },
    ]

    meta_start_chunk = _pack_start_element_chunk(
        elem_ns=NO_ENTRY,
        elem_name=meta_data_idx,
        attributes=meta_attrs,
        line=app_elem['line'],
    )
    meta_end_chunk = _pack_end_element_chunk(
        elem_ns=NO_ENTRY,
        elem_name=meta_data_idx,
        line=app_elem['line'],
    )

    insertion = meta_start_chunk + meta_end_chunk
    # SSL pinning meta-data 子元素（P-CAPTURE）
    if ssl_pins and ssl_pins_idx >= 0 and ssl_pins_val_idx >= 0:
        ssl_meta_attrs = [
            {
                'ns':        android_uri_idx,
                'name':      name_attr_idx,
                'raw_value': ssl_pins_idx,
                'data_type': TYPE_STRING,
                'data':      ssl_pins_idx,
            },
            {
                'ns':        android_uri_idx,
                'name':      value_attr_idx,
                'raw_value': ssl_pins_val_idx,
                'data_type': TYPE_STRING,
                'data':      ssl_pins_val_idx,
            },
        ]
        ssl_meta_start = _pack_start_element_chunk(
            elem_ns=NO_ENTRY, elem_name=meta_data_idx, attributes=ssl_meta_attrs, line=app_elem['line'])
        ssl_meta_end = _pack_end_element_chunk(
            elem_ns=NO_ENTRY, elem_name=meta_data_idx, line=app_elem['line'])
        insertion = insertion + ssl_meta_start + ssl_meta_end
    # 统一响应姿态 meta-data 子元素（P-CAPTURE）
    if strengthen and strengthen_idx >= 0 and strengthen_val_idx >= 0:
        str_meta_attrs = [
            {
                'ns':        android_uri_idx,
                'name':      name_attr_idx,
                'raw_value': strengthen_idx,
                'data_type': TYPE_STRING,
                'data':      strengthen_idx,
            },
            {
                'ns':        android_uri_idx,
                'name':      value_attr_idx,
                'raw_value': strengthen_val_idx,
                'data_type': TYPE_STRING,
                'data':      strengthen_val_idx,
            },
        ]
        str_meta_start = _pack_start_element_chunk(
            elem_ns=NO_ENTRY, elem_name=meta_data_idx, attributes=str_meta_attrs, line=app_elem['line'])
        str_meta_end = _pack_end_element_chunk(
            elem_ns=NO_ENTRY, elem_name=meta_data_idx, line=app_elem['line'])
        insertion = insertion + str_meta_start + str_meta_end
    # P0-C 内存级 anti-dump 开关 meta-data 子元素
    if antidump and antidump_idx >= 0 and antidump_val_idx >= 0:
        ad_meta_attrs = [
            {
                'ns':        android_uri_idx,
                'name':      name_attr_idx,
                'raw_value': antidump_idx,
                'data_type': TYPE_STRING,
                'data':      antidump_idx,
            },
            {
                'ns':        android_uri_idx,
                'name':      value_attr_idx,
                'raw_value': antidump_val_idx,
                'data_type': TYPE_STRING,
                'data':      antidump_val_idx,
            },
        ]
        ad_meta_start = _pack_start_element_chunk(
            elem_ns=NO_ENTRY, elem_name=meta_data_idx, attributes=ad_meta_attrs, line=app_elem['line'])
        ad_meta_end = _pack_end_element_chunk(
            elem_ns=NO_ENTRY, elem_name=meta_data_idx, line=app_elem['line'])
        insertion = insertion + ad_meta_start + ad_meta_end
    # A·强反 Frida 开关 meta-data 子元素
    if antifrida and antifrida_idx >= 0 and antifrida_val_idx >= 0:
        af_meta_attrs = [
            {
                'ns':        android_uri_idx,
                'name':      name_attr_idx,
                'raw_value': antifrida_idx,
                'data_type': TYPE_STRING,
                'data':      antifrida_idx,
            },
            {
                'ns':        android_uri_idx,
                'name':      value_attr_idx,
                'raw_value': antifrida_val_idx,
                'data_type': TYPE_STRING,
                'data':      antifrida_val_idx,
            },
        ]
        af_meta_start = _pack_start_element_chunk(
            elem_ns=NO_ENTRY, elem_name=meta_data_idx, attributes=af_meta_attrs, line=app_elem['line'])
        af_meta_end = _pack_end_element_chunk(
            elem_ns=NO_ENTRY, elem_name=meta_data_idx, line=app_elem['line'])
        insertion = insertion + af_meta_start + af_meta_end
    insertion_size = len(insertion)
    # 注意：meta-data 是独立的子 chunk，不计入 application StartElement 的 chunkSize
    # app_size_growth 仅记录 application 元素自身的变化（如新增属性），不包含子元素

    # 插入位置：application StartElement 之后（属性区末尾）
    app_attr_end = app_chunk_start + 16 + 20 + app_elem['attribute_count'] * 20
    data[app_attr_end:app_attr_end] = insertion

    # 7. 更新大小（AXML 要求所有 chunk 和文件大小均为 4 字节对齐）
    new_app_size = app_elem['chunk_size'] + app_size_growth
    #   应用 chunk 内部补齐
    while new_app_size % 4 != 0:
        data.insert(app_chunk_start + new_app_size, 0)
        new_app_size += 1
    _update_chunk_size(data, app_chunk_start, new_app_size)

    # 7.5 全部 meta-data 注入完成后，按最终文档顺序重建 ResourceMap。
    #     严格安装器按 RM[i] 取第 i 个属性的资源 ID；原包 RM 只覆盖原属性，
    #     注入的 meta-data 位于其后会越界解析不到 → INSTALL_PARSE_FAILED_*
    #     重建后 meta-data 的 name=0x01010003 / value=0x01010024 必被正确解析。
    _rebuild_resource_map(data, pool_start, strings)

    #   文件尾部补齐
    while len(data) % 4 != 0:
        data.append(0)
    _update_file_size(data, len(data))

    return bytes(data)
