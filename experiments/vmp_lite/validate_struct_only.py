# 仅做结构对比(快速)，验证 4 字节二元 op 修正后结构 mismatch 是否归零。
# 复用 validate_vmp.py 的真实枚举 + 结构对比逻辑(A 部分)，去掉语义 fuzz(B 部分)。
import os, sys, zipfile, logging
from androguard.misc import AnalyzeDex
for _n in list(logging.root.manager.loggerDict):
    if _n.startswith('androguard'):
        logging.getLogger(_n).setLevel(logging.ERROR)
logging.getLogger('androguard').setLevel(logging.ERROR)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "experiments", "vmp_lite"))
import vmp_compile
import vmp_protect

APK = os.environ.get("VMP_APK", "D:/APK/ylyk_5.9.4/app-Ptest-5.9.4-2026-08-04.apk")
MASK64 = 0xFFFFFFFFFFFFFFFF

def ag_operands(ops):
    out = []
    for item in ops:
        kind = item[0]; val = item[1] if len(item) > 1 else None
        if 'REGISTER' in str(kind): out.append(('r', val))
        elif 'LITERAL' in str(kind): out.append(('i', val))
        elif 'OFFSET' in str(kind): out.append(('o', val))
        else: out.append(('x', val))
    return out

ag_index = {}
z = zipfile.ZipFile(APK)
for dn in sorted(n for n in z.namelist() if n.endswith('.dex')):
    t = '__tmp_v_%s' % os.path.basename(dn)
    open(t, 'wb').write(z.read(dn))
    try:
        ret = AnalyzeDex(t)
        vm = [x for x in ret if hasattr(x, 'get_classes')][0]
        for c in vm.get_classes():
            cn = c.get_name()
            for m in c.get_methods():
                code = m.get_code()
                if code is None: continue
                key = (cn, m.get_name(), m.get_descriptor().replace(' ', ''))
                lst = [(ins.get_name(), ag_operands(ins.get_operands())) for ins in m.get_instructions()]
                ag_index[key] = lst
    finally:
        try: os.remove(t)
        except OSError: pass

total_methods = 0; safe_methods = 0; struct_mismatch = 0; struct_examples = []
for dn, db in [(dn, z.read(dn)) for dn in sorted(n for n in z.namelist() if n.endswith('.dex'))]:
    dex = bytearray(db)
    cdo = vmp_protect._classdef_off(dex)
    cds = vmp_protect._classdef_size(dex)
    for ci in range(cds):
        cd_pos = cdo + ci*32
        cls_name = vmp_protect._type_name(dex, vmp_protect._u32(dex, cd_pos))
        cd_off = vmp_protect._u32(dex, cd_pos + 0x18)
        if cd_off == 0: continue
        st, _ = vmp_protect._parse_class_data(dex, cd_off)
        for lst in (st['dm'], st['vm']):
            for (midx, af, co) in lst:
                if co == 0: continue
                total_methods += 1
                nm, ds = vmp_protect._method_name_desc(dex, midx)
                key = (cls_name, nm, ds)
                safe, reason = vmp_compile.classify(dex, co)
                if not safe:
                    continue
                safe_methods += 1
                ag = ag_index.get(key)
                if ag is None:
                    struct_mismatch += 1
                    if len(struct_examples) < 5:
                        struct_examples.append((key, 'no-androguard-entry', None, None))
                    continue
                my = vmp_compile.decode_method(dex, co)[1]
                if len(my) != len(ag):
                    struct_mismatch += 1
                    if len(struct_examples) < 5:
                        struct_examples.append((key, 'len', len(my), len(ag)))
                    continue
                ok = True
                for a, b in zip(my, ag):
                    if a['name'] != b[0]:
                        ok = False; break
                    mine_ops = []
                    for f in ('ra','rb','rc'):
                        if f in a: mine_ops.append(('r', a[f]))
                    if 'imm' in a: mine_ops.append(('i', a['imm'] & MASK64))
                    if 'off' in a and 'unit_off' in a:
                        mine_ops.append(('o', a['off'] - a['unit_off']))
                    elif 'off' in a:
                        mine_ops.append(('o', a['off']))
                    ag_ops = []
                    for k, v in b[1]:
                        if k == 'i': v = v & MASK64
                        if k in ('r','i','o'): ag_ops.append((k, v))
                    if sorted(mine_ops) != sorted(ag_ops):
                        ok = False; break
                if not ok:
                    struct_mismatch += 1
                    if len(struct_examples) < 8:
                        struct_examples.append((key, 'ops', my[:1], ag[:1]))
                    continue

print("结构对比: 方法=%d  安全子集=%d  struct_mismatch=%d" % (total_methods, safe_methods, struct_mismatch))
for e in struct_examples:
    print("  -", e)
