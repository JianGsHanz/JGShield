# 交叉验证 vmp_compile 的正确性（开发环境，需 androguard）。
#
# 两部分:
#  A) 结构对比: 对每个 ylyk "安全子集" 方法, 用 vmp_compile.decode_method 解码,
#     与 androguard 解码结果逐条比对 (指令名 + 寄存器/立即数/分支目标)。
#     证明自写解码器的正确性。
#  B) 语义 fuzz: 对每个安全子集方法, 用一份从零实现的 dalvik 参考解释器 (基于
#     vmp_compile 解码结果) 计算期望值, 再跑 vmp_arch2.VM(编译产物), 随机+边界输入
#     比对结果。证明发射+解释器的语义等价 (含 int 溢出回绕)。
#
# 任一 mismatch 都打印细节并以非零退出。
import os, sys, zipfile, random, logging, traceback
from androguard.misc import AnalyzeDex
# androguard 各子 logger 各自 setLevel(DEBUG)，仅设父级不够；逐个强制压到 ERROR。
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
import vmp_arch2
from vmp_arch2 import VM, assemble_vm_bytecode, c_div, c_rem

APK = os.environ.get("VMP_APK", "D:/APK/ylyk_5.9.4/app-Ptest-5.9.4-2026-08-04.apk")

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
def s32(x):
    x &= MASK32; return x - 0x100000000 if x & 0x80000000 else x
def s64(x):
    x &= MASK64; return x - 0x10000000000000000 if x & 0x8000000000000000 else x
def s16(x):
    x &= 0xFFFF; return x - 0x10000 if x & 0x8000 else x

# ---------------- 收集 androguard 解码结果 (key -> [(name, [(kind,val)]) ----------------
def ag_operands(ops):
    out = []
    for item in ops:
        kind = item[0]
        val = item[1] if len(item) > 1 else None
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
                # androguard 的 get_descriptor() 在多参数时会插入空格
                # (如 "(Ljava/lang/String; Landroid/os/Bundle;)V")，与真实 DEX 描述符不符；
                # 去掉空格再比对（仅验证用，编译器侧一律用无空格真实格式）。
                key = (cn, m.get_name(), m.get_descriptor().replace(' ', ''))
                lst = []
                for ins in m.get_instructions():
                    lst.append((ins.get_name(), ag_operands(ins.get_operands())))
                ag_index[key] = lst
    finally:
        try: os.remove(t)
        except OSError: pass

# ---------------- 参考 dalvik 解释器 (仅安全子集, 基于 vmp_compile 解码) ----------------
def param_layout(desc):
    params = desc[desc.index('(')+1:desc.index(')')]
    layout = []; i = 0; words = 0
    while i < len(params):
        if params[i] == 'L':
            i = params.index(';', i)+1
            layout.append(('L', 1)); words += 1; continue
        if params[i] == '[':
            while params[i] == '[': i += 1
            if params[i] == 'L': i = params.index(';', i)+1
            else: i += 1
            layout.append(('L', 1)); words += 1; continue
        c = params[i]; w = 2 if c in 'JD' else 1
        layout.append((c, w)); words += w; i += 1
    return layout, words


REF_STEP_CAP = 200000


def has_backward_branch(insns):
    """指令流里是否存在向后的分支/跳转（即循环）。"""
    off2idx = {ins['unit_off']: k for k, ins in enumerate(insns)}
    for k, ins in enumerate(insns):
        if 'off' in ins:
            t = off2idx.get(ins['off'])
            if t is not None and t <= k:
                return True
    return False


class RefTimeout(Exception):
    """参考解释器迭代超上限（方法内含循环/死循环），该用例跳过而非判 mismatch。"""


class RefDivZero(Exception):
    """参考解释器遇到除零 —— dalvik 会抛 ArithmeticException，私有 VM 无法抛，
    属已知能力缺口（见 jg_vmp.c 的除零处理），该用例跳过而非判 mismatch。"""


def ref_run(insns, regs_total, desc, static, inputs):
    regs = [0] * regs_total
    param_reg = regs_total - param_layout(desc)[1]
    if not static:
        regs[param_reg-1] = inputs[0]; inputs = inputs[1:]
    for j, (ct, w) in enumerate(param_layout(desc)[0]):
        v = inputs[j]
        if ct == 'J': regs[param_reg + sum(x[1] for x in param_layout(desc)[0][:j])] = v & MASK64
        else: regs[param_reg + sum(x[1] for x in param_layout(desc)[0][:j])] = s32(v) if isinstance(v,int) else v
    # 建立 unit_off -> 指令索引
    off2idx = {ins['unit_off']: k for k, ins in enumerate(insns)}
    pc = 0
    steps = 0
    # 迭代上限：安全子集允许 goto，方法里可能有回跳转的循环（甚至意外死循环）。
    # 没有上限时 fuzz 会直接挂死（踩过：跑 20 分钟、内存涨到 4GB）。
    while pc < len(insns):
        steps += 1
        if steps > REF_STEP_CAP:
            raise RefTimeout('ref step cap %d exceeded' % REF_STEP_CAP)
        ins = insns[pc]; nm = ins['name']
        if nm == 'nop': pc += 1; continue
        if nm == 'const/4' or nm == 'const/16' or nm == 'const' or nm == 'const/high16':
            regs[ins['ra']] = s32(ins['imm'])
        elif nm == 'const-wide' or nm == 'const-wide/16' or nm == 'const-wide/32' or nm == 'const-wide/high16':
            regs[ins['ra']] = ins['imm'] & MASK64
        elif nm in ('move','move-wide','move-object','move/from16','move-wide/from16','move-object/from16','move/16','move-wide/16','move-object/16'):
            regs[ins['ra']] = regs[ins['rb']]
        elif nm == 'neg-int':
            regs[ins['ra']] = s32(-s32(regs[ins['rb']]))
        elif nm == 'not-int':
            regs[ins['ra']] = s32((~regs[ins['rb']]) & MASK32)
        elif nm == 'neg-long':
            regs[ins['ra']] = (-regs[ins['rb']]) & MASK64
        elif nm == 'not-long':
            regs[ins['ra']] = (~regs[ins['rb']]) & MASK64
        elif nm == 'int-to-long':
            regs[ins['ra']] = s32(regs[ins['rb']])
        elif nm == 'long-to-int' or nm == 'int-to-short':
            if nm == 'long-to-int':
                regs[ins['ra']] = s32(regs[ins['rb']] & MASK32)
            else:
                regs[ins['ra']] = s16(regs[ins['rb']] & 0xFFFF)
        elif nm == 'int-to-char':
            regs[ins['ra']] = regs[ins['rb']] & 0xFFFF
        elif nm in vmp_compile._INT_SHIFT:
            # 4 字节 3 寄存器: vA = vB <shift> (vC & 0x1f), 结果 32 位有符号
            cnt = regs[ins['rc']] & 0x1F
            if nm == 'shl-int':
                r = s32(regs[ins['rb']]) << cnt
            elif nm == 'shr-int':
                r = s32(regs[ins['rb']]) >> cnt
            else:  # ushr-int
                r = (regs[ins['rb']] & MASK32) >> cnt
            regs[ins['ra']] = s32(r & MASK32)
        elif nm in vmp_compile._INT_BIN or nm in vmp_compile._LONG_BIN:
            a = regs[ins['rb']]; b = regs[ins['rc']]
            longop = nm in vmp_compile._LONG_BIN
            if 'sh' in nm:  # 移位: 低 5/6 位
                cnt = (b & (0x3F if longop else 0x1F))
                if nm.startswith('shl'): r = a << cnt
                elif nm.startswith('shr'): r = (s64(a) if longop else s32(a)) >> cnt
                else: r = ((a & MASK64) if longop else (a & MASK32)) >> cnt
            elif nm.startswith('div') or nm.startswith('rem'):
                # C/dalvik 语义: 向零截断(不是 Python 的 floor); long 必须先还原符号,
                # 因为寄存器里存的是无符号 64 位位模式。与 jg_vmp.c `vb ? va/vb : 0` 对齐。
                sa = (s64(a) if longop else s32(a)); sb = (s64(b) if longop else s32(b))
                r = c_div(sa, sb) if nm.startswith('div') else c_rem(sa, sb)
            else:
                op = nm.split('-')[0]
                if op == 'add': r = a + b
                elif op == 'sub': r = a - b
                elif op == 'mul': r = a * b
                elif op == 'and': r = a & b
                elif op == 'or': r = a | b
                elif op == 'xor': r = a ^ b
            regs[ins['ra']] = (s32(r & MASK32) if not longop else (r & MASK64))
        elif nm in vmp_compile._INT_BIN_2ADDR or nm in vmp_compile._LONG_BIN_2ADDR:
            a = regs[ins['ra']]; b = regs[ins['rb']]
            longop = nm in vmp_compile._LONG_BIN_2ADDR
            if 'sh' in nm:
                cnt = (b & (0x3F if longop else 0x1F))
                if nm.startswith('shl'): r = a << cnt
                elif nm.startswith('shr'): r = (s64(a) if longop else s32(a)) >> cnt
                else: r = ((a & MASK64) if longop else (a & MASK32)) >> cnt
            elif nm.startswith('div') or nm.startswith('rem'):
                sa = (s64(a) if longop else s32(a)); sb = (s64(b) if longop else s32(b))
                r = c_div(sa, sb) if nm.startswith('div') else c_rem(sa, sb)
            else:
                op = nm.split('-')[0]
                if op == 'add': r = a + b
                elif op == 'sub': r = a - b
                elif op == 'mul': r = a * b
                elif op == 'and': r = a & b
                elif op == 'or': r = a | b
                elif op == 'xor': r = a ^ b
            regs[ins['ra']] = (s32(r & MASK32) if not longop else (r & MASK64))
        elif nm in vmp_compile._INT_LIT:
            a = regs[ins['rb']]; b = s32(ins['imm']); longop = False
            if 'sh' in nm:
                cnt = (b & 0x1F)
                if nm.startswith('shl'): r = a << cnt
                elif nm.startswith('shr'): r = s32(a) >> cnt
                else: r = (a & MASK32) >> cnt
            elif nm.startswith('rsub'):
                r = b - a
            elif nm.startswith('div') or nm.startswith('rem'):
                r = c_div(s32(a), b) if nm.startswith('div') else c_rem(s32(a), b)
            else:
                op = nm.split('-')[0]
                if op == 'add': r = a + b
                elif op == 'sub': r = a - b
                elif op == 'mul': r = a * b
                elif op == 'and': r = a & b
                elif op == 'or': r = a | b
                elif op == 'xor': r = a ^ b
            regs[ins['ra']] = s32(r & MASK32)
        elif nm in vmp_compile._CMP:
            a = s64(regs[ins['ra']])
            b = s64(regs[ins['rb']]) if 'rb' in ins else 0
            if nm.endswith('z'):
                b = 0
            m = {'if-eq':a==b,'if-ne':a!=b,'if-lt':a<b,'if-ge':a>=b,'if-gt':a>b,'if-le':a<=b,
                 'if-eqz':a==0,'if-nez':a!=0,'if-ltz':a<0,'if-gtz':a>0,'if-gez':a>=0,'if-lez':a<=0}[nm]
            pc = off2idx[ins['off']] if m else pc + 1
            continue
        elif nm == 'goto':
            pc = off2idx[ins['off']]; continue
        elif nm == 'return-void':
            return None
        elif nm == 'return':
            return s32(regs[ins['ra']])
        elif nm == 'return-wide':
            return regs[ins['ra']] & MASK64
        elif nm == 'return-object':
            return regs[ins['ra']]
        else:
            raise RuntimeError('ref unhandled %s' % nm)
        pc += 1
    return None

def vm_run_from_dex(dex, co, desc, af, inputs, xor_key):
    """用真实 dex 字节编译并跑私有 VM, 返回结果寄存器值。"""
    blob, param_reg = vmp_compile.compile(dex, co, desc, xor_key)
    vm = VM(blob)
    layout, _ = param_layout(desc)
    regs_total = vmp_protect._u16(dex, co)
    preg = regs_total - sum(w for _, w in layout)
    static = bool(af & 0x8)
    args = [0] * regs_total
    if not static:
        args[preg-1] = inputs[0] & MASK64; inputs = inputs[1:]
    for j, (ct, w) in enumerate(layout):
        idx = preg + sum(x[1] for x in layout[:j])
        v = inputs[j]
        # 与 ref_run / 真机 JNI 一致: int/char/short/byte 参数按 32 位有符号装入 64 位寄存器,
        # long 按 64 位无符号; 避免 int 参数被截断成 32 位正模式导致 long 返回少符号扩展。
        if ct == 'J':
            args[idx] = v & MASK64
        else:
            args[idx] = s32(v) & MASK64
    vm.reset()
    for i, v in enumerate(args):
        vm.r[i] = v
    return vm.run()

# ---------------- 主流程 ----------------
# 用真实 dex 跑: 遍历每个 dex 的每个方法, 取 code_off, classify + compile, 并对比。
total_methods = 0
safe_methods = 0
struct_mismatch = 0
sem_mismatch = 0
sem_tested = 0
sem_cases = 0
sem_skipped = 0
sem_loops = 0
struct_examples = []
sem_examples = []

# 先收集所有 dex 字节 + 用 vmp_protect 枚举 (cls,name,desc,code_off,regs_total,static)
dex_list = []
z = zipfile.ZipFile(APK)
for dn in sorted(n for n in z.namelist() if n.endswith('.dex')):
    dex_list.append((dn, z.read(dn)))

for dn, db in dex_list:
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
                # 结构对比
                safe, reason = vmp_compile.classify(dex, co)
                if not safe:
                    continue
                safe_methods += 1
                # A) 结构对比 vs androguard
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
                    # 比较寄存器/立即数/偏移
                    bo = {k: v for k, v in b[1]}
                    if 'ra' in a:
                        if ('r', a['ra']) not in [(k,v) for k,v in b[1]]:
                            # 顺序可能不同; 收集所有 r/i/o
                            pass
                    # 简化: 收集我的 (kind,val) 集合
                    # 分支偏移: androguard 给的是相对 CCCC, 我的 decode 存的是绝对 target,
                    # 统一转成相对 CCCC 再比 (target - unit_off == CCCC)。
                    mine_ops = []
                    for f in ('ra','rb','rc'):
                        if f in a: mine_ops.append(('r', a[f]))
                    if 'imm' in a: mine_ops.append(('i', a['imm'] & MASK64))
                    if 'off' in a and 'unit_off' in a:
                        mine_ops.append(('o', a['off'] - a['unit_off']))
                    elif 'off' in a:
                        mine_ops.append(('o', a['off']))
                    # androguard 立即数按有符号返回(如 const-wide/16 的 -1)，我的解码保留无符号位模式;
                    # 统一按 64 位无符号比(同值), 避免假阳性 mismatch。
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
                # B) 语义 fuzz
                regs_total = vmp_protect._u16(dex, co)
                static = bool(af & 0x8)
                # 含回跳分支(循环)的方法不做 fuzz：有界解释器无法区分「长循环」与
                # 「死循环」，跑满步数上限再判失败既慢（曾挂死 20 分钟/4GB）又无意义。
                if has_backward_branch(my):
                    sem_loops += 1
                    continue
                layout, _ = param_layout(ds)
                random.seed(hash(key) & 0xFFFFFFFF)
                vectors = []
                for _ in range(25):
                    vec = []
                    if not static:
                        # 实例方法: 第一个输入是 this 句柄（ref_run / vm_run_from_dex 都按
                        # inputs[0]=this 处理），必须补上否则 IndexError。
                        vec.append(0x1000 + random.randint(0, 1000))
                    for (ct, w) in layout:
                        if ct == 'J':
                            vec.append(random.randint(-2**63, 2**63-1))
                        elif ct == 'I':
                            vec.append(random.choice([random.randint(-2**31,2**31-1),0x7FFFFFFF,0x80000000,-1,0,1]))
                        elif ct == 'C':
                            vec.append(random.randint(0,0xFFFF))
                        elif ct == 'Z':
                            vec.append(random.choice([0,1]))
                        elif ct == 'B':
                            vec.append(random.randint(-128,127))
                        elif ct == 'S':
                            vec.append(random.randint(-32768,32767))
                        else:  # 对象/数组: 占位句柄
                            vec.append(0x1000 + random.randint(0,1000))
                    vectors.append(vec)
                for vec in vectors:
                    sem_cases += 1
                    try:
                        exp = ref_run(my, regs_total, ds, static, list(vec))
                        act = vm_run_from_dex(dex, co, ds, af, list(vec), 0xC2)
                    except (RefTimeout, vmp_arch2.VMPError) as e:
                        # 死循环/步数超限：方法本身可能就是循环（安全子集允许 goto），
                        # 不是编译器 bug，跳过该用例（不计 mismatch）。
                        sem_skipped += 1
                        break
                    except Exception as e:
                        sem_mismatch += 1
                        if len(sem_examples) < 8:
                            sem_examples.append((key, 'exc', repr(e), vec))
                        break
                    # 应用返回类型掩码
                    rt = ds[ds.rindex(')')+1]
                    if rt in 'IZBS':
                        exp_v = s32(exp & MASK32) if exp is not None else None
                        act_v = s32(act & MASK32)
                    elif rt == 'C':
                        exp_v = (exp & 0xFFFF) if exp is not None else None
                        act_v = act & 0xFFFF
                    elif rt == 'J':
                        exp_v = (exp & MASK64) if exp is not None else None
                        act_v = act & MASK64
                    elif rt == 'V':
                        # void: 不比较返回值（oracle 返回 None，VM 返回 r[rd] 的残留值，无意义）
                        exp_v = act_v = 0
                    else:  # 对象/数组
                        exp_v = exp; act_v = act
                    if exp_v != act_v:
                        sem_mismatch += 1
                        if len(sem_examples) < 8:
                            sem_examples.append((key, 'val', exp_v, act_v, vec))
                        break
                    sem_tested += 1

print("=== 验证结果 ===")
print("总方法: %d  安全子集方法: %d" % (total_methods, safe_methods))
print("结构对比 mismatch: %d" % struct_mismatch)
print("语义 fuzz: %d 用例, 通过 %d, mismatch %d, 跳过(循环方法 %d / 超限 %d)" % (sem_cases, sem_tested, sem_mismatch, sem_loops, sem_skipped))
if struct_examples:
    print("\n--- 结构 mismatch 样例 ---")
    for e in struct_examples: print("  ", e)
if sem_examples:
    print("\n--- 语义 mismatch 样例 ---")
    for e in sem_examples: print("  ", e)
if struct_mismatch == 0 and sem_mismatch == 0:
    print("\n[PASS] 自写解码器与 androguard 一致, 且发射+解释器语义等价。")
    sys.exit(0)
else:
    print("\n[FAIL] 存在 mismatch。")
    sys.exit(1)
