# -*- coding: utf-8 -*-
"""确定性验证：dist/jiagu_gui.exe 里打包的源码是否包含指定改动。

背景（2026-09-11 两轮踩坑）：
  1) 后台 PyInstaller 曾因 PermissionError [WinError 5]（杀软瞬时锁 48MB 新文件）静默失败，
     而 `ls -l dist/jiagu_gui.exe` 仍有旧文件 ⇒ 只看文件存在会误报成功、交付旧 exe。
  2) exe 里 grep 不到源码属正常（spec 把 src/ 以压缩 CArchive 打进 exe）。要真正验证，
     必须用 PyInstaller 的归档读取器把条目抠出来看。

用法：
  _build_venv/Scripts/python.exe tools/diag/verify_exe.py                # 默认全部检查
  _build_venv/Scripts/python.exe tools/diag/verify_exe.py --list         # 列出归档内 src/ 条目
  _build_venv/Scripts/python.exe tools/diag/verify_exe.py --dump <条目名>  # 抠出单个条目到 _wk_diag/

判定：退出码 0 = 全部命中；1 = 有缺失（会明确列出缺哪个）。
"""
import os
import sys

# 本脚本位于 <repo>/tools/diag/，仓库根 = 上两级
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXE = os.path.join(ROOT, 'dist', 'jiagu_gui.exe')

# (归档内条目路径, [必须出现的标记串], 说明)
CHECKS = [
    (r'src\native\jg_method_restore_hook.c',
     ['JG_MAPS_SCAN_MAX_VMA', 'maps-scan v2', 'skip_vma'],
     'maps 自扫代价闸（2026-09-11 冷启动 -692ms）'),
    (r'src\java\com\gx\runtime\GxApp.java',
     ['dexHeaderConsistent', 'hdrSkipped'],
     'DEX 头自检（Java Adler32 替代空转 SHA-1）'),
]


def main():
    from PyInstaller.archive.readers import CArchiveReader

    if not os.path.exists(EXE):
        print('未找到 %s' % EXE)
        return 1
    st = os.stat(EXE)
    import time
    print('exe: %s  %d B  mtime=%s' % (EXE, st.st_size,
          time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime))))

    # mtime 链：exe 必须晚于所有被检查的源码
    worst = None
    for entry, _, _ in CHECKS:
        rel = os.path.join(ROOT, entry.replace('\\', '/'))
        if os.path.exists(rel):
            if worst is None or os.path.getmtime(rel) > worst[1]:
                worst = (rel, os.path.getmtime(rel))
    if worst:
        print('最新被检源码: %s  mtime=%s' % (worst[0], time.strftime('%Y-%m-%d %H:%M', time.localtime(worst[1]))))
        if st.st_mtime < worst[1]:
            print('!! exe 比源码旧 —— 必须重打')
            return 1

    a = CArchiveReader(EXE)
    names = set(a.toc)
    if '--list' in sys.argv:
        for n in sorted(names):
            if n.replace('\\', '/').startswith('src/'):
                print('  ', n)
        return 0
    if '--dump' in sys.argv:
        target = sys.argv[sys.argv.index('--dump') + 1]
        data = a.extract(target)
        if isinstance(data, tuple):
            data = data[1]
        out = os.path.join(ROOT, '_wk_diag', os.path.basename(target))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, 'wb') as f:
            f.write(data)
        print('写出', out, len(data), 'B')
        return 0

    ok = True
    for entry, markers, desc in CHECKS:
        if entry not in names:
            print('[缺失] %s  —— 归档内没有该条目！%s' % (entry, desc))
            ok = False
            continue
        data = a.extract(entry)
        if isinstance(data, tuple):
            data = data[1]
        txt = data.decode('utf-8', 'replace')
        miss = [m for m in markers if m not in txt]
        if miss:
            print('[失败] %s  %s\n        缺标记: %s' % (entry, desc, miss))
            ok = False
        else:
            print('[通过] %s  %s  (%d B, 标记 %s 全在)' % (entry, desc, len(data), ','.join(markers)))
    print()
    print('VERIFY_EXE=%s' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
