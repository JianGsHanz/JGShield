# -*- mode: python ; coding: utf-8 -*-
"""JGShield GUI 打包配置（跨平台）。

- Windows: onefile windowed exe，自包含全部加固工具（含 Windows 原生二进制）。
- macOS:   onefile .app（BUNDLE），自包含跨平台 jar + darwin 版原生二进制。
- Linux:   onefile 可执行（EXE, console=False）。
"""
import os
import sys

block_cipher = None

# 仓库根目录（spec 所在目录），避免硬编码绝对路径（如 E:/jiagu）
# PyInstaller 执行 spec 时不会定义 __file__，但会注入 SPECPATH（spec 目录绝对路径）作为兜底
try:
    ROOT = os.path.dirname(os.path.abspath(__file__))
except NameError:
    ROOT = SPECPATH
IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"


def _exe(name):
    return name + ".exe" if IS_WINDOWS else name


# 跨平台 datas：jar 通用；原生二进制按平台选文件名
_datas = [
    ('tools/apktool.jar',         'tools'),
    ('tools/uber-apk-signer.jar', 'tools'),
    ('tools/common.jks',          'tools'),
    ('tools/common.cer',          'tools'),
    ('tools/apksigner.jar',       'tools'),
    ('tools/d8.jar',              'tools'),
    ('tools/android.jar',         'tools'),
    ('build/dex/stub.dex',        'build/dex'),
]
# 壳源码：加固时 build_stub 默认 rebuild_stub=True（按随机包名重编），
# 故 java 源码与 native 源码必须在冻结后也能被找到（路径解析为 _MEIPASS/src/...）
_datas += [
    ('src/java',   'src/java'),
    ('src/native', 'src/native'),
]
# native 反篡改库（按 ABI 分目录），加固时注入 APK 的 lib/<abi>/；不存在时不影响打包
if os.path.isdir(os.path.join(ROOT, 'tools', 'libjgguard')):
    for _abi in sorted(os.listdir(os.path.join(ROOT, 'tools', 'libjgguard'))):
        _so = os.path.join('tools', 'libjgguard', _abi, 'libjgguard.so')
        if os.path.isfile(os.path.join(ROOT, _so)):
            _datas.append((_so, 'tools/libjgguard/%s' % _abi))
if IS_WINDOWS:
    _datas += [
        ('tools/aapt.exe',            'tools'),
        ('tools/libwinpthread-1.dll', 'tools'),
        ('tools/adb.exe',             'tools'),
        ('tools/AdbWinApi.dll',       'tools'),
        ('tools/AdbWinUsbApi.dll',    'tools'),
    ]
else:
    # macOS / Linux：原生二进制无扩展名
    _datas += [
        ('tools/aapt', 'tools'),
        ('tools/adb',  'tools'),
    ]

a = Analysis(
    ['jiagu_gui.py'],
    pathex=[ROOT],
    binaries=[],
    datas=_datas,
    hiddenimports=[
        'Crypto.Cipher.AES',
        'Crypto.Hash.HMAC',
        'Crypto.Hash.SHA256',
        'harden',
        'verify',
        'verify_payload',
        'device_check',
        'batch_harden',
        'config',
        'axml_editor',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['gen_samples', 'matplotlib', 'numpy', 'PIL', 'tkinter.test'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

if IS_MAC:
    app = BUNDLE(
        pyz,
        a.scripts,
        a.binaries,
        a.zipfiles,
        a.datas,
        [],
        name='jiagu_gui',
        icon=None,
        bundle_identifier='com.jiagu.shield',
        info_plist={
            'NSHighResolutionCapable': 'True',
            'NSRequiresAquaSystemAppearance': False,
        },
        # windowed（无控制台黑窗）；macOS 上等同于 exe 的 console=False
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.zipfiles,
        a.datas,
        [],
        name='jiagu_gui',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,               # 关闭 UPX，避免杀软误报
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,           # windowed（无控制台黑窗）
        disable_windowed_traceback=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        icon=None,
    )
