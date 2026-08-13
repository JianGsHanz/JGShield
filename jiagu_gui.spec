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
ROOT = os.path.dirname(os.path.abspath(__file__))
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
    ('build/dex/stub.dex',        'build/dex'),
]
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
