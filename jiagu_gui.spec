# -*- mode: python ; coding: utf-8 -*-
"""JGShield GUI 打包配置 —— onefile windowed exe，自包含全部加固工具。"""

block_cipher = None

a = Analysis(
    ['jiagu_gui.py'],
    pathex=['E:/jiagu'],
    binaries=[],
    datas=[
        # 仅 bundle 加固/回测/设备验证所需的工具，排除 android.jar(13MB)、d8.jar 等无用大文件
        ('tools/apktool.jar',         'tools'),
        ('tools/uber-apk-signer.jar', 'tools'),
        ('tools/common.jks',          'tools'),
        ('tools/common.cer',          'tools'),
        ('tools/aapt.exe',            'tools'),
        ('tools/libwinpthread-1.dll', 'tools'),
        ('tools/apksigner.jar',       'tools'),
        ('tools/adb.exe',             'tools'),
        ('tools/AdbWinApi.dll',       'tools'),
        ('tools/AdbWinUsbApi.dll',    'tools'),
        ('build/dex/stub.dex',        'build/dex'),
    ],
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
