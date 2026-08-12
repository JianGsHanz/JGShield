import zipfile, os, re, subprocess, tempfile, shutil

APK = 'D:/APK/test_ylsn_1.5.0/app-huawei-1.5.0-2026-08-10.apk'
OUT = 'E:/jiagu/dist/output/test_orig_manifest.apk'
JAVA = 'C:/Program Files/Java/jdk-11.0.21/bin/java.exe'
SIGNER = 'E:/jiagu/tools/uber-apk-signer.jar'
KS = 'E:/jiagu/tools/common.jks'

with open('E:/jiagu/build/dex/stub.dex', 'rb') as f:
    stub = f.read()
payload = b'JGS1' + b'\x00' * 12

tmpdir = tempfile.mkdtemp()
unsigned = os.path.join(tmpdir, 'unsigned.apk')
signed_dir = os.path.join(tmpdir, 'signed')

with zipfile.ZipFile(APK, 'r') as zin:
    with zipfile.ZipFile(unsigned, 'w', zipfile.ZIP_DEFLATED) as zout:
        # Write ORIGINAL manifest first (UNMODIFIED)
        orig_mf = zin.read('AndroidManifest.xml')
        zout.writestr(zipfile.ZipInfo('AndroidManifest.xml'), orig_mf)
        # Copy rest, skip original Manifest, classes*.dex, META-INF
        for info in zin.infolist():
            fn = info.filename
            if fn == 'AndroidManifest.xml':
                continue
            if re.match(r'classes(\d*)\.dex$', fn):
                continue
            if fn.startswith('META-INF/'):
                continue
            zout.writestr(info, zin.read(fn))
        # Add stub dex and payload
        zout.writestr(zipfile.ZipInfo('classes.dex'), stub)
        zout.writestr(zipfile.ZipInfo('jg'), payload)

# Sign
r = subprocess.run([
    JAVA, '-jar', SIGNER,
    '--apks', unsigned,
    '--ks', KS,
    '--ksAlias', 'common',
    '--ksPass', '123123',
    '--ksKeyPass', '123123',
    '--out', signed_dir
], capture_output=True, text=True)
signed = os.path.join(signed_dir, 'unsigned-aligned-signed.apk')
if os.path.exists(signed):
    shutil.copy(signed, OUT)
    print('OK: %s (%d bytes)' % (OUT, os.path.getsize(OUT)))
else:
    print('SIGN FAILED:')
    print(r.stdout[-500:])
    print(r.stderr[-500:])
