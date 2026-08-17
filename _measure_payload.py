import zipfile, struct, sys, os, zlib

apk = sys.argv[1] if len(sys.argv) > 1 else r"E:\jiagu\output\h_p33_ylyk_a.apk"

with zipfile.ZipFile(apk) as z:
    names = z.namelist()
    jg = z.read("jg")
    dex_entries = [(n, z.getinfo(n).file_size) for n in names if n.endswith(".dex")]

def u32(b, o):
    return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)

data = jg
p = 0
magic = data[p:p+4]; p += 4
dex_count = u32(data, p); p += 4
dex_total = 0
per_dex_blob = []
for i in range(dex_count):
    blen = u32(data, p); p += 4
    blob = data[p:p+blen]; p += blen
    dex_total += 4 + blen
    per_dex_blob.append(blen)
asset_count = u32(data, p); p += 4
asset_total = 0
for i in range(asset_count):
    nl = u32(data, p); p += 4; name = data[p:p+nl]; p += nl
    blen = u32(data, p); p += 4; blob = data[p:p+blen]; p += blen
    asset_total += 4 + nl + 4 + blen

mcount = u32(data, p); p += 4
method_total = 4
stream_blob_total = 0
meta_blob_total_uncomp = 0
meta_blob_total_comp = 0
method_blob_lens = []
for i in range(mcount):
    dex_idx = u32(data, p); p += 4
    ec = u32(data, p); p += 4
    sln = u32(data, p); p += 4; sblob = data[p:p+sln]; p += sln
    mlb = u32(data, p); p += 4; mblob = data[p:p+mlb]; p += mlb
    method_total += 12 + sln + 4 + mlb
    stream_blob_total += sln
    meta_blob_total_comp += mlb
    try:
        meta_unc = zlib.decompress(mblob)
        meta_blob_total_uncomp += len(meta_unc)
    except Exception as e:
        meta_blob_total_uncomp += -1
    method_blob_lens.append(sln)
    _ = dex_idx, ec, sblob, mblob
salt = data[p:p+32]
salt_present = (len(salt) == 32 and p + 32 == len(data))

print(f"APK total size : {os.path.getsize(apk)/1e6:.2f} MB ({os.path.getsize(apk):,} B)")
print(f"jg payload size: {len(data)/1e6:.2f} MB ({len(data):,} B)")
print(f"  MAGIC        : {magic}")
print(f"  dex_count    : {dex_count}  (DEX段 total = {dex_total/1e6:.2f} MB)")
print(f"    per-dex blob bytes: min={min(per_dex_blob):,}, max={max(per_dex_blob):,}, sum={sum(per_dex_blob):,}")
print(f"  asset_count  : {asset_count}  (asset段 total = {asset_total/1e6:.2f} MB)")
print(f"  method_count : {mcount}  (method段 total = {method_total/1e6:.2f} MB)")
print(f"    stream_blob(encrypted insns) total = {stream_blob_total/1e6:.2f} MB  (per-dex: {[f'{x/1e6:.2f}' for x in method_blob_lens]})")
print(f"    meta_blob(zlib(method_idx,code_off,insns_size)) compressed = {meta_blob_total_comp/1e6:.2f} MB"
      f"  | uncompressed(3*u32*entries) = {meta_blob_total_uncomp/1e6:.2f} MB")
print(f"    meta 压缩比 = {meta_blob_total_uncomp/meta_blob_total_comp:.2f}x" if meta_blob_total_comp else "n/a")
print(f"  salt(32B)    : present={salt_present}")
print(f"  recons len   : {p+32:,} vs payload {len(data):,}")
print(f"  -> DEX段 + method段 = {(dex_total+method_total)/1e6:.2f} MB")
print(f"  -> method段 单独 = {method_total/1e6:.2f} MB  (stream={stream_blob_total/1e6:.2f} + meta={meta_blob_total_comp/1e6:.2f} + overhead={ (method_total-stream_blob_total-meta_blob_total_comp)/1e6:.2f})")
print("  dex entries in zip:", [(n, s) for n, s in dex_entries])
