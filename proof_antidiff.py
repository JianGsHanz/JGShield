"""抗跨构建 diff 证明：同一输入两次加固，载荷 salt 尾随 + 密文应不同。"""
import zipfile, sys

def read_jg(path):
    with zipfile.ZipFile(path) as z:
        return z.read("jg")

a = read_jg(sys.argv[1])
b = read_jg(sys.argv[2])
print("len(A)=%d len(B)=%d" % (len(a), len(b)))
print("len equal        : %s" % (len(a) == len(b)))
salt_a = a[-32:]; salt_b = b[-32:]
print("salt(A)=%s" % salt_a.hex())
print("salt(B)=%s" % salt_b.hex())
print("salt differ      : %s  <-- 抗跨构建 diff 关键证据" % (salt_a != salt_b))
print("payload differ   : %s  <-- 密钥随 salt 变 -> 全部密文不同" % (a != b))
# 比较第一块 dex blob 的密文（应在 magic+count 之后）
p = 4 + 4
la = int.from_bytes(a[p:p+4], "little"); lb = int.from_bytes(b[p:p+4], "little")
print("dex0 blob len A=%d B=%d" % (la, lb))
blob_a = a[p+4:p+4+la]; blob_b = b[p+4:p+4+lb]
print("dex0 ciphertext differ: %s" % (blob_a != blob_b))
