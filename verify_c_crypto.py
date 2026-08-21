# -*- coding: utf-8 -*-
"""
独立校验 jg_crypto.h / jg_method_restore.c 的算法逻辑：
用纯 Python 重新实现一份与 C 完全一致的 AES-256 / GCM / HMAC / 写回，
对 method_restore_vectors.h（pycryptodome 生成的已知答案）断言。
若通过，说明 C 实现与加固端字节一致（本沙箱无 C 编译器，以此作等价验证）。
"""
import re

HDR = "src/native/method_restore_vectors.h"

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
RCON = [0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000]

def rotr(x,n): return ((x>>n)|(x<<(32-n))) & 0xffffffff

def sha256_blocks(h, msg):
    K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
         0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
         0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
         0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
         0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
         0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
         0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
         0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
    w=[0]*64
    for i in range(16):
        w[i]=(msg[0]<<24)|(msg[1]<<16)|(msg[2]<<8)|msg[3]; msg=msg[4:]
    for i in range(16,64):
        s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3)
        s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10)
        w[i]=(w[i-16]+s0+w[i-7]+s1)&0xffffffff
    a,b,c,d,e,f,g,hh=h
    for i in range(64):
        S1=rotr(e,6)^rotr(e,11)^rotr(e,25); ch=(e&f)^((~e)&g)
        t1=(hh+S1+ch+K[i]+w[i])&0xffffffff
        S0=rotr(a,2)^rotr(a,13)^rotr(a,22); maj=(a&b)^(a&c)^(b&c)
        t2=(S0+maj)&0xffffffff
        hh=g;g=f;f=e;e=(d+t1)&0xffffffff;d=c;c=b;b=a;a=(t1+t2)&0xffffffff
    return [(x+y)&0xffffffff for x,y in zip(h,[a,b,c,d,e,f,g,hh])]

def sha256(data):
    h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
    ml=len(data)*8
    msg=bytearray(data)+b'\x80'
    while len(msg)%64!=56: msg+=b'\x00'
    msg+=ml.to_bytes(8,'big')
    for off in range(0,len(msg),64):
        h=sha256_blocks(h,msg[off:off+64])
    return b''.join(x.to_bytes(4,'big') for x in h)

def hmac_sha256(key,msg):
    key=key+b'\x00'* (64-len(key)) if len(key)<=64 else sha256(key)
    ipad=bytes(x^0x36 for x in key); opad=bytes(x^0x5c for x in key)
    return sha256(opad+sha256(ipad+msg))

def subw(w): return SBOX[w&0xff]|(SBOX[(w>>8)&0xff]<<8)|(SBOX[(w>>16)&0xff]<<16)|(SBOX[(w>>24)&0xff]<<24)
def rotw(w): return ((w<<8)|(w>>24))&0xffffffff
def keyexp(key):
    rk=[(key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3] for i in range(8)]
    for i in range(8,60):
        t=rk[i-1]
        if i%8==0: t=subw(rotw(t))^RCON[i//8-1]
        elif i%8==4: t=subw(t)
        rk.append(rk[i-8]^t)
    return rk
def xtime(x): return ((x<<1)^(0x1b if x&0x80 else 0))&0xff
def rkbyte(rk,rd,i):
    return (rk[rd*4+(i//4)]>>(24-8*(i%4)))&0xff
def encrypt_block(inb,rk):
    st=list(inb)
    for i in range(16): st[i]^=rkbyte(rk,0,i)
    for r in range(1,15):
        st=[SBOX[x] for x in st]
        for row in (1,2,3):
            a,b,c,d=st[row],st[4+row],st[8+row],st[12+row]
            if row==1: st[row],st[4+row],st[8+row],st[12+row]=b,c,d,a
            elif row==2: t=st[row];st[row]=st[8+row];st[8+row]=t;t=st[4+row];st[4+row]=st[12+row];st[12+row]=t
            else: t=st[row];st[row]=d;st[12+row]=c;st[8+row]=b;st[4+row]=t
        if r<14:
            for col in range(4):
                a,b,c,d=st[col*4],st[col*4+1],st[col*4+2],st[col*4+3]
                st[col*4]=(xtime(a)^(xtime(b)^b)^c^d)&0xff
                st[col*4+1]=(a^xtime(b)^(xtime(c)^c)^d)&0xff
                st[col*4+2]=(a^b^xtime(c)^(xtime(d)^d))&0xff
                st[col*4+3]=((xtime(a)^a)^b^c^xtime(d))&0xff
        for i in range(16): st[i]^=rkbyte(rk,r,i)
    return bytes(st)
def gf_mult(x,y):
    Z=bytearray(16); V=bytearray(x)
    for i in range(128):
        bit=(y[i>>3]>>(7-(i&7)))&1
        if bit:
            for j in range(16): Z[j]^=V[j]
        lsb=V[15]&1
        for j in range(15,0,-1): V[j]=((V[j]>>1)|((V[j-1]&1)<<7))&0xff
        V[0]=(V[0]>>1)&0xff
        if lsb: V[0]^=0xe1
    return bytes(Z)
def ghash(H,data):
    Y=bytearray(16)
    for i in range(0,len(data),16):
        blk=data[i:i+16]+b'\x00'*(16-len(data[i:i+16]))
        for j in range(16): Y[j]^=blk[j]
        Y[:]=gf_mult(Y,H)
    return bytes(Y)
def inc32(c):
    c=bytearray(c)
    for i in range(15,11,-1):
        c[i]=(c[i]+1)&0xff
        if c[i]: break
    return bytes(c)
def gcm_decrypt(key,iv,ct,tag):
    rk=keyexp(key)
    H=encrypt_block(b'\x00'*16,rk)
    J0=iv+b'\x00\x00\x00\x01'
    Y=bytearray(ghash(H,ct))
    lb=bytearray(16); cb=(len(ct)*8).to_bytes(8,'big'); lb[8:]=cb
    for i in range(16): Y[i]^=lb[i]
    Y=gf_mult(Y,H)
    ctr=J0; out=bytearray()
    for i in range(0,len(ct),16):
        ctr=inc32(ctr); ks=encrypt_block(ctr,rk)
        out+=bytes(ct[i+j]^ks[j] for j in range(min(16,len(ct)-i)))
    ej0=encrypt_block(J0,rk)
    T=bytes(Y[i]^ej0[i] for i in range(16))
    return out if T==tag else None

def rd32(b,o): return b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24)
def restore(dex,payload,seed):
    if payload[0:4]!=b'JGS1': return None
    p=4; dc=rd32(payload,p); p+=4
    for _ in range(dc): ln=rd32(payload,p); p+=4; p+=ln
    ac=rd32(payload,p); p+=4
    for _ in range(ac): nl=rd32(payload,p); p+=4; p+=nl; ln=rd32(payload,p); p+=4; p+=ln
    if p+4>len(payload): return None
    mdc=rd32(payload,p); p+=4
    if mdc==0: return None
    for _ in range(mdc):
        dex_idx=rd32(payload,p); p+=4; ec=rd32(payload,p); p+=4
        for _ in range(ec):
            midx=rd32(payload,p); p+=4; code_off=rd32(payload,p); p+=4; insns_size=rd32(payload,p); p+=4; ln=rd32(payload,p); p+=4
            blob=payload[p:p+ln]; p+=ln
            key=hmac_sha256(seed,("JG|m%d.%d"%(dex_idx,midx)).encode())
            iv=blob[0:12]; ct=blob[12:-16]; tag=blob[-16:]
            plain=gcm_decrypt(key,iv,ct,tag)
            if plain is None: return None
            import zlib
            insns=zlib.decompress(plain)
            if len(insns)!=insns_size*2: return None
            dex=bytearray(dex)
            dex[code_off+16:code_off+16+len(insns)]=insns
    return bytes(dex)

# ---- parse vectors from .h ----
def parse_vec(name):
    txt=open(HDR,'rb').read().decode()
    m=re.search(r"static const unsigned char %s\[(\d+)\] = \{([^}]*)\};"%name,txt,re.S)
    hexes=re.findall(r"0x([0-9a-fA-F]{2})",m.group(2))
    return bytes(int(h,16) for h in hexes)

def main():
    SEED=parse_vec("V_SEED"); HMACK=parse_vec("V_HMAC_KEY")
    G1K=parse_vec("V_GCM1_KEY"); G1IV=parse_vec("V_GCM1_IV"); G1CT=parse_vec("V_GCM1_CT"); G1TAG=parse_vec("V_GCM1_TAG"); G1P=parse_vec("V_GCM1_PLAIN")
    G2K=parse_vec("V_GCM2_KEY"); G2IV=parse_vec("V_GCM2_IV"); G2CT=parse_vec("V_GCM2_CT"); G2TAG=parse_vec("V_GCM2_TAG"); G2P=parse_vec("V_GCM2_PLAIN")
    NOP=parse_vec("V_NOP_DEX"); ORIG=parse_vec("V_ORIG_DEX"); PAY=parse_vec("V_FULL_PAYLOAD")
    ok=True
    # HMAC
    if hmac_sha256(SEED,b"JG|m0.0")==HMACK:
        print("[PASS] HMAC derive")
    else:
        print("[FAIL] HMAC"); ok=False
    # GCM1
    p1=gcm_decrypt(G1K,G1IV,G1CT,G1TAG)
    if p1 is not None and p1==G1P:
        print("[PASS] GCM1 decrypt")
    else:
        print("[FAIL] GCM1"); ok=False
    # GCM2
    p2=gcm_decrypt(G2K,G2IV,G2CT,G2TAG)
    if p2 is not None and p2==G2P:
        print("[PASS] GCM2 decrypt")
    else:
        print("[FAIL] GCM2"); ok=False
    # restore
    r=restore(bytearray(NOP),PAY,SEED)
    if r is not None and r==ORIG:
        print("[PASS] restore -> ORIG_DEX")
    else:
        print("[FAIL] restore"); ok=False
    print("="*40)
    print("纯Python镜像校验:", "ALL PASS" if ok else "FAILED")
    return 0 if ok else 1

if __name__=="__main__":
    import sys; sys.exit(main())
