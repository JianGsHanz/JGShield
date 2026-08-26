package com.jiagu.obf;

/**
 * DEX string decryptor. Loaded as a standalone obf.dex into the same classloader as the app.
 * Algorithm: base64-decode -> XOR with fixed 16-byte key -> UTF-8. Must match dex_obf.py encryptor.
 * Pure java.lang, no android dependency, so it is JVM-unit-testable offline.
 */
public class ObfStr {
    private static final byte[] KEY = "JGShieldDEXobf01".getBytes();
    private static final String B64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    public static String d(String s) {
        if (s == null) return null;
        byte[] ct = b64decode(s);
        byte[] out = new byte[ct.length];
        for (int i = 0; i < ct.length; i++) {
            out[i] = (byte) (ct[i] ^ KEY[i % KEY.length]);
        }
        try {
            return new String(out, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return new String(out);
        }
    }

    public static byte[] b64decode(String s) {
        int len = s.length();
        int olen = len * 6 / 8;
        byte[] out = new byte[olen];
        int acc = 0, bits = 0, idx = 0;
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (c == '=') break;
            int v = B64.indexOf(c);
            if (v < 0) continue;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[idx++] = (byte) ((acc >> bits) & 0xFF);
            }
        }
        if (idx < olen) {
            byte[] t = new byte[idx];
            java.lang.System.arraycopy(out, 0, t, 0, idx);
            out = t;
        }
        return out;
    }
}
