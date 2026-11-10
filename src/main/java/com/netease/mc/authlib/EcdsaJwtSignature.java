package com.netease.mc.authlib;

import com.netease.mc.authlib.exception.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/**
 * JWT 的 ES384 签名是 R||S 原文拼接（P-384 各 48 字节，共 96 字节），
 * 而 {@link Signature} 需要的是 DER SEQUENCE { INTEGER r, INTEGER s }。
 * 本类负责这个转换并完成验签。
 */
final class EcdsaJwtSignature {

    private final byte[] der;

    EcdsaJwtSignature(String jws) {
        byte[] raw;
        try {
            raw = Base64.getUrlDecoder().decode(jws);
        } catch (IllegalArgumentException e) {
            throw Sneaky.sneaky(new ParseException("broken signature"));
        }
        if (raw.length != 96) {
            throw Sneaky.sneaky(new ParseException("broken signature"));
        }
        Component r = Component.read(raw, 0, 48);
        Component s = Component.read(raw, 48, 96);

        int length = 4 + r.length + s.length;
        this.der = new byte[length + 2];
        this.der[0] = 0x30;
        this.der[1] = (byte) length;
        Component.write(raw, r, this.der, 2);
        Component.write(raw, s, this.der, 4 + r.length);
    }

    boolean verify(ECPublicKey key, byte[] content) {
        try {
            Signature signature = Signature.getInstance("SHA384withECDSA");
            signature.initVerify(key);
            signature.update(content);
            return signature.verify(this.der);
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            return false;
        }
    }

    /** 原始签名中一半（r 或 s）在 DER INTEGER 里的位置与长度。 */
    private static final class Component {

        final int offset;
        /** DER 里要写的内容长度，必要时已为符号位加 1。 */
        final int length;
        final boolean negative;

        private Component(int offset, int length, boolean negative) {
            this.offset = offset;
            this.length = length;
            this.negative = negative;
        }

        static Component read(byte[] raw, int from, int to) {
            int offset = from;
            // 去掉前导零，和 BigInteger 的规范形式对齐。
            while (offset < to - 1 && raw[offset] == 0) {
                offset++;
            }
            int length = to - offset;
            boolean negative = (raw[offset] & 0x80) != 0;
            if (negative) {
                // 最高位为 1 时 DER 需要补一个 0x00，否则会被当成负数。
                length++;
            }
            return new Component(offset, length, negative);
        }

        static void write(byte[] raw, Component component, byte[] out, int at) {
            out[at] = 0x02;
            out[at + 1] = (byte) component.length;
            if (component.negative) {
                out[at + 2] = 0;
                System.arraycopy(raw, component.offset, out, at + 3, component.length - 1);
            } else {
                System.arraycopy(raw, component.offset, out, at + 2, component.length);
            }
        }
    }
}
