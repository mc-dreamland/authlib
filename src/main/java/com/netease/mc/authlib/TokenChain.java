package com.netease.mc.authlib;

import com.netease.mc.authlib.exception.*;

/**
 * 网易（中国版）《我的世界》登录握手所使用的 JWT 令牌链校验器。
 *
 * <p>链固定为两段：</p>
 * <pre>
 *   chain[0]  根令牌 / certificate authority
 *             ES384 JWT，用内置的网易根公钥验签；
 *             payload 必须 certificateAuthority = true，
 *             并通过 identityPublicKey 把下一步的可信公钥下发出来。
 *
 *   chain[1]  客户端令牌
 *             ES384 JWT，用上一段下发的公钥验签；
 *             payload 必须有 extraData，那就是最终返回的 Profile。
 * </pre>
 *
 * <p>校验通过后 {@link Profile#clientPubKey} 被填成"签发 chain[1] 的那把公钥"，
 * 即根令牌下发的中转公钥。</p>
 *
 * <p>注意：本类只校验 chain[0] 和 chain[1]，更长的链中多余的元素被忽略。
 * 这是原实现的行为，此处保持一致。</p>
 */
public final class TokenChain {

    /** 网易根 CA 公钥：EC P-384，X.509 SubjectPublicKeyInfo，标准 Base64。 */
    private static final String ROOT_PUBLIC_KEY =
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEEsmU+IF/XeAF3yiqJ7Ko36btx6JtdB26wV9Eyw4AYR/nmesznkfXxwQ4B0NkSnGIZccbb2f3nFUYughKSoAcNHx+lQm8F9h9RwhrNgeN907z06LUA2AqWcwqasxyaU0E";

    /** 下一段令牌必须使用的签名公钥（初始为根 CA 公钥）。 */
    private String trustedKey = ROOT_PUBLIC_KEY;

    private TokenChain() {
    }

    /** 仅用于测试：换一个根公钥起链（真实根私钥在网易手里，测试只能自己造一对）。 */
    private TokenChain(String rootPublicKey) {
        this.trustedKey = rootPublicKey;
    }

    /**
     * 验证单段 JWT：header 的 alg/x5u 必须匹配预期，签名必须由 trustedKey 验证通过，
     * payload 的 nbf/exp 必须覆盖当前时间且带 identityPublicKey。
     * 成功后把 trustedKey 换成 payload 里的 identityPublicKey，供下一段使用。
     */
    private <T extends JwtPayload> T verify(String jwt, Class<T> payloadType) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw Sneaky.sneaky(new ParseException("broken JWT"));
        }
        // 签名覆盖的是 "header.payload" 这段原文。
        byte[] signedContent = jwt.substring(0, jwt.length() - parts[2].length() - 1).getBytes(Jwt.CHARSET);
        EcdsaJwtSignature signature = new EcdsaJwtSignature(parts[2]);

        JwtHeader header = Jwt.decode(parts[0], JwtHeader.class);
        if (!header.alg.equals("ES384")) {
            throw Sneaky.sneaky(new AuthException("only support ES384"));
        }
        // x5u 必须逐字等于预期公钥，避免服务端随便换密钥。
        if (!header.x5u.equals(this.trustedKey)) {
            throw Sneaky.sneaky(new AuthException("untrusted key"));
        }
        if (!signature.verify(Jwt.decodePublicKey(this.trustedKey), signedContent)) {
            throw Sneaky.sneaky(new VerificationException("signature mismatch"));
        }

        T payload = Jwt.decode(parts[1], payloadType);
        long now = Jwt.now();
        if (now < payload.nbf || now > payload.exp) {
            throw Sneaky.sneaky(new VerificationException(String.format(
                    "signature is outdated [%d, %d] / %d", payload.nbf, payload.exp, now)));
        }
        if (payload.identityPublicKey == null) {
            throw Sneaky.sneaky(new VerificationException("broken key chain"));
        }
        this.trustedKey = payload.identityPublicKey;
        return payload;
    }

    /**
     * 校验整条令牌链并取出 Profile。
     *
     * @param chain 至少两段 JWT；只有前两段会被校验
     * @return 链尾令牌 extraData 里的 Profile，clientPubKey 已填好
     */
    public static Profile check(String[] chain) {
        return check(chain, ROOT_PUBLIC_KEY);
    }

    /**
     * 与 {@link #check(String[])} 逻辑完全相同，只是把根公钥做成参数。
     *
     * <p>这个重载是为了让测试能用自己的 P-384 根密钥造链——网易根私钥拿不到，
     * 不换根公钥就没法构造"验签能过"的用例。生产调用方仍然走单参数版本。</p>
     */
    static Profile check(String[] chain, String rootPublicKey) {
        if (chain.length < 2) {
            throw Sneaky.sneaky(new ParseException("too short chain"));
        }
        TokenChain verifier = new TokenChain(rootPublicKey);

        String rootToken = chain[0];
        // 根令牌验证开销最大，命中缓存时直接复用其下发的公钥。
        String delegatedKey = TrustCache.instance().get(rootToken);
        if (delegatedKey == null) {
            CertificateAuthorityPayload root =
                    verifier.verify(rootToken, CertificateAuthorityPayload.class);
            if (!root.certificateAuthority) {
                throw Sneaky.sneaky(new VerificationException("unexpected root token"));
            }
            TrustCache.instance().put(rootToken, verifier.trustedKey, root.exp);
        } else {
            verifier.trustedKey = delegatedKey;
        }

        ProfilePayload leaf = verifier.verify(chain[1], ProfilePayload.class);
        if (leaf.extraData == null) {
            throw Sneaky.sneaky(new VerificationException("unexpected token"));
        }
        Profile profile = leaf.extraData;
        profile.clientPubKey = verifier.trustedKey;
        return profile;
    }
}
