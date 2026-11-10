package com.netease.mc.authlib;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import com.netease.mc.authlib.exception.*;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** JWT 编解码与密钥解码的公共工具。 */
final class Jwt {

    static final Charset CHARSET = StandardCharsets.UTF_8;

    private static final Gson GSON = new Gson();

    private Jwt() {
    }

    /** 当前时间（秒），与 JWT 的 nbf/exp 单位一致。 */
    static long now() {
        return System.currentTimeMillis() / 1000L;
    }

    /** base64url 解码一段 JWT，再反序列化成给定类型。 */
    static <T> T decode(String part, Class<T> type) {
        try {
            return GSON.fromJson(new String(Base64.getUrlDecoder().decode(part), CHARSET), type);
        } catch (JsonParseException | IllegalArgumentException e) {
            throw Sneaky.sneaky(new ParseException("broken JSON"));
        }
    }

    /** 标准 base64 的 X.509 SubjectPublicKeyInfo 解成 EC 公钥。 */
    static ECPublicKey decodePublicKey(String base64) {
        try {
            return (ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64)));
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            throw Sneaky.sneaky(new ParseException("broken key"));
        }
    }
}
