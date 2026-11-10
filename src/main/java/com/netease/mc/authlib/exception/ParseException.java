package com.netease.mc.authlib.exception;

/** 结构不合法：JWT 段数不对、JSON/base64/公钥解不开、链太短。 */
public final class ParseException extends AuthException {

    public ParseException(String message) {
        super(message);
    }
}
