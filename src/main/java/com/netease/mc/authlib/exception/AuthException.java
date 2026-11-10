package com.netease.mc.authlib.exception;

/** 令牌链相关的受检异常基类。 */
public class AuthException extends Exception {

    public AuthException(String message) {
        super(message);
    }
}
