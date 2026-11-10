package com.netease.mc.authlib.exception;

/** 结构合法但校验不通过：签名不符、token 过期、密钥链断裂、根令牌缺 CA 标记。 */
public final class VerificationException extends AuthException {

    public VerificationException(String message) {
        super(message);
    }
}
