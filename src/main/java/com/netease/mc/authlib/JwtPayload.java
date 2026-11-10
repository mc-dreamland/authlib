package com.netease.mc.authlib;

/** 所有 JWT payload 共有的时间窗与密钥链接字段。 */
class JwtPayload {

    long nbf;
    long exp;
    String identityPublicKey;

    JwtPayload() {
    }
}
