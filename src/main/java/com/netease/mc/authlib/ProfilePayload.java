package com.netease.mc.authlib;

/** 客户端令牌 payload：额外带 extraData，即最终返回的 Profile。 */
class ProfilePayload extends JwtPayload {

    Profile extraData;

    private ProfilePayload() {
    }
}
