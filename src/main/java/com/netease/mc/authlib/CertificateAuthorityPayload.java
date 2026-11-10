package com.netease.mc.authlib;

/** 根令牌 payload：额外带 certificateAuthority 标记，必须为 true。 */
class CertificateAuthorityPayload extends JwtPayload {

    boolean certificateAuthority;

    private CertificateAuthorityPayload() {
    }
}
