package com.netease.mc.authlib;

import java.util.UUID;

/**
 * 令牌链末段 extraData 里携带的玩家档案，字段名同时就是 JSON 键名（Gson 反射绑定），
 * 因此不能随意改名。
 */
public class Profile {

    public UUID identity;
    public String XUID;
    public String displayName;
    public long uid;
    public short version;
    public String env;
    public String clientPubKey;

    @Override
    public String toString() {
        return "Profile{identity=" + identity
                + ", XUID=" + XUID
                + ", displayName=" + displayName
                + ", uid=" + uid
                + ", version=" + version
                + ", env=" + env
                + ", clientPubKey=" + clientPubKey + '}';
    }
}
