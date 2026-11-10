package com.netease.mc.authlib;

import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * 根令牌 -> 下发公钥 的短期缓存：同一条链在一次登录里可能被校验多次，
 * 命中缓存就不必再用根 CA 公钥验一次签名。条目在根令牌 exp 到期时被清理。
 */
final class TrustCache {

    private static final TrustCache INSTANCE = new TrustCache();

    /** 按 exp 排序，队首是最早过期的条目。 */
    private final PriorityQueue<Entry> expiries = new PriorityQueue<Entry>();
    private final Map<String, String> keys = new HashMap<String, String>();

    private TrustCache() {
    }

    static TrustCache instance() {
        return INSTANCE;
    }

    synchronized String get(String rootToken) {
        prune();
        return keys.get(rootToken);
    }

    synchronized void put(String rootToken, String delegatedKey, long expiresAt) {
        prune();
        if (keys.put(rootToken, delegatedKey) == null) {
            expiries.add(new Entry(rootToken, expiresAt));
        }
    }

    /** 清掉已经过期的条目。调用方必须持锁。 */
    private void prune() {
        long now = Jwt.now();
        while (!expiries.isEmpty() && expiries.peek().expiresAt < now) {
            keys.remove(expiries.poll().rootToken);
        }
    }

    private static final class Entry implements Comparable<Entry> {

        final String rootToken;
        final long expiresAt;

        Entry(String rootToken, long expiresAt) {
            this.rootToken = rootToken;
            this.expiresAt = expiresAt;
        }

        @Override
        public int compareTo(Entry other) {
            return Long.compare(this.expiresAt, other.expiresAt);
        }
    }
}
