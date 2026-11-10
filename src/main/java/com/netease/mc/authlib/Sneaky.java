package com.netease.mc.authlib;

/**
 * 把受检异常当作运行时异常抛出。
 *
 * <p>原 jar 的 {@code TokenChain.check(String[])} 与内部 verify 方法都<b>没有</b> {@code throws} 声明，
 * 却会抛出受检的 {@code AuthException} 子类——这是 Lombok {@code @SneakyThrows} 生成的效果。
 * 为了保持 {@code check} 的调用签名不变（游戏侧调用时不写 try/catch），这里用同样的手法复现：
 * 编译期不检查，运行期抛出的仍是原始的 {@code AuthException}/{@code ParseException}/
 * {@code VerificationException} 实例。</p>
 */
final class Sneaky {

    private Sneaky() {
    }

    /** 用法：{@code throw Sneaky.sneaky(new ParseException("broken JWT"));} */
    static RuntimeException sneaky(Throwable cause) {
        Sneaky.<RuntimeException>throwUnchecked(cause);
        // 不会执行到这里。
        return new IllegalStateException(cause);
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> void throwUnchecked(Throwable cause) throws T {
        throw (T) cause;
    }
}
