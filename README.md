# authlib — 网易《我的世界》登录令牌链校验器


## 这是什么

`com.netease.mc.authlib` 是网易《我的世界》中国版登录握手用的 **JWT 令牌链校验器**，
不是 Mojang `authlib` 的补丁：它用 **ES384 + EC P-384** 验证两段式令牌链，
从链尾令牌的 `extraData` 里取出 `Profile`。Mojang 官方那套用 RS256 / RSA。

## 快速开始

```bash
mvn clean package install     # 产出 target/authlib-test-1.2.jar并推送至本地Maven库
```
