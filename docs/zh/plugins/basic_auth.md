# basic_auth

HTTP Basic 认证（RFC 7617）。适用于预发环境、内部面板，以及浏览器场景下不必单独做登录页的情况。

- **步骤：** `request`（固定）
- **注册名：** `basic_auth`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `basic_auth`。 |
| `authorizations` | string[] | — | **必填，非空。** `user:password` 的 Base64，每个账号一条。 |
| `delay` | duration | 无 | 失败应答前休眠时长，用于减缓暴力尝试。 |
| `hide_credentials` | bool | `false` | 转发上游前剥离 `Authorization`。 |
| `ip_fail_limit` | int | `0` | 同一客户端 IP 密码错误多少次后以 `403` 拦截。`0` 为关闭。 |
| `ip_fail_window` | duration | `5m` | 失败次数的统计时长，也是 IP 被拦截的最长时间。 |

`authorizations` 条目在启动时校验是否为合法 base64，拼写错误会让 `pingap -t` 失败，而不是静默把所有人锁在外面。凭据按常量时间比较；`Basic` scheme 按 RFC 7235 的要求不区分大小写匹配。

## 生成条目

```bash
echo -n "pingap:123123" | base64
# cGluZ2FwOjEyMzEyMw==
```

## 示例

```toml
[plugins.staging]
category = "basic_auth"
authorizations = [
    "cGluZ2FwOjEyMzEyMw==",   # pingap:123123
    "YWRtaW46c2VjcmV0",       # admin:secret
]
delay = "1s"
hide_credentials = true
ip_fail_limit = 5
ip_fail_window = "10m"

[locations.staging]
upstream = "app"
path = "/"
plugins = ["staging"]
```

验证：

```bash
curl -i http://127.0.0.1:6188/
# HTTP/1.1 401 Unauthorized
# www-authenticate: Basic realm="Access to the staging site"
# Authorization is missing

curl -i -u pingap:123123 http://127.0.0.1:6188/
# HTTP/1.1 200 OK
```

## 响应

| Situation | Status | Body |
| --- | --- | --- |
| 无 `Authorization` 头 | 401 + `WWW-Authenticate` | `Authorization is missing` |
| 用户名或密码错误 | 401 + `WWW-Authenticate`（在 `delay` 之后） | `Invalid user or password` |
| 客户端 IP 被 `ip_fail_limit` 拦截 | 403 | `Forbidden, too many failures` |

## 使用说明

- Basic 认证每次请求都会发送密码（仅 base64，非加密）。务必在 TLS 上使用。
- `delay` 会阻塞请求任务。繁忙监听器上应远小于 1 秒，或改用短 delay 配合 [`limit`](limit.md)。
- 上游不需要凭据时，`hide_credentials = true` 是更安全的默认，可避免凭据进入上游日志。

## 拦截反复失败的 IP

设置 `ip_fail_limit` 后，每次密码错误都会计入该客户端 IP。IP 达到上限后，在窗口结束前都返回 `403 Forbidden, too many failures`，即使提供了正确的凭据：

- 窗口从该 IP 第一次被计数的失败开始，持续 `ip_fail_window`。设为 `5` 和 `10m` 时，前一分钟内错 5 次，该 IP 会在剩下的九分钟内被拦截。被拒绝的请求不计数，因此不会延长拦截。
- 只有错误的凭据才计数。没有 `Authorization` 请求头是每个浏览器弹出登录框之前的第一个请求，永远不计数。
- 登录成功不会清除之前的失败次数，它们随窗口一起过期。
- 最多同时跟踪 4096 个客户端 IP，超出后淘汰最少使用的，最坏只会让某个 IP 提前解除拦截。
- 计数按进程独立，与 `limit` 插件相同。

失败次数按客户端无法自己指定的地址计数：

| `basic.trusted_proxies` | 计数用的地址 |
| --- | --- |
| 已配置 | 客户端 IP：经过列表里的代理时，取 `X-Forwarded-For` 中从右数第一个不在列表里的地址，否则取对端地址 |
| 未配置 | 连接本身的对端地址，不看 `X-Forwarded-For` 和 `X-Real-IP` |

因此，前面有代理或 CDN 而没有把它写进 `trusted_proxies` 时，所有客户端共用代理的地址和同一个计数：任何人输错几次密码，所有人都会被拦截到窗口结束。请把代理加入列表。

到 0.15.0 为止，没有配置可信代理时按 `X-Forwarded-For` 计数，而任何客户端都能写这个头：每次猜测换一个地址就永远不会被拦截，填别人的地址还能让别人被拦截。admin 登录失败的锁定按同样的方式计数。
