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

`authorizations` 条目在启动时校验是否为合法 base64，拼写错误会让 `pingap -t` 失败，而不是静默把所有人锁在外面。凭据按常量时间比较。

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

## 使用说明

- Basic 认证每次请求都会发送密码（仅 base64，非加密）。务必在 TLS 上使用。
- `delay` 会阻塞请求任务。繁忙监听器上应远小于 1 秒，或改用短 delay 配合 [`limit`](limit.md)。
- 上游不需要凭据时，`hide_credentials = true` 是更安全的默认，可避免凭据进入上游日志。
