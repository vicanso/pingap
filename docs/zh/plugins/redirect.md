# redirect

发出 HTTP 重定向，用于强制 HTTPS 和/或添加路径前缀。

- **步骤：** `request`（固定）
- **注册名：** `redirect`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `redirect`。 |
| `http_to_https` | bool | `false` | `true` 把明文 HTTP 请求跳转到 HTTPS；`false` 不改变请求的协议。 |
| `prefix` | string | — | 要前置的路径前缀。缺失前导 `/` 时补上；长度 ≤ 1 的值忽略。 |
| `status` | int | `307` | `301`、`302`、`303`、`307`、`308` 之一。其他值是配置错误。 |

## 示例

```toml
[plugins.forceHttps]
category = "redirect"
http_to_https = true
status = 301

[servers.http]
addr = "0.0.0.0:80"
locations = ["redirect"]

[locations.redirect]
path = "/"
plugins = ["forceHttps"]
```

`GET http://example.com/a?b=1` → `301 Location: https://example.com/a?b=1`。

带前缀：

```toml
[plugins.apiPrefix]
category = "redirect"
http_to_https = true
prefix = "/api"
```

`GET http://example.com/users` → `Location: https://example.com/api/users`。

## 行为

当协议无需改变 **且** 路径已以 `prefix` 开头时，插件跳过请求。协议需要改变只有一种情况：`http_to_https = true` 而请求是明文 HTTP。否则以 `status` 响应，`Location` 由目标协议、请求的域名、`prefix` 与原始的路径和查询串构成。

不配 `http_to_https` 时插件只补前缀，跳转沿用请求本身的协议：在 HTTPS 监听上，`https://a.test/users` 跳到 `https://a.test/api/users`，`https://a.test/api/users` 直接放行。（不配 `http_to_https` 以前的含义是“强制明文 HTTP”，只配前缀的插件挂在 HTTPS 监听上会把所有请求都跳到 `http://`。本插件不再提供从 HTTPS 跳回 HTTP 的能力。）

只补前缀时保留请求的端口，因为协议不变、监听也不变：`example.com:8080/users` 跳到 `http://example.com:8080/api/users`。改变协议的跳转不带端口，落到新协议的默认端口上，因为旧端口并不提供新协议。

状态码选择：

| Status | Method preserved | Cached by browsers |
| --- | --- | --- |
| `301` | 否（POST 可能变 GET） | 永久 — 难以撤销 |
| `302` | 否 | 否 |
| `307` | 是 | 否 |
| `308` | 是 | 永久 |

## 使用说明

- 只有路径缺少 `prefix` 时才会补上，所以对已经带前缀的 URL 做协议跳转，结果仍是 `/api/users`，不会变成 `/api/api/users`。
- “已是 HTTPS” 的判断基于 Pingap 终止的连接 TLS 状态。在 TLS 终止的负载均衡之后，每个请求都像明文 HTTP，本插件会循环——应在负载均衡处跳转，或不要在此处挂本插件。
- `301`/`308` 会被浏览器积极缓存。先从 `307` 开始，配置验证后再改永久码。
