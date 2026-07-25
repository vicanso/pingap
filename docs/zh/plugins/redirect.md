# redirect

发出 HTTP 重定向，用于强制协议（通常 HTTP → HTTPS）和/或添加路径前缀。

- **步骤：** `request`（固定）
- **注册名：** `redirect`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `redirect`。 |
| `http_to_https` | bool | `false` | `true` 强制 HTTPS；`false` 强制明文 HTTP。 |
| `prefix` | string | — | 要前置的路径前缀。缺失前导 `/` 时补上；长度 ≤ 1 的值忽略。 |
| `status` | int | `307` | `301`、`302`、`307`、`308` 之一。其他值变为 `307`。 |

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

当协议已符合 `http_to_https` **且** 路径已以 `prefix` 开头时，插件跳过请求。否则以 `status` 响应，`Location` 由目标协议、请求 `Host`、`prefix` 与原始 URI 构成。

状态码选择：

| Status | Method preserved | Cached by browsers |
| --- | --- | --- |
| `301` | 否（POST 可能变 GET） | 永久 — 难以撤销 |
| `302` | 否 | 否 |
| `307` | 是 | 否 |
| `308` | 是 | 永久 |

## 使用说明

- 一旦发生重定向，`prefix` 会无条件前置。若协议不匹配但路径*已经*带前缀，发出的 `Location` 会重复（`/api/api/users`）。请把 `prefix` 用在路径本身不含该前缀的 location 上，或仅做协议跳转的服务器上不设 `prefix`。
- “已是 HTTPS” 的判断基于 Pingap 终止的连接 TLS 状态。在 TLS 终止的负载均衡之后，每个请求都像明文 HTTP，本插件会循环——应在负载均衡处跳转，或不要在此处挂本插件。
- `301`/`308` 会被浏览器积极缓存。先从 `307` 开始，配置验证后再改永久码。
