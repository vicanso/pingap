# forward_auth

将认证决策委托给外部 HTTP 服务，类似 nginx 的 `auth_request` 或 Traefik 的 ForwardAuth。对每个请求 Pingap 向 `auth_url` 发 `GET`；`2xx` 放行，其他状态码原样回传客户端——从而支持重定向到登录页等流程。

- **步骤：** `request`（固定）
- **注册名：** `forward_auth`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `forward_auth`。 |
| `auth_url` | string | — | **必填。** 认证端点。启动时解析，拼写错误会让 `pingap -t` 失败。 |
| `request_headers` | string[] | *(全部)* | 要转发的原始请求头。为空则转发全部。 |
| `add_headers` | string[] | — | 成功时从认证响应复制到上游请求的头。 |
| `timeout` | duration | `10s` | 子请求超时。 |

## 认证服务收到什么

子请求始终是对 `auth_url` 的 `GET`（**不**追加原始路径），携带所选原始头，以及：

| Header | Value |
| --- | --- |
| `x-forwarded-method` | 原始 HTTP 方法 |
| `x-forwarded-uri` | 原始路径与查询串 |
| `x-forwarded-host` | 原始 `Host` |
| `x-forwarded-for` | Pingap 解析的客户端 IP |

## 示例

```toml
[plugins.forwardAuth]
category = "forward_auth"
auth_url = "http://auth-service:9000/verify"
request_headers = ["Cookie", "Authorization"]
add_headers = ["X-User-Id", "X-User-Role"]
timeout = "3s"

[locations.app]
upstream = "app"
path = "/"
plugins = ["forwardAuth"]
```

此配置下，`GET /dashboard` 会发出：

```
GET /verify HTTP/1.1
Host: auth-service:9000
Cookie: session=…
x-forwarded-method: GET
x-forwarded-uri: /dashboard
x-forwarded-host: example.com
x-forwarded-for: 1.2.3.4
```

若服务返回 `200` 且带 `X-User-Id: 42`，上游看到的 `GET /dashboard` 会附带 `X-User-Id: 42`。若返回 `302 Location: /login`，客户端会收到该重定向。

## 行为

| Auth service result | Client sees |
| --- | --- |
| `2xx` | 请求继续；`add_headers` 复制到上游请求 |
| 其他状态 | 该状态码、头与正文原样回传 |
| 不可达 / 超时 | `502 Bad Gateway`，正文 `Forward auth request failed` |

回传响应会剥离 `content-length`、`transfer-encoding` 与 `connection`，因为 Pingap 会重新组帧。非法 HTTP 状态码降级为 `403`。

## 使用说明

- 每个请求都有一次子请求成本。认证服务应本地且快速，在其侧积极缓存，或仅把本插件挂到真正需要的 location。
- `timeout` 限制整个子请求。过大时认证故障会变成延迟故障；通常 1–3 s 合适。
- `request_headers` 为空会把 `Authorization`、Cookie 等全部转给 `auth_url`。认证服务由他人运营时请显式列出。
- 认证*成功*响应中的 `Set-Cookie` 等不会传给客户端——只有 `add_headers` 会，且只加到上游请求上。
