# limit

一个插件内两种限制器：

- **`rate`** — 按滑动窗口计量的单位时间请求数。
- **`inflight`** — 进行中的并发请求，用原子计数，请求结束时自动释放。

两者都可按客户端 IP、请求头、Cookie 或查询参数作为键。

- **步骤：** `request`（默认）或 `proxy_upstream` — 可配置
- **注册名：** `limit`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `limit`。 |
| `type` | string | `rate` | `inflight` 为并发，其他为速率。 |
| `tag` | string | `ip` | `ip`、`header`、`cookie` 或 `query`。 |
| `key` | string | — | 请求头 / Cookie / 查询参数名。`tag = "ip"` 时忽略。 |
| `max` | int | `0` | 每个 `interval` 允许的请求数（rate），或并发数（inflight）。 |
| `interval` | duration | `10s` | 速率窗口。`inflight` 忽略。 |
| `weight` | int | `50` | 0–100。当前窗口相对上一窗口的权重。 |
| `step` | string | `request` | `request` 或 `proxy_upstream`。其他值为配置错误。 |

### `max` 与 `interval` 如何作用

对 `type = "rate"`，`max` 除以 `interval` 秒数（下限为 1）得到每秒预算，再与滑动窗口估计比较。因此 `max = 600, interval = "60s"` 表示“平均每秒约 10 次”，而不是“任意 60 秒桶内 600 次”。

`weight` 在估计当前速率时混合上一窗口与当前窗口：`(prev * (1 - w) + curr * w) / interval`。较低值更平滑突发，较高值反应更快。`weight = 0` 回退为仅使用上一窗口。

## 示例

按 IP 限速：

```toml
[plugins.rateLimit]
category = "limit"
type = "rate"
tag = "ip"
max = 600
interval = "60s"
```

按 Cookie 限制用户并发：

```toml
[plugins.userInflight]
category = "limit"
type = "inflight"
tag = "cookie"
key = "deviceId"
max = 10
```

保护昂贵上游，按 API Key 头计数，且只计真正到达后端的请求（缓存命中不计）：

```toml
[plugins.upstreamGuard]
category = "limit"
type = "inflight"
tag = "header"
key = "X-API-Key"
max = 20
step = "proxy_upstream"
```

## 行为

| Situation | Result |
| --- | --- |
| 键值缺失或为空 | **不限流** — 请求放行 |
| 未超限 | `Continue` |
| 超限 | `429 Too Many Requests`，正文 `Plugin limit, exceed limit <value>/<max>` |

## 使用说明

- 空键放行很重要：`tag = "header"` 且 `key = "X-API-Key"` 时，匿名请求完全不受限。请在前面串认证插件，或再加一个按 `ip` 的 `limit`。
- 计数器按进程。负载均衡后多个 Pingap 实例时，有效限额约为实例数倍。
- `step = "proxy_upstream"` 在缓存插件之后运行，缓存命中不消耗配额——适合保护源站，不适合防滥用。
- `max = 0` 对 `inflight` 会拒绝一切（第一个请求计数已为 1，大于 0）。
