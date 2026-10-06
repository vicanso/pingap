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
| `type` | string | `rate` | `rate` 或 `inflight`。其他值是配置错误。 |
| `tag` | string | `ip` | `ip`、`header`、`cookie` 或 `query`。其他值是配置错误。`ip` 指连接的对端地址；请求经过 `basic.trusted_proxies` 里的代理时，用转发头里的地址。 |
| `key` | string | — | header / cookie / query 参数名。除 `tag = "ip"` 外**必填**。 |
| `max` | int | — | **必填。**每个 `interval` 允许的请求数（rate），或并发数（inflight）。负数是配置错误。 |
| `interval` | duration | `10s` | rate 的窗口，至少 `1ms`。`inflight` 忽略。 |
| `step` | string | `request` | `request` 或 `proxy_upstream`。其他值为配置错误。 |

### `max` 与 `interval` 如何作用

对 `type = "rate"`，`max` 是同一个键在任意一个 `interval` 内允许的请求数。限流器为每个键保留两个计数（当前窗口和上一个窗口），按下面的方式估算最近一个 `interval` 内的请求数：

```
上一窗口 × (1 − 当前窗口已经过去的比例) + 当前窗口
```

会让估算值超过 `max` 的请求返回 `429`。所以 `max = 600, interval = "60s"` 允许一个之前空闲的客户端一次发出 600 个请求，之后把它限制在每秒 10 个左右。

- 被拒绝的请求不计数。超限的客户端每个 interval 仍然能得到 `max` 个请求，不会因为不断重试而一直被拒绝。
- 这是估算，不是逐条记录：估算时假设上一窗口的请求是均匀分布的。如果客户端把 `max` 个请求全压在一个窗口的末尾，随着这个窗口的权重衰减，它在下一个窗口里还能再通过几个，最坏情况下在一个 interval 长度的时间段内接近 `2 × max`。长期平均下来速率被限制在 `max`。反过来，`max` 很小（1 或 2）时，恰好按 `max` 的速率发送的客户端会有一部分请求被拒绝，这类限制请留一点余量。

`weight` 已废弃。它按固定比例（默认 `50`）混合两个窗口，对限流器来说是新面孔的客户端因此能发出两倍于 `max` 的请求，`weight = 0` 时则完全不受限。配置里仍然写着这个键时可以正常加载，会打印一条告警并忽略它。**限额比以前严格**：以前每个 interval 最多能放行 `2 × max`，现在是 `max`。

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
| 超限 | `429 Too Many Requests`，正文 `Plugin limit, exceed limit <value>/<max>`；`rate` 限流器附带 `Retry-After: <interval 秒数>` |

## 使用说明

- `tag = "ip"` 且没有配置 `basic.trusted_proxies` 时不看 `X-Forwarded-For`：前面有代理而没有列入时，所有客户端都是代理的地址，共用一份额度。请把代理加进去。（以前任何来源的转发头都会被采用，每次请求换一个值就永远不会被限。）
- 空键放行很重要：`tag = "header"` 且 `key = "X-API-Key"` 时，匿名请求完全不受限。请在前面串认证插件，或再加一个按 `ip` 的 `limit`。
- 计数器按进程。负载均衡后多个 Pingap 实例时，有效限额约为实例数倍。
- `step = "proxy_upstream"` 在缓存插件之后运行，缓存命中不消耗配额——适合保护源站，不适合防滥用。
- `max = 0` 对 `inflight` 会拒绝一切（第一个请求计数已为 1，大于 0）。
- 一个 location 可以挂多个限制，例如一个按 IP、一个按 API key。它们各自计数，请求要同时满足全部限制。
