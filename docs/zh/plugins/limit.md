# limit

一个插件内两种限制器：

- **`rate`** — 按滑动窗口计量的单位时间请求数。
- **`inflight`** — 进行中的并发请求，用原子计数，请求结束时自动释放。

两者都可按客户端 IP、请求头、Cookie、查询参数，或 TLS 连接的 [JA4 指纹](#按-tls-指纹)作为键。

- **步骤：** `request`（默认）或 `proxy_upstream` — 可配置
- **注册名：** `limit`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `limit`。 |
| `type` | string | `rate` | `rate` 或 `inflight`。其他值是配置错误。 |
| `tag` | string | `ip` | `ip`、`header`、`cookie`、`query`、`ja4` 或 `ip_ja4`。其他值是配置错误。`ip` 指连接的对端地址；请求经过 `basic.trusted_proxies` 里的代理时，用转发头里的地址。`ja4` 和 `ip_ja4` 见[按 TLS 指纹](#按-tls-指纹)。 |
| `key` | string | — | header / cookie / query 参数名。`tag` 为 `header`、`cookie`、`query` 时**必填**；其他 `tag` 不读取它，填了会在 `pingap -t`、启动和重载时打印告警（同样的告警只打印一次）。 |
| `max` | int | — | **必填。**每个 `interval` 允许的请求数（rate），或并发数（inflight）。负数是配置错误。 |
| `interval` | duration | `10s` | rate 的窗口，至少 `1ms`。`inflight` 忽略。 |
| `step` | string | `request` | `request` 或 `proxy_upstream`。其他值为配置错误。 |
| `headers` | bool | `false` | 通过 `X-RateLimit-Limit`、`X-RateLimit-Remaining`、`X-RateLimit-Reset` 把额度告诉客户端。见[额度响应头](#额度响应头)。 |
| `status` | int | `429` | 超限时响应的状态码，`400` 到 `599`。 |
| `message` | string | — | 超限时响应的正文，替代 `Plugin limit, exceed limit <value>/<max>`。 |
| `missing_key` | string | `pass` | 请求里取不到键值时怎么办：`pass` 放行且不限流；`reject` 返回 `400`。 |
| `dry_run` | bool | `false` | 本应拒绝的请求（超限，或 `missing_key = "reject"` 时没有键值）照常放行，改为记录本应返回的响应。见[只记录不拦截](#只记录不拦截)。 |

### `max` 与 `interval` 如何作用

对 `type = "rate"`，`max` 是同一个键在任意一个 `interval` 内允许的请求数。限流器为每个键保留两个计数（当前窗口和上一个窗口），按下面的方式估算最近一个 `interval` 内的请求数：

```
上一窗口 × (1 − 当前窗口已经过去的比例) + 当前窗口
```

会让估算值超过 `max` 的请求返回 `429`。所以 `max = 600, interval = "60s"` 允许一个之前空闲的客户端一次发出 600 个请求，之后把它限制在每秒 10 个左右。

- 被拒绝的请求不计数。超限的客户端每个 interval 仍然能得到 `max` 个请求，不会因为不断重试而一直被拒绝。
- 这是估算，不是逐条记录：估算时假设上一窗口的请求是均匀分布的。如果客户端把 `max` 个请求全压在一个窗口的末尾，随着这个窗口的权重衰减，它在下一个窗口里还能再通过几个，最坏情况下在一个 interval 长度的时间段内接近 `2 × max`。长期平均下来速率被限制在 `max`。反过来，`max` 很小（1 或 2）时，恰好按 `max` 的速率发送的客户端会有一部分请求被拒绝，这类限制请留一点余量。

`weight` 已废弃。它按固定比例（默认 `50`）混合两个窗口，对限流器来说是新面孔的客户端因此能发出两倍于 `max` 的请求，`weight = 0` 时则完全不受限。配置里仍然写着这个键时可以正常加载，`pingap -t`、启动和重载时会打印一条告警，并忽略它。**限额比以前严格**：以前每个 interval 最多能放行 `2 × max`，现在是 `max`。

### 按 TLS 指纹

`tag = "ja4"` 按连接的 [JA4 指纹](../crates/proxy.md#ja4-指纹)计数：即客户端的 TLS 栈是什么，不管它的 `User-Agent` 怎么写。TLS 栈相同的客户端，不论来自哪个地址，都共用一份额度，所以把请求分散到一批代理上的爬虫仍然被算作一个。同一个浏览器版本的所有用户也是如此：适合用在只给脚本、不给浏览器调用的 location 上，或者把 `max` 当作一类客户端的上限。

`tag = "ip_ja4"` 按地址和指纹的组合计数。同一个办公室出口地址后面，失控的脚本有自己的一份额度，不会把浏览器的额度用光。没有指纹的请求只按地址计数。

只有 TLS 连接、且 server 开启了 `ja4 = true` 才有指纹。没有指纹时，`tag = "ja4"` 取不到键值，由 `missing_key` 决定；要整类拒绝某些客户端，用 [`ja4_restriction`](ja4_restriction.md)。带这类限流的 location 挂在没有开启 `ja4 = true` 的 server 上时，`pingap -t`、启动以及引入它的那次重载都会打印告警，重载里才设置的 `ja4 = true`（要等重启才生效）也算：这可能是有意的，比如同一个 location 也通过明文 http 提供。同样的告警只打印一次。

- 在终结 TLS、再重新连接 Pingap 的代理或 CDN 后面，看到的是代理的指纹：`tag = "ja4"` 会把所有请求当成同一个客户端，整个 location 共用一份额度。（`ip_ja4` 在 `basic.trusted_proxies` 列出的代理后面会按客户端地址计数。）
- 指纹由客户端决定。刻意伪装成浏览器的工具会复制浏览器的指纹，从而用光所有使用该浏览器的人的额度；每次改变 cipher 或扩展列表的工具，每次都会得到新的键、新的额度；Pingap 没能完整读到的 ClientHello（超过 16 KiB，或拆成多个 record、合计超过 18 KiB）根本不计算指纹，在 `missing_key = "pass"` 下也就不受限制。JA4 限流能管住不费这些心思的客户端——大多数爬虫都是如此；对付刻意规避的，要同时按地址计数。

### 只记录不拦截

`dry_run = true` 时不拒绝任何请求。本应被拒绝的请求照常放行，改为记录一条警告日志：

```
WARN pingap_plugin: dry run, the request would have been refused category="limit" location="api" status=429 reason=Plugin limit, exceed limit 11/10 matched="1.2.3.4" client_ip="1.2.3.4" method="GET" uri=/api/items request_id="" skipped=0
```

`matched` 是拒绝所依据的请求内容：`limit` 是键值，`ja4_restriction` 是指纹，还有 `User-Agent`、`Referer`、国家码，`uri_block` 是 uri 中命中的部分。`client_ip` 是按地址判断的规则所用的地址（未配置 `basic.trusted_proxies` 时是对端地址），`request_id` 是 [`request_id`](request_id.md) 插件生成的 ID（该插件先运行时才有）。每个插件每个时钟秒最多记 10 行，以免一条会拦下流量冲击的规则把冲击原样写进日志：超出的只计数不记录，下一行的 `skipped` 是自上一行以来没有记录的次数。之后没有新的一行时，这部分计数不会记录。

计数按真正拦截时的情况进行：被拒绝的请求和拦截时一样从 `rate` 的计数里扣除，`inflight` 也不为本应拒绝的请求占位。所以日志里记录的正是开启拦截后会被拒绝的请求，确认无误后再关掉这个选项即可。额度响应头不体现没有真正执行的拒绝：`headers = true` 时，额度内的请求照常报告剩余额度，超限的请求不报告，location 上其他限流器的额度也保持不变。`ip_restriction`、`ua_restriction`、`referer_restriction`、`ja4_restriction`、`geo_restriction` 和 `uri_block` 也有同样的选项。

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

按 TLS 栈限流，不论来自哪个地址，用在浏览器不会调用的 API 上（需要 server 开启 `ja4 = true`）：

```toml
[plugins.perClientKind]
category = "limit"
type = "rate"
tag = "ja4"
max = 300
interval = "60s"
```

## 行为

| Situation | Result |
| --- | --- |
| 键值缺失或为空 | **不限流** — 请求放行。`missing_key = "reject"` 时：`400 Bad Request`，正文 `Plugin limit, the header X-API-Key is required`（或 `the cookie …`、`the query parameter …`、`a TLS connection with a JA4 fingerprint …`） |
| 未超限 | `Continue` |
| 超限 | `429 Too Many Requests`（或 `status`），正文 `Plugin limit, exceed limit <value>/<max>`（或 `message`）；`rate` 限流器附带 `Retry-After: <interval 秒数>` |

### 额度响应头

`headers = true` 时把当前额度告诉客户端：

| Header | Value |
| --- | --- |
| `X-RateLimit-Limit` | `max` |
| `X-RateLimit-Remaining` | 计入本次请求之后还剩多少；被拒绝时为 `0` |
| `X-RateLimit-Reset` | 不再发请求的话，多少秒后额度全部恢复。只有 `rate` 有：`inflight` 没有这样一个时间 |

这三个头会加在上游的响应上、插件自己的拒绝响应上，同一 location 的其他插件直接返回的响应上（比如排在它后面的认证插件返回的 `401`），以及上游故障时代理自己发出的错误页上（`502`、`504`）。`X-RateLimit-Reset` 是上限：估算值是逐渐衰减的，一部分额度会更早恢复；被拒绝之后应以 `Retry-After` 为准。一个 location 上有多个 `limit` 都开启了上报时，告诉客户端的是剩余最少的那一个；被拒绝时带的是做出拒绝的那个 `limit` 的额度，它没有开启上报时就不带。

## 使用说明

- `tag = "ip"` 且没有配置 `basic.trusted_proxies` 时不看 `X-Forwarded-For`：前面有代理而没有列入时，所有客户端都是代理的地址，共用一份额度。请把代理加进去。（以前任何来源的转发头都会被采用，每次请求换一个值就永远不会被限。）
- 空键放行很重要：`tag = "header"` 且 `key = "X-API-Key"` 时，匿名请求完全不受限。请在前面串认证插件，或再加一个按 `ip` 的 `limit`。
- 计数用的是固定大小的概率结构，不是每个键一行的表：`rate` 有 4 行计数器，每行 1024 个（`inflight` 每行 8192 个），一个键在每行各记一个，取这 4 个里最小的作为它的计数。共用计数器的键只会把彼此的计数抬高，不会压低；一个键的 4 个计数器每一个都和别的键共用时，它才会被多算。一个 interval 内有三百个不同的键时，这种情况不到百分之一；一千个时约七分之一；三千个时五分之四；再多就几乎每个键都会被多算。被多算的键没到 `max` 就被限流，多算的量是 4 个计数器里“邻居”加得最少的那一个。在繁忙的站点上按客户端地址、用很长的 `interval` 做 `rate` 限流时最容易遇到；可以缩短 interval，或者换一个取值更少的键。
- 计数器按进程。负载均衡后多个 Pingap 实例时，有效限额约为实例数倍。
- `step = "proxy_upstream"` 在缓存插件之后运行，缓存命中不消耗配额——适合保护源站，不适合防滥用。
- `max = 0` 对 `inflight` 会拒绝一切（第一个请求计数已为 1，大于 0）。
- 一个 location 可以挂多个限制，例如一个按 IP、一个按 API key。它们各自计数，请求要同时满足全部限制。
