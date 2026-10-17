# mirror

把 location 的请求复制一份发到另一个地址，响应直接丢弃。用于拿线上流量验证服务的新版本：镜像目标返回什么、花多长时间、甚至在不在线，对客户端都没有影响，客户端的请求照常发往上游。

[`traffic_splitting`](traffic_splitting.md) 是把请求分给两个上游，`mirror` 是两边都发。

- **步骤：** `request`（默认）或 `proxy_upstream`
- **注册名：** `mirror`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `mirror`。 |
| `target` | string | — | **必填。** 副本发往哪里：`http://10.0.0.2:8080`，或者带一段加在请求路径前面的路径，如 `https://shadow.internal/v2`。不能带查询串。 |
| `percentage` | int | `100` | 复制的请求比例，`0` 到 `100`。 |
| `methods` | string[] | `["GET", "HEAD"]` | 复制哪些方法的请求。 |
| `max_body_size` | size | `0` | 复制的请求体大小上限，如 `"64kb"`。`0` 表示带请求体的请求不镜像。 |
| `timeout` | duration | `5s` | 一个副本最多花多长时间，包括读取响应。 |
| `max_inflight` | int | `100` | 同时在途的副本数量上限。超出上限的副本不发送。 |
| `host` | string | — | 副本的 `Host`。不设置时用请求自己的。 |
| `compare` | bool | `false` | 镜像对副本返回的状态码和上游对请求返回的不一致时，记一条警告日志。见[对比响应](#对比响应)。 |
| `step` | string | `request` | `request`，或者 `proxy_upstream`（只复制即将发往上游的请求）。 |

## 示例

```toml
# API 的所有读请求同时发给新版本
[plugins.shadow]
category = "mirror"
target = "http://10.0.0.2:8080"

# 同上，并且记下新版本返回不一致的请求
[plugins.shadowCompared]
category = "mirror"
target = "http://10.0.0.2:8080"
compare = true

# 再加上十分之一的写请求，请求体不超过 64 kB
[plugins.shadowWrites]
category = "mirror"
target = "http://10.0.0.2:8080"
methods = ["GET", "HEAD", "POST", "PUT"]
max_body_size = "64kb"
percentage = 10

[locations.api]
upstream = "api"
path = "/api"
plugins = ["shadow"]
```

## 行为

- **副本**的方法、路径和查询串与上游收到的一致（即 location 的 `rewrite` 之后），请求头照搬，去掉属于客户端连接的那些（`Connection`、`Transfer-Encoding` 等）。`X-Forwarded-For`、`X-Real-IP`、`X-Forwarded-Proto` 按代理看到的客户端设置。响应边读边丢弃，不在内存里保留，不跟随重定向。
- 副本的地址是按 URL 拼出来的，会被规范化：`..` 路径段会被解析掉（写成 `%2e%2e` 也一样），个别字符会被百分号编码。上游收到的是客户端发来的原始路径；对这类路径，两边可能不一样。
- **在独立的任务里发送。** 请求不等它；目标慢、拒绝连接或者返回 `500`，对客户端都没有影响。
- **`X-Pingap-Mirror: 1`** 标记一个副本。带着这个头进来的请求不会再被镜像：否则两个互相镜像的代理会把一个请求无限传下去。镜像目标也可以据此知道这是一个副本。
- **请求体。** 没有请求体的请求在插件执行时立即复制。带请求体的在请求体传完之后复制，用的是它在发往上游的过程中留下的那一份：每个正在上传的请求最多 `max_body_size`，放在内存里；在途副本已经达到 `max_inflight` 时不再保留请求体。请求体更大的（按 `Content-Length` 判断，或者实际传下来才发现）完全不镜像；请求体没传完就失败的请求也不镜像。
- **`max_inflight`** 限制了一个不应答的目标能占住多少资源：它的每个副本都要等到 `timeout`，同时最多等这么多个。副本从发出的那一刻起才计入在途数量——带请求体的请求是在请求体传完之后。超出的请求照常服务，只是不镜像。
- 失败的副本会计数，并在第 1、2、4、8……次失败时写一行日志，这样目标挂掉时不会每个请求都写一行。

## 对比响应

`compare = true` 时，镜像响应的状态码会和上游的对比，不一致的记一条日志：

```
WARN pingap_plugin::mirror: the mirror answered with another status category="mirror" method=GET path="/api/items" status=200 mirror_status=500 request_id="" skipped=0
```

`status` 是上游的，`mirror_status` 是镜像的；`path` 是请求的路径，不含查询串（副本的路径前面还加了 `target` 的路径）。两边都有结果时才对比，哪边后到就在哪边到时对比：慢的镜像最多等到 `timeout`，客户端从来不用等。

- 只对比状态码，不对比响应头和响应体。
- 上游没有响应的请求——被插件直接响应、来自缓存、连不上上游——没有可对比的；没有得到响应的副本也没有：发送失败或超时（按上文记录），或者根本没发。
- 客户端请求本身不是条件请求时，上游返回的 `304` 是它对缓存重新验证的回答，不参与对比：副本并没有发出这样的请求。缓存在后台刷新过期内容的请求（`stale-while-revalidate`）不会被镜像。
- 和[只记录不拦截](limit.md#只记录不拦截)一样，每个插件每个时钟秒最多记 10 行：其余计数，下一行的 `skipped` 是没有记录的次数。

## 使用说明

- 默认只复制不会在目标上改动数据的方法。被镜像的 `POST` 会执行两次：上游一次，镜像目标一次。请把镜像指向可以这样做的地方——有自己的数据库，或者运行在演练模式的服务。
- 凭据会和其他请求头一起复制：`Authorization`、cookie。镜像目标需要和上游一样可信。
- 客户端自己带上 `X-Pingap-Mirror` 就可以让请求不被镜像。这是防回环的代价，不要假定镜像目标能看到每一个请求。
- 在插件执行之前就被应答的请求（被排在它前面的插件应答）不会镜像。`step = "proxy_upstream"` 时，由缓存应答的请求也不会镜像。
- 请求体是在请求发往上游时复制的。被后面的插件直接应答的请求不会发往上游，如果它带请求体，就不会被镜像。
- 把它排在决定“谁可以访问”的插件（`key_auth`、`jwt`）后面：被它们拒绝的请求就到不了镜像目标。
