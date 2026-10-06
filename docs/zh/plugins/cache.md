# cache

HTTP 响应缓存，后端可为内存 [TinyUFO](https://github.com/cloudflare/pingora/tree/main/tinyufo) 或文件存储，支持缓存键控制、惊群防护与 IP 限制的 `PURGE` 方法。

- **步骤：** `request`（固定）
- **注册名：** `cache`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `cache`。 |
| `directory` | string | 内存 | 空或 `memory://…` 选内存后端；其他值作为文件缓存目录。 |
| `namespace` | string | — | 隔离条目；文件后端时成为子目录。 |
| `headers` | string[] | — | 追加到缓存键的请求头（变体缓存）。每个头在键里占一个固定位置，请求没带这个头时位置也保留；值里的 `:` 写成 `%3A`，不会被当成两个位置之间的分隔。 |
| `vary_headers` | string[] | — | 源站 `Vary` 响应头的白名单：只有这些请求头可以产生缓存变体。不设则按源站列出的全部处理。 |
| `max_ttl` | duration | — | 条目寿命上限，封顶上游 `Cache-Control`。 |
| `max_file_size` | bytesize | `1mb` | 大于此尺寸的响应不缓存。 |
| `lock` | duration | `1s` | 防惊群的缓存锁窗口。任意非零时长都有效；`0s` 关闭锁定。 |
| `lock_retries` | int | `2` | 等锁的请求在放弃、自行回源之前重新查询缓存的次数。 |
| `eviction` | bool | `false` | `true` 启用 LRU 淘汰。仅内存后端有效。 |
| `predictor` | bool | `false` | `true` 启用可缓存性预测。 |
| `check_cache_control` | bool | `false` | 要求响应带 `Cache-Control`，否则不存储。 |
| `purge_ip_list` | string[] | `[]` | 允许发起 `PURGE` 的 IP / CIDR。既不是 IP 也不是 CIDR 的条目会在配置校验时报错。校验的是哪个地址见[谁可以清理](#谁可以清理)。 |
| `skip` | string | — | 路径+查询串的正则；匹配的请求完全绕过缓存。 |

### 后端选择

```toml
directory = ""                                   # memory, default size
directory = "memory://pingap?max_size=100mb"     # memory, explicit size
directory = "/opt/pingap/cache"                  # file cache
directory = "/opt/pingap/cache?inactive=1h&reading_max=1000"
```

后端查询参数全集见 [pingap-cache](../crates/cache.md)。

## 示例

```toml
[plugins.httpCache]
category = "cache"
directory = "/opt/pingap/cache"
namespace = "web"
headers = ["Accept-Encoding"]
max_ttl = "1h"
max_file_size = "10mb"
lock = "2s"
eviction = true
predictor = true
purge_ip_list = ["127.0.0.1", "10.0.0.0/8"]
skip = "^/api/"

[locations.web]
upstream = "web"
path = "/"
plugins = ["httpCache"]
```

清理：

```bash
# 单个 URL（同时移除 GET 与 HEAD 两个变体）
curl -X PURGE http://127.0.0.1:6188/assets/app.js
# 204 No Content       -> 已移除（幂等：无缓存时同样返回 204）
# 403 Forbidden        -> IP 不在 purge_ip_list 中

# 整个 namespace（仅文件后端且配置了 namespace）
curl -X PURGE http://127.0.0.1:6188/*
# 200 "purged: 12, fail: 0"
# 501 Not Implemented  -> 未配置 namespace，或内存缓存后端
```

`PURGE /*` 清空该插件缓存的全部内容：namespace 在文件后端以目录形式存在，是精确 URL 之外唯一无需索引即可清除的粒度（存储文件名是完整键的哈希，URL 前缀在磁盘上没有对应结构）。清除会连同内存热层一起清空，而且是整个热层（热层无法按 namespace 查找）：只在内存里的条目也会被清掉，其他 namespace 的条目之后从磁盘重新读入。清除只作用于本机——多实例部署需要对每个节点分别发起。

## 谁可以清理

请求的地址在 `purge_ip_list` 里时才允许 `PURGE`；列表为空时任何人都不能清理。这个地址取哪一个，取决于 `basic.trusted_proxies`：

- **已配置：** 取客户端 IP，按 [`ip_restriction`](ip_restriction.md#客户端-ip-解析) 里说明的规则经可信代理解析。
- **未配置：** 取连接本身的对端地址，不看 `X-Forwarded-For` 和 `X-Real-IP`。没有可信代理时这两个头只是请求自己的说法：允许 `127.0.0.1` 的列表，会放行任何带 `X-Forwarded-For: 127.0.0.1` 的请求。

因此，经过负载均衡或 CDN 发送的 `PURGE`，需要把该代理写进 `trusted_proxies`。否则校验的是代理自己的地址。

## 行为

- 仅处理 `GET`、`HEAD` 与 `PURGE`；其他方法跳过插件。
- 存什么、存多久，取决于源站的 `Cache-Control`：
  - 带 `no-store`、`no-cache` 或 `private` 的响应不存储，有效期为零的响应也不存储。
  - 有效期优先取源站的 `s-maxage`，没有时取 `max-age`，并受 `max_ttl` 限制。
  - 没有给出有效期的响应保留一秒，前提是其状态码属于 HTTP 定义的“可启发式缓存”的一类：200、203、204、206、300、301、308、404、405、410、414、501。其他状态码（如 5xx 或 302）只有在源站给出有效期时才存储。`check_cache_control` 更严格：没有 `Cache-Control` 头的响应一律不存储。
- 属于某一个客户端的响应不会被存储：
  - 带 `Set-Cookie` 头的响应：否则所有从缓存取到它的客户端都会收到同一个 cookie。确实要缓存这类响应时，用 `upstream` 模式的 [`response_headers`](response_headers.md) 插件在存储前去掉这个头。
  - 请求带 `Authorization` 头时的响应，除非源站用 `public`、`s-maxage` 或 `must-revalidate` 标明可以共享。开启了 `hide_credentials` 的 [`basic_auth`](basic_auth.md) 插件会在这项检查之前移除该请求头，因此它保护的站点照常缓存。
- 缓存键由 `namespace`、所列 `headers` 的值、请求方法、域名、路径和查询串组成。域名取小写且不含端口，协议不在键里，所以 `http://Example.com:8080/x` 与 `https://example.com/x` 是同一个条目，HTTP/1.1 与 HTTP/2 一致；`other.com/x` 则是另一个条目。
- `PURGE` 会同时按 `GET` 与 `HEAD` 构建键，因此清理 `/x` 会移除两种方法创建的条目。它清理的是请求所发往的域名：在插件可达的任意监听上发送，并带上要清理的站点的 `Host`。若配置了 `headers`，`PURGE` 请求也要带上相同的头——它们是键的一部分。
- 会遵循源站的 `Vary` 响应头：它列出的请求头的每种取值组合在同一个键下存为独立变体，`Vary: *` 则视为不可缓存。`vary_headers` 限制哪些头可以这样做，因为 `Vary: Cookie` 或 `Vary: User-Agent` 意味着每个客户端一个变体。`PURGE` 只清主槽位，其后的变体变得不可达，由淘汰或 inactive 扫描回收。
- `lock` 使同一键上的并发未命中等待第一个，而不是全部打到源站。
- 遵循源站的 `Cache-Control: stale-while-revalidate=<seconds>`；未包含该 directive 的条目不会在重新验证时返回过期内容。新鲜期过后，在该时间窗内 pingap 立即返回旧内容，并由持有锁的一个请求在后台向源站刷新；超出时间窗则等待或执行普通重新验证。SWR 需要非零 `lock`，`lock = "0s"` 会禁用它。`max_ttl` 只限制新鲜期，不限制 SWR 时间窗。后台重新验证会走完整请求管线，产生访问日志、更新指标，并再次执行 request 步骤插件。
- 缓存读/写计数写入请求上下文，访问日志中可用 `{:cache_lookup_time}` / `{:cache_lock_time}`。

## 使用说明

- **没有配置 `basic.trusted_proxies` 时，`PURGE` 不再采用 `X-Forwarded-For`。** 到 0.15.0 为止，任何来源的这个头都会被采用。经过未列入可信代理的代理发送的清理请求，升级后会返回 `403`；把该代理加入列表即可，见[谁可以清理](#谁可以清理)。
- **从 0.15.0 及更早版本升级后缓存会清空。** 到该版本为止，只有 HTTP/2 请求的键包含域名，HTTP/1.1 下同一个 `cache` 插件后面的两个站点共用条目。这些版本写入的条目在现在的键下找不到：升级后缓存从空开始，文件缓存里的旧条目留在磁盘上，由 inactive 扫描清除。
- **`eviction` 与 `predictor` 按取值生效。** 以前只要键存在就开启，所以 `eviction = false`（admin 表单选“否”时保存的值）反而会开启。如果配置里靠写 `false` 来表示开启，需要改成 `true`。
- **只带了部分 `headers` 的请求会换一个缓存键。** `headers = ["X-A", "X-B"]` 时，以前各个值直接拼接、不保留位置，只带 `X-A: 1` 的请求和只带 `X-B: 1` 的请求共用一个条目。现在每个头占一个位置。所列的头全带或全不带的请求，键不变；只带了其中一部分的请求以前写入的条目不会再被命中，等过期后回收。头的值里含有 `:` 或 `%`（例如 `Origin`）的条目同理：这两个字符现在在键里会被转义。
- **`example.com.` 与 `example.com` 分开缓存。** 域名末尾写出根标签时，路由按不带点的域名处理，但转发给上游的 `Host` 保持原样，所以它的响应用单独的键保存。
- **`eviction` 需要有界后端。** 仅在后端报告非零 `max_size` 时接线，文件后端没有——因此 `eviction` 实际仅对内存有效。文件缓存条目由 inactive 扫描回收（`?inactive=…`）。
- **每个进程只有一个内存后端。** 第一个请求内存缓存的 `cache` 插件创建进程级单例；第二个声明不同 `max_size` 或 `mode` 时会静默复用第一个。用 `namespace` 分隔内容，不要再声明第二个 `directory`。
- 每个不同的 `lock` 时长会在进程生命周期内分配一把共享锁，因此重要的是不同取值的数量，而不是插件实例数。
- 按 `Accept-Encoding` 缓存时请搭配 [`accept_encoding`](accept_encoding.md)，否则变体数量会爆炸。
