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
| `headers` | string[] | — | 追加到缓存键的请求头（变体缓存）。 |
| `max_ttl` | duration | — | 条目寿命上限，封顶上游 `Cache-Control`。 |
| `max_file_size` | bytesize | `1mb` | 大于此尺寸的响应不缓存。 |
| `lock` | duration | `1s` | 防惊群的缓存锁窗口。**仅支持 `1s`、`2s`、`3s`**；其他值静默关闭锁定。 |
| `eviction` | bool | 缺席 | 键存在即启用 LRU 淘汰。 |
| `predictor` | bool | 缺席 | 键存在即启用可缓存性预测。 |
| `check_cache_control` | bool | `false` | 要求响应带 `Cache-Control`，否则不存储。 |
| `purge_ip_list` | string[] | `[]` | 允许发起 `PURGE` 的 IP / CIDR。 |
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
curl -X PURGE http://127.0.0.1:6188/assets/app.js
# 204 No Content       -> removed
# 403 Forbidden        -> your IP is not in purge_ip_list
```

## 行为

- 仅处理 `GET`、`HEAD` 与 `PURGE`；其他方法跳过插件。
- 缓存键由请求 URI、`namespace` 与所列 `headers` 的值推导。`PURGE` 按 `GET` 方式构建键，因此清理 `/x` 会移除 `GET /x` 创建的条目。
- `lock` 使同一键上的并发未命中等待第一个，而不是全部打到源站。
- 缓存读/写计数写入请求上下文，访问日志中可用 `{:cache_lookup_time}` / `{:cache_lock_time}`。

## 使用说明

- **`eviction` 需要有界后端。** 仅在后端报告非零 `max_size` 时接线，文件后端没有——因此 `eviction` 实际仅对内存有效。文件缓存条目由 inactive 扫描回收（`?inactive=…`）。
- **每个进程只有一个内存后端。** 第一个请求内存缓存的 `cache` 插件创建进程级单例；第二个声明不同 `max_size` 或 `mode` 时会静默复用第一个。用 `namespace` 分隔内容，不要再声明第二个 `directory`。
- 非 1/2/3 秒的 `lock` 会关闭锁定而非报错。请优先 `"1s"`、`"2s"` 或 `"3s"`。
- 按 `Accept-Encoding` 缓存时请搭配 [`accept_encoding`](accept_encoding.md)，否则变体数量会爆炸。
