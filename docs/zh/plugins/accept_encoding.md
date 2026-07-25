# accept_encoding

在请求路由前将客户端 `Accept-Encoding` 改写为规范形式，使上游与缓存看到小而可预测的值集合，而不是浏览器随手发来的内容。

解决的两类问题：

- **缓存碎片化。** 对源站而言 `gzip, deflate, br` 与 `br, gzip` 相同，却是不同缓存变体。两者都改写为 `br` 可合并。
- **不需要的编码。** 支持 zstd 的上游可能产生希望由 Pingap 自行压缩、或中间件无法处理的响应。

- **步骤：** `early_request`（固定——必须在路由与缓存之前）
- **注册名：** `accept_encoding`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `accept_encoding`。 |
| `encodings` | string | `""` | 要保留的编码，逗号分隔，**按优先级排序**。 |
| `only_one_encoding` | bool | `false` | 仅保留客户端实际接受的第一个编码。 |

输出头按 `encodings` 顺序遍历并保留客户端列出的项，因此结果顺序是你的，不是客户端的。匹配在逗号/`;` 词边界上进行，并尊重 `q=0`，故 `x-gzip` 不匹配 `gzip`，`gzip;q=0` 视为“不可接受”。

客户端完全未发 `Accept-Encoding` 时插件不做任何事。若配置的编码无一可接受，则整头移除。

## 示例

优先 zstd，其次 brotli，再 gzip，且只转发最优一个：

```toml
[plugins.acceptEncoding]
category = "accept_encoding"
encodings = "zstd, br, gzip"
only_one_encoding = true
```

| Client sends | Forwarded |
| --- | --- |
| `gzip, deflate, br` | `br` |
| `zstd, gzip` | `zstd` |
| `deflate` | *(header removed)* |
| `br;q=0, gzip` | `gzip` |

保留完整有序列表（上游自行选择时有用）：

```toml
[plugins.acceptEncoding]
category = "accept_encoding"
encodings = "br, gzip"
```

客户端的 `gzip, br` 会变成 `br, gzip`。

## 使用说明

- 与 [`cache`](cache.md) 搭配，并把 `Accept-Encoding` 加入缓存键头；规范化值可限制变体数量。
- 由 [`compression`](compression.md) 负责压缩时，只列出 Pingap 配置会产出的编码。
