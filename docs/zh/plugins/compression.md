# compression

使用 gzip、brotli 与 zstd 的响应压缩。两种模式：

- **下游模式**（默认）— 配置 pingora 内置压缩模块，在发往客户端时压缩。
- **上游模式**（`mode = "upstream"`）— Pingap 在上游响应体流经时自行压缩，从而可应用 content-type 与最小长度规则。

- **步骤：** `early_request`（固定）；上游模式还会钩住 `upstream_response` 与 `upstream_response_body`
- **注册名：** `compression`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `compression`。 |
| `gzip_level` | int | `0` | 0–9。`0` 禁用 gzip。 |
| `br_level` | int | `0` | 0–11。`0` 禁用 brotli。 |
| `zstd_level` | int | `0` | 0–22。`0` 禁用 zstd。 |
| `mode` | string | `response` | `response`（下游模式）或 `upstream`（流式压缩器）。其他值是配置错误。 |

超出范围的级别会被截断到范围内（负数按 `0`）。
| `min_length` | int | `0` | 仅上游模式：`Content-Length` 低于此值则跳过。 |
| `decompression` | bool | 缺席 | 键存在则切换对压缩上游响应的解压。 |

算法优先级固定：**zstd > brotli > gzip**。客户端接受的第一个已启用算法胜出，与客户端把它写在第几位无关：浏览器发送 `gzip, deflate, br, zstd`，启用了 zstd 就用 zstd。为此，`response` 模式下插件会把选中的算法移到请求 `Accept-Encoding` 的最前面（`zstd, gzip, deflate, br`），上游收到的也是这个顺序；编码集合不变。

## 示例

标准下游压缩：

```toml
[plugins.compression]
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 3
```

上游模式并设尺寸下限，避免压缩过小的 JSON：

```toml
[plugins.compression]
category = "compression"
mode = "upstream"
gzip_level = 6
br_level = 6
min_length = 1024
```

## 不会被压缩的响应

两种模式下，以下两类响应都按上游发来的样子原样转发：

- `Content-Type: text/event-stream`。压缩器只在缓冲区写满或响应体结束时才输出，事件流里的事件每条只有几个字节、随产生随发送，压缩后会在流关闭时一起到达客户端。
- 带 `Cache-Control: no-transform` 的响应，它禁止改变内容编码（RFC 9111 5.2.2.6）。在下游模式下这也包括 `decompression`：上游已压缩的响应原样转发，不解压。上游用其他格式做流式输出（按行分隔的 JSON、分块的 AI 补全）时，可以加上这个头，让分块在开启了压缩的 location 上照常流出。

## 上游模式细节

仅当**全部**满足时压缩：

1. 有响应体：HEAD 应答、`1xx`、`204` 与 `304` 不处理，否则即便什么都不编码也会输出格式的头尾。
2. 尚无 `Content-Encoding`，且不属于上面两类响应。也不是响应体的一部分：`206` 或带 `Content-Range` 的响应原样透传。以前范围请求要的 100 个字节会被压缩后返回，而 `Content-Range` 仍按原始字节计数。
3. `Content-Type` 可压缩：`application/json`、`application/xml`、`text/html`，或任意 `text/*`。
4. 客户端接受已启用算法之一。
5. `min_length` 为 `0`，或存在 `Content-Length` 且至少为 `min_length`。无 `Content-Length` 的响应总会被压缩。

压缩时移除 `Content-Length`，设置 `Transfer-Encoding: chunked` 与 `Content-Encoding`，并增量编码正文。同时移除 `Accept-Ranges`，把强 `ETag` 改成弱校验（`"v1"` 变为 `W/"v1"`），和 nginx 以及 pingora 自带的压缩做法一致：这两个头描述的是上游发出的字节，而现在的响应体已经不是那些字节。`ETag` 是在发往客户端时弱化的，缓存命中的响应同样处理；缓存里存的仍是上游给出的原始校验值，重新验证时用的是上游认识的值。

客户端接受某个已启用的编码时，发往上游的请求只要求这一种编码：`Accept-Encoding` 被改写为该编码（访问日志里看到的也是改写后的值）。如果原样转发客户端的头，自己会压缩的上游会按它喜欢的编码应答（客户端同时接受 `br` 和 `gzip` 时返回 `br`），配了 `cache` 插件时这份响应会存进这里选定的编码对应的键，再返回给只接受那一种编码的客户端。客户端不接受任何已启用的编码时，这个头原样转发；上游此时如果自己压缩了又没有声明，插件会给响应补上 `Vary: Accept-Encoding`，让缓存把不同请求头得到的响应分开。一个压缩级别都没开时，插件不改请求，也不动缓存键。

发往客户端时，任何带 `Content-Encoding` 的响应都会加上 `Vary: Accept-Encoding`（除非 `Vary` 已包含它或 `*`），让 Pingap 前面的缓存区分不同编码。它在 `response` 步骤而非上游响应上添加，因此 Pingap 自身的缓存（已按所选编码作为键）不会被请求头的各种写法进一步拆分；缓存命中的压缩响应每次也会同样加上。

上游模式还会把所选编码追加到缓存键，使缓存条目按编码区分。[`cache`](cache.md) 插件的 `PURGE` 会把每种编码的条目都清掉。

## 使用说明

- 下游模式不看 `Content-Type`；pingora 模块有自己的规则。需要显式控制时用上游模式。
- 本插件对 `Accept-Encoding` 做子串检测，因此 `x-gzip` 可能启用 gzip，且不处理 `q=0`。若对客户端重要，请在前面放 [`accept_encoding`](accept_encoding.md) 规范化请求头。
- 压缩已压缩格式（JPEG、PNG、MP4、`.gz`）浪费 CPU。上游模式的 content-type 列表会处理；下游模式依赖上游 `Content-Type` 正确。
- Brotli 超过 level 9、zstd 超过 level 12 对动态响应收益很小但很吃 CPU。两者用 4–6 是合理默认。
