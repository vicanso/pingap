# compression

使用 gzip、brotli 与 zstd 的响应压缩。两种模式：

- **下游模式**（默认）— 配置 pingora 内置压缩模块，在发往客户端时压缩。
- **上游模式**（`mode = "upstream"`）— Pingap 在上游响应体流经时自行压缩，发生在响应到达 [`cache`](cache.md) 插件之前，所以缓存里存的是压缩后的内容。

`types`、`min_length`、`skip` 决定哪些响应会被压缩，两种模式都适用。

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
| `types` | string[] | 随模式 | 要压缩的内容类型，每项是一个前缀（`text/`、`application/json`）；`*` 表示任意类型。见[哪些响应会被压缩](#哪些响应会被压缩)。 |
| `min_length` | int | `0` | `Content-Length` 低于此值的响应不压缩。没有 `Content-Length` 的响应会压缩。 |
| `skip` | string | — | 正则表达式；路径和查询串匹配的请求不压缩。 |
| `decompression` | bool | 缺席 | 键存在则切换对压缩上游响应的解压。 |

超出范围的级别会被截断到范围内（负数按 `0`）。

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

静态站点：压缩文本，不压缩字体和文档（`font/woff2`、`application/pdf`），`/download/` 下的内容也不压缩：

```toml
[plugins.compression]
category = "compression"
gzip_level = 6
br_level = 6
types = [
  "text/",
  "application/json",
  "application/javascript",
  "application/xml",
  "image/svg+xml",
]
min_length = 256
skip = "^/download/"
```

## 哪些响应会被压缩

- **`types`**——每项是内容类型的开头，比较时不区分大小写，也不看参数（`; charset=utf-8`）：`text/` 包含所有 `text/*`，`application/json` 包含它本身以及其他以它开头的类型（`application/json-seq`）。`*` 表示任意类型。没有 `Content-Type` 的响应始终不压缩。不配置时两种模式各用各的规则：

  | 模式 | 不配置 `types` | 配置 `types` |
  | --- | --- | --- |
  | 下游 | pingora 的规则：`text/*`、`application/*`、`font/*`、`image/svg+xml`、图标类型和 `binary/octet-stream`，类型里带 `zip` 的除外 | 列出的类型里 pingora 的规则也接受的那些 |
  | 上游 | `application/json`、`application/xml`、`text/html`、所有 `text/*` | 列出的类型，仅此而已 |

  空列表是配置错误，而不是“什么都不压缩”。
- **`min_length`**——`Content-Length` 表明长度不足的响应原样转发。没有 `Content-Length`（分块传输）的响应会压缩：做决定时还不知道它有多长。下游模式下 pingora 自己还有一个 20 字节的下限。
- **`skip`**——正则表达式，匹配的对象是请求的路径和查询串（`/download/a.html?raw=1`），取客户端发来的原样：location 的 `rewrite` 不影响它看到的内容。匹配的请求按“客户端不接受任何编码”处理。

下游模式的列表只能收窄 pingora 的规则：把 `image/png` 写进去并不会让 pingora 压缩它。它的用处在于那条规则里范围很宽的 `application/*` 和 `font/*`：其中有本来就压缩过的格式（`font/woff2`、`application/pdf`、预压缩的 `application/wasm`），也有不值得花 CPU 的内容（`application/octet-stream` 的下载）。

下游模式下，`types` 和 `min_length` 对其他插件直接返回的响应同样生效，主要是 [`directory`](directory.md) 的文件：pingora 对它们和其他响应一样压缩，除非用列表限定。

此前 `min_length` 只在上游模式下读取。默认模式的配置里如果已经带了这个键，从这个版本起会生效。

## 不会被压缩的响应

两种模式下，以下两类响应都按上游发来的样子原样转发：

- `Content-Type: text/event-stream`。压缩器只在缓冲区写满或响应体结束时才输出，事件流里的事件每条只有几个字节、随产生随发送，压缩后会在流关闭时一起到达客户端。
- 带 `Cache-Control: no-transform` 的响应，它禁止改变内容编码（RFC 9111 5.2.2.6）。在下游模式下这也包括 `decompression`：上游已压缩的响应原样转发，不解压。上游用其他格式做流式输出（按行分隔的 JSON、分块的 AI 补全）时，可以加上这个头，让分块在开启了压缩的 location 上照常流出。

## 上游模式细节

仅当**全部**满足时压缩：

1. 有响应体：HEAD 应答、`1xx`、`204` 与 `304` 不处理，否则即便什么都不编码也会输出格式的头尾。
2. 尚无 `Content-Encoding`，且不属于上面两类响应。也不是响应体的一部分：`206` 或带 `Content-Range` 的响应原样透传。以前范围请求要的 100 个字节会被压缩后返回，而 `Content-Range` 仍按原始字节计数。
3. `Content-Type` 可压缩：配置了 `types` 时是其中之一，否则是 `application/json`、`application/xml`、`text/html`，或任意 `text/*`。
4. 客户端接受已启用算法之一，且请求没有被 `skip` 排除。
5. `min_length` 为 `0`，或存在 `Content-Length` 且至少为 `min_length`。无 `Content-Length` 的响应总会被压缩。

压缩时移除 `Content-Length`，设置 `Transfer-Encoding: chunked` 与 `Content-Encoding`，并增量编码正文。同时移除 `Accept-Ranges`，把强 `ETag` 改成弱校验（`"v1"` 变为 `W/"v1"`），和 nginx 以及 pingora 自带的压缩做法一致：这两个头描述的是上游发出的字节，而现在的响应体已经不是那些字节。`ETag` 是在发往客户端时弱化的，缓存命中的响应同样处理；缓存里存的仍是上游给出的原始校验值，重新验证时用的是上游认识的值。

客户端接受某个已启用的编码时，发往上游的请求只要求这一种编码：`Accept-Encoding` 被改写为该编码（访问日志里看到的也是改写后的值）。如果原样转发客户端的头，自己会压缩的上游会按它喜欢的编码应答（客户端同时接受 `br` 和 `gzip` 时返回 `br`），配了 `cache` 插件时这份响应会存进这里选定的编码对应的键，再返回给只接受那一种编码的客户端。客户端不接受任何已启用的编码时，这个头原样转发；上游此时如果自己压缩了又没有声明，插件会给响应补上 `Vary: Accept-Encoding`，让缓存把不同请求头得到的响应分开。一个压缩级别都没开时，插件不改请求，也不动缓存键。

发往客户端时，任何带 `Content-Encoding` 的响应都会加上 `Vary: Accept-Encoding`（除非 `Vary` 已包含它或 `*`），让 Pingap 前面的缓存区分不同编码。它在 `response` 步骤而非上游响应上添加，因此 Pingap 自身的缓存（已按所选编码作为键）不会被请求头的各种写法进一步拆分；缓存命中的压缩响应每次也会同样加上。

响应用哪种编码（包括 `skip` 的结果）在请求进来时一次定下，写进缓存键的就是这个结果；压缩响应时按它来，而不是按后续步骤处理过的请求重新判断（location 的 rewrite、`key_auth` 从查询串里去掉的参数、其他插件改写的 `Accept-Encoding`）。

上游模式还会把所选编码追加到缓存键，使缓存条目按编码区分。[`cache`](cache.md) 插件的 `PURGE` 会把每种编码的条目都清掉。

## 使用说明

- 不配置 `types` 时，下游模式把内容类型交给 pingora 的模块判断，除了文本，所有 `application/*` 和 `font/*` 它都会压缩。用 `types` 指定要压缩的类型。
- `Accept-Encoding` 按 token 边界匹配并遵守 `q=0`，用的是和 [`accept_encoding`](accept_encoding.md) 相同的判断，所以 `x-gzip` 不会启用 gzip，`gzip;q=0` 视为不接受。
- 压缩已压缩格式（WOFF2、PDF、`.gz`）浪费 CPU。上游模式的 content-type 列表会处理；下游模式下 pingora 不压缩图片、视频和类型里带 `zip` 的内容，其余的靠 `types` 排除。
- `Accept-Encoding: *` 不会被当作接受已启用的编码，和 nginx 一样：必须写出编码的名字。
- Brotli 超过 level 9、zstd 超过 level 12 对动态响应收益很小但很吃 CPU。两者用 4–6 是合理默认。
