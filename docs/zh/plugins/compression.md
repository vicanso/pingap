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
| `mode` | string | *(下游)* | 设为 `upstream` 使用流式压缩器。 |
| `min_length` | int | `0` | 仅上游模式：`Content-Length` 低于此值则跳过。 |
| `decompression` | bool | 缺席 | 键存在则切换对压缩上游响应的解压。 |

算法优先级固定：**zstd > brotli > gzip**。客户端接受的第一个已启用算法胜出。

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

## 上游模式细节

仅当**全部**满足时压缩：

1. 尚无 `Content-Encoding`。
2. `Content-Type` 可压缩：`application/json`、`application/xml`、`text/html`，或任意 `text/*`。
3. 客户端接受已启用算法之一。
4. `min_length` 为 `0`，或存在 `Content-Length` 且至少为 `min_length`。无 `Content-Length` 的响应总会被压缩。

压缩时移除 `Content-Length`，设置 `Transfer-Encoding: chunked` 与 `Content-Encoding`，并增量编码正文。

上游模式还会把所选编码追加到缓存键，使缓存条目按编码区分。

## 使用说明

- 下游模式不看 `Content-Type`；pingora 模块有自己的规则。需要显式控制时用上游模式。
- 本插件对 `Accept-Encoding` 做子串检测，因此 `x-gzip` 可能启用 gzip，且不处理 `q=0`。若对客户端重要，请在前面放 [`accept_encoding`](accept_encoding.md) 规范化请求头。
- 压缩已压缩格式（JPEG、PNG、MP4、`.gz`）浪费 CPU。上游模式的 content-type 列表会处理；下游模式依赖上游 `Content-Type` 正确。
- Brotli 超过 level 9、zstd 超过 level 12 对动态响应收益很小但很吃 CPU。两者用 4–6 是合理默认。
