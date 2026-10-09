# bandwidth_limit

限制响应正文的发送速度，每秒不超过指定的字节数。用于分发大文件的站点：不限速时，一个带宽充足的客户端会在下载期间占满全部带宽。

- **步骤：** `request`（固定）
- **注册名：** `bandwidth_limit`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `bandwidth_limit`。 |
| `rate` | size | — | 每秒字节数，如 `"1mb"`、`"200kb"`。必填，大于 `0`。 |
| `after` | size | `0` | 每个响应最前面这么多字节不限速，之后的部分按 `rate` 发送。 |
| `path` | string | — | 匹配请求路径的正则。未设置表示该 location 的所有请求。 |

## 示例

```toml
# 每个下载 1 MB/s，前 1 MB 不限速
[plugins.downloads]
category = "bandwidth_limit"
rate = "1mb"
after = "1mb"

[plugins.files]
category = "directory"
path = "/var/www/downloads"

[locations.downloads]
path = "/downloads"
plugins = ["downloads", "files"]
```

```toml
# 只限制上游的视频文件
[plugins.video]
category = "bandwidth_limit"
rate = "500kb"
path = "\\.(mp4|webm)$"
```

## 行为

插件只负责说明“多快”，实际的节奏由写正文的地方来控制：

- 来自上游或缓存的响应，由代理控制，按它转发的正文计算：在改写正文的插件（`sub_filter`）之后、为客户端压缩（[`compression`](compression.md) 插件的默认模式）之前。会被压缩的文本在线路上的实际速度比 `rate` 低，低多少取决于压缩掉了多少；下载类的内容在线路上的大小和计数一致。`mode = "upstream"` 时插件先压缩，计数的是压缩后的正文；
- [`directory`](directory.md) 插件流式发送的文件，由该插件控制。`bandwidth_limit` 要排在 `directory` **前面**：直接应答的插件会结束插件列表，排在它后面的不会执行。

正文的第一片立即发出，之后每一片都要等到“此前已发送的部分”按速率用够了时间才发。响应头不会被拖住。除最后一片以外的部分用够时间，正文就发完了：300 kB 按每秒 100 kB、每片 64 KiB 发送，大约需要 2.6 秒。

速度按“已经发了多少、用了多长时间”来算，所以客户端自己读得慢的时间也算在内：读得慢的客户端不会被再限一次。没用掉的时间也不会攒下来——停了一分钟的下载，之后不会一下子补发一分钟的量。

## 使用说明

- 限制是**按响应**的，不是按客户端。开四条连接就有四倍的速度；要限制连接数请用 [`limit`](limit.md)（`type = "inflight"`）。
- 一次写出的正文不会被拖住，因为它前面没有需要等待的内容：
  - 插件一次性应答的内容：mock、错误页、`directory` 插件里不超过 `chunk_size` 的文件；
  - 被 [`sub_filter`](sub_filter.md) 改写过的响应：它要攒到完整才整块放出；
  - 代理写出正文第一部分时已经从上游读到的内容：上游比限速快时，这部分最多几百 KB。后面的内容会为它补足等待时间。

  限速面向的是下载，体积是这个量级的很多倍。`after` 是有意提供同样的效果，只是范围可以更大。
- `after` 适合同时提供页面和下载的 location：页面在限速开始之前就发完了。
- 分片就是正文到达时的分片：来自缓存的响应按 64 KiB 一片，`directory` 的文件按 `chunk_size`，来自上游的响应则是代理在等待期间读到的内容，一次最多四次 64 KiB 的读取。速率远小于分片大小时，客户端看到的是一段一段到达，而不是平滑的数据流：一片立即到达，然后停顿这一片按速率所需的时间——`rate = "1kb"` 配 64 KiB 的分片就是一分钟。读超时比这个停顿短的客户端会放弃。
- 同一个 location 上还有 [`cache`](cache.md) 时，尚未进缓存的响应是边转发边写入缓存的，速度就是第一个请求它的客户端的速率。在这次下载完成之前，对同一对象的其他请求会等它——最多等缓存插件的 `lock` 那么久——然后自己去请求上游。写入完成之后，每次命中都按各自的速率从缓存发送。
- 升级后的连接（websocket）不是正文，不受限制。
- 代理自己在后台重新获取缓存内容（`stale-while-revalidate`）也不受限制：没有人在等这些字节，客户端已经按自己的速率从缓存拿到了响应。
