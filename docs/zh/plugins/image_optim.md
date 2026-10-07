# image_optim

当客户端声明支持时，将 PNG/JPEG 响应重编码为现代格式（WebP 或 AVIF），否则就地重编码。实现位于 [`pingap-imageoptim`](../crates/imageoptim.md) crate。

- **步骤：** `early_request`（贡献缓存键）、`upstream_response` 与 `upstream_response_body`（实际转换）
- **注册名：** `image_optim`
- **需要 cargo feature `imageoptim`**（包含在 `full` 中）

```bash
cargo build --features=imageoptim
```

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `image_optim`。 |
| `output_types` | string | `""` | 逗号分隔的目标格式，按优先顺序排列，如 `avif,webp`。每一项是 `avif`、`webp`、`jpeg`、`png` 之一，其他值是配置错误。 |
| `png_quality` | int | `90` | 1–100。不设置或 `0` 表示默认值；其他越界的值是配置错误，下面三项同样如此。（以前会先被截成一个字节，`300` 会被当成 `44`。） |
| `jpeg_quality` | int | `80` | 1–100。 |
| `avif_quality` | int | `75` | 1–100。 |
| `avif_speed` | int | `3` | 1–10。越高越快、文件越大。 |

仅状态码为 `200`、类型为 `image/png` 或 `image/jpeg` 的上游响应是候选。其余原样透传，`Content-Length` 超过 20 MB 或带有 `Content-Encoding` 的图片也原样透传。

## 示例

```toml
[plugins.imageOptim]
category = "image_optim"
output_types = "avif,webp"
png_quality = 85
jpeg_quality = 80
avif_quality = 70
avif_speed = 4

[plugins.imageCache]
category = "cache"
directory = "/opt/pingap/cache"
max_file_size = "10mb"

[locations.images]
upstream = "images"
path = "/images"
plugins = ["imageCache", "imageOptim"]
```

## 行为

在 `early_request` 阶段查看客户端 `Accept`，收集客户端接受的已配置输出 MIME 类型，排序后追加到缓存键——因此支持 AVIF 的浏览器与旧浏览器得到不同缓存条目，而不会互相污染。[`cache`](cache.md) 插件的 `PURGE` 会把每一种格式组合的条目都清掉。（以前是在 `request` 阶段追加，排在前面的 `cache` 插件处理清除请求时还不知道格式是键的一部分。）

转换后的响应会去掉 `Accept-Ranges`，强 `ETag` 改成弱校验：这两个头描述的是上游发出的图片。`ETag` 是在发往客户端时弱化的，插件读写范围内的各类图片都会处理，来自缓存的也一样；缓存里保留上游原始的校验值，用于重新验证。

在 `upstream_response` 阶段，当 content type 为 `image/png` 或 `image/jpeg` 且请求带有 `Accept` 头时进行转换。目标格式是 `output_types` 中客户端接受的第一个；一个都不接受时保持图片原有的格式，按配置的质量重新编码。`Content-Type` 设置为目标格式，例如 `image/avif`。

正文收齐之后转换一次。发出去的始终是一张图片：

- 无法转换时原样发送原图：图片解码失败，或者单边超过 16384 像素、总像素超过 4000 万。尺寸在解码之前从图片头里读取，所以描述超大图片的小文件不会带来开销。
- 上游没有给出 `Content-Length` 时，最多收集 20 MB，超过之后正文按到达的顺序直接转发。

这两种情况下 `Content-Type` 已经发出并且写的是目标格式，而正文是原图。浏览器按图片内容识别并正常显示；如果有更严格的程序读取这些图片，请把原图控制在上述限制之内。

## 使用说明

- **务必与 [`cache`](cache.md) 搭配。** 重编码 AVIF 很贵（`avif_speed` 在质量与 CPU 间权衡）；按请求做会主导 CPU 画像。
- 顺序重要：把缓存插件列在本插件之前，命中时可无需重编码。
- 转换在处理该请求的工作线程上执行。`basic.work_stealing` 开启（默认）时，这个线程上的其他连接在此期间转交给别的线程；关闭时它们需要等待。
- `avif_speed` 是主要旋钮。`1`–`2` 文件最小，仅在缓存后合理；`4`–`6` 是较稳妥的在线默认。
- `Accept` 检查是对 `image/<type>` 的子串测试，因此 `output_types = "webp"` 匹配含 `image/webp` 的 `Accept`。
