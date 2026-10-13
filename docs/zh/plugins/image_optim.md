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
| `png_quality` | int | `90` | 1–100：png 的调色板要与原图接近到什么程度，见 [PNG](#png)。不设置或 `0` 表示默认值；其他越界的值是配置错误，下面三项同样如此。（以前会先被截成一个字节，`300` 会被当成 `44`。） |
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

在 `upstream_response` 阶段，当 content type 为 `image/png` 或 `image/jpeg` 且请求带有 `Accept` 头时进行转换。目标格式是 `output_types` 中客户端接受的第一个；一个都不接受时保持图片原有的格式，按配置的质量重新编码；按原格式重新编码之后没有变小的图片原样发出——图标、已经带调色板的 png、质量比配置值更低的 jpeg 都属于这种情况。`Content-Type` 设置为目标格式，例如 `image/avif`。

正文收齐之后转换一次。发出去的始终是一张图片：

- 无法转换时原样发送原图：图片解码失败，或者单边超过 16384 像素、总像素超过 4000 万。尺寸在解码之前从图片头里读取，所以描述超大图片的小文件不会带来开销。
- 上游没有给出 `Content-Length` 时，最多收集 20 MB，超过之后正文按到达的顺序直接转发。

这两种情况下 `Content-Type` 已经发出并且写的是目标格式，而正文是原图。浏览器按图片内容识别并正常显示；如果有更严格的程序读取这些图片，请把原图控制在上述限制之内。

### PNG

png 的颜色会被缩减成一个调色板：最多 256 种，每种颜色带自己的 alpha。`png_quality` 决定这个调色板要与原图接近到什么程度。

- 颜色不超过 256 种的图片，颜色逐像素原样保留，与取值无关。
- 颜色更多的图片，调色板由 [NeuQuant](https://github.com/image-rs/color_quant) 生成（用图片的颜色训练一个神经网络），并做抖动：每个像素的误差有四分之三传给相邻像素，这样渐变不会断成色带。
- `100` 时调色板取能取到的最大值。低于 `100` 时，只要误差还在这个值允许的范围内，调色板就减半——128、64、32 种颜色。允许的误差以峰值信噪比计：默认值 `90` 对应 44 dB，随取值均匀下降，最低时为 30 dB。这里比较的是调色板和原图，每个像素取离它最近的调色板颜色；抖动在这之后进行，大约要损失 1 到 2 dB。插画、带渐变的截图这类图片，取值越低文件越小。
- 只要图片里有一种颜色到它所用调色板颜色的距离超过整张图片允许误差的二十倍，调色板同样不再减半。
- 离所有调色板颜色都这么远的颜色——图表上的标记、地图上的图钉这类只有少数像素才有、周围又没有相近颜色的——会得到单独的一项调色板颜色，前提是能找到一项让图片其余部分损失更小的来让出，并且最多占调色板的十六分之一。这是尽力而为，不是保证：这样的颜色再多，剩下的仍然会变成最接近的现有颜色。
- 256 种颜色也达不到要求的图片，不管取值多少都用 256 种。对大多数照片来说，调低这个值不会有变化；照片应该输出为 `webp` 或 `avif`，或者保持 `jpeg`。

颜色按实际看到的样子比较，即先乘以 alpha。完全透明的像素保持完全透明，在输出里不带颜色；半透明的像素其颜色保留到它的 alpha 所能分辨的精度。带透明像素的图片，调色板里有一项留给它们。

同一个构建每次转换同一张图片，得到的字节都相同。

0.16 及之前调色板由 `imagequant` 生成，它的许可证是 GPL-3.0-or-later。`color_quant` 是 MIT：现在 `full` 构建不再包含 copyleft 许可证的代码，同一张图片输出的 png 也不再是原来的字节。

## 使用说明

- **务必与 [`cache`](cache.md) 搭配。** 重编码 AVIF 很贵（`avif_speed` 在质量与 CPU 间权衡）；按请求做会主导 CPU 画像。
- 顺序重要：把缓存插件列在本插件之前，命中时可无需重编码。
- 转换在处理该请求的工作线程上执行。`basic.work_stealing` 开启（默认）时，这个线程上的其他连接在此期间转交给别的线程；关闭时它们需要等待。
- `avif_speed` 是主要旋钮。`1`–`2` 文件最小，仅在缓存后合理；`4`–`6` 是较稳妥的在线默认。
- `Accept` 检查是对 `image/<type>` 的子串测试，因此 `output_types = "webp"` 匹配含 `image/webp` 的 `Accept`。
