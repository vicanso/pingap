# image_optim

当客户端声明支持时，将 PNG/JPEG 响应重编码为现代格式（WebP 或 AVIF），否则就地重编码。实现位于 [`pingap-imageoptim`](../crates/imageoptim.md) crate。

- **步骤：** `request`（贡献缓存键）、`upstream_response` 与 `upstream_response_body`（实际转换）
- **注册名：** `image_optim`
- **需要 cargo feature `imageoptim`**（包含在 `full` 中）

```bash
cargo build --features=imageoptim
```

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `image_optim`。 |
| `output_types` | string | `""` | 逗号分隔的目标格式，如 `avif,webp`。 |
| `png_quality` | int | `90` | 1–100。越界重置为默认。 |
| `jpeg_quality` | int | `80` | 1–100。 |
| `avif_quality` | int | `75` | 1–100。 |
| `avif_speed` | int | `3` | 1–10。越高越快、文件越大。 |

仅 `image/png` 与 `image/jpeg` 上游响应是候选。其余原样透传。

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

在 `request` 阶段查看客户端 `Accept`，收集客户端接受的已配置输出 MIME 类型，排序后追加到缓存键——因此支持 AVIF 的浏览器与旧浏览器得到不同缓存条目，而不会互相污染。

在 `upstream_response` 阶段，当 content type 为 `image/png` 或 `image/jpeg` 且客户端接受 `output_types` 之一时进行转换，正文在流式过程中重编码。

## 使用说明

- **务必与 [`cache`](cache.md) 搭配。** 重编码 AVIF 很贵（`avif_speed` 在质量与 CPU 间权衡）；按请求做会主导 CPU 画像。
- 顺序重要：把缓存插件列在本插件之前，命中时可无需重编码。
- `avif_speed` 是主要旋钮。`1`–`2` 文件最小，仅在缓存后合理；`4`–`6` 是较稳妥的在线默认。
- `Accept` 检查是对 `image/<type>` 的子串测试，因此 `output_types = "webp"` 匹配含 `image/webp` 的 `Accept`。
