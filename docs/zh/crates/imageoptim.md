# Pingap ImageOptim

为 [Pingap](https://github.com/vicanso/pingap) 提供即时图片优化。

本 crate 提供 `image_optim` 插件：拦截上游返回的 PNG 与 JPEG 响应并重编码——同一格式降质，或在客户端声明接受时转为现代格式（WebP 或 AVIF）。

目标是在不改源站的前提下获得现代格式的带宽收益：源站继续存 PNG/JPEG，Pingap 按客户端协商。

## 构建

本 crate 在 cargo feature 之后，默认不编译：

```bash
cargo build --features=imageoptim     # or --features=full
```

## 支持格式

| Direction | Formats |
| --- | --- |
| 输入（来自上游） | `image/png`、`image/jpeg` |
| 输出（到客户端） | `png`、`jpeg`、`webp`、`avif` |

## 配置

注册为插件 category `image_optim`：

```toml
[plugins.imageOptim]
category = "image_optim"
output_types = "avif,webp"
png_quality = 85
jpeg_quality = 80
avif_quality = 70
avif_speed = 4
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `output_types` | string | `""` | 逗号分隔的目标格式。每个变为 `image/<format>` 并与客户端 `Accept` 匹配。 |
| `png_quality` | int | `90` | 1–100；越界重置为默认。 |
| `jpeg_quality` | int | `80` | 1–100。 |
| `avif_quality` | int | `75` | 1–100。 |
| `avif_speed` | int | `3` | 1–10。越高编码越快、文件越大。 |

完整插件文档（含与缓存的交互）见 [image_optim 插件](../plugins/image_optim.md)。

## 工作原理

1. **`request` 步骤** — 检查客户端 `Accept`。客户端接受的每个已配置输出 MIME 类型排序后追加到缓存键，使支持 AVIF 与旧客户端得到不同缓存条目。
2. **`upstream_response` 步骤** — 若响应为 PNG 或 JPEG 且客户端接受 `output_types` 之一，安装正文修改器并将响应改为 chunked。
3. **`upstream_response_body` 步骤** — 缓冲并重编码正文，更新 `Content-Type` 为所选格式。

## 底层编码器

| Format | Crate |
| --- | --- |
| PNG | `imagequant` + `lodepng` |
| JPEG | `mozjpeg` |
| WebP / AVIF | `image`（带 `webp` 与 `avif` features） |

部分会编译原生代码，因此本 crate 可选：会使默认构建明显更慢、更大。

## 性能

重编码是 CPU 密集型，AVIF 更贵。务必在前面放 [`cache`](../plugins/cache.md) 插件，使每种变体只转换一次而非每个请求一次，并在 location 的 `plugins` 中把缓存列在 **`image_optim` 之前**。

`avif_speed` 是主要权衡旋钮：`1`–`2` 文件最小，仅在热缓存后可行；`4`–`6` 是合理的在线默认。

## 许可证

Apache-2.0。
