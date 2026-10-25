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

由 `pingap_imageoptim::register()` 注册为插件 category `image_optim`。`pingap` 二进制在第一次使用插件工厂时调用它；自己写程序使用本 crate 的，要在创建插件之前调用：

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
| `png_quality` | int | `90` | 1–100：png 的调色板要与原图接近到什么程度。不设置或 `0` 表示默认值，其他越界的值是配置错误（下面三项同样如此）。 |
| `jpeg_quality` | int | `80` | 1–100。 |
| `avif_quality` | int | `75` | 1–100。 |
| `avif_speed` | int | `3` | 1–10。越高编码越快、文件越大。 |

完整插件文档（含与缓存的交互）见 [image_optim 插件](../plugins/image_optim.md)。

## 工作原理

1. **`request` 步骤** — 检查客户端 `Accept`。客户端接受的每个已配置输出 MIME 类型排序后追加到缓存键，使支持 AVIF 与旧客户端得到不同缓存条目。
2. **`upstream_response` 步骤** — 若响应为 PNG 或 JPEG 且客户端接受 `output_types` 之一，安装正文修改器并将响应改为 chunked。
3. **`upstream_response_body` 步骤** — 缓冲并重编码正文，更新 `Content-Type` 为所选格式。

## 底层编码器

| Format | Crate | 许可证 |
| --- | --- | --- |
| PNG | `color_quant`（调色板）+ `lodepng`（文件） | MIT、Zlib |
| JPEG | `mozjpeg` | IJG、Zlib、BSD-3-Clause |
| WebP / AVIF | `image`（带 `webp` 与 `avif` features；AVIF 用 `ravif` 和 `rav1e`） | MIT 或 Apache-2.0、BSD-3-Clause、BSD-2-Clause |

部分会编译原生代码，因此本 crate 可选：会使默认构建明显更慢、更大。

其中没有 copyleft 许可证的依赖。0.16 及之前 png 的调色板来自 `imagequant`，它是 GPL-3.0-or-later，使 `full` 构建整体成为该许可证下的作品。

### png 的调色板

调色板由 [`color_quant`](https://github.com/image-rs/color_quant) 的 NeuQuant 生成：一个神经元数量等于颜色数量的网络。`src/quantize.rs` 负责准备训练数据，并处理它给出的结果：

- **统计颜色**，颜色先乘以 alpha，这样一个像素的颜色按它实际显现的程度计入。颜色不超过 256 种的图片原样保留这些颜色，不经过网络，也与质量取值无关：换成颜色更少的调色板再加上抖动产生的噪点，文件多半反而更大。其余图片用最多 65536 个像素的样本训练网络，每种颜色出现的次数按它在图片中的占比分配（颜色不超过 32768 种时每种至少出现一次；超过时把各通道高位相同的颜色合并）。不足 16384 个像素的图片会重复到这个数量：每个像素只见过一次的网络，结果会差好几个 dB。
- **校正调色板**：每一项移到它所对应颜色的均值上。神经元停在均值附近，很少正好在均值上，对一片纯色来说就是差一级，抖动之后会变成一片相邻颜色的噪点。
- **没有神经元靠近的颜色单独占一项**，最多十六分之一。网络描述的是大多数颜色所在的位置，图表上的一个标记在里面没有自己的位置。让出的那一项，取的是"其像素改用最近的另一项时损失最小"的那一项——通常是两个神经元共用的或者没有像素使用的——并且只有损失小于这种颜色的收益时才让：把图片另一小块区域唯一的一项拿走，曾经让一块阴影变成了不透明的蓝色。
- **`png_quality` 是对误差的限制**，误差在这里计算：每个像素到它所用调色板颜色的均方距离，以峰值信噪比表示（90 对应 44 dB，最低时为 30 dB）；离调色板最远的那一种颜色，允许的距离是它的二十倍。调色板从 256 种颜色开始，只要两条都满足就减半，最少到 32；取 100 时不减半。NeuQuant 的文档要求 64 个以上的神经元，代码里说没有针对少于 26 个的情况调过；32 个神经元的网络和其他大小一样，误差在限制内才会被采用。
- **像素在这里映射到调色板**，每个像素的误差有四分之三传给相邻像素，隔行反向，传给任何一个像素的量每个通道不超过 24 级。没有使用 `image::imageops::dither`：它遇到宽度为一个像素的图片会数组越界，而 release 构建（`panic = "abort"`）遇到 panic 就退出。
- **完全透明的像素保持完全透明**：它们使用调色板里的透明项；网络没有给出这一项时会补上。

## 性能

重编码是 CPU 密集型，AVIF 更贵。务必在前面放 [`cache`](../plugins/cache.md) 插件，使每种变体只转换一次而非每个请求一次，并在 location 的 `plugins` 中把缓存列在 **`image_optim` 之前**。

`avif_speed` 是主要权衡旋钮：`1`–`2` 文件最小，仅在热缓存后可行；`4`–`6` 是合理的在线默认。

## 许可证

Apache-2.0。
