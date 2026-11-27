# sub_filter

在响应体中搜索替换，类似 nginx 的 `sub_filter` 与 `subs_filter` 模块。适用于改写绝对 URL、注入 script 标签，或修补无法修改的上游。

- **步骤：** `response` 与 `response_body`（默认），或通过 `step = "upstream_response"` 设为 `upstream_response` 与 `upstream_response_body`；同时在 `request` 阶段运行
- **注册名：** `sub_filter`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `sub_filter`。 |
| `step` | string | `response` | `response`（在发往客户端时改写）或 `upstream_response`（在 [`cache`](cache.md) 存储之前改写上游响应，命中缓存时直接返回已改写内容而无需重复过滤）。其他值为配置错误。 |
| `filters` | string[] | `[]` | 替换规则；见下方语法。 |
| `path` | string | — | 请求路径上的正则。未设置表示所有路径。 |
| `status_codes` | string | — | 逗号分隔的状态码，如 `"200,201"`。未设置表示全部；不是数字的项是配置错误。 |
| `types` | string[] | — | 要改写的内容类型，按前缀匹配：`["text/html", "application/json"]`、`["text/"]`。未设置表示所有响应，不论类型。 |
| `max_size` | size | — | 改写的正文大小上限，如 `"1mb"`。更大的正文原样透传。未设置表示不限。设置 `max_size` 会使插件进入整段缓冲模式。 |
| `max_buffer_size` | size | `64 MiB` | 当前插件实例在缓冲模式下所有并发响应共享的内存上限，如 `"64mb"`。仅在缓冲模式（配置了 `subs_filter` 正则规则或 `max_size`）下生效；超出上限时，响应会 fail-open 降级并原样透传。必须大于 `0`。 |

## 规则语法

```
sub_filter  '<literal>' '<replacement>' [flags]
subs_filter '<regex>'   '<replacement>' [flags]
```

两段文本各自可以用单引号或双引号包裹，所以带其中一种引号的文本用另一种来写（`sub_filter "it's" 'it is'`）。替换内容可以为空，即把找到的内容删掉（`sub_filter '<script src="/old.js"></script>' ''`）。

| Flag | Meaning |
| --- | --- |
| `g` | 替换每一处，而非仅第一处 |
| `i` | 大小写不敏感（仅 `subs_filter`） |

`subs_filter` 的替换使用 [`regex`](https://docs.rs/regex/latest/regex/#syntax) crate 语法，捕获组写作 `$1`、`$2` 或 `${name}`。

## 示例

```toml
[plugins.rewriteLinks]
category = "sub_filter"
path = "^/docs"
status_codes = "200"
filters = [
    "sub_filter  'http://old.example.com' 'https://new.example.com' g",
    "subs_filter '<title>(.*?)</title>' '<title>$1 — Docs</title>' i",
    "sub_filter  '</head>' '<script src=\"/analytics.js\"></script></head>'",
]

[locations.docs]
upstream = "docs"
path = "/docs"
plugins = ["rewriteLinks"]
```

过滤器按列表顺序运行，每一条作用于前一条的输出。

## 行为

插件生效时会移除 `Content-Length` 并改为 `Transfer-Encoding: chunked`。正文的处理方式取决于规则类型与是否设置 `max_size`：

- **流式模式（仅含字面 `sub_filter` 规则且未设置 `max_size`）：** 使用滑动窗口流式替换器，将小分片合并到 `8 KiB` 后逐片输出，跨片边界仅保留每条规则 `pattern.len() - 1` 字节的重叠部分，无需把整段响应体缓存在内存中；该模式下不涉及 `max_buffer_size`。
- **缓冲模式（包含任意 `subs_filter` 正则规则，或设置了 `max_size`）：** 将响应体缓存在内存中，在流结束时应用全部规则并输出结果；没有命中的规则不会产生拷贝。若响应没有 `Content-Length` 且超过 `max_size`，或使当前插件实例的并发缓冲总量超过 `max_buffer_size`（默认 `64 MiB`），则触发 fail-open：把已缓冲的内容按原样发出，后续分片直接原样透传。

没有可改写正文的响应会原样放过：HEAD 应答、`1xx`、`204`、`304`，以及 `Content-Encoding` 不是 `identity` 的响应（压缩字节永远不会匹配）。响应体的一部分（`206` 或带 `Content-Range` 的响应）同样原样放过：改写之后它已经不是原始内容的某一段，而响应头还在声明它是哪一段。

为了不让客户端通过范围请求拿到没改写的内容，插件在 `request` 阶段把它生效的请求（按 `path`）上的 `Range` 和 `If-Range` 去掉：向上游要的是完整响应体，缓存也一样（否则缓存会自己从存下的响应里截取范围）。客户端收到的是带改写后内容的 `200`，这对范围请求是合法的应答。

被改写的响应会去掉 `Accept-Ranges`，强 `ETag` 改成弱校验（`W/"v1"`）：这两个头描述的是上游发出的响应体。

## 使用说明

- **执行阶段（`step = "upstream_response"`）：** 默认情况下（`step = "response"`），
  `sub_filter` 在 [`cache`](cache.md) 之后、发往客户端之前改写正文，因此每次缓存命中都会再次执行过滤。将 `step` 设为 `"upstream_response"` 后，改写会在 `cache` 落盘之前作用于上游响应，使后续缓存命中直接返回已改写后的内容；默认模式下的下游 [`compression`](compression.md) 仍会在发往客户端时正常压缩缓存内容。无论选择哪一步，剥离 `Range` 与要求明文正文的标记仍在 `request` 阶段执行。
- **仅缓冲模式会把整段响应体缓存在内存**（当任意规则为 `subs_filter` 正则，或配置了 `max_size` 时）。仅使用字面 `sub_filter` 规则且未配置 `max_size` 时，插件按 `8 KiB` 分片流式替换，内存占用只与模式重叠长度成正比。在缓冲模式下，请用 `path` 与 `status_codes` 收窄范围，远离大文件或流式端点，或显式限定：
  - **`types`**：其他类型的响应完全不动——照常流式转发，保留 `Content-Length`，不进内存。没有写明类型的响应同样不动。不配 `types` 时，同一个 location 上的图片或下载也会按页面处理（在缓冲模式下会被整个缓冲）。
  - **`max_size`**：更大的正文不动。`Content-Length` 已经说明超限的，完全不碰；没有给出长度的，先缓冲到上限，超过之后把已缓冲的部分和后续内容原样放行，整个正文都不改写。由于需要缓冲到上限才能判定，配置 `max_size` 会使字面规则也关闭流式模式、转为整段缓冲。
  - **`max_buffer_size`**：限制同一插件实例在缓冲模式下所有并发响应同时占用的内存总上限（默认 `64 MiB`）。一旦新分片会超出共享预算，该响应立即 fail-open 原样透传，避免并发大响应耗尽内存。
  `types` 和 `max_size` 不配置就不生效，和插件一直以来的行为一致。nginx 的 `sub_filter_types` 默认是 `text/html`，对应 `types = ["text/html"]`。
  这些选项都不会让范围请求恢复：`Range` 和 `If-Range` 是在请求阶段、还不知道响应类型和大小的时候，从插件按 `path` 生效的所有请求上去掉的。和页面在同一个 `path` 下的下载会原样透传，但不能断点续传；要保留续传，请用 `path` 把它排除在插件之外。
- 压缩过的上游响应会被跳过而不是改写：上游若返回 gzip，过滤器永远不会匹配。请要求上游不压缩，或用默认模式的 [`compression`](compression.md) 由 Pingap 压缩，它在改写之后压缩。`mode = "upstream"` 时，本插件生效的响应（按它的 `path`）不会被压缩：这种模式在任何 response 步骤的插件看到响应体之前就压缩，和列表里的顺序无关，以前对接受压缩的客户端，这里就没有内容可以改写了。
- 解析失败的规则是启动错误，`pingap -t` 可捕获引号问题。单引号包裹的文本里不能有单引号，双引号包裹的不能有双引号，没有转义写法。
- 替换在原始字节上进行；跨多字节 UTF-8 边界的正则匹配由正则引擎处理，但字面模式必须与正文中完全一致。
