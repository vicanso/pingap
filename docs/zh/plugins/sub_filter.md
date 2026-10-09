# sub_filter

在响应体中搜索替换，类似 nginx 的 `sub_filter` 与 `subs_filter` 模块。适用于改写绝对 URL、注入 script 标签，或修补无法修改的上游。

- **步骤：** `response` 与 `response_body`
- **注册名：** `sub_filter`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `sub_filter`。 |
| `filters` | string[] | `[]` | 替换规则；见下方语法。 |
| `path` | string | — | 请求路径上的正则。未设置表示所有路径。 |
| `status_codes` | string | — | 逗号分隔的状态码，如 `"200,201"`。未设置表示全部；不是数字的项是配置错误。 |
| `types` | string[] | — | 要改写的内容类型，按前缀匹配：`["text/html", "application/json"]`、`["text/"]`。未设置表示所有响应，不论类型。 |
| `max_size` | size | — | 改写的正文大小上限，如 `"1mb"`。更大的正文原样透传。未设置表示不限。 |

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

插件生效时会移除 `Content-Length`，改为 `Transfer-Encoding: chunked`，缓冲整段正文，在流结束时应用过滤器并输出结果。没有命中的规则不会产生拷贝。

没有可改写正文的响应会原样放过：HEAD 应答、`1xx`、`204`、`304`，以及 `Content-Encoding` 不是 `identity` 的响应（压缩字节永远不会匹配）。响应体的一部分（`206` 或带 `Content-Range` 的响应）同样原样放过：改写之后它已经不是原始内容的某一段，而响应头还在声明它是哪一段。

为了不让客户端通过范围请求拿到没改写的内容，插件在 `request` 阶段把它生效的请求（按 `path`）上的 `Range` 和 `If-Range` 去掉：向上游要的是完整响应体，缓存也一样（否则缓存会自己从存下的响应里截取范围）。客户端收到的是带改写后内容的 `200`，这对范围请求是合法的应答。

被改写的响应会去掉 `Accept-Ranges`，强 `ETag` 改成弱校验（`W/"v1"`）：这两个头描述的是上游发出的响应体。

## 使用说明

- **整段响应体先缓冲到内存**再替换。请用 `path` 与 `status_codes` 收窄范围，远离大文件或流式端点，或者说明它是给什么用的：
  - **`types`**：其他类型的响应完全不动——照常流式转发，保留 `Content-Length`，不进内存。没有写明类型的响应同样不动。不配 `types` 时，同一个 location 上的图片或下载也会被整个缓冲、像页面一样搜索。
  - **`max_size`**：更大的正文不动。`Content-Length` 已经说明超限的，完全不碰；没有给出长度的，先缓冲到上限，超过之后把已缓冲的部分和后续内容原样放行，整个正文都不改写。
  两项都是不配置就不生效，和插件一直以来的行为一致。nginx 的 `sub_filter_types` 默认是 `text/html`，对应 `types = ["text/html"]`。
  这两项都不会让范围请求恢复：`Range` 和 `If-Range` 是在请求阶段、还不知道响应类型和大小的时候，从插件按 `path` 生效的所有请求上去掉的。和页面在同一个 `path` 下的下载会原样透传，但不能断点续传；要保留续传，请用 `path` 把它排除在插件之外。
- 压缩过的上游响应会被跳过而不是改写：上游若返回 gzip，过滤器永远不会匹配。请要求上游不压缩，或在本插件之后用 [`compression`](compression.md) 由 Pingap 压缩。
- 解析失败的规则是启动错误，`pingap -t` 可捕获引号问题。单引号包裹的文本里不能有单引号，双引号包裹的不能有双引号，没有转义写法。
- 替换在原始字节上进行；跨多字节 UTF-8 边界的正则匹配由正则引擎处理，但字面模式必须与正文中完全一致。
