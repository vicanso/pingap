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
| `status_codes` | string | — | 逗号分隔的状态码，如 `"200,201"`。未设置表示全部。 |

## 规则语法

```
sub_filter  '<literal>' '<replacement>' [flags]
subs_filter '<regex>'   '<replacement>' [flags]
```

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

插件生效时会移除 `Content-Length`，改为 `Transfer-Encoding: chunked`，缓冲整段正文，在流结束时应用过滤器并输出结果。

## 使用说明

- **整段响应体先缓冲到内存**再替换。请用 `path` 与 `status_codes` 收窄范围，远离大文件或流式端点。
- 压缩过的上游响应在此是不透明字节：上游若返回 gzip，过滤器不会匹配。请要求上游不压缩，或在本插件之后用 [`compression`](compression.md) 由 Pingap 压缩。
- 解析失败的规则是启动错误，`pingap -t` 可捕获引号问题。模式与替换须用单引号包裹，且自身不能含单引号。
- 替换在原始字节上进行；跨多字节 UTF-8 边界的正则匹配由正则引擎处理，但字面模式必须与正文中完全一致。
