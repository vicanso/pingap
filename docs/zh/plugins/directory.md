# directory

从目录提供静态文件：MIME 检测、ETag、`Cache-Control`、HTTP range、大文件分块流式、强制下载与可选 HTML 目录索引。

- **步骤：** `request`（默认）或 `proxy_upstream` — 可配置
- **注册名：** `directory`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `directory`。 |
| `path` | string | — | **必填。** 根目录。`~` 会展开，路径会转为绝对路径。 |
| `index` | string | `index.html` | 对 `/` 提供的文件。缺失前导 `/` 时会补上。 |
| `autoindex` | bool | `false` | 为目录生成 HTML 列表。 |
| `chunk_size` | bytesize | `4kb` | 流式块大小；也是启用流式的阈值。下限 4 KB。 |
| `max_age` | duration | — | `Cache-Control: max-age=…`。不应用于 `text/html`。 |
| `private` | bool | `false` | 向 `Cache-Control` 添加 `private`。 |
| `charset` | string | — | 追加到 `text/*` 的 `Content-Type`。 |
| `download` | bool | `false` | 添加 `Content-Disposition: attachment`。 |
| `headers` | string[] | — | 额外响应头，格式 `Name: value`。 |
| `step` | string | `request` | `request` 或 `proxy_upstream`。 |

## 示例

提供构建好的 SPA：

```toml
[plugins.web]
category = "directory"
path = "/var/www/app"
index = "index.html"
chunk_size = "64kb"
max_age = "1h"
charset = "utf-8"
headers = ["X-Content-Type-Options: nosniff"]

[locations.web]
path = "/"
plugins = ["web"]
```

可浏览的下载区：

```toml
[plugins.files]
category = "directory"
path = "~/Downloads"
autoindex = true
download = true
chunk_size = "1mb"
```

Range 请求：

```bash
curl -r 0-1023 -i http://127.0.0.1:6188/big.iso
# HTTP/1.1 206 Partial Content
# content-range: bytes 0-1023/734003200
# accept-ranges: bytes
```

## 行为

- 每个响应带 `Accept-Ranges: bytes` 与由大小和 mtime 导出的弱 ETag（`W/"<size hex>-<mtime hex>"`）。
- `text/html` 视为不可缓存，不应用 `max_age`——SPA 壳保持新鲜，而带 hash 的资源可缓存。
- 支持 `bytes=start-end`、`bytes=start-` 与 `bytes=-suffix`；多 range 只取第一个。不可满足的 range 返回 `416`，带 `Content-Range: bytes */<size>`。
- 不大于 `chunk_size` 的文件读入内存一次发送；更大的流式发送。
- `autoindex` 列表跳过点文件。

## 响应

| Situation | Status |
| --- | --- |
| 找到文件 | `200`，range 请求为 `206` |
| 规范化后路径逃出 `path` | `403` |
| 文件缺失 | `404 Not Found` |
| 其他 IO 错误 | `500 File access error` |
| 非法 range | `416 Range Not Satisfiable` |

## 使用说明

- `index` 仅在根路径 `/` 且 `autoindex` 关闭时替换。对 `/docs/` 等子目录请求在未启用 `autoindex` 时返回 `404`。
- 路径穿越防护是词法的：拼接后规范化且仍须以 `path` 开头。**服务目录内指向外部的符号链接**不会被该检查捕获，请勿服务含不可信 symlink 的树。
- `autoindex` 会暴露文件名、大小与时间戳。非公开内容请配合 [`basic_auth`](basic_auth.md) 或 [`ip_restriction`](ip_restriction.md)。
- 提供大媒体时把 `chunk_size` 设得远高于 4 KB；它直接控制流式时的系统调用频率。
