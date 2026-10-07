# directory

从目录提供静态文件：MIME 检测、ETag 与 `Last-Modified`、`Cache-Control`、HTTP range、大文件分块流式、预压缩文件、单页应用的回退页面、强制下载与可选 HTML 目录索引。

- **步骤：** `request`（默认）或 `proxy_upstream` — 可配置
- **注册名：** `directory`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `directory`。 |
| `path` | string | — | **必填**，缺少时是配置错误。根目录。`~` 会展开，路径会转为绝对路径。 |
| `index` | string | `index.html` | 目录请求（`/` 或任意深度的子目录）提供的文件。缺失前导 `/` 时会补上。 |
| `autoindex` | bool | `false` | 为目录生成 HTML 列表。 |
| `chunk_size` | bytesize | `4kb` | 流式块大小；也是启用流式的阈值。可写大小字符串或字节数；下限 4 KB。无法解析的值是配置错误。 |
| `max_age` | duration | — | `Cache-Control: max-age=…`。不应用于 `text/html`。无法解析的时长是配置错误。 |
| `private` | bool | `false` | 向 `Cache-Control` 添加 `private`。 |
| `charset` | string | — | 追加到 `text/*` 的 `Content-Type`。 |
| `download` | bool | `false` | 添加 `Content-Disposition: attachment`。 |
| `follow_symlinks` | bool | `true` | 为 `false` 时，解析符号链接之后文件仍须位于 `path` 之下。目录的 `index` 文件按同样的规则检查。 |
| `fallback` | string | — | 目录里的一个文件，从根目录写起（`/index.html`）。请求的路径不存在时以 `200` 返回它。只对最后一段没有扩展名的路径生效。见[单页应用](#单页应用)。 |
| `precompressed` | string[] | — | 文件旁边可以另存的压缩形式，按优先顺序：`br`（`app.js.br`）、`gzip`（`app.js.gz`）、`zstd`（`app.js.zst`）。见[预压缩文件](#预压缩文件)。 |
| `hidden` | bool | `false` | 是否提供以点开头的内容。为 `false` 时，路径里有这样的段（`/.env`、`/.git/config`）就返回 `404`；`.well-known` 不受影响。 |
| `headers` | string[] | — | 额外响应头，格式 `Name: value`。 |
| `step` | string | `request` | `request` 或 `proxy_upstream`。 |

## 示例

提供构建好的 SPA：

```toml
[plugins.web]
category = "directory"
path = "/var/www/app"
index = "index.html"
fallback = "/index.html"
precompressed = ["br", "gzip"]
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

## 单页应用

有自己路由（`/users/1`）的页面在磁盘上只是一个文件，刷新页面或直接打开这样的链接，请求的是一个并不存在的路径。`fallback = "/index.html"` 让这类请求以 `200` 返回这个文件。

只有最后一段没有扩展名的路径才这样处理：`/users/1`、`/v1.2/users/` 是路由；而不存在的 `/assets/main.js`、`/logo.png` 是缺失的文件，仍然返回 `404`——如果用页面去应答，它们会被当成脚本解析或显示成破图。以斜杠结尾的路径不论最后一段长什么样都算路由（`/v1.2/`）；存在但没有 `index` 文件的目录同样返回回退文件。回退文件必须在 `path` 之内；它本身不存在时仍是 `404`。

## 预压缩文件

配置 `precompressed = ["br", "gzip"]` 后，客户端的 `Accept-Encoding` 接受 `br`、并且存在 `app.js.br` 时，对 `app.js` 的请求直接返回 `app.js.br`：`Content-Encoding: br`，`Content-Type` 是 `app.js` 的，`Content-Length` 是压缩文件的。列表的顺序就是优先顺序；客户端不接受的、权重为 `q=0` 的、或者没有对应文件的压缩形式会被跳过，都没有时返回文件本身。

- 开启后，文件的每个响应都带 `Vary: Accept-Encoding`，未压缩的也一样，缓存据此区分。通过 `headers` 配置的 `Vary` 会保留，并在其中补上 `Accept-Encoding`。
- 压缩文件的 ETag 以压缩形式结尾（`W/"<size>-<mtime>-br"`）。
- 带 `Range` 的请求从文件本身应答，压缩形式的响应不带 `Accept-Ranges`。
- 压缩文件只是已有文件的另一种形式：没有 `app.js` 时，`/app.js` 不会返回 `app.js.br`。
- 这里不做任何压缩。压缩文件由打包工具生成；或者不开这个选项，改用 [`compression`](compression.md) 插件。

## 行为

- `If-None-Match` 命中文件 ETag 的请求回 `304 Not Modified`，无正文（弱比较，`W/` 前缀不影响，`*` 总是命中）。没有 `If-None-Match` 时，`If-Modified-Since` 不早于文件的修改时间也得到同样的回答。
- 每个响应带由大小和 mtime 导出的弱 ETag（`W/"<size hex>-<mtime hex>"`）和作为 `Last-Modified` 的 mtime；除[预压缩](#预压缩文件)的文件外还带 `Accept-Ranges: bytes`。
- 路径里有以点开头的段时返回 `404`，除非 `hidden = true`：`/.env`、`/.git/config`、`/a/.cache/x`，不论这个点是怎么写的（`/%2eenv`）。`.well-known` 是例外。这是新的行为：以前这类文件和其他文件一样会被返回。
- `text/html` 视为不可缓存，不应用 `max_age`——SPA 壳保持新鲜，而带 hash 的资源可缓存。
- 只处理 `GET` 和 `HEAD`。`OPTIONS` 返回 `204`，带 `Allow: GET, HEAD, OPTIONS`（这样排在本插件之后的 [`cors`](cors.md) 插件仍能完成预检）；其他方法返回 `405 Method Not Allowed`，带同样的 `Allow`。
- 目录不带结尾斜杠（`/docs`）时重定向到带斜杠的地址（`301`，`Location: ./docs/`，查询串保留），这样索引页或目录列表里的相对链接才会解析到目录内。重定向按客户端发来的路径和查询串计算，而不是 location 的 `rewrite` 改写之后的；目标是相对地址，前面有去掉前缀的代理时同样正确。
- 支持 `bytes=start-end`、`bytes=start-` 与 `bytes=-suffix`；多 range 只取第一个。suffix 比文件长时返回整个文件（`206`）。格式正确但超出文件范围的 range 返回 `416`，带 `Content-Range: bytes */<size>`。不是字节范围的 `Range`（`bytes=5-2`、其他单位）按 RFC 9110 忽略，以 `200` 返回整个文件。
- 支持 `If-Range`：只有它的值等于文件当前的 ETag，或者和它的 `Last-Modified` 逐字相同时 range 才生效，否则返回整个文件。
- `206` 响应带的缓存头（`max_age`、`private`）与完整文件相同，与范围大小无关。
- `HEAD` 请求只读文件元数据，响应头和 `Content-Length` 与 `GET` 相同，不读取文件内容。
- 不大于 `chunk_size` 的文件读入内存一次发送；更大的流式发送。两种情况下响应都带 `Content-Length`，状态码与请求一致：range 请求不论范围大小都是 `206` 并带 `Content-Range`。
- `autoindex` 列表按名称排序并跳过点文件（开启 `hidden` 时不跳过）；名称经 HTML 转义、链接经百分号编码，因此名为 `<script>` 或 `a b.txt` 的文件能正确列出并链接。

## 响应

| Situation | Status |
| --- | --- |
| 找到文件 | `200`，range 请求为 `206` |
| 规范化后路径逃出 `path` | `403` |
| 文件缺失 | `404 Not Found`，或以 `200` 返回 `fallback` 文件 |
| 路径里有以点开头的段且未开启 `hidden` | `404 Not Found` |
| 其他 IO 错误 | `500 File access error` |
| range 超出文件范围 | `416 Range Not Satisfiable` |
| `OPTIONS` | `204 No Content`，带 `Allow` |
| `GET`/`HEAD`/`OPTIONS` 之外的方法 | `405 Method Not Allowed` |
| 目录缺少结尾斜杠 | `301` 到带斜杠的同一路径 |

## 使用说明

- `autoindex` 关闭时，任意深度的目录请求都提供其 `index` 文件（`/docs/` 会找到 `docs/index.html`）；开启时返回列表。
- 路径穿越防护默认是词法的：拼接后规范化且仍须以 `path` 开头，可以拦住 `../`，但拦不住**服务目录内指向外部的符号链接**。设置 `follow_symlinks = false` 后还会比较解析出的真实路径，代价是每个请求多一次 `realpath`。检查针对实际要发送的文件，所以目录的 `index` 文件如果链接到目录树之外，通过 `/dir/` 访问和通过 `/dir/index.html` 访问一样会被拒绝。默认值保持 `true`，把内容链接进目录树的部署不受影响；只要目录里可能出现不是你创建的符号链接，就应当关闭。根目录本身是符号链接时两种设置都可用，因为根目录在启动时解析一次。
- `autoindex` 会暴露文件名、大小与时间戳。非公开内容请配合 [`basic_auth`](basic_auth.md) 或 [`ip_restriction`](ip_restriction.md)。
- 提供大媒体时把 `chunk_size` 设得远高于 4 KB；它直接控制流式时的系统调用频率。
