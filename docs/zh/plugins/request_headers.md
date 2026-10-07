# request_headers

在请求发往上游之前添加、设置、删除、重命名请求头。它和 [`response_headers`](response_headers.md) 是一对：配置项相同，方向相反。

location 可以用 `proxy_set_headers`、`proxy_add_headers` 为上游设置和追加请求头。这个插件用来做它们做不到的事——删掉一个头、给头改名、只在客户端没带时才设置——以及让多个 location 共用同一组规则。

- **步骤：** `request`（默认）或 `proxy_upstream` — 可配置
- **注册名：** `request_headers`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `request_headers`。 |
| `add_headers` | string[] | — | `Name: value` — 追加，保留请求已有的值。 |
| `set_headers` | string[] | — | `Name: value` — 替换请求已有的值。 |
| `set_headers_not_exists` | string[] | — | `Name: value` — 仅在请求没有这个头时设置。 |
| `remove_headers` | string[] | — | 要删除的头名，该头的全部值都会删除。 |
| `rename_headers` | string[] | — | `Old-Name: New-Name` — 移动该头的全部值。 |
| `step` | string | `request` | `request` 或 `proxy_upstream`。其他值为配置错误。 |

不是 `Name: value`（`rename_headers` 是 `Old-Name: New-Name`）形式的条目，或者不合法的头名，都是配置错误，`pingap -t` 会报出来。针对 `Content-Length`、`Transfer-Encoding` 的规则同样是配置错误：它们说明请求体如何分帧，值和实际的请求体对不上时，上游读到的就不是客户端发出的那个请求了。针对 `Host` 的规则也是配置错误：HTTP/2 客户端的请求转给 HTTP/1 上游时，`Host` 会在本插件运行之后按请求的 authority 重新设置，规则只对一部分客户端有效；请用 location 的 `proxy_set_headers` 来设置，它对所有客户端都有效。

操作始终按以下顺序执行，与声明顺序无关：

1. `add_headers`
2. `remove_headers`
3. `set_headers`
4. `set_headers_not_exists`
5. `rename_headers`

## 动态值

值恰好是下面某一项（不含其他内容）时会被替换：

| Variable | 展开为 |
| --- | --- |
| `$hostname` | 代理所在主机名 |
| `$host` | 请求的目标主机 |
| `$scheme` | `http` 或 `https`，按客户端的连接方式 |
| `$remote_addr` | 连接对端的地址 |
| `$client_ip` | 客户端地址：经过 `basic.trusted_proxies` 里的代理时用代理转发的地址，否则是对端地址 |
| `$forwarded_proto` / `$forwarded_port` / `$forwarded_host` | 客户端使用的协议、端口和域名：可信代理在 `X-Forwarded-Proto` / `-Port` / `-Host` 里给出的值，没有时是当前连接的 |
| `$remote_port` | 客户端端口 |
| `$server_addr` / `$server_port` | 请求到达的地址和端口 |
| `$ja4` | 客户端的 JA4 TLS 指纹，需要 server 开启 `ja4 = true` |
| `$proxy_add_x_forwarded_for` | 已有的 `X-Forwarded-For` 加上客户端地址 |
| `$http_<name>` | 请求头 `<name>` 的值；下划线代表连字符，`$http_user_agent` 读取的是 `User-Agent` |
| `$<NAME>` | 环境变量 `NAME` |
| `:<key>` | 请求上下文中的值 |

取值用的是请求到达时的样子，在插件的任何规则生效之前：`X-From: $http_x_client` 和 `set_headers = ["X-Client: ..."]` 写在一起时，复制的是客户端发来的值。解析不了的值按配置里写的原样发送。

## 示例

不把客户端的 cookie 和 `Authorization` 发给用不到它们的上游，同时把来访者的信息带过去：

```toml
[plugins.cleanRequest]
category = "request_headers"
remove_headers = ["Cookie", "Authorization", "X-Internal-Key"]
set_headers = ["X-Real-IP: $remote_addr", "X-Forwarded-Proto: $scheme"]
set_headers_not_exists = ["Accept-Language: en"]
rename_headers = ["X-Api-Key: X-Internal-Key"]

[locations.assets]
upstream = "assets"
path = "/assets"
plugins = ["cleanRequest"]
```

## 使用说明

- 修改的是请求本身。排在它后面的插件看到的是修改后的结果，排在前面的看到的是原始请求：如果认证插件要读取被它删除的头，就把它放在认证插件之后。
- `step = "proxy_upstream"` 时它在查缓存之后运行，所以缓存命中的请求不会经过它，缓存键（[`cache`](cache.md) 插件的 `headers`）用的也是修改前的头。
- location 自己的 `proxy_set_headers`、`proxy_add_headers` 在请求发出时才应用，晚于本插件；两边都设置了同一个头时以 location 的为准。
- `rename_headers` 是追加到目标名上，所以改名到请求已有的头上会得到两个值，而不是替换。目标名是上游信任的头时，像示例那样把它也列进 `remove_headers`：删除先执行，客户端自己带来的同名头会先被去掉。
- 本插件添加、设置或改名得到的头，从此属于代理。客户端不能通过在 `Connection` 头里点名它来让它被丢掉——那是用来不把客户端自己的逐跳头转给上游的机制。
- 访问日志读到的是插件处理之后的请求：被删除的头，`{>name}` 打印不出来。
