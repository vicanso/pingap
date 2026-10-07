# redirect

发出 HTTP 重定向：跳到 HTTPS、跳到站点的规范域名、补上路径前缀，或者按规则把请求的路径跳到别处。

- **步骤：** `request`（固定）
- **注册名：** `redirect`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `redirect`。 |
| `http_to_https` | bool | `false` | `true` 把明文 HTTP 请求跳转到 HTTPS；`false` 不改变请求的协议。 |
| `prefix` | string | — | 要前置的路径前缀。缺失前导 `/` 时补上；长度 ≤ 1 的值忽略。 |
| `host` | string | — | 站点的规范域名，不在默认端口上时带上端口。请求的域名不是它时会被重定向过去。 |
| `rules` | string[] | — | `"<正则> <目标> [状态码]"`：路径匹配正则时跳到目标，取第一条匹配的规则。见[规则](#规则)。 |
| `status` | int | `307` | `301`、`302`、`303`、`307`、`308` 之一。其他值是配置错误。 |

## 示例

```toml
[plugins.forceHttps]
category = "redirect"
http_to_https = true
status = 301

[servers.http]
addr = "0.0.0.0:80"
locations = ["redirect"]

[locations.redirect]
path = "/"
plugins = ["forceHttps"]
```

`GET http://example.com/a?b=1` → `301 Location: https://example.com/a?b=1`。

带前缀：

```toml
[plugins.apiPrefix]
category = "redirect"
http_to_https = true
prefix = "/api"
```

`GET http://example.com/users` → `Location: https://example.com/api/users`。

规范域名和路径迁移写在同一个插件里：

```toml
[plugins.canonical]
category = "redirect"
http_to_https = true
host = "example.com"
status = 301
rules = [
    '^/blog/(\d+)/(.*)$ /posts/$2',
    '^/docs/(?<page>[^/]+)$ https://docs.example.com/${page}.html 308',
    '^/download$ /files/latest 302',
]
```

`GET http://www.example.com/blog/2023/hello?ref=x` → `301 Location: https://example.com/posts/hello?ref=x`：协议、域名、路径一步到位。

## 规则

一条规则由正则、目标和可选的状态码组成，用空格分隔。规则按书写顺序尝试，第一条正则匹配上路径的生效；没有规则匹配的请求交给 `http_to_https`、`host`、`prefix` 处理。

- **正则**匹配的是选择 location 时用的那种路径：消去了 `.` 和 `..`，`//` 视为一个斜杠，并且保持可以写回 URL 的形式。`/public/../old/x` 就是 `/old/x`，规则从 `/old/a%20b` 里捕获到的是 `a%20b`。语法是 [`regex`](https://docs.rs/regex) crate 的；不加 `^`、`$` 锚定时匹配路径中的任意位置。
- **目标**是一个以 `/` 开头的路径（`/new/$1`）或完整的 URL（`https://…`，或 `$scheme://$host/…`）。`$1`、`$2`、`${name}` 代表正则捕获的内容；后面紧跟字母或数字时写成 `${1}`。`$host`、`$scheme` 代表重定向要去的域名和协议。
- **跳到哪里由规则决定，不由请求决定。**路径形式的目标自己以斜杠开头，捕获到的内容只能落在域名之后：`'^/old(.*)$ $1'` 会被拒绝，因为 `/old@evil.example` 会被跳到 `http://example.com@evil.example`；请写成 `/$1` 或 `'^/old(/.*)$ /new$1'`。URL 形式的目标里，域名只能是固定的名字或 `$host`，并且捕获的内容之前要有一个 `/`：`https://new.example.com$1` 同样会被拒绝。
- 目标是**路径**时，协议、域名和端口沿用请求原本要被重定向到的（或请求进来时的），请求的查询串也会带上，除非目标自己写了查询串。目标是 **URL** 时原样作为 `Location`。
- 规则上的**状态码**只对这条规则生效，替代插件的 `status`。
- 规则用单引号书写，避免 TOML 解释其中的反斜杠。

解析不了的规则——没有目标、状态码不是重定向状态码、正则编译不过、目标既不是路径也不是 URL、URL 的域名部分用了捕获——是配置错误。

## 行为

没有任何需要跳转的理由时，插件跳过请求：协议符合要求，域名就是 `host`（或没有配 `host`），路径已经以 `prefix` 开头，也没有规则匹配。协议需要改变只有一种情况：`http_to_https = true` 而请求是明文 HTTP。否则只发一次重定向，把所有变化合在一起：目标协议、域名，以及规则的目标或 `prefix` 加原始路径，再加查询串。

不配 `http_to_https` 时插件只补前缀，跳转沿用请求本身的协议：在 HTTPS 监听上，`https://a.test/users` 跳到 `https://a.test/api/users`，`https://a.test/api/users` 直接放行。（不配 `http_to_https` 以前的含义是“强制明文 HTTP”，只配前缀的插件挂在 HTTPS 监听上会把所有请求都跳到 `http://`。本插件不再提供从 HTTPS 跳回 HTTP 的能力。）

只补前缀时保留请求的端口，因为协议不变、监听也不变：`example.com:8080/users` 跳到 `http://example.com:8080/api/users`。改变协议的跳转不带端口，落到新协议的默认端口上，因为旧端口并不提供新协议。

状态码选择：

| Status | Method preserved | Cached by browsers |
| --- | --- | --- |
| `301` | 否（POST 可能变 GET） | 永久 — 难以撤销 |
| `302` | 否 | 否 |
| `307` | 是 | 否 |
| `308` | 是 | 永久 |

## 使用说明

- 只有路径缺少 `prefix` 时才会补上，所以对已经带前缀的 URL 做协议跳转，结果仍是 `/api/users`，不会变成 `/api/api/users`。
- “已是 HTTPS” 的判断基于 Pingap 终止的连接 TLS 状态。在 TLS 终止的负载均衡之后，每个请求都像明文 HTTP，本插件会循环——应在负载均衡处跳转，或不要在此处挂本插件。
- `301`/`308` 会被浏览器积极缓存。先从 `307` 开始，配置验证后再改永久码。
