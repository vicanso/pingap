# cors

跨域资源共享。直接应答预检 `OPTIONS`，并在真实响应上附加 CORS 头。

- **步骤：** 预检在 `request`，实际响应在 `response`
- **注册名：** `cors`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `cors`。 |
| `path` | string | — | 正则；仅匹配路径应用 CORS。未设置表示所有路径。 |
| `allow_origin` | string | `*` | `Access-Control-Allow-Origin` 的值。支持 `$http_origin` 镜像请求，此时会同时加上 `Vary: Origin`，没有 `Origin` 的请求不会得到 CORS 头。 |
| `allow_origins` | string[] | — | 放行的来源列表，用来替代 `allow_origin`：每一项是一个来源（`https://app.example.com`），或者 `~` 加一个要匹配整个来源的正则。见[来源列表](#来源列表)。 |
| `allow_methods` | string | `GET, POST, PUT, PATCH, DELETE, OPTIONS` | `Access-Control-Allow-Methods` 的值。 |
| `allow_headers` | string | — | `Access-Control-Allow-Headers` 的值。 |
| `allow_credentials` | bool | `false` | 发出 `Access-Control-Allow-Credentials: true`。 |
| `expose_headers` | string | — | `Access-Control-Expose-Headers` 的值。 |
| `max_age` | duration | `1h` | `Access-Control-Max-Age` 的值。`0` 省略该头。 |

## 示例

公开只读 API：

```toml
[plugins.cors]
category = "cors"
path = "^/api/"
allow_origin = "*"
allow_methods = "GET, OPTIONS"
allow_headers = "Content-Type"
max_age = "24h"
```

需凭证的跨源 SPA API：

```toml
[plugins.cors]
category = "cors"
path = "^/api/"
allow_origin = "$http_origin"
allow_methods = "GET, POST, PUT, DELETE, OPTIONS"
allow_headers = "Content-Type, Authorization, X-Requested-With"
expose_headers = "X-Request-Id, X-Total-Count"
allow_credentials = true
max_age = "1h"
```

检查：

```bash
curl -i -X OPTIONS http://127.0.0.1:6188/api/users \
  -H 'Origin: https://app.example.com' \
  -H 'Access-Control-Request-Method: POST'
# HTTP/1.1 204 No Content
# access-control-allow-origin: https://app.example.com
# access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
# access-control-allow-credentials: true
# access-control-max-age: 3600
```

## 来源列表

配置 `allow_origins` 后，`Origin` 在列表里的请求会在 `Access-Control-Allow-Origin` 里拿回自己的来源，并带上其他 CORS 头。其他来源的请求什么 CORS 头都拿不到，它的预检请求由插件直接回 `204`（不带这些头），而不是转给上游。上游自己返回的放行头（`Access-Control-Allow-Origin`、`-Credentials`、`-Methods`、`-Headers`、`-Expose-Headers`、`-Max-Age`）不论来源在不在列表里都会从响应里去掉：放行谁、怎么放行，由这个插件决定而不是上游——只有这里配了 `allow_credentials` 才允许凭证，不管上游发了什么。

- 条目是浏览器发送的来源的写法——协议、主机，以及非默认时的端口——比较时不区分大小写。`app.example.com`、`https://app.example.com/`、`https://app.example.com:443` 这样的写法是配置错误，空列表也是。WebView 里应用页面的来源（`capacitor://localhost`）和其他来源一样可以写。
- 以 `~` 开头的条目是匹配整个来源的正则：不论有没有写 `^`、`$`，两端都会被锚定，否则 `example\.com` 也会匹配 `https://example.com.evil.net`。用单引号书写，避免 TOML 解释反斜杠。
- `allow_origin` 和 `allow_origins` 是同一件事的两种写法，同时配置是配置错误。

只要结果取决于来源（配了 `allow_origins`，或者 `allow_origin = "$http_origin"`），匹配路径上的每个响应都带 `Vary: Origin`，不论请求有没有带 `Origin`。以前不带 `Origin` 的请求的响应不加这个头，被共享缓存存下来之后，会被原样回放给后面的跨域请求。

## 行为

| Request | Result |
| --- | --- |
| 匹配路径上的 `OPTIONS` | `204 No Content` 带全部 CORS 头；不调用上游 |
| 任意方法，请求有 `Origin` | 向响应追加 CORS 头 |
| 同一 location 的其他插件直接返回响应（`401`、`429`、重定向、[`directory`](directory.md) 返回的任意大小的文件） | 同样追加 CORS 头 |
| `Origin` 不在 `allow_origins` 中 | 不加 CORS 头；`OPTIONS` 直接回 `204`（不带这些头），不调用上游 |
| 任意方法，无 `Origin` | 响应不变；结果取决于来源时会加 `Vary: Origin` |
| 路径不匹配 `path` | 两阶段均跳过插件 |

## 使用说明

- `allow_origin = "*"` 与 `allow_credentials = true` 的组合，浏览器会拒绝其中带凭证的请求。`$http_origin` 配凭证则是真的能用，而且对谁都能用：它把任意 Origin 原样反射回去，访问者打开的任何网站都能带着他的 cookie 发请求。这两种组合插件加载时都会告警；需要凭证时把前端的来源列在 `allow_origins` 里。
- `allow_origin` 是固定值时，匹配路径上的**任意** `OPTIONS` 都会被预检应答，无论是否带 `Origin` 与 `Access-Control-Request-Method`。用 `$http_origin` 或 `allow_origins` 时，不带 `Origin` 的 `OPTIONS` 交给上游。若上游需要看到所有 `OPTIONS`（如 WebDAV），请收窄 `path`。
- `allow_origin` 只能是单个值；允许列表用 `allow_origins`。
- 预检完全绕过上游，成本很低。
- 认证、限流插件直接返回的响应同样带 CORS 头，与 `cors` 在插件列表里的位置无关。没有这些头时，浏览器不会把响应交给页面，页面看到的是请求失败，而不是 `401`。出于同样的原因，Pingap 因上游故障发出的错误页（`502`、`504`）也带这些头；以前不带。
