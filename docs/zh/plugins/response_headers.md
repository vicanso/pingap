# response_headers

添加、设置、删除与重命名响应头。值支持与 Pingap 其他头处理相同的动态替换，可将请求上下文暴露给客户端。

- **步骤：** `response`（默认）或通过 `mode` 使用 `upstream_response`
- **注册名：** `response_headers`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `response_headers`。 |
| `add_headers` | string[] | — | `Name: value` — 追加，保留已有值。 |
| `set_headers` | string[] | — | `Name: value` — 替换任何已有值。 |
| `set_headers_not_exists` | string[] | — | `Name: value` — 仅在头不存在时设置。 |
| `remove_headers` | string[] | — | 要删除的头名。 |
| `rename_headers` | string[] | — | `Old-Name: New-Name` — 移动该头的全部值。 |
| `preset` | string | — | `security` 设置一组安全相关的头，只在响应里没有同名头时设置。见[安全头预设](#安全头预设)。 |
| `always` | bool | `false` | 规则也作用于不是来自上游的响应：同一 location 的其他插件直接返回的响应，以及代理自己的错误页。只能用于 `mode = "response"`。 |
| `mode` | string | *(response)* | `upstream` 改为改写上游响应头。`response`、`upstream` 以外的值是配置错误。 |

不是 `Name: value`（`rename_headers` 是 `Old-Name: New-Name`）形式的条目是配置错误。以前没有冒号的条目会被静默丢弃，写错的 `mode` 会被当成 `response`。

操作始终按以下顺序执行，与声明顺序无关：

1. `add_headers`
2. `remove_headers`
3. `set_headers`
4. `set_headers_not_exists`
5. `rename_headers`

因此第 1 步添加且出现在 `remove_headers` 中的头会被删掉；第 5 步重命名看到的是之前步骤的结果。

## 安全头预设

`preset = "security"` 在响应没有对应头时设置：

| Header | Value |
| --- | --- |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Strict-Transport-Security` | `max-age=31536000`，只在客户端是经 https 访问时添加：当前连接是 TLS，或者请求经过 `basic.trusted_proxies` 里的代理、并且代理在 `X-Forwarded-Proto` 里说是 https |

上游已经返回了其中某个头时以上游的为准，插件自己的规则也优先：预设旁边再写 `set_headers = ["X-Frame-Options: DENY"]`，结果是 `DENY`。`includeSubDomains` 和 `preload` 是对整个域名的承诺，不在预设里；确实需要时用 `set_headers` 自己加。预设请用在 `response` 模式下：`upstream` 模式里这些头会随缓存的响应一起存下来，有没有 `Strict-Transport-Security` 取决于填充缓存的那个请求。

## 作用于 location 的所有响应

本插件的头是加在上游的响应上的。认证插件返回的 `401`、`429`、重定向、[`directory`](directory.md) 返回的文件，以及上游不可用时 Pingap 自己发出的错误页，都不是来自上游，也就不带这些头——而这些恰恰是最容易漏掉安全头的地方。

`always = true` 让规则同样作用于这些响应。它通常和 `preset` 一起用：

```toml
[plugins.securityHeaders]
category = "response_headers"
preset = "security"
always = true
```

错误页只有在 location 的插件已经为这个请求运行过之后才会带上这些头。没有匹配到任何 location 的请求没有插件可以问；被 location 自身的限制（`client_max_body_size`、`max_processing`）在插件之前挡下的请求也一样。

开启 `always` 后，所有规则都会作用于这些响应，包括删除和替换类的规则。`set_headers = ["Cache-Control: public, max-age=3600"]` 会把 `401` 或维护通知上的 `no-store` 也替换掉：其他响应有自己理由设置的头，请用 `set_headers_not_exists`。代理自己错误页的长度和类型不受规则影响。

## 动态值

| Variable | Expands to |
| --- | --- |
| `$hostname` | 代理主机名 |
| `$remote_addr` | 连接对端的地址 |
| `$client_ip` | 客户端地址：经过 `basic.trusted_proxies` 里的代理时用代理转发的地址，否则是对端地址 |
| `$forwarded_proto` / `$forwarded_port` / `$forwarded_host` | 客户端使用的协议、端口和域名：可信代理在 `X-Forwarded-Proto` / `-Port` / `-Host` 里给出的值，没有时是当前连接的 |
| `$remote_port` | 客户端端口 |
| `$upstream_addr` | 所选上游地址 |
| `$ja4` | 客户端的 JA4 TLS 指纹，需 server 设置 `ja4 = true` |
| `$proxy_add_x_forwarded_for` | 已有 `X-Forwarded-For` 加上客户端地址 |
| `$http_<name>` | 请求头 `<name>` 的值；下划线代表横线，`$http_user_agent` 读取的是 `User-Agent` |
| `$<NAME>` | 环境变量 `NAME` |
| `:<key>` | 请求上下文中的值 |

## 示例

安全头与一点调试信息：

```toml
[plugins.respHeaders]
category = "response_headers"
set_headers = [
    "X-Frame-Options: DENY",
    "X-Content-Type-Options: nosniff",
    "Referrer-Policy: strict-origin-when-cross-origin",
]
set_headers_not_exists = ["Cache-Control: no-cache"]
add_headers = ["X-Served-By: $hostname"]
remove_headers = ["Server", "X-Powered-By"]
rename_headers = ["X-Internal-Trace: X-Trace-Id"]
```

在 Pingap 自身缓存与响应处理看到之前改写上游响应：

```toml
[plugins.fixUpstream]
category = "response_headers"
mode = "upstream"
remove_headers = ["Set-Cookie"]
set_headers = ["Cache-Control: public, max-age=3600"]
```

## `mode`

| `mode` | Hook | When to use |
| --- | --- | --- |
| 未设置 | `response` | 常规：面向客户端的响应 |
| `upstream` | `upstream_response` | 影响缓存或后续响应插件 |

一个实例只处理二者之一，不会同时处理。

## 使用说明

- `remove_headers` 与 `rename_headers` 的名称必须是合法 HTTP 头名，否则启动失败，`pingap -t` 会报告。
- `rename_headers` 向目标追加，因此重命名到已存在的头会产生两个值，而非覆盖。`Set-Cookie` 这类多值头会连同全部值一起移动。
- 无法解析的动态值回退为字面配置字符串，因此 `$hostnam` 这类拼写错误会原样发出。
