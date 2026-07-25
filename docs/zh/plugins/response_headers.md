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
| `rename_headers` | string[] | — | `Old-Name: New-Name` — 移动值。 |
| `mode` | string | *(response)* | `upstream` 改为改写上游响应头。 |

操作始终按以下顺序执行，与声明顺序无关：

1. `add_headers`
2. `remove_headers`
3. `set_headers`
4. `set_headers_not_exists`
5. `rename_headers`

因此第 1 步添加且出现在 `remove_headers` 中的头会被删掉；第 5 步重命名看到的是之前步骤的结果。

## 动态值

| Variable | Expands to |
| --- | --- |
| `$hostname` | 代理主机名 |
| `$remote_addr` | 客户端地址 |
| `$remote_port` | 客户端端口 |
| `$upstream_addr` | 所选上游地址 |
| `$proxy_add_x_forwarded_for` | 已有 `X-Forwarded-For` 加上客户端地址 |
| `$http_<name>` | 请求头 `<name>` 的值 |
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
- `rename_headers` 向目标追加，因此重命名到已存在的头会产生两个值，而非覆盖。
- 无法解析的动态值回退为字面配置字符串，因此 `$hostnam` 这类拼写错误会原样发出。
