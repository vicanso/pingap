# maintenance

把一个 location 的所有请求都应答成“站点维护中”的通知，同时放行做维护的人。

[`mock`](mock.md) 插件可以让所有人都得到 `503`——包括做维护的人，他们也就看不到自己正在处理的站点了。

- **步骤：** `request`（固定）
- **注册名：** `maintenance`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `maintenance`。 |
| `enabled` | bool | `true` | 设为 `false` 关闭插件，不必把它从 location 上摘掉：页面内容和白名单留在配置里，下次维护时再打开。 |
| `status` | int | `503` | 通知的状态码，`400` 到 `599`。 |
| `retry_after` | duration | — | 以秒数作为 `Retry-After` 发送。 |
| `message` | string | `Service is under maintenance` | 通知正文，按 `text/plain` 发送。 |
| `html` | string | — | 通知正文，按 `text/html` 发送。和 `message` 只能配一个。 |
| `allow_ip_list` | string[] | — | 放行的 IP 与 CIDR。 |
| `allow_header` | string | — | `Name: value`：带这个请求头且值相同的请求放行。 |

## 示例

```toml
[plugins.maintenance]
category = "maintenance"
retry_after = "30m"
html = "<h1>Back at 03:00 UTC</h1><p>We are upgrading the database.</p>"
allow_ip_list = ["10.0.0.0/8", "203.0.113.7"]
allow_header = "X-Maintenance-Pass: 7c2f0e5a"

[locations.app]
upstream = "app"
plugins = ["maintenance", "auth"]
```

其他人得到的是：

```
HTTP/1.1 503 Service Unavailable
Retry-After: 1800
Content-Type: text/html; charset=utf-8
Cache-Control: private, no-store
```

## 行为

| Request | Result |
| --- | --- |
| `enabled = false` | 放行，等同于没有挂这个插件 |
| 带有 `allow_header` 且值相同 | 放行 |
| 客户端地址在 `allow_ip_list` 中 | 放行 |
| 其他 | `status` 与通知内容 |

## 使用说明

- 把它排在 location 插件列表的最前面，被挡下的请求就不会再产生后面的任何开销。
- `allow_ip_list` 比对的是对端地址；请求经过 `basic.trusted_proxies` 里的代理时，用代理转发的客户端地址。其他来源的 `X-Forwarded-For` 只是请求自己的说法，不会被采用。
- `allow_header` 是一个共享密钥：放行靠的是它的值，比较用常量时间。只写名字不写值是配置错误。可以用于发布流水线里的检查，或者配合给请求加头的浏览器扩展使用。
- 通知带 `no-store`：被缓存存下来的话，维护结束之后它还会继续被返回。
- 切换 `enabled` 是对插件的一次修改，和其他修改一样在下一次重载时生效。
