# ua_restriction

按 `User-Agent` 用正则做允许/拒绝列表。

- **步骤：** `request`（固定）
- **注册名：** `ua_restriction`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `ua_restriction`。 |
| `ua_list` | string[] | `[]` | 正则模式，启动时编译成一个集合，一次扫描完成匹配。 |
| `type` | string | `allow` | `deny` 拦截匹配的 UA；其他值仅允许匹配的 UA。 |
| `message` | string | `Request is forbidden` | 403 响应正文。 |
| `dry_run` | bool | `false` | 本应拒绝的请求照常放行，改为记录一条警告日志：新规则可以先在真实流量上观察，再真正拦截。见[只记录不拦截](limit.md#只记录不拦截)。 |

模式使用 [`regex`](https://docs.rs/regex/latest/regex/#syntax) crate 语法，且**不锚定**——`go-http-client` 可匹配头中任意位置。需要精确值时用 `^…$`。非法模式会导致启动错误，`pingap -t` 可捕获。

## 示例

拦截脚本客户端与特定爬虫：

```toml
[plugins.blockBots]
category = "ua_restriction"
type = "deny"
ua_list = [
    "go-http-client/1\\.1",
    "(Twitterspider)/(\\d+)\\.(\\d+)",
    "^python-requests/",
    "curl/",
]
message = "Automated access is not allowed"
```

仅放行已知内部客户端：

```toml
[plugins.internalClient]
category = "ua_restriction"
type = "allow"
ua_list = ["^my-service/\\d+\\.\\d+$"]
```

## 行为

| `User-Agent` | `type = "allow"` | `type = "deny"` |
| --- | --- | --- |
| 匹配某模式 | 允许 | **403** |
| 无一匹配 | **403** | 允许 |
| 头缺失 | **403** | 允许 |

## 使用说明

- 允许模式下缺失 `User-Agent` 会被拦截。许多健康检查与监控探针不发 UA——请排除这些路径或为它们添加模式。
- `User-Agent` 极易伪造，只能挡幼稚脚本，挡不住有意绕过。真正的门禁请用 [`key_auth`](key_auth.md) 或 [`ip_restriction`](ip_restriction.md)。
- TOML 字符串中反斜杠需转义：写 `"\\d+"`，或使用字面量字符串 `'\d+'`。
