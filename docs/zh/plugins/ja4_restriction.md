# ja4_restriction

按 TLS 连接的 [JA4 指纹](../crates/proxy.md#ja4-指纹)做允许/拒绝列表：即客户端的 TLS 栈是什么，不管它的 `User-Agent` 怎么写。一个自称 Chrome 的脚本，握手方式仍然是它所用的库的。

- **步骤：** `request`（固定）
- **注册名：** `ja4_restriction`
- **需要请求所在的 server 开启 `ja4 = true`**

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `ja4_restriction`。 |
| `ja4_list` | string[] | — | **必填。**与指纹的 `ja4` 形式匹配的正则表达式，启动时编译成一个集合。写完整的指纹即匹配它本身。 |
| `type` | string | `allow` | `allow` **只**放行匹配的指纹；`deny` 拒绝匹配的指纹。不区分大小写；其他值是配置错误。 |
| `message` | string | `Request is forbidden` | 403 响应正文。 |
| `dry_run` | bool | `false` | 本应拒绝的请求照常放行，改为记录一条警告日志：新规则可以先在真实流量上观察，再真正拦截。见[只记录不拦截](limit.md#只记录不拦截)。 |

指纹形如 `t13d1516h2_8daaf6152771_e5627efa2ab1`：协议与 TLS 版本、是否带 SNI、cipher 与扩展的个数、第一个 ALPN 值的首尾两个字符（`h2`；`http/1.1` 为 `h1`；没有 ALPN 为 `00`），然后是 cipher 列表的哈希，以及扩展列表（不含 SNI 与 ALPN）连同签名算法的哈希。正则**不锚定**：`^t13d` 是所有带 SNI 的 TLS 1.3 客户端，`_8daaf6152771_` 是一组 cipher。正则写错是启动错误，`pingap -t` 能检查出来。

## 示例

面向浏览器的站点，拒绝最高只支持 TLS 1.2 的客户端：当前的浏览器都支持 1.3，老的库和工具则不然。先观察会拒绝哪些请求：

```toml
[plugins.noOldTls]
category = "ja4_restriction"
type = "deny"
ja4_list = ["^t1[0-2]"]
message = "Please use a current browser"
dry_run = true
```

要拒绝特定的 TLS 栈，把它们的指纹从访问日志（`{:ja4}`）里完整地复制到 `ja4_list`。

内部 API 只允许 TLS 1.3 客户端：

```toml
[plugins.modernTls]
category = "ja4_restriction"
type = "allow"
ja4_list = ["^t13"]
```

## 行为

| 指纹 | `type = "allow"` | `type = "deny"` |
| --- | --- | --- |
| 匹配某条规则 | 放行 | **403** |
| 不匹配任何规则 | **403** | 放行 |
| 没有指纹（明文 http、server 未开启 `ja4`，或 Pingap 没能完整读到 ClientHello：超过 16 KiB、拆成多个 record 合计超过 18 KiB，或 5 秒内没有发完） | **403** | 放行 |

## 使用说明

- 先在 server 上开启 `ja4 = true`。不开启时所有请求都没有指纹，允许名单会拒绝全部请求。插件所在的 location 挂在没有开启它、或 `ja4 = true` 还在等重启生效的 server 上时，`pingap -t`、启动以及引入它的那次重载都会打印告警。
- 不发送指纹的客户端能绕过拒绝名单：把 ClientHello 填充到超过 16 KiB，或者拆成很多个小 record，就没有指纹。拒绝名单能管住不费这种心思的客户端；要管住其余的，用允许名单。
- 要列出的指纹可以从访问日志里找：`{:ja4}` 输出每个请求的指纹，和 `{user_agent}` 放在一起看，哪个自称对不上一目了然。
- 指纹标识的是 TLS 栈，而不是某个客户端：同一浏览器版本的所有用户共用一个指纹，浏览器或库升级后指纹也会变。拒绝名单只放工具类的 TLS 栈；允许名单上线前先用 `dry_run` 观察。
- 在终结 TLS 的代理或 CDN 后面，看到的是代理的指纹。
- 想对某类客户端限速而不是拒绝，可以在 [`limit`](limit.md#按-tls-指纹) 里按指纹计数。
