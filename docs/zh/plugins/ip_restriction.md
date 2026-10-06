# ip_restriction

按客户端 IP 地址或 CIDR 范围做允许/拒绝列表。

- **步骤：** `request`（固定）
- **注册名：** `ip_restriction`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `ip_restriction`。 |
| `ip_list` | string[] | `[]` | IPv4/IPv6 地址与 CIDR 范围。既不是 IP 也不是 CIDR 的条目会在配置校验时报错。 |
| `type` | string | `allow` | `deny` 拦截列表中的 IP；其他值（含未设置）仅允许列表中的 IP。 |
| `message` | string | `Request is forbidden` | 403 响应正文。 |

`type` 与 `"deny"` 做字面比较。其他任何值（含空）都视为允许列表模式，因此空 `ip_list` 且未设 `type` 会拦截所有请求。请显式设置 `type`。

## 示例

仅允许内网访问管理路径：

```toml
[plugins.internalOnly]
category = "ip_restriction"
type = "allow"
ip_list = ["127.0.0.1", "10.0.0.0/8", "192.168.1.0/24", "::1"]
message = "Internal access only"

[locations.admin]
upstream = "admin"
path = "/admin"
plugins = ["internalOnly"]
```

拒绝若干滥用网段：

```toml
[plugins.blockList]
category = "ip_restriction"
type = "deny"
ip_list = ["1.2.3.4", "203.0.113.0/24"]
```

## 客户端 IP 解析

列表比对的是一个客户端无法自行指定的地址。直连时就是连接的对端地址；在负载均衡或 CDN 之后，是该代理通过 `X-Forwarded-For` / `X-Real-IP` 报告的地址——但前提是这个代理写在了 `basic.trusted_proxies` 里：

```toml
[basic]
trusted_proxies = ["10.0.0.0/8"]
```

配置了 `trusted_proxies` 之后：

- 不是来自可信代理的连接，以对端地址作为客户端 IP，忽略它带来的转发头。
- 经过可信代理时，`X-Forwarded-For` 从右向左读。每一级代理都会把收到请求的来源地址追加在末尾，所以属于可信代理的条目被跳过，第一个不属于可信代理的条目就是客户端。它左边的内容是该客户端自己发来的，不会被采用：从 `10.0.0.2` 收到 `X-Forwarded-For: 6.6.6.6, 9.9.9.9` 时，客户端是 `9.9.9.9`。多行 `X-Forwarded-For` 按一个列表处理，条目可以带端口（`9.9.9.9:4321`、`[2001:db8::1]:4321`）。
- 没有 `X-Forwarded-For` 时取 `X-Real-IP`，再没有则取对端地址。

可信代理自己也要配置正确：把来源地址追加到 `X-Forwarded-For`（nginx：`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`）；如果它根本不发送这个头，就要由它来设置 `X-Real-IP`。代理把这两个头按客户端发来的样子原样转发时，客户端 IP 仍然由客户端说了算。

没有配置 `trusted_proxies` 时不看转发头，地址就是对端地址。如果 pingap 前面有代理而代理没有列在其中，所有请求的地址都是这个代理的地址：允许列表要么全部放行、要么全部拒绝，拒绝列表永远匹配不到客户端。请把代理加进 `trusted_proxies`。

（以前没有配置可信代理时，任何来源的转发头都会被采用：`10.0.0.0/8` 的允许列表会放行任何发送 `X-Forwarded-For: 10.1.2.3` 的客户端。现在按 IP 的 [`limit`](limit.md)、[`geo_restriction`](geo_restriction.md) 以及 [`combined_auth`](combined_auth.md) 的 `ip_list` 也遵循同一规则。访问日志里的客户端 IP 和 `hash:ip` 不是访问控制，仍按原来的方式读取转发头。）

通过双栈监听（`[::]:80`）接入的 IPv4 客户端，地址是 `::ffff:1.2.3.4`。它按 `1.2.3.4` 匹配、记录和计数，`ip_list` 和 `trusted_proxies` 里的 IPv4 条目对它同样生效。

## 响应

| Situation | Status | Body |
| --- | --- | --- |
| 策略拦截 | 403 | `message` |
| 客户端 IP 无法解析 | 400 | 解析错误文本 |

## 使用说明

- 结果是普通 403，无 `Retry-After` 或挑战；若需节流而非拦截，请用 [`limit`](limit.md)。
- 国家级规则见 [`geo_restriction`](geo_restriction.md)。
