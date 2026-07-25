# ip_restriction

按客户端 IP 地址或 CIDR 范围做允许/拒绝列表。

- **步骤：** `request`（固定）
- **注册名：** `ip_restriction`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `ip_restriction`。 |
| `ip_list` | string[] | `[]` | IPv4/IPv6 地址与 CIDR 范围。 |
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

客户端 IP 来自 `pingap_core::get_client_ip`，优先 `X-Forwarded-For` / `X-Real-IP`，否则回退到对端地址。请配置 `basic.trusted_proxies`，仅在来自真实负载均衡的连接上信任这些头——否则任意客户端可伪造 IP 绕过允许列表。

```toml
[basic]
trusted_proxies = ["10.0.0.0/8"]
```

## 响应

| Situation | Status | Body |
| --- | --- | --- |
| 策略拦截 | 403 | `message` |
| 客户端 IP 无法解析 | 400 | 解析错误文本 |

## 使用说明

- 结果是普通 403，无 `Retry-After` 或挑战；若需节流而非拦截，请用 [`limit`](limit.md)。
- 国家级规则见 [`geo_restriction`](geo_restriction.md)。
