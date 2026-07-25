# combined_auth

面向机器到机器 API 的签名请求认证。调用方用 `app_id` 标识自身，用 HMAC 风格摘要证明持有共享密钥，签名中的时间戳限制被截获请求的可重放时长。还可按应用附加可选 IP 允许列表。

- **步骤：** `request`（固定）
- **注册名：** `combined_auth`

## 配置

`authorizations` 为表数组，每个应用一条：

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `combined_auth`。 |
| `authorizations` | table[] | — | **必填。** 每个应用一条。 |
| `authorizations[].app_id` | string | — | 调用方以 `?app_id=` 发送的标识。无此项的条目被跳过。 |
| `authorizations[].secret` | string | — | 共享密钥。字面量 `*` 会禁用该应用的**所有**检查。 |
| `authorizations[].deviation` | int | `0` | 允许的最大时钟偏差（秒）。 |
| `authorizations[].ip_list` | string[] | — | 允许使用该 app id 的 IP / CIDR。 |

## 请求格式

调用方发送三个查询参数：

| Parameter | Meaning |
| --- | --- |
| `app_id` | 使用 `authorizations` 中的哪一条 |
| `ts` | 当前 Unix 时间（秒） |
| `digest` | `hex(sha256("<secret>:<ts>"))`，大小写不敏感 |

注意：`digest` 只覆盖密钥与时间戳——认证的是*调用方*，而非请求体或路径。

## 示例

```toml
[plugins.appAuth]
category = "combined_auth"

[[plugins.appAuth.authorizations]]
app_id = "pingap"
secret = "123123"
deviation = 60
ip_list = ["127.0.0.1", "192.168.1.0/24"]

[[plugins.appAuth.authorizations]]
app_id = "internal"
secret = "*"          # unrestricted, use with care
```

客户端：

```bash
APP_ID=pingap
SECRET=123123
TS=$(date +%s)
DIGEST=$(printf '%s:%s' "$SECRET" "$TS" | shasum -a 256 | cut -d' ' -f1)

curl "http://127.0.0.1:6188/api/orders?app_id=$APP_ID&ts=$TS&digest=$DIGEST"
```

## 校验顺序

1. `app_id` 存在且已知——否则 401。
2. `secret == "*"` → 立即放行（跳过 IP、时间戳与摘要检查）。
3. 配置了 `ip_list` 时，客户端 IP 必须匹配。
4. `ts` 存在、为数字，且 `|now - ts| <= deviation`。
5. `digest` 存在且等于期望值，常量时间比较。

任一失败返回 **401**，带 `cache-control: private, no-store`，正文为原因（例如 `Plugin combined_auth invalid, message: digest is invalid`）。

## 使用说明

- `deviation` 默认为 `0`，实际会拒绝一切请求：请显式设置。30–120 秒较合理——更大值会扩大重放窗口。
- `secret = "*"` 也会绕过 IP 允许列表。若只需未认证但限 IP，请改用 [`ip_restriction`](ip_restriction.md)。
- 时间戳校验要求代理与客户端时钟同步；请运行 NTP。
- 摘要不覆盖 URL，截获的签名在 `deviation` 窗口内可用于任意路径。窗口应尽量短，并全程使用 TLS。
