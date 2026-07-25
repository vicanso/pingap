# csrf

使用双提交 Cookie 模式的 CSRF 防护。客户端从 `token_path` 获取签名令牌（同时写入 Cookie），之后每次会改变状态的请求必须在请求头中回显该令牌。跨站攻击者能让浏览器带上 Cookie，但无法读取 Cookie 来设置请求头。

- **步骤：** `request`（固定）
- **注册名：** `csrf`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `csrf`。 |
| `token_path` | string | — | **必填。** 签发新令牌的路径。 |
| `key` | string | — | **必填。** 签名密钥。所有实例必须一致。 |
| `name` | string | `x-csrf-token` | 请求头与 Cookie 共用的名称。 |
| `ttl` | duration | `0`（永不过期） | 令牌寿命；同时作为 Cookie `Max-Age`。 |

## 令牌格式

```
<nanoid(12)>.<unix-seconds in hex>.<base64(sha256(id "." ts  ‖ key))>
```

签名以常量时间校验，没有 `key` 无法伪造令牌。

## 示例

```toml
[plugins.csrf]
category = "csrf"
token_path = "/csrf-token"
key = "WjrXUG47wu"
ttl = "1h"

[locations.app]
upstream = "app"
path = "/"
plugins = ["csrf"]
```

浏览器侧：

```js
// once per session / page load
await fetch("/csrf-token", { credentials: "same-origin" });
// -> 204 No Content, Set-Cookie: x-csrf-token=…; Path=/; Max-Age=3600

const token = document.cookie.match(/x-csrf-token=([^;]+)/)[1];

await fetch("/api/orders", {
  method: "POST",
  headers: { "x-csrf-token": token, "content-type": "application/json" },
  credentials: "same-origin",
  body: JSON.stringify({ sku: "abc" }),
});
```

## 行为

| Request | Result |
| --- | --- |
| 任意路径上的 `GET`/`HEAD`/`OPTIONS` | 跳过，无需令牌 |
| `token_path` 上任意方法 | `204`，带 `Set-Cookie` 与 `cache-control: private, no-store` |
| 其他方法，请求头缺失 | `401`，`Csrf token is empty or invalid` |
| 其他方法，请求头 ≠ Cookie | `401` |
| 其他方法，签名错误或过期 | `401` |

## 使用说明

- `token_path` 精确匹配，且在安全方法检查**之前**判断，因此任意方法都会应答。
- Cookie 仅设置 `Path=/`。Pingap 不设置 `Secure`、`HttpOnly` 或 `SameSite`——`HttpOnly` 反而会破坏该模式，因为 JavaScript 需要读 Cookie 构造请求头。请在前面终止 TLS，并在应用层考虑 `SameSite` 策略。
- 同一负载均衡后的每个 Pingap 实例必须共享 `key`，否则一节点签发的令牌会被另一节点拒绝。
- `ttl = 0` 表示令牌永不过期；更建议设置明确寿命。
