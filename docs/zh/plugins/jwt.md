# jwt

JWT 认证，支持三种校验模式，并可选用一个端点把上游响应签发为令牌。

- **步骤：** 校验在 `request`；签发时还会钩住 `response` / `response_body`
- **注册名：** `jwt`

## 校验模式

由配置的密钥字段决定模式，并按以下顺序尝试：

1. **静态非对称密钥** — `algorithm` 为 `RS256` `RS384` `RS512` `PS256` `PS384` `PS512` `ES256` `ES384` 之一，且 `public_key` 为 PEM。算法被固定，令牌声明不同 `alg` 会被拒绝（防止算法混淆降级）。
2. **远程 JWKS** — 设置了 `jwks_url`。按令牌 `kid` 选钥并固定该 JWK 的算法；仅接受非对称算法。密钥缓存 `jwks_ttl`，单飞刷新冷却为 `min(jwks_ttl, 10s)`，刷新失败可复用过期缓存。
3. **HMAC** — 否则使用 `secret` 配合 `HS256` 或 `HS512`。

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `jwt`。 |
| `header` | string | — | 持有令牌的头；会剥离 `Bearer ` 前缀。 |
| `cookie` | string | — | 持有令牌的 Cookie。 |
| `query` | string | — | 持有令牌的查询参数。 |
| `secret` | string | — | HMAC 共享密钥。未设置 `public_key` 或 `jwks_url` 时必填。 |
| `algorithm` | string | `HS256` | 签名算法；签发时也使用该算法。 |
| `public_key` | string | — | PEM 公钥，非对称 `algorithm` 时必填。 |
| `jwks_url` | string | — | JWKS 端点 URL。 |
| `jwks_ttl` | duration | `1h` | 拉取的 JWKS 密钥新鲜度。 |
| `auth_path` | string | — | 签发令牌（而非消费）的路径。 |
| `delay` | duration | 无 | 无效令牌应答前休眠。 |

`header` / `cookie` / `query` 按该顺序只使用第一个有值的；至少设置其一。

## 示例

### HMAC

```toml
[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
secret = "123123"
algorithm = "HS256"
auth_path = "/login"
delay = "1s"

[locations.api]
upstream = "api"
path = "/"
plugins = ["jwtAuth"]
```

```bash
# mint
curl -X POST http://127.0.0.1:6188/login -d '{"id":"u-1","exp":1893456000}'
# {"token": "eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiAiSldUIn0.…"}

# use
curl -H "Authorization: Bearer eyJ…" http://127.0.0.1:6188/api/me
```

### 远程 JWKS（Auth0、Keycloak、Cognito…）

```toml
[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
jwks_url = "https://example.auth0.com/.well-known/jwks.json"
jwks_ttl = "1h"
```

### 静态公钥

```toml
[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
algorithm = "RS256"
public_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A…
-----END PUBLIC KEY-----
"""
```

## 令牌签发（`auth_path`）

对 `auth_path` 的请求完全跳过校验。回程时插件把上游响应体替换为：

```json
{"token": "<header>.<upstream body base64url>.<signature>"}
```

并设置 `content-type: application/json`，改为 chunked 传输。因此上游返回的是*声明*（`{"id":"u-1","exp":…}`），而不是令牌本身。

签发仅支持 HMAC——签名始终用 `secret` 以 `HS256` 或 `HS512` 计算。只有上游 `2xx` 才会签名；错误响应原样透传，避免失败登录被签成永不过期令牌。

## 响应

| Situation | Status | Body |
| --- | --- | --- |
| 未找到令牌 | 401 | `Jwt authorization is missing` |
| 不是三段点分结构（HMAC 模式） | 401 | `Jwt authorization format is invalid` |
| 签名错误或不支持的 `alg` | 401（在 `delay` 之后） | `Jwt authorization is invalid` |
| `exp` 已过期（HMAC 模式） | 401 | `Jwt authorization is expired` |

## 使用说明

- 非对称与 JWKS 路径通过 `jsonwebtoken` 一并校验签名与 `exp`；不校验 `aud`。
- HMAC 模式下算法取自令牌头，同时接受 `HS256` 与 `HS512`，因此仅设置 `algorithm = "HS512"` 并不会拒绝 `HS256` 令牌。`none` 及其他值会被拒绝。
- `auth_path` 与请求路径做精确相等比较。
- `auth_path` 下路径设计上就是未认证的——若外围 location 另有保护，请把签发路径单独拆到自己的 location。
