# jwt

JWT 认证，支持三种校验模式，并可选用一个端点把上游响应签发为令牌。

- **步骤：** 校验在 `request`；签发时还会钩住 `response` / `response_body`
- **注册名：** `jwt`

## 校验模式

由配置的密钥字段决定模式，并按以下顺序尝试：

1. **静态非对称密钥** — `algorithm` 为 `RS256` `RS384` `RS512` `PS256` `PS384` `PS512` `ES256` `ES384` 之一，且 `public_key` 为 PEM。算法被固定，令牌声明不同 `alg` 会被拒绝（防止算法混淆降级）。
2. **远程 JWKS** — 设置了 `jwks_url`。按令牌 `kid` 选钥并固定令牌声明的算法；仅接受非对称算法。没有 `kid` 的令牌会逐一尝试所有密钥，没有 `kid` 的密钥（典型的单密钥 JWKS）会被保留而不是丢弃。密钥缓存 `jwks_ttl`，单飞刷新冷却为 `min(jwks_ttl, 10s)`，刷新失败可复用过期缓存。冷却从上一次尝试算起，不论成功与否：端点不可用期间，每个冷却周期只请求一次，其余请求直接用已有的缓存判断，不会排队等待。
3. **HMAC** — 否则使用 `secret` 配合 `HS256` 或 `HS512`。

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `jwt`。 |
| `header` | string | — | 持有令牌的头；会剥离 `Bearer` scheme（不区分大小写）。 |
| `cookie` | string | — | 持有令牌的 Cookie。 |
| `query` | string | — | 持有令牌的查询参数。校验前会对取到的值做百分号解码。 |
| `secret` | string | — | HMAC 共享密钥。未设置 `public_key` 或 `jwks_url` 时必填。 |
| `algorithm` | string | `HS256` | 签名算法；签发时也使用该算法。 |
| `public_key` | string | — | PEM 公钥，非对称 `algorithm` 时必填。 |
| `jwks_url` | string | — | JWKS 端点 URL。 |
| `jwks_ttl` | duration | `1h` | 拉取的 JWKS 密钥新鲜度。 |
| `auth_path` | string | — | 签发令牌（而非消费）的路径。 |
| `require_exp` | bool | `true` | 令牌是否必须带 `exp`（三种校验模式都适用），以及 `auth_path` 的响应是否必须带 `exp` 才签发。见[过期时间](#过期时间)。 |
| `leeway` | duration | `60s` | 签发方的时钟和代理的时钟允许相差多少：三种校验模式下 `exp` 和 `nbf` 都按这个宽限判断。最大 `1d`。见[过期时间](#过期时间)。 |
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

响应体是逐字节签名的，所以发往上游的 `auth_path` 请求不带客户端的 `Accept-Encoding`，声明以未压缩的形式返回。上游仍然压缩时返回 `502`，而不是签出一个载荷是 gzip 数据的令牌。

签发仅支持 HMAC——签名始终用 `secret` 以 `HS256` 或 `HS512` 计算。只有上游 `2xx` 才会签名；错误响应原样透传，避免失败登录被签成令牌。

## 过期时间

没有 `exp` 的令牌只要密钥不换就一直有效，所以默认处处要求 `exp`：

- **校验**——三种模式下，载荷里没有 `exp`（或为 `null`）的令牌都返回 `401`。HMAC 模式以前会接受这样的令牌，两种公钥模式一直不接受。
- **签发**——上游返回的声明原样签名，不会补任何字段。声明不是带数值 `exp` 的 JSON 对象时不签发令牌，对 `auth_path` 的请求失败：返回 `502`；如果上游的响应头在响应体到达之前已经转发给客户端，则在响应中途关闭连接。

`require_exp = false` 恢复以前的行为，供确实需要永不过期令牌的部署使用：所有模式都接受没有 `exp` 的令牌，`auth_path` 对 `2xx` 响应不论内容一律签名。带了 `exp` 的令牌过期后仍然会被拒绝。

签发方的时钟和代理的时钟不会完全一致，所以两个时间声明都有 `leeway` 的宽限（不设置时为 `60s`）：`exp` 比代理的时钟早出这个宽限才算过期，`nbf` 比代理的时钟晚出这个宽限才算尚未生效。三种模式一致。两种公钥模式一直有 60 秒宽限（来自校验它们的库），HMAC 模式以前没有：签发方的时钟快一秒，它的令牌在一种配置下会偶尔被答成 `Jwt authorization is not yet valid`，在另一种配置下则从不会。`leeway = "0s"` 让所有模式精确到秒，对 HMAC 模式来说就是以前的行为；用默认值时，这个模式的令牌在 `exp` 之后最多一分钟内仍被接受。

## 响应

| Situation | Status | Body |
| --- | --- | --- |
| 未找到令牌 | 401 | `Jwt authorization is missing` |
| 不是三段点分结构，或载荷不是 JSON 对象（HMAC 模式） | 401 | `Jwt authorization format is invalid` |
| 签名错误或不支持的 `alg` | 401（在 `delay` 之后） | `Jwt authorization is invalid` |
| `exp` 已过去超过 `leeway`（HMAC 模式） | 401 | `Jwt authorization is expired` |
| 没有 `exp` 且 `require_exp` 开启（HMAC 模式） | 401 | `Jwt authorization has no exp` |
| `nbf` 还差超过 `leeway` 才到（HMAC 模式） | 401 | `Jwt authorization is not yet valid` |
| `auth_path` 的声明没有 `exp` 且 `require_exp` 开启 | 502，或关闭连接 | 错误页 |

## 使用说明

- 非对称与 JWKS 路径通过 `jsonwebtoken` 一并校验签名、`exp` 与 `nbf`；不校验 `aud`。HMAC 路径校验同样两个声明，用同样的 `leeway`，整数或浮点数都接受，且不要求头部带 `typ`。`delay` 只作用于签名错误，那是唯一能靠猜测得到的结果。
- HMAC 模式下显式配置的 `algorithm` 会被强制执行：配置 `HS512` 时拒绝 `HS256` 令牌，反之亦然。不设置 `algorithm` 时两者都接受。`none` 及其他值一律拒绝；密钥路径无法校验的 `algorithm`（`HS384`，或没有 `public_key` / `jwks_url` 的非对称算法）在启动时就会报错。
- `auth_path` 与请求路径做精确相等比较。
- `auth_path` 下路径设计上就是未认证的——若外围 location 另有保护，请把签发路径单独拆到自己的 location。
