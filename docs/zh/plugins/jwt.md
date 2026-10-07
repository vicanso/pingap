# jwt

JWT 认证，支持三种校验模式，并可选用一个端点把上游响应签发为令牌。

- **步骤：** 校验在 `request`；签发时还会钩住 `response` / `response_body`
- **注册名：** `jwt`

## 校验模式

由配置的密钥字段决定模式，并按以下顺序尝试：

1. **静态非对称密钥** — `algorithm` 为 `RS256` `RS384` `RS512` `PS256` `PS384` `PS512` `ES256` `ES384` `EdDSA` 之一，且 `public_key` 为 PEM（`EdDSA` 对应 Ed25519 公钥）。算法被固定，令牌声明不同 `alg` 会被拒绝（防止算法混淆降级）。
2. **远程 JWKS** — 设置了 `jwks_url`。按令牌 `kid` 选钥并固定令牌声明的算法；仅接受非对称算法。没有 `kid` 的令牌会逐一尝试所有密钥，没有 `kid` 的密钥（典型的单密钥 JWKS）会被保留而不是丢弃。密钥缓存 `jwks_ttl`，单飞刷新冷却为 `min(jwks_ttl, 10s)`，刷新失败可复用过期缓存。冷却从上一次尝试算起，不论成功与否：端点不可用期间，每个冷却周期只请求一次，其余请求直接用已有的缓存判断，不会排队等待。
3. **HMAC** — 否则使用 `secret` 配合 `HS256`、`HS384` 或 `HS512`。

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
| `issuers` | string[] | — | 配置后，令牌的 `iss` 必须是其中之一。见[声明](#声明)。 |
| `audiences` | string[] | — | 配置后，令牌的 `aud` 必须包含其中之一。 |
| `required_claims` | string[] | — | 令牌必须带有的声明，不论取值。 |
| `claims_to_headers` | string[] | — | 每项是 `声明:请求头`：令牌校验通过后，把该声明放进这个请求头发给上游。 |
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

### 声明：令牌是给谁的，持有者是谁

```toml
[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
jwks_url = "https://example.auth0.com/.well-known/jwks.json"
issuers = ["https://example.auth0.com/"]
audiences = ["https://api.example.com"]
required_claims = ["sub"]
claims_to_headers = ["sub:X-User-Id", "scope:X-User-Scope"]
```

## 声明

签名说明令牌是谁签发的，不说明它是签给谁用的。身份提供方用同一把密钥给在它那里注册的所有应用签发令牌，不校验 `aud` 的话，发给别的应用的令牌在这里同样通过。下面四项在三种校验模式下行为一致，都在签名、`exp`、`nbf` 通过之后判断。

- `issuers`——令牌的 `iss` 必须等于其中一项，按原样比较（区分大小写，结尾的 `/` 也算）。没有 `iss` 或者它不是字符串的令牌会被拒绝。
- `audiences`——令牌的 `aud`（一个字符串或字符串列表）必须包含其中一项。没有 `aud` 的令牌会被拒绝。
- `required_claims`——列出的每个声明都必须存在。不看取值，但 `null` 视为没有。
- `claims_to_headers`——每项是 `声明:请求头`。令牌校验通过后，声明写进发往上游的请求的这个头：

  | 声明 | 请求头 |
  | --- | --- |
  | 字符串、数字、布尔值 | 值的文本形式 |
  | 以上类型的列表 | 各项用 `,` 连接 |
  | 对象、`null`、含对象的列表、不能作为请求头的值（带换行） | 不设置 |
  | 令牌里没有 | 不设置 |

  客户端自己带的同名请求头**总是会被删除**，令牌里没有这个声明时也一样：读取 `X-User-Id` 的上游拿到的要么是令牌里的值，要么什么都没有，不会是客户端填的。客户端在 `Connection` 头里点名这个头、想让它在转发途中被去掉，也不起作用；把它写成 `X_User_Id` 发过来也一样——对代理来说那是另一个头，但对 CGI、WSGI、Rack、PHP 后面的上游来说是同一个变量（`HTTP_X_USER_ID`），所以和目标名只差 `_` / `-` 的头会一并删除。`Host`、`Content-Length`、`Transfer-Encoding`、`Connection` 不能作为目标。只能指定顶层声明；请求头名称取最后一个冒号之后的部分，所以可以指定用 url 命名的声明（`https://example.com/roles:X-Roles`）。列表用普通的 `,` 连接，所以本身带逗号的一项，在按逗号拆分的上游看来是两项。

声明只由这个插件、在挂了它的 location 上传递。信任 `X-User-Id` 的上游不能同时从没挂这个插件的 location 访问到，那里客户端自带的头会原样通过。

对 `auth_path` 的请求不带令牌：不做任何校验，也没有声明可传。`claims_to_headers` 里列出的请求头同样会从这些请求里删掉。

## 令牌签发（`auth_path`）

对 `auth_path` 的请求完全跳过校验。回程时插件把上游响应体替换为：

```json
{"token": "<header>.<upstream body base64url>.<signature>"}
```

并设置 `content-type: application/json`，改为 chunked 传输。因此上游返回的是*声明*（`{"id":"u-1","exp":…}`），而不是令牌本身。

响应体是逐字节签名的，所以发往上游的 `auth_path` 请求不带客户端的 `Accept-Encoding`，声明以未压缩的形式返回。上游仍然压缩时返回 `502`，而不是签出一个载荷是 gzip 数据的令牌。

签发仅支持 HMAC——签名始终用 `secret` 以 `HS256`、`HS384` 或 `HS512` 计算。只有上游 `2xx` 才会签名；错误响应原样透传，避免失败登录被签成令牌。

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
| `iss` 不在 `issuers` 里 | 401 | `Jwt authorization issuer is not allowed` |
| `aud` 不包含 `audiences` 里的任何一项 | 401 | `Jwt authorization audience is not allowed` |
| 缺少 `required_claims` 里的某个声明 | 401 | `Jwt authorization has no <声明>` |
| `auth_path` 的声明没有 `exp` 且 `require_exp` 开启 | 502，或关闭连接 | 错误页 |

## 使用说明

- 非对称与 JWKS 路径通过 `jsonwebtoken` 一并校验签名、`exp` 与 `nbf`；`iss` 和 `aud` 只在配置了 `issuers` / `audiences` 时才校验。HMAC 路径校验同样两个时间声明，用同样的 `leeway`，整数或浮点数都接受，且不要求头部带 `typ`。`delay` 针对的是靠猜测能得到的结果。HMAC 模式下只有签名错误会等待；两种公钥模式下，校验库对令牌的各种失败（包括过期）只给一个结果，所以每一种都会等待。因为签发方、受众或缺少声明被拒绝的令牌签名是对的，任何模式下都立即应答。
- HMAC 模式下显式配置的 `algorithm` 会被强制执行：配置 `HS512` 时拒绝 `HS256` 令牌，反之亦然。不设置 `algorithm` 时 `HS256`、`HS384`、`HS512` 都接受。`none` 及其他值一律拒绝；密钥路径无法校验的 `algorithm`（没有 `public_key` / `jwks_url` 的非对称算法）在启动时就会报错。
- 任何模式都不支持 `ES512`：校验公钥模式所用的库没有 P-521。
- `auth_path` 与请求路径做精确相等比较。
- `auth_path` 下路径设计上就是未认证的——若外围 location 另有保护，请把签发路径单独拆到自己的 location。
