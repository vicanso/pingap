# oidc

只放行在 OpenID Connect 身份提供方（Keycloak、Authentik、Dex、Google、Microsoft Entra ID、Okta 等）登录过的用户。给没有自带登录的内部站点加一道登录，这是最常见的做法。

没有会话的浏览器访问页面时，被重定向到身份提供方。它带着一个 code 回来，Pingap 用这个 code 向身份提供方换取 ID token；token 用身份提供方的公钥校验，然后用其中的用户信息建立会话。会话保存在加密的 cookie 里：代理这一侧不存任何东西，所有持有同一个 `cookie_secret` 的实例都能读取。

- **步骤：** `request`（固定）
- **注册名：** `oidc`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `oidc`。 |
| `issuer` | string | — | **必填。** 身份提供方的地址，和它自己声明的一致。会读取 `<issuer>/.well-known/openid-configuration`。 |
| `client_id` | string | — | **必填。** 本站点在身份提供方注册的 id。 |
| `client_secret` | string | — | 对应的密钥。公开客户端留空。 |
| `cookie_secret` | string | — | **必填。** 加密会话用的密钥，至少 16 个字符。所有实例必须相同。 |
| `redirect_path` | string | `/oauth2/callback` | 身份提供方把浏览器送回来的路径。 |
| `redirect_url` | string | — | 浏览器看到的 `redirect_path` 的完整地址，只有和请求里的不一致时才需要。 |
| `logout_path` | string | — | 结束会话的路径。不设置则没有。 |
| `scopes` | string[] | `[]` | 在 `openid` 之外额外请求的 scope，`openid` 总是会请求。 |
| `cookie_name` | string | `pingap_oidc` | 会话 cookie 的名字。不能以 `__Host-` 开头。 |
| `session_ttl` | duration | `12h` | 一次登录保持多久。至少 `1m`。 |
| `claims_to_headers` | string[] | `[]` | `claim:Header-Name`：把身份提供方给出的用户信息发给上游。请求头名取最后一个冒号之后的部分，所以名字是 `https://example.com/roles` 这样的 claim 也能用。不能是 `Host`、`Connection`、`Content-Length`、`Transfer-Encoding`。 |

`client_secret` 和 `cookie_secret` 是凭据：配置变更的日志里会被遮蔽，可以写成 `$ENV:NAME` 或 `$FILE:/path`。

## 示例

```toml
[plugins.login]
category = "oidc"
issuer = "https://id.example.com/realms/staff"
client_id = "wiki"
client_secret = "$ENV:WIKI_OIDC_SECRET"
cookie_secret = "$FILE:/run/secrets/wiki-cookie"
scopes = ["email", "profile"]
claims_to_headers = ["email:X-User-Email", "groups:X-User-Groups"]
logout_path = "/oauth2/logout"

[locations.wiki]
upstream = "wiki"
host = "wiki.example.com"
plugins = ["login"]
```

在身份提供方那边，把 `https://wiki.example.com/oauth2/callback` 登记为这个客户端的回调地址。

## 请求的处理

- **有会话：** 转发给上游。`claims_to_headers` 里的每一项，把对应的 claim 写进请求头；客户端自己写的同名请求头会先被去掉，不论有没有会话——只是把 `-` 写成 `_` 的名字（`X_User_Email`）也一样去掉，对 CGI、WSGI、Rack、PHP 后面的上游来说它们是同一个变量。客户端也不能通过在 `Connection` 里点名的方式让这些请求头被去掉。claim 是文本、数字、布尔值时原样发送，是它们的列表时用逗号连接；其他类型、或者用户没有这个 claim 时，不发送这个请求头。
- **没有会话，浏览器在访问页面**（`GET` 且 `Sec-Fetch-Mode: navigate`；浏览器不发这个头时，看 `Accept` 里有没有 `text/html`）：重定向到身份提供方。
- **没有会话，其他请求**（脚本发起的 fetch、提交的表单、API 客户端）：`401 Login required`。这类请求没法跟着跳到登录页，提交的表单还会丢掉提交的内容。
- **`redirect_path`：** 登录的最后一步，见下文。
- **`logout_path`：** 去掉会话 cookie；身份提供方有结束自己会话的地址（`end_session_endpoint`）时，把浏览器带着 `client_id` 重定向过去，否则返回一句 `Logged out`。到这个路径的任何请求都会这样处理，不看方法、也不看来源：其他站点可以把浏览器引到这里让用户退出登录，但也仅此而已。

`redirect_path`（以及 `logout_path`）必须能匹配到带有这个插件的 location——可以是提供页面的那个，也可以是另一个带同一个插件的。它们和客户端发来的原始路径比较，登录后回到的页面也是客户端发来的原始地址：location 的 `rewrite` 不影响这两点。

## 登录过程

1. 浏览器被重定向到身份提供方的 `authorization_endpoint`，带着 `response_type=code`、客户端、scope、随机的 `state` 和 `nonce`，以及 PKCE 的 challenge（`S256`）。属于这次登录的东西——state、nonce、PKCE 的 verifier、浏览器原本要去的页面——保存在一个只发给 `redirect_path` 的加密 cookie 里，有效 10 分钟。两个标签页同时登录各有各的 cookie；一次登录完成时，会顺带清掉没有走完的那些登录留下的 cookie。页面地址太长、放不进 cookie 时（约 2.6 KB），登录后不回到那个页面，而是回到 `/`。
2. 身份提供方把浏览器带着 `code` 和 `state` 送回 `redirect_path`。请求里没有带着这个 state 对应的登录 cookie 时，返回 `400`，不会去问身份提供方。
3. 用 code 向 `token_endpoint` 换取 token（带上 PKCE 的 verifier；客户端用 `client_secret_basic` 认证，身份提供方声明不支持时用 `client_secret_post`）。
4. ID token 必须由身份提供方的某个公钥签名（`jwks_uri`，只接受非对称算法）、由 `issuer` 签发、受众是这个 `client_id`、没有过期，并且带着这次登录的 `nonce`。任何一项不满足都是 `502 Login failed`，原因在日志里（`oidc login failed`）。
5. 会话的内容是 `sub` 和 `claims_to_headers` 里列出的 claim，有效期 `session_ttl`，cookie 带 `HttpOnly`、`SameSite=Lax`，站点通过 TLS 访问时还带 `Secure`。浏览器被送回它原本要去的页面——只会是本站的路径，不会是其他站点。

身份提供方拒绝登录（`error=access_denied`）时返回 `403`。

## 说明

- **会话就是登录那一刻身份提供方说的话。** 在 `session_ttl` 到期之前不会再去问：用户在身份提供方被删除、被移出某个组之后，会话仍然有效到那时。`session_ttl` 应该按这件事能容忍多久来定。没有 refresh token，也不支持 back-channel logout。
- **`cookie_secret`。** 拿到它的人可以伪造任何人的会话。修改它会让所有会话失效。除此之外，没有办法提前结束某一个会话。
- **会话的大小。** 必须放得进一个 cookie（加密后约 3.8 KB）。某个要发给上游的 claim 里有几百个组的用户放不下，登录会失败，日志里是 `the session does not fit a cookie`。
- **前面还有代理或 CDN 时**，告诉身份提供方的回调地址是按请求拼出来的：到 Pingap 的连接是 TLS 就用 `https`，主机名取请求的 `Host`。这和浏览器实际使用的地址不一致时，设置 `redirect_url`；这时 cookie 是否带 `Secure` 看它是不是 `https`。
- **身份提供方的元数据** 在第一个需要它的请求到来时读取，保留一小时；公钥保留一小时，token 指明的公钥不在其中时重新读取。身份提供方连不上不影响已有会话的请求。连不上期间只是隔一段时间（一次尝试结束 10 秒之后）才再试一次，不是每个请求都去试：其余的请求立即得到 `502`。
- **和 `cache` 一起用时：** 把这个插件放在它前面，和所有“决定谁能访问”的插件一样。缓存里的响应是给所有有会话的人的，不是给某一个用户的：属于单个用户的内容要在上游标记 `Cache-Control: private`。
- **多个 location 共用一次登录。** cookie 是按主机名生效的。同一个主机名下共用这个插件的 location 共用会话；另配一个 `cookie_name` 和 `redirect_path` 都不同的插件，则有自己独立的登录。
