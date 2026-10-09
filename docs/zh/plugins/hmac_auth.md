# hmac_auth

用共享密钥给请求签名，格式采用 HTTP Signatures（`draft-cavage-http-signatures`）。签名是针对单个请求的：覆盖方法、路径、查询串、配置要求的请求头，开了 `validate_body` 时还包括正文。即使在线路上被截获，也不能用于另一个路径或另一份正文。

[`combined_auth`](combined_auth.md) 的签名只覆盖密钥和时间，在有效期内可以用于任何请求。这不够用的时候用 `hmac_auth`。

- **步骤：** `request`（固定）
- **注册名：** `hmac_auth`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `hmac_auth`。 |
| `keys` | string[] | — | **必填。** `key_id:secret`。第一个冒号之后的全部内容都是密钥。 |
| `signed_headers` | string[] | `["host", "date"]` | 签名必须覆盖的请求头。请求目标总是必须覆盖。`date` 可以由 `x-date` 满足。 |
| `clock_skew` | duration | `5m` | 被签名的 `Date`（或 `X-Date`）与代理时钟允许相差多少。至少 `1s`。 |
| `validate_body` | bool | `false` | 正文必须与被签名的 `Content-Digest` 或 `Digest` 头一致，并且请求必须说明正文的长度。 |
| `hide_credentials` | bool | `false` | 转发给上游之前去掉 `Authorization`。 |

## 示例

```toml
[plugins.signed]
category = "hmac_auth"
keys = ["app1:6f2aaf3c66424c1a", "app2:0d5f0a9be7b14c55"]
signed_headers = ["host", "date"]
validate_body = true
hide_credentials = true

[locations.api]
upstream = "api"
path = "/api"
plugins = ["signed"]
```

## 如何签名

客户端发送：

```http
POST /api/orders?dry_run=1 HTTP/1.1
Host: api.example.com
Date: Fri, 09 Oct 2026 08:00:00 GMT
Content-Length: 8
Content-Digest: sha-256=:A3ySFO73TMOIfzpPCFtOF9digNr9JzsO4WDAnEuhz9Q=:
Authorization: Signature keyId="app1",algorithm="hmac-sha256",headers="(request-target) host date content-digest",signature="<base64>"

{"id":1}
```

`headers` 按顺序列出被签名的内容。被签名的文本是每项一行，用换行符（`\n`）连接，末尾没有换行：

```text
(request-target): post /api/orders?dry_run=1
host: api.example.com
date: Fri, 09 Oct 2026 08:00:00 GMT
content-digest: sha-256=:A3ySFO73TMOIfzpPCFtOF9digNr9JzsO4WDAnEuhz9Q=:
```

- `(request-target)` 是小写的方法、一个空格、客户端发送的路径和查询串。
- 请求头是小写的名称、冒号、一个空格、去掉首尾空白的值。同名头出现多次时，各个值用 `, ` 连接。
- `signature` 是用 `keyId` 对应的密钥对上面文本计算的 HMAC，base64 编码。`algorithm` 是 `hmac-sha256`（不写时也是它）或 `hmac-sha512`。

用 `curl` 和 `openssl`：

```bash
date=$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S GMT')
text=$(printf '(request-target): get /api/users?page=2\nhost: api.example.com\ndate: %s' "$date")
signature=$(printf '%s' "$text" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64)
curl https://api.example.com/api/users?page=2 -H "Date: $date" \
  -H "Authorization: Signature keyId=\"app1\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date\",signature=\"$signature\""
```

## 行为

- **必须签名的内容。** `(request-target)` 总是必须的，加上 `signed_headers` 里的每个请求头。覆盖得不够的签名一律拒绝，覆盖更多则没有问题。
- **时间。** 签名里有 `date` 或 `x-date` 时，它必须在代理时钟的 `clock_skew` 范围内：这决定了在线路上被看到的请求还能被重放多久。两者都被签名时取 `x-date`（浏览器不能设置 `Date`）。格式是 HTTP 日期，或者 1970 年以来的秒数。把 `date` 从 `signed_headers` 里去掉，就等于对不签时间的客户端取消了这个限制。
- **被签名的路径是客户端发来的那个。** location 的 `rewrite` 不影响签名校验。
- **`validate_body`。** 带正文的请求必须在 `Content-Digest`（`sha-256=:<base64>:`，RFC 9530）或 `Digest`（`SHA-256=<base64>`）里给出摘要，并且对这个头签名；也接受 `sha-512`。
  - 请求还必须用 `Content-Length` 说明正文的长度。长度未知的正文（chunked 上传、不带长度的 HTTP/2 流）以 `411` 拒绝：在上游收完所有分片之前，无法知道哪一片是最后一片。（没有正文、却用单独一帧而不是随请求头结束流的 HTTP/2 请求也算在内；常见的客户端不会这样做。）
  - 正文在转发给上游的过程中校验，摘要在“凑满声明长度的那一片”上比较，这一片此时还没有转发。发现不是被签名的那份时，请求在这里以 `401` 结束：上游拿到的是请求头和不足声明长度的正文，拿不到完整的请求。上游怎么处理一个中断的请求由它自己决定。正文比声明的短或者长，同样拒绝。
  - 没有正文的请求不需要摘要，签了摘要的会立即校验。
- 被后面的插件直接应答、或者由缓存应答的请求，正文没有人读取，因而不会被校验。和所有决定“谁可以访问”的插件一样，把 `hmac_auth` 排在 [`cache`](cache.md) 前面。
- **和 `cache` 一起用。** 带 `Authorization` 的请求，它的响应属于请求者自己：只有源站说明可以共享（`public`、`s-maxage`、`must-revalidate`）时才会存进缓存。判断依据是上游收到的请求。开了 `hide_credentials` 之后上游分不出是谁签的名，响应会被缓存，并提供给所有签名有效的客户端，和 [`basic_auth`](basic_auth.md) 一样。如果上游靠别的信息区分调用方（比如一个被签名的请求头），请把这个头加进 cache 插件的 `headers`，或者不要开缓存。
- 被签名的请求头如果有不是文本的值（可见 ASCII 之外的字节），请求会被拒绝，而不是跳过这个值。
- **拒绝。** 请求进来时就被拒绝的，返回 `401` 和 `WWW-Authenticate: Signature realm="pingap",headers="..."`，后者列出必须签名的内容。正文说明请求哪里不对（没有签名、某个头没有覆盖、时间相差太多）；密钥不存在和签名不匹配都返回 `Signature invalid`，不加区分。正文没有长度的是 `411`。正文传到一半发现不是被签名的那份时，请求以代理的 `401` 错误页结束，不带上面那个头。

## 使用说明

- 密钥以明文写在配置里，admin 里也是原样显示。日志，以及写进日志、发给 webhook 的配置差异里，`keys` 显示为校验和。
- HTTP/2 没有 `Host` 头，这时请求的主机名同样作为 `host` 参与签名。
- 插件不记录见过的请求：在 `clock_skew` 之内，同一个请求可以原样再发一次，但不能被改动。
- 插件不会额外告诉上游是谁在调用。上游可以从 `Authorization` 里读 `keyId`（除非 `hide_credentials` 把这个头去掉了）；或者让客户端把自己的名字放在一个单独的请求头里，并把这个头加进 `signed_headers`。
