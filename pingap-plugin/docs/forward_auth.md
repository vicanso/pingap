# forward_auth

Delegates the authentication decision to an external HTTP service, the way
nginx's `auth_request` or Traefik's ForwardAuth do. For every request Pingap
issues a `GET` to `auth_url`; a `2xx` lets the request through, anything else is
relayed back to the client verbatim — which is what makes redirect-to-login flows
work.

- **Step:** `request` (fixed)
- **Registered as:** `forward_auth`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `forward_auth`. |
| `auth_url` | string | — | **Required.** Auth endpoint. Parsed at startup, so typos fail `pingap -t`. |
| `request_headers` | string[] | *(all)* | Which original request headers to forward. Empty forwards everything. |
| `add_headers` | string[] | — | Headers copied from the auth response onto the upstream request on success. The client's own headers of these names never reach the upstream. |
| `timeout` | duration | `10s` | Per-subrequest timeout. |

## What the auth service receives

The subrequest is always a `GET` to `auth_url` (the original path is *not*
appended), carrying the selected original headers plus:

| Header | Value |
| --- | --- |
| `x-forwarded-method` | Original HTTP method |
| `x-forwarded-uri` | Original path and query, as the client sent them (not normalized) |
| `x-forwarded-host` | Original `Host` |
| `x-forwarded-proto` | `https` when the client connected over TLS, else `http` |
| `x-forwarded-for` | Client IP as resolved by Pingap |
| `x-real-ip` | The same client IP |

These six are written by Pingap alone. A request that arrives with headers of
the same names has them left out of the subrequest, and so is its `Forwarded`
header: a client cannot have the auth service decide about another path,
method, host or address than its own. The client IP follows
[`basic.trusted_proxies`](ip_restriction.md#client-ip-resolution) like every
other use of the client IP.

`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`,
`Proxy-Connection`, `TE`, `Trailer`, `Upgrade` and `Expect` are never forwarded,
whatever `request_headers` says: they describe the client's connection or a body
the bodiless `GET` does not carry, and the auth service would otherwise wait for
a body that never comes.

## Example

```toml
[plugins.forwardAuth]
category = "forward_auth"
auth_url = "http://auth-service:9000/verify"
request_headers = ["Cookie", "Authorization"]
add_headers = ["X-User-Id", "X-User-Role"]
timeout = "3s"

[locations.app]
upstream = "app"
path = "/"
plugins = ["forwardAuth"]
```

With this config, `GET /dashboard` produces:

```
GET /verify HTTP/1.1
Host: auth-service:9000
Cookie: session=…
x-forwarded-method: GET
x-forwarded-uri: /dashboard
x-forwarded-host: example.com
x-forwarded-for: 1.2.3.4
```

If the service answers `200` with `X-User-Id: 42`, the upstream sees
`GET /dashboard` with `X-User-Id: 42` added. If it answers
`302 Location: /login`, the client gets that redirect.

## Behaviour

| Auth service result | Client sees |
| --- | --- |
| `2xx` | Request proceeds; `add_headers` are set on the upstream request from the auth response |
| Any other status | That status, its headers and its body, relayed as-is |
| Unreachable / timed out | `502 Bad Gateway`, body `Forward auth request failed` |

`content-length`, `transfer-encoding`, `connection` and the other hop-by-hop
headers are stripped from the relayed response because Pingap re-frames it. A
status outside the valid HTTP range degrades to `403`. Headers the auth service
sends more than once reach the client as often: every `Set-Cookie` of a login
redirect, every `WWW-Authenticate` challenge.

The headers named in `add_headers` carry the auth service's word to the
upstream, and nothing else does: each of them is removed from the request
first, then set from the auth response when the response has it. A client that
sends `X-User-Id: admin` itself does not get that value through, whether the
auth service returns the header or not.

Redirects from the auth service are never followed: a `302` is relayed as the
decision. Following it, as an HTTP client does by default, would have turned the
login page's `200` into an approval.

## Usage notes

- Every request costs one subrequest. Keep the auth service local and fast, cache
  aggressively on its side, or scope this plugin to the locations that need it.
- `timeout` bounds the whole subrequest. A generous value turns an auth outage
  into a latency outage; 1–3 s is usually right.
- Leaving `request_headers` empty forwards `Authorization`, cookies and
  everything else to `auth_url`. List explicitly when the auth service is
  operated by someone else.
- Trailing state such as `Set-Cookie` from a *successful* auth response is not
  propagated to the client — only `add_headers` are, and only onto the upstream
  request.
- Every entry of `request_headers` and `add_headers` has to be a header name,
  in any case. One that is not (`X Bad`, `X-User:`, an empty string) is a
  configuration error and reported by `pingap -t`; it used to load and then
  match nothing, so what the auth service said under that name never reached
  the upstream.
