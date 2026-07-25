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
| `add_headers` | string[] | — | Headers copied from the auth response onto the upstream request on success. |
| `timeout` | duration | `10s` | Per-subrequest timeout. |

## What the auth service receives

The subrequest is always a `GET` to `auth_url` (the original path is *not*
appended), carrying the selected original headers plus:

| Header | Value |
| --- | --- |
| `x-forwarded-method` | Original HTTP method |
| `x-forwarded-uri` | Original path and query |
| `x-forwarded-host` | Original `Host` |
| `x-forwarded-for` | Client IP as resolved by Pingap |

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
| `2xx` | Request proceeds; `add_headers` are copied onto the upstream request |
| Any other status | That status, its headers and its body, relayed as-is |
| Unreachable / timed out | `502 Bad Gateway`, body `Forward auth request failed` |

`content-length`, `transfer-encoding` and `connection` are stripped from the
relayed response because Pingap re-frames it. A status outside the valid HTTP
range degrades to `403`.

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
