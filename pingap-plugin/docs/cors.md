# cors

Cross-Origin Resource Sharing. Answers preflight `OPTIONS` requests directly and
attaches the CORS headers to real responses.

- **Step:** `request` for preflight, `response` for the actual response
- **Registered as:** `cors`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `cors`. |
| `path` | string | — | Regex; only matching paths get CORS treatment. Unset means all paths. |
| `allow_origin` | string | `*` | Value for `Access-Control-Allow-Origin`. Supports `$http_origin` to mirror the request. |
| `allow_methods` | string | `GET, POST, PUT, PATCH, DELETE, OPTIONS` | Value for `Access-Control-Allow-Methods`. |
| `allow_headers` | string | — | Value for `Access-Control-Allow-Headers`. |
| `allow_credentials` | bool | `false` | Emit `Access-Control-Allow-Credentials: true`. |
| `expose_headers` | string | — | Value for `Access-Control-Expose-Headers`. |
| `max_age` | duration | `1h` | Value for `Access-Control-Max-Age`. `0` omits the header. |

## Examples

Public read-only API:

```toml
[plugins.cors]
category = "cors"
path = "^/api/"
allow_origin = "*"
allow_methods = "GET, OPTIONS"
allow_headers = "Content-Type"
max_age = "24h"
```

Credentialed API for a single-page app on another origin:

```toml
[plugins.cors]
category = "cors"
path = "^/api/"
allow_origin = "$http_origin"
allow_methods = "GET, POST, PUT, DELETE, OPTIONS"
allow_headers = "Content-Type, Authorization, X-Requested-With"
expose_headers = "X-Request-Id, X-Total-Count"
allow_credentials = true
max_age = "1h"
```

Check it:

```bash
curl -i -X OPTIONS http://127.0.0.1:6188/api/users \
  -H 'Origin: https://app.example.com' \
  -H 'Access-Control-Request-Method: POST'
# HTTP/1.1 204 No Content
# access-control-allow-origin: https://app.example.com
# access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
# access-control-allow-credentials: true
# access-control-max-age: 3600
```

## Behaviour

| Request | Result |
| --- | --- |
| `OPTIONS` on a matching path | `204 No Content` with all CORS headers; upstream is not called |
| Any method, request has `Origin` | CORS headers appended to the response |
| Any method, no `Origin` | Response untouched |
| Path does not match `path` | Plugin skipped in both phases |

## Usage notes

- `allow_origin = "*"` together with `allow_credentials = true` is rejected by
  browsers. Use `$http_origin` when you need credentials — but only when the
  location is otherwise access-controlled, since it reflects any origin back.
- Preflight is answered for **any** `OPTIONS` request on a matching path, whether
  or not it carries `Origin` and `Access-Control-Request-Method`. If your
  upstream needs to see `OPTIONS` (for example WebDAV), narrow `path`.
- `allow_origin` supports a single value only; use `$http_origin` plus an
  upstream/edge check to implement an origin allow-list.
- The preflight response bypasses the upstream entirely, so it is cheap.
