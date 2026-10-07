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
| `allow_origin` | string | `*` | Value for `Access-Control-Allow-Origin`. Supports `$http_origin` to mirror the request, in which case `Vary: Origin` is added as well and a request without an `Origin` gets no CORS headers. |
| `allow_origins` | string[] | — | The origins that are let in, in place of `allow_origin`: each entry an origin (`https://app.example.com`) or `~` and a regular expression the whole origin has to match. See [A list of origins](#a-list-of-origins). |
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

The same for a known set of front ends, which is what to use with credentials:

```toml
[plugins.cors]
category = "cors"
path = "^/api/"
allow_origins = [
    "https://app.example.com",
    "https://admin.example.com",
    '~https://[a-z0-9-]+\.preview\.example\.com',
    "http://localhost:5173",
]
allow_headers = "Content-Type, Authorization"
allow_credentials = true
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

## A list of origins

With `allow_origins`, a request whose `Origin` is on the list gets it back in
`Access-Control-Allow-Origin` with the other CORS headers. One from any other
origin gets none of them, and its preflight is answered `204` without them
rather than passed on. What the upstream itself answers to let an origin in
(`Access-Control-Allow-Origin`, `-Credentials`, `-Methods`, `-Headers`,
`-Expose-Headers`, `-Max-Age`) is taken off the response either way: it is
this plugin and not the upstream that says who is let in, and with what -
credentials only with `allow_credentials` here, whatever the upstream sends.

- An entry is an origin as a browser sends it - scheme, host and, where it is
  not the default, port - compared without regard to case. `app.example.com`,
  `https://app.example.com/` or `https://app.example.com:443` is a
  configuration error, and so is a list with nothing on it. The origin of an
  app in a web view (`capacitor://localhost`) is one like any other.
- An entry that starts with `~` is a regular expression for the whole origin:
  it is anchored at both ends whether or not it says so, since a pattern
  that matched anywhere would take `example\.com` for
  `https://example.com.evil.net` as well. Write it in single quotes so that
  TOML leaves the backslashes alone.
- `allow_origin` and `allow_origins` are two ways to say the same thing;
  setting both is a configuration error.

Every response on a matching path carries `Vary: Origin` once the answer goes
by the origin - with `allow_origins` and with `allow_origin = "$http_origin"`
alike, and whether or not the request had an `Origin`. It used to be left off
the response to a request without one, which a shared cache then replayed to
the cross-origin request that came next.

## Behaviour

| Request | Result |
| --- | --- |
| `OPTIONS` on a matching path | `204 No Content` with all CORS headers; upstream is not called |
| Any method, request has `Origin` | CORS headers appended to the response |
| Another plugin of the location answers (a `401`, a `429`, a redirect, a file of [`directory`](directory.md) of any size) | CORS headers appended to that response as well |
| An `Origin` that is not in `allow_origins` | No CORS headers; an `OPTIONS` is answered `204` without them and the upstream is not called |
| Any method, no `Origin` | Response untouched, apart from `Vary: Origin` where the answer goes by the origin |
| Path does not match `path` | Plugin skipped in both phases |

## Usage notes

- `allow_origin = "*"` together with `allow_credentials = true` is rejected by
  browsers for a request that carries credentials. `$http_origin` with
  credentials does work, and for everyone: it reflects any origin back, so
  every site the visitor has open may act with the visitor's cookies. The
  plugin warns of either pairing when it is loaded; list the front ends in
  `allow_origins` when you need credentials.
- With a fixed `allow_origin`, preflight is answered for **any** `OPTIONS`
  request on a matching path, whether or not it carries `Origin` and
  `Access-Control-Request-Method`. With `$http_origin` or `allow_origins` an
  `OPTIONS` without an `Origin` is left to the upstream. If your upstream
  needs to see every `OPTIONS` (for example WebDAV), narrow `path`.
- `allow_origin` is a single value; an allow-list is what `allow_origins` is
  for.
- The preflight response bypasses the upstream entirely, so it is cheap.
- A response that an auth or limit plugin produces carries the CORS headers too,
  wherever `cors` stands in the plugin list. Without them the browser withholds
  the response from the page, which sees a failed request and not the `401`.
  The error page Pingap sends for an upstream failure (`502`, `504`) carries
  them as well, for the same reason; it used not to.
