# redirect

Issues HTTP redirects to force a scheme (usually HTTP → HTTPS) and/or to add a
path prefix.

- **Step:** `request` (fixed)
- **Registered as:** `redirect`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `redirect`. |
| `http_to_https` | bool | `false` | `true` forces HTTPS; `false` forces plain HTTP. |
| `prefix` | string | — | Path prefix to prepend. A leading `/` is added if missing; values of length ≤ 1 are ignored. |
| `status` | int | `307` | One of `301`, `302`, `307`, `308`. Anything else becomes `307`. |

## Example

```toml
[plugins.forceHttps]
category = "redirect"
http_to_https = true
status = 301

[servers.http]
addr = "0.0.0.0:80"
locations = ["redirect"]

[locations.redirect]
path = "/"
plugins = ["forceHttps"]
```

`GET http://example.com/a?b=1` → `301 Location: https://example.com/a?b=1`.

With a prefix:

```toml
[plugins.apiPrefix]
category = "redirect"
http_to_https = true
prefix = "/api"
```

`GET http://example.com/users` → `Location: https://example.com/api/users`.

## Behaviour

The plugin skips the request when the scheme already matches `http_to_https`
**and** the path already starts with `prefix`. Otherwise it responds with
`status` and a `Location` built from the target scheme, the request `Host`,
`prefix` and the original URI.

Status choice:

| Status | Method preserved | Cached by browsers |
| --- | --- | --- |
| `301` | No (POST may become GET) | Permanently — hard to undo |
| `302` | No | No |
| `307` | Yes | No |
| `308` | Yes | Permanently |

## Usage notes

- `prefix` is only prepended when the path is missing it, so a scheme redirect
  on an already prefixed url keeps `/api/users` rather than producing
  `/api/api/users`.
- Detection of "already HTTPS" uses the TLS state of the connection Pingap
  terminated. Behind a TLS-terminating load balancer every request looks like
  plain HTTP and this plugin would loop — redirect at the load balancer instead,
  or drop this plugin there.
- `301`/`308` are cached aggressively by browsers. Start with `307` and switch to
  a permanent code once the setup is proven.
