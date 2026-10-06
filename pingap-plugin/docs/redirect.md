# redirect

Issues HTTP redirects to force HTTPS and/or to add a path prefix.

- **Step:** `request` (fixed)
- **Registered as:** `redirect`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `redirect`. |
| `http_to_https` | bool | `false` | `true` sends plain HTTP requests to HTTPS. `false` leaves the scheme of the request as it is. |
| `prefix` | string | — | Path prefix to prepend. A leading `/` is added if missing; values of length ≤ 1 are ignored. |
| `status` | int | `307` | One of `301`, `302`, `303`, `307`, `308`. Anything else is a configuration error. |

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

The plugin skips the request when the scheme is what it should be **and** the
path already starts with `prefix`. The scheme is only ever wrong for a plain
HTTP request with `http_to_https = true`. Otherwise it responds with `status`
and a `Location` built from the target scheme, the request host, `prefix` and
the original path and query.

Without `http_to_https` the plugin only adds the prefix and the redirect keeps
the scheme the request came with: on an HTTPS listener `https://a.test/users`
goes to `https://a.test/api/users`, and `https://a.test/api/users` is passed
through. (An unset `http_to_https` used to mean "force plain HTTP", so a
prefix-only plugin on an HTTPS listener redirected every request to `http://`.
Redirecting HTTPS back to HTTP is no longer something this plugin does.)

The port of the request is kept when only the prefix is added, since the
scheme, and so the listener, stays the same: `example.com:8080/users` goes to
`http://example.com:8080/api/users`. A redirect that changes the scheme leaves
the port out and lands on the default port of the new scheme, as the old port
is not where the new scheme is served.

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
