# redirect

Issues HTTP redirects: to HTTPS, to the name a site goes by, to a path with a
prefix, or wherever a rule sends the path of the request.

- **Step:** `request` (fixed)
- **Registered as:** `redirect`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `redirect`. |
| `http_to_https` | bool | `false` | `true` sends plain HTTP requests to HTTPS. `false` leaves the scheme of the request as it is. |
| `prefix` | string | — | Path prefix to prepend. A leading `/` is added if missing; values of length ≤ 1 are ignored. |
| `host` | string | — | The name the site goes by, with a port where it is not on the default one. A request for any other host is redirected to it. |
| `rules` | string[] | — | `"<pattern> <target> [status]"`: a path the pattern matches is sent to the target, the first rule that matches. See [Rules](#rules). |
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

The name of the site and a path that moved, in one plugin:

```toml
[plugins.canonical]
category = "redirect"
http_to_https = true
host = "example.com"
status = 301
rules = [
    '^/blog/(\d+)/(.*)$ /posts/$2',
    '^/docs/(?<page>[^/]+)$ https://docs.example.com/${page}.html 308',
    '^/download$ /files/latest 302',
]
```

`GET http://www.example.com/blog/2023/hello?ref=x` →
`301 Location: https://example.com/posts/hello?ref=x`: the scheme, the host
and the path in one step.

## Rules

A rule is a regular expression, a target and optionally a status, separated by
spaces. The rules are tried in the order they are written and the first whose
pattern matches the path decides; a request no rule matches is left to
`http_to_https`, `host` and `prefix`.

- **The pattern** is matched against the path the way a location is chosen:
  with `.` and `..` resolved and `//` as one slash, written so that it can go
  into a URL again. `/public/../old/x` is `/old/x`, and what a rule captures
  of `/old/a%20b` is `a%20b`. The syntax is that of the
  [`regex`](https://docs.rs/regex) crate; a pattern matches anywhere in the
  path unless it is anchored with `^` and `$`.
- **The target** is a path that starts with `/` (`/new/$1`) or a whole URL
  (`https://…`, or `$scheme://$host/…`). `$1`, `$2` and `${name}` stand for
  what the pattern captured; write `${1}` where a letter or digit follows.
  `$host` and `$scheme` stand for the host and scheme the redirect goes to.
- **Where to is for the rule to say**, not for the request. A path target
  begins with a slash of its own, so what the pattern captured stays behind
  the host: `'^/old(.*)$ $1'` is refused, since `/old@evil.example` would
  have gone to `http://example.com@evil.example`; write `/$1` or
  `'^/old(/.*)$ /new$1'`. In a URL the host is a name or `$host`, followed by
  a `/` before anything captured: `https://new.example.com$1` is refused too.
- A **path** keeps the scheme, host and port the request would otherwise be
  redirected to or came on, and takes the query of the request along unless
  the target has one of its own. A **URL** is the `Location` as it is.
- **The status** of a rule takes the place of the plugin's `status` for that
  rule.
- Write a rule in single quotes, so that TOML leaves its backslashes alone.

A rule that does not parse - no target, a status that is not a redirect, a
pattern that does not compile, a target that is neither a path nor a URL, a
capture in the host of a URL - is a configuration error.

## Behaviour

The plugin skips the request when there is nothing to send the client
anywhere for: the scheme is what it should be, the host is the one of `host`
(or none is set), the path already starts with `prefix`, and no rule matches.
The scheme is only ever wrong for a plain HTTP request with
`http_to_https = true`. Otherwise it responds with one redirect that has all
of it: the target scheme, the host, and either the target of the rule or
`prefix` and the original path, with the query.

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
