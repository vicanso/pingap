# mock

Returns a canned response instead of proxying, optionally after a delay. Handy
for stubbing an endpoint that does not exist yet, keeping a maintenance page up,
serving `/robots.txt` without an upstream, or testing client timeout handling.

- **Step:** `request` (default) or `proxy_upstream` — configurable
- **Registered as:** `mock`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `mock`. |
| `path` | string | `""` | Exact path to mock. Empty matches **every** path in the location. |
| `status` | int | `200` | Response status. An invalid code falls back to `200`. |
| `headers` | string[] | — | Response headers as `Name: value`. |
| `data` | string | `""` | Response body. |
| `delay` | duration | none | Sleep before responding. |
| `step` | string | `request` | `request` or `proxy_upstream`. Any other value is a configuration error. |

## Examples

Stub an API endpoint:

```toml
[plugins.mockUsers]
category = "mock"
path = "/api/users"
status = 200
headers = ["Content-Type: application/json"]
data = '{"users":[{"id":1,"name":"pingap"}]}'
```

Maintenance page for a whole location:

```toml
[plugins.maintenance]
category = "mock"
status = 503
headers = ["Content-Type: text/html; charset=utf-8", "Retry-After: 600"]
data = "<h1>Back shortly</h1>"

[locations.app]
upstream = "app"
path = "/"
plugins = ["maintenance"]
```

Simulate a slow backend:

```toml
[plugins.slowEndpoint]
category = "mock"
path = "/api/slow"
delay = "5s"
data = "ok"
```

Serve `robots.txt` with no upstream at all:

```toml
[plugins.robots]
category = "mock"
path = "/robots.txt"
headers = ["Content-Type: text/plain"]
data = """
User-agent: *
Disallow: /admin
"""
```

## Behaviour

`path` is compared for exact equality — there is no prefix or regex matching. A
non-matching path skips the plugin and the request proceeds normally. When it
does match, the upstream is never contacted.

## Usage notes

- Leaving `path` empty short-circuits the entire location. That is exactly what
  you want for a maintenance page and exactly what you do not want if you meant
  to stub one endpoint.
- `delay` holds the request task open for its duration. A large delay plus real
  traffic will pile up connections; combine with [`limit`](limit.md) when
  experimenting on a live listener.
- At `request` the mock also short-circuits caching and any later plugin in the
  chain. Use `step = "proxy_upstream"` to let cache hits through and mock only
  the requests that would otherwise reach the origin.
