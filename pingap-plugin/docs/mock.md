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
| `status` | int | `200` | Response status. A code outside `200`–`999` is a configuration error: an interim status (`1xx`) is not a response, and the client would wait for one that never comes. |
| `headers` | string[] | — | Response headers as `Name: value`. An invalid name or value is a configuration error. |
| `data` | string | `""` | Response body. |
| `delay` | duration | none | Sleep before responding. |
| `percentage` | int | `100` | The share of the matching requests that get the mock, `0` to `100`; the others go on as if the plugin were not there. |
| `delay_only` | bool | `false` | After `delay` the request goes on to the upstream and gets its real response. Needs `delay`. |
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

Fail a part of the traffic, or slow it down, to see what its clients do
(fault injection):

```toml
# one request in ten is answered 503 without reaching the upstream
[plugins.flaky]
category = "mock"
status = 503
percentage = 10

# one in five waits two seconds and is then served as usual
[plugins.sluggish]
category = "mock"
delay = "2s"
delay_only = true
percentage = 20
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
non-matching path skips the plugin and the request proceeds normally. A request
that matches and is answered by the mock never reaches the upstream. Two cases
do go on to it: the share that `percentage` does not choose, and, with
`delay_only`, every request once it has waited.

## Usage notes

- `percentage` is by chance, request by request: `10` is one in ten over many
  requests, not every tenth. `0` turns the plugin off without taking it out
  of the configuration. A value outside `0`-`100` is a configuration error.
- Leaving `path` empty short-circuits the entire location. That is exactly what
  you want for a maintenance page and exactly what you do not want if you meant
  to stub one endpoint.
- `delay` holds the request task open for its duration. A large delay plus real
  traffic will pile up connections; combine with [`limit`](limit.md) when
  experimenting on a live listener.
- At `request` a request the mock answers also short-circuits caching and any
  later plugin in the chain. Use `step = "proxy_upstream"` to let cache hits
  through and mock only the requests that would otherwise reach the origin.
  A request that is not answered - not chosen by `percentage`, or only delayed
  by `delay_only` - goes through the cache and the later plugins as usual.
- A `delay` of `0` is no delay, and `delay_only` with it is a configuration
  error like `delay_only` without one.
