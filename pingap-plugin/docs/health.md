# health

Answers a path with whether the upstreams behind this instance can take
requests: a readiness probe for a load balancer or for Kubernetes.

The [`ping`](ping.md) plugin answers `pong` for as long as the process runs,
which says that the proxy is up and nothing of what is behind it.

- **Step:** `request` (fixed)
- **Registered as:** `health`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `health`. |
| `path` | string | — | **Required.** The path that is answered, compared for exact equality. |
| `upstreams` | string[] | *(all)* | Names of the upstreams to look at. Empty looks at every upstream. |
| `min_healthy` | int | `1` | How many healthy backends each of them needs. At least `1`. |

## Example

```toml
[plugins.ready]
category = "health"
path = "/ready"
upstreams = ["api", "auth"]

[locations.app]
upstream = "api"
plugins = ["ready"]
```

```bash
curl -i http://127.0.0.1:6188/ready
# HTTP/1.1 200 OK
# {"ready":true,"upstreams":{"api":{"healthy":2,"total":2,"ready":true},"auth":{"healthy":1,"total":1,"ready":true}}}
```

With every backend of `api` down:

```
HTTP/1.1 503 Service Unavailable
{"ready":false,"upstreams":{"api":{"healthy":0,"total":2,"ready":false,"unhealthy_backends":["10.0.0.1:8080","10.0.0.2:8080"]},"auth":{"healthy":1,"total":1,"ready":true}}}
```

## Behaviour

| Situation | Result |
| --- | --- |
| Path is not `path` | Plugin skipped |
| Every upstream looked at has `min_healthy` healthy backends | `200` |
| One of them has fewer | `503`, with the upstream and its unhealthy backends in the body |
| An upstream named in `upstreams` does not exist | `503`, `"reason":"no such upstream"` |

A backend is healthy when its health check says so. The circuit breaker is
not looked at: a backend it is holding back still counts. Every backend counts
as healthy until the first round of checks of its upstream has run.

## Usage notes

- A transparent upstream has no backends of its own to check. It is left out
  when every upstream is looked at, and counts as ready when it is named.
- The answer is about the upstreams, not about the location the plugin is on:
  name the ones this instance cannot do without. With `upstreams` empty, one
  upstream that nobody needs any more keeps the whole instance out of rotation.
- The response names upstreams and backend addresses. Put it on a listener or
  a location that is not reachable from outside, or behind
  [`ip_restriction`](ip_restriction.md).
- Use `ping` for liveness - is the process there - and this for readiness.
