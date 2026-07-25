# ping

A liveness endpoint. Requests to `path` get `200 pong`; everything else passes
through untouched.

- **Step:** `request` (fixed)
- **Registered as:** `ping`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `ping`. |
| `path` | string | `""` | Exact path to answer. |

## Example

```toml
[plugins.pingPath]
category = "ping"
path = "/ping"

[locations.app]
upstream = "app"
path = "/"
plugins = ["pingPath"]
```

```bash
curl -i http://127.0.0.1:6188/ping
# HTTP/1.1 200 OK
# pong
```

Kubernetes:

```yaml
livenessProbe:
  httpGet:
    path: /ping
    port: 6188
  periodSeconds: 10
```

## Behaviour

`path` is compared for exact equality. The plugin answers regardless of HTTP
method. If `path` is left empty it never matches a normal request, so the plugin
is a no-op.

## Usage notes

- This checks that the Pingap process is accepting and answering requests. It
  says nothing about upstream health — for that, expose [`stats`](stats.md), or
  configure `health_check` on the upstream and watch the Prometheus metrics.
- The response is a shared static value, so the endpoint is essentially free and
  safe to probe often.
- Put the plugin on a location whose path prefix contains the probe path, and
  before any auth plugin in the `plugins` list, so probes are not challenged.
