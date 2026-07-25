# limit

Two limiters in one plugin:

- **`rate`** — requests per interval, measured with a sliding window.
- **`inflight`** — concurrent in-progress requests, tracked with an atomic
  counter released automatically when the request finishes.

Either one can be keyed by client IP, a header, a cookie or a query parameter.

- **Step:** `request` (default) or `proxy_upstream` — configurable
- **Registered as:** `limit`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `limit`. |
| `type` | string | `rate` | `inflight` for concurrency, anything else for rate. |
| `tag` | string | `ip` | `ip`, `header`, `cookie` or `query`. |
| `key` | string | — | Name of the header / cookie / query parameter. Ignored when `tag = "ip"`. |
| `max` | int | `0` | Allowed requests per `interval` (rate), or concurrent requests (inflight). |
| `interval` | duration | `10s` | Rate window. Ignored by `inflight`. |
| `weight` | int | `50` | 0–100. How much the current window counts versus the previous one. |
| `step` | string | `request` | `request` or `proxy_upstream`. Any other value is a configuration error. |

### How `max` and `interval` interact

For `type = "rate"`, `max` is divided by `interval` in seconds (floored at 1) to
get a per-second budget, and the limiter compares that against a sliding-window
estimate. `max = 600, interval = "60s"` therefore means "10 requests per second
on average", not "600 in any 60 second bucket".

`weight` blends the previous and current window when estimating the current rate:
`(prev * (1 - w) + curr * w) / interval`. Lower values smooth bursts, higher
values react faster. `weight = 0` falls back to using the previous window alone.

## Examples

Per-IP rate limit:

```toml
[plugins.rateLimit]
category = "limit"
type = "rate"
tag = "ip"
max = 600
interval = "60s"
```

Per-user concurrency limit, keyed on a cookie:

```toml
[plugins.userInflight]
category = "limit"
type = "inflight"
tag = "cookie"
key = "deviceId"
max = 10
```

Protect an expensive upstream, keyed on an API key header, and only count
requests that actually reach the backend (cache hits are not charged):

```toml
[plugins.upstreamGuard]
category = "limit"
type = "inflight"
tag = "header"
key = "X-API-Key"
max = 20
step = "proxy_upstream"
```

## Behaviour

| Situation | Result |
| --- | --- |
| Key value is missing or empty | **Not limited** — the request passes |
| Within limit | `Continue` |
| Over limit | `429 Too Many Requests`, body `Plugin limit, exceed limit <value>/<max>` |

## Usage notes

- The empty-key pass-through matters: with `tag = "header"` and `key =
  "X-API-Key"`, anonymous requests are entirely unlimited. Chain an
  authentication plugin in front, or add a second `limit` on `ip`.
- Counters are per process. With multiple Pingap instances behind a load
  balancer the effective limit multiplies by the instance count.
- `step = "proxy_upstream"` runs after the cache plugin, so cache hits do not
  consume budget — usually what you want for origin protection, and not what you
  want for abuse protection.
- `max = 0` rejects everything for `inflight` (the first request already has a
  count of 1 which is `> 0`).
