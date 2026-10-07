# limit

Two limiters in one plugin:

- **`rate`** — requests per interval, counted over a sliding window.
- **`inflight`** — concurrent in-progress requests, tracked with an atomic
  counter released automatically when the request finishes.

Either one can be keyed by client IP, a header, a cookie or a query parameter.

- **Step:** `request` (default) or `proxy_upstream` — configurable
- **Registered as:** `limit`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `limit`. |
| `type` | string | `rate` | `rate` or `inflight`. Anything else is a configuration error. |
| `tag` | string | `ip` | `ip`, `header`, `cookie` or `query`. Anything else is a configuration error. `ip` is the address of the connection, or the forwarded one through a proxy listed in `basic.trusted_proxies`. |
| `key` | string | — | Name of the header / cookie / query parameter. **Required** unless `tag = "ip"`. |
| `max` | int | — | **Required.** Allowed requests per `interval` (rate), or concurrent requests (inflight). Negative is an error. |
| `interval` | duration | `10s` | Rate window, at least `1ms`. Ignored by `inflight`. |
| `step` | string | `request` | `request` or `proxy_upstream`. Any other value is a configuration error. |
| `headers` | bool | `false` | Tell the client its budget in `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`. See [Quota headers](#quota-headers). |
| `status` | int | `429` | Status of the response to a request over the limit, `400` to `599`. |
| `message` | string | — | Body of that response, in place of `Plugin limit, exceed limit <value>/<max>`. |
| `missing_key` | string | `pass` | What becomes of a request that has no value for the key: `pass` lets it through, unlimited; `reject` answers it `400`. |

### How `max` and `interval` interact

For `type = "rate"`, `max` is the number of requests a key gets in any one
`interval`. The limiter keeps two counters per key, for the current window
and the one before it, and estimates the requests of the last `interval` as

```
previous window × (1 − elapsed share of the current window) + current window
```

A request that would take the estimate above `max` is answered `429`. So
`max = 600, interval = "60s"` lets a client that was idle send 600 requests at
once and then holds it to about 10 per second.

- A request that is turned away is not counted. A client over its limit keeps
  getting `max` per interval; it is not locked out for as long as it retries.
- It is an estimate, not a log of every request: it assumes the requests of
  the previous window were spread evenly over it. A client that sends its
  `max` at the very end of one window is then let through a few more times
  as that window fades, and can reach close to twice `max` within one
  interval-long span in the worst case. Averaged over time the rate is held
  to `max`. The other way round, a client sending exactly `max` per interval
  with a very small `max` (1 or 2) will see some of its requests refused;
  give such limits a little room.

`weight` is gone. It blended the two windows by a fixed share (`50` by
default), which let a client that was new to the limiter through twice as
often as `max` says, and with `weight = 0` every time. A config that still has
the key loads, logs a warning and ignores it. **Limits are stricter than they
were**: what used to pass at up to `2 × max` per interval is now held to
`max`.

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
| Key value is missing or empty | **Not limited** — the request passes. With `missing_key = "reject"`: `400 Bad Request`, body `Plugin limit, the header X-API-Key is required` (or `the cookie …`, `the query parameter …`) |
| Within limit | `Continue` |
| Over limit | `429 Too Many Requests` (or `status`), body `Plugin limit, exceed limit <value>/<max>` (or `message`); a `rate` limiter adds `Retry-After: <interval in seconds>` |

### Quota headers

With `headers = true` the client is told where it stands:

| Header | Value |
| --- | --- |
| `X-RateLimit-Limit` | `max` |
| `X-RateLimit-Remaining` | What is left of it, this request counted; `0` on a refusal |
| `X-RateLimit-Reset` | In how many seconds the whole budget is back if nothing more is sent. `rate` only: an `inflight` limit has no such time |

They are set on the upstream's response, on the plugin's own refusal, and on
the response another plugin of the location answers with (a `401` from an
authentication plugin after this one). An error page of the proxy itself
(`502`, `504`) does not carry them. `X-RateLimit-Reset` is an upper bound: the
estimate fades gradually, so some of the budget is back sooner, and after a
refusal `Retry-After` is the time to go by. With more than one `limit` on a
location reporting, the client is told about the one with the least left; a
refusal carries the budget of the limit that refused, and none when that limit
does not report.

## Usage notes

- With `tag = "ip"` and no `basic.trusted_proxies`, `X-Forwarded-For` is not
  looked at: behind a proxy that is not listed there every client shares the
  proxy's address and so one budget. List the proxy. (The header used to be
  believed from anyone, and a new value with every request was never limited.)
- The empty-key pass-through matters: with `tag = "header"` and `key =
  "X-API-Key"`, anonymous requests are entirely unlimited. Chain an
  authentication plugin in front, or add a second `limit` on `ip`.
- Counters are a fixed-size sketch, not a table with a row for every key: a
  key is counted in four counters, one in each of four rows of 1024 for `rate`
  (rows of 8192 for `inflight`), and its count is the smallest of the four.
  Keys that share a counter can only push each other's count up, never down,
  and a key is over-counted only when every one of its four counters is shared
  with some other key. With three hundred distinct keys in an interval that is
  under one key in a hundred; with a thousand it is about one in seven, with
  three thousand four in five, and beyond that nearly all of them. Such a key
  is limited earlier than `max`, by the least that its neighbours add in any
  of the four. A `rate` limit by client address with a long `interval` on a
  busy site is where this shows; shorten the interval, or key on something
  with fewer values.
- Counters are per process. With multiple Pingap instances behind a load
  balancer the effective limit multiplies by the instance count.
- `step = "proxy_upstream"` runs after the cache plugin, so cache hits do not
  consume budget — usually what you want for origin protection, and not what you
  want for abuse protection.
- `max = 0` rejects everything for `inflight` (the first request already has a
  count of 1 which is `> 0`).
- A location can carry several limits, for example one per IP and one per API
  key. Each counts on its own, and a request has to fit within all of them.
