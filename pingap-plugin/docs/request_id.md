# request_id

Ensures every request carries a unique identifier. If the incoming request
already has one, it is kept (so ids stay stable across service boundaries);
otherwise a new one is generated, inserted into the request header and stored in
the request context for logging.

- **Step:** `request` (default) or `proxy_upstream` — configurable
- **Registered as:** `request_id`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `request_id`. |
| `algorithm` | string | `uuid` | `nanoid` for short URL-safe ids; anything else means UUID v7. |
| `size` | int | `8` | Length of the generated nanoid. Ignored for UUID. |
| `header_name` | string | `X-Request-Id` | Header to read and write. |
| `step` | string | `request` | `request` or `proxy_upstream`. Any other value is a configuration error. |

## Examples

UUID v7 — time-ordered, which makes log sorting and index locality nicer:

```toml
[plugins.requestId]
category = "request_id"
algorithm = "uuid"
```

Short ids, custom header:

```toml
[plugins.requestId]
category = "request_id"
algorithm = "nanoid"
size = 12
header_name = "X-Trace-Id"
```

Reference it from the access log and echo it back to the client:

```toml
[servers.test]
access_log = "{when_utc_iso} {request_id} {method} {uri} {status} {latency_human}"

[plugins.echoId]
category = "response_headers"
set_headers = ["X-Request-Id: $http_x_request_id"]
```

## Behaviour

| Situation | Result |
| --- | --- |
| `header_name` present on the request | Value copied into the context; header left as-is |
| `header_name` absent | New id generated, set on the request header and in the context |

The id is exposed as `{request_id}` in access logs and as
`ctx.state.request_id` to other plugins.

## Usage notes

- Because an existing header is trusted verbatim, a client can choose its own
  request id — including one that collides with someone else's. If ids must be
  trustworthy, strip the header at the edge (`response_headers` with `mode =
  "upstream"` will not help here; remove it on the incoming side or terminate at
  a trusted proxy first).
- `nanoid` with `size = 8` gives roughly 47 bits of entropy — fine for
  correlating logs, not for anything security-sensitive. Use a larger size or
  UUID v7 for high-volume systems.
- Put this plugin first in the location's `plugins` list so that later plugins
  and any error responses already have an id to log.
