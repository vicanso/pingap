# cache

HTTP response caching backed by either an in-memory [TinyUFO] store or a
file-based store, with cache-key control, stampede protection and an
IP-restricted `PURGE` method.

- **Step:** `request` (fixed)
- **Registered as:** `cache`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `cache`. |
| `directory` | string | memory | Empty or `memory://…` selects the memory backend; any other value is a file cache directory. |
| `namespace` | string | — | Isolates entries; with a file backend it becomes a subdirectory. |
| `headers` | string[] | — | Request headers appended to the cache key (variant caching). |
| `max_ttl` | duration | — | Upper bound on entry lifetime, capping upstream `Cache-Control`. |
| `max_file_size` | bytesize | `1mb` | Responses larger than this are not cached. |
| `lock` | duration | `1s` | Cache-lock window against stampedes. Any non-zero duration works; `0s` disables locking. |
| `eviction` | bool | absent | Presence of the key enables LRU eviction. Memory backend only. |
| `predictor` | bool | absent | Presence of the key enables the cacheability predictor. |
| `check_cache_control` | bool | `false` | Require a `Cache-Control` header on the response, otherwise do not store it. |
| `purge_ip_list` | string[] | `[]` | IPs / CIDRs allowed to issue `PURGE`. |
| `skip` | string | — | Regex on path+query; matching requests bypass the cache entirely. |

### Backend selection

```toml
directory = ""                                   # memory, default size
directory = "memory://pingap?max_size=100mb"     # memory, absolute size
directory = "memory://pingap?max_size=20"        # memory, 20% of the budget
directory = "/opt/pingap/cache"                  # file cache
directory = "/opt/pingap/cache?inactive=1h&reading_max=1000"
```

See [pingap-cache](../../pingap-cache/README.md) for the full set of backend
query parameters.

## Example

```toml
[plugins.httpCache]
category = "cache"
directory = "/opt/pingap/cache"
namespace = "web"
headers = ["Accept-Encoding"]
max_ttl = "1h"
max_file_size = "10mb"
lock = "2s"
eviction = true
predictor = true
purge_ip_list = ["127.0.0.1", "10.0.0.0/8"]
skip = "^/api/"

[locations.web]
upstream = "web"
path = "/"
plugins = ["httpCache"]
```

Purging:

```bash
curl -X PURGE http://127.0.0.1:6188/assets/app.js
# 204 No Content       -> removed
# 403 Forbidden        -> your IP is not in purge_ip_list
```

## Behaviour

- Only `GET`, `HEAD` and `PURGE` are handled; every other method skips the
  plugin.
- The cache key is derived from the request URI plus `namespace` plus the values
  of the `headers` you listed. `PURGE` builds the key as if the request were a
  `GET`, so purging `/x` removes the entry created by `GET /x`.
- `lock` makes concurrent misses for the same key wait for the first one instead
  of all hitting the origin.
- Cache read/write counts are recorded into the request context and are available
  in access logs as `{:cache_lookup_time}` / `{:cache_lock_time}`.

## Usage notes

- **`eviction` needs a bounded backend.** It is only wired up when the backend
  reports a non-zero `max_size`, which the file backend does not — so `eviction`
  is memory-only, and setting it on a file cache logs an error and is ignored.
  File cache entries are reclaimed by the inactive sweep instead (`?inactive=…`).
- **One memory backend per process.** The memory cache is a process-wide
  singleton created by the first `cache` plugin that asks for it; a second
  declaration with a different `max_size` or `mode` silently reuses the first
  one. Use `namespace` to separate content, not a second `directory`.
- Each distinct `lock` duration allocates one shared lock for the lifetime of
  the process, so the number of distinct values matters, not the number of
  plugin instances.
- Pair with [`accept_encoding`](accept_encoding.md) when caching by
  `Accept-Encoding`, otherwise the number of variants explodes.

[TinyUFO]: https://github.com/cloudflare/pingora/tree/main/tinyufo
