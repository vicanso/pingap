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
| `headers` | string[] | — | Request headers appended to the cache key (variant caching). Each header has its place in the key, kept when the request does not carry it; a `:` inside a value is written `%3A` so that it cannot be taken for the border between two of them. |
| `vary_headers` | string[] | — | Allow list for the origin's `Vary` response header: only these request headers may create cache variants. Unset honours every header the origin names. |
| `max_ttl` | duration | — | Upper bound on entry lifetime, capping upstream `Cache-Control`. |
| `max_file_size` | bytesize | `1mb` | Responses larger than this are not cached. |
| `lock` | duration | `1s` | Cache-lock window against stampedes. Any non-zero duration works; `0s` disables locking. |
| `lock_retries` | int | `2` | How many times a request that waited on the lock re-checks the cache before it gives up and fetches from upstream itself. |
| `eviction` | bool | `false` | `true` enables LRU eviction. Memory backend only. |
| `predictor` | bool | `false` | `true` enables the cacheability predictor. |
| `check_cache_control` | bool | `false` | Require a `Cache-Control` header on the response, otherwise do not store it. |
| `purge_ip_list` | string[] | `[]` | IPs / CIDRs allowed to issue `PURGE`. An entry that is neither fails configuration validation. See [who may purge](#who-may-purge) for the address that is checked. |
| `skip` | string | — | Regex on path+query; matching requests bypass the cache entirely. |
| `default_ttl` | duration | `1s` | How long a response is kept when the origin names no lifetime, for the statuses that are kept by default. `0s` keeps none of them. See [Lifetimes of your own](#lifetimes-of-your-own). |
| `status_ttl` | string[] | — | `status:duration` entries (`"404:10s"`, `"301:1h"`): the same per status, also for a status that is not kept by default. `0s` keeps that status out. |
| `bypass_headers` | string[] | — | A request with any of these headers is neither answered from the cache nor stored. |
| `bypass_cookies` | string[] | — | The same for a request with any of these cookies. |
| `ignore_query` | string[] | — | Query parameters that are left out of the cache key (`utm_source`, `fbclid`). The others are put in order by name. Not together with `query_allow`. |
| `query_allow` | string[] | — | The only query parameters that are a part of the cache key, in order by name. |
| `respect_client_no_cache` | bool | `false` | `true` lets a client have what is cached revalidated with the origin, with `Cache-Control: no-cache` or `max-age=0`. |

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
# one url (removes both the GET and the HEAD variant)
curl -X PURGE http://127.0.0.1:6188/assets/app.js
# 204 No Content       -> removed (idempotent: also 204 when nothing was cached)
# 403 Forbidden        -> your IP is not in purge_ip_list

# the whole namespace (file backend with a configured namespace only)
curl -X PURGE http://127.0.0.1:6188/*
# 200 "purged: 12, fail: 0"
# 501 Not Implemented  -> no namespace configured, or memory cache backend
```

`PURGE /*` empties everything this plugin cached: the namespace survives as a
directory in the file backend, so it is the one granularity beyond an exact url
that can be purged without an index (storage file names are hashes of the full
key — a url prefix does not map to anything on disk). The purge empties the
in-memory hot layer along with the files — the whole layer, since it cannot be
searched by namespace: objects that were in memory only are gone too, and the
other namespaces read theirs back from disk. It only cleans the local instance:
in a multi-instance deployment, issue the request on every node.

## Lifetimes of your own

What the origin says about its response comes first: a lifetime in
`Cache-Control`, or an `Expires`. A response that says nothing is kept for one
second when its status is one of those listed under [Behaviour](#behaviour),
and not at all otherwise. Two options change that, and only that:

```toml
[plugins.pageCache]
category = "cache"
default_ttl = "30s"
status_ttl = ["404:10s", "301:1h", "302:1m", "410:0s"]
max_ttl = "1h"
```

- `default_ttl` replaces the one second, for the same statuses.
- `status_ttl` names a lifetime per status and wins over `default_ttl`. It
  can name a status that is not kept by default (`302`, even `500`) and keep
  one out with `0s`. Not `304`, which is a configuration error: it renews
  what was stored as a `200`, for as long as a `200` is kept.
- `max_ttl` caps these like any other lifetime, and `check_cache_control`
  still refuses a response that has no `Cache-Control` header at all.
- A response the origin marks `no-store`, `no-cache`, `private` or
  `max-age=0`, one that sets a cookie, and one to a request with
  `Authorization` stay out as before: these options give a lifetime to a
  response that has none, they do not overrule the origin. A `max-age` that
  does not read as a number counts as the origin having named one.

## What the key is made of, and who gets past the cache

```toml
[plugins.pageCache]
category = "cache"
ignore_query = ["utm_source", "utm_medium", "utm_campaign", "fbclid", "gclid"]
bypass_cookies = ["session"]
bypass_headers = ["X-Preview"]
```

- With `ignore_query` or `query_allow` set, the query of the cache key is made
  of the parameters that are kept, in the order of their names: `?b=2&a=1`
  and `?a=1&b=2` are one entry, and a tracking parameter no longer makes one
  entry per visitor. Parameters of the same name keep the order they came in.
  Names are compared as written, without decoding. **The upstream is asked
  with that same query**, not with the one the client sent: a parameter that
  is not a part of the key does not reach it, on the requests the plugin
  handles (a `POST`, a request that `skip` matches or one that is bypassed
  goes as it came). Sent on, it would be the
  upstream that decided what the response depends on, and a parameter spelled
  in a way the rule does not know and the upstream does (`p%61ge=2`, `Page=2`,
  `x=1;page=2`) would put page 2 into the cache as the page without a number,
  for everyone. So an upstream that reads a tracking parameter itself no
  longer sees it on a location with this plugin. Only the request to the
  upstream is changed: the access log (`{uri}`, `{query}`) and the other
  plugins still see what the client sent. The query is taken once all the
  plugins of the request have run, so a parameter another plugin removes
  (`key_auth` with `hide_credentials`) is in neither the key nor the request
  to the upstream, wherever that plugin is listed.
  Without either option the key and the request are as they came, as before;
  setting one changes the keys, and what is cached under the old ones is
  fetched again once.
- A request with one of `bypass_headers` or `bypass_cookies` is somebody's
  own - a logged in session, a preview - and the cache is not asked: it goes
  to the upstream and what it gets is not kept. A cookie is found by its exact
  name, whatever else the `Cookie` header holds. The plugin does not look at
  cookies otherwise (see below), so this is how to keep the pages of logged
  in users apart from the cached ones. A `PURGE` is not bypassed.
- `respect_client_no_cache` is off by default because it hands the decision
  to the client: with it, a request carrying `Cache-Control: no-cache` or
  `max-age=0` (what a browser sends on reload) or `Pragma: no-cache` has the
  cached response revalidated with the origin before it is served - a
  conditional request when the stored response has a validator - and anyone
  can make the origin work that way. Leave it off on a public site. It holds
  for a response that has expired and would be served while it is refreshed
  (`stale-while-revalidate`) as well, and such a client gets an error rather
  than the stored copy when the origin can not be reached.

## Who may purge

A `PURGE` is allowed when the address of the request is in `purge_ip_list`;
with an empty list nobody may purge. Which address that is depends on
`basic.trusted_proxies`:

- **Set:** the client IP, resolved through the trusted proxies as described
  under [`ip_restriction`](ip_restriction.md#client-ip-resolution).
- **Not set:** the address of the connection itself. `X-Forwarded-For` and
  `X-Real-IP` are not looked at, since without trusted proxies they are
  whatever the request says: a list allowing `127.0.0.1` would let in anyone
  who sends `X-Forwarded-For: 127.0.0.1`.

So a `PURGE` sent through a load balancer or CDN needs that proxy listed in
`trusted_proxies`. Without it the address checked is the proxy's own.

## Behaviour

- Only `GET`, `HEAD` and `PURGE` are handled; every other method skips the
  plugin.
- What is stored, and for how long, follows the origin's `Cache-Control`:
  - A `no-store`, `no-cache` or `private` response is not stored, nor is one
    with a lifetime of zero.
  - The lifetime is `s-maxage` when the origin sends one and `max-age`
    otherwise, capped by `max_ttl`.
  - Without either, the lifetime runs until the origin's `Expires`, capped by
    `max_ttl` like the others. An `Expires` that is over, or not a date (`0`
    and `-1` are how origins say "do not cache"), means the response is not
    stored. Both used to slip through: `Expires` a year ahead was kept for a
    year whatever `max_ttl` said, and an expired one was written to the cache
    on every request.
  - A response without a lifetime is kept for one second, provided its status
    is one HTTP calls heuristically cacheable: 200, 203, 204, 206, 300, 301,
    308, 404, 405, 410, 414 or 501. Any other status, a 5xx or a 302 for
    example, is only stored when the origin gives it a lifetime.
    `default_ttl` and `status_ttl` change both, see
    [Lifetimes of your own](#lifetimes-of-your-own).
    `check_cache_control` goes further and stores nothing that comes without a
    `Cache-Control` header.
- Two kinds of response are taken to belong to one client and are not stored.
  That is all the plugin goes by: it does not look at the request's `Cookie`,
  so a page that differs by cookie and comes without `Cache-Control` is stored
  like any other, for the one second above, and served to whoever asks next.
  For such pages have the origin send `Cache-Control: private`, or turn on
  `check_cache_control`, or leave their paths out with `skip`. `Vary: Cookie`
  from the origin keeps one copy per cookie instead, but only while
  `vary_headers` is unset or lists `Cookie`: a header left out of that list is
  not varied on, and everyone is back to one shared copy.
  - One with a `Set-Cookie` header: everyone served from the cache would get
    the same cookie. To cache such a response anyway, remove the header before
    it is stored, with a [`response_headers`](response_headers.md) plugin in
    `upstream` mode.
  - One to a request with an `Authorization` header, unless the origin marks
    it as shareable with `public`, `s-maxage` or `must-revalidate`. A
    [`basic_auth`](basic_auth.md) plugin with `hide_credentials` removes the
    header before this check, so a site behind it is cached as usual.
- The cache key is the `namespace`, the values of the `headers` you listed,
  the method, the host, the path and the query. The host is taken in lower case
  and without its port, and the scheme is not part of the key, so
  `http://Example.com:8080/x` and `https://example.com/x` are one entry, over
  HTTP/1.1 and HTTP/2 alike, while `other.com/x` is another.
- `PURGE` builds the key for both `GET` and `HEAD`, so purging `/x` removes the
  entries created by either method. It purges the host it is sent to: send the
  `Host` of the site whose entry is to go, on any listener the plugin is
  reachable through. If `headers` are configured, send them on the `PURGE`
  request too — they are part of the key.
- Other plugins add to the key what a response was made for: `compression` in
  `upstream` mode the coding (`zstd`, `br`, `gzip` or none), `image_optim` the
  image formats the client accepts. A `PURGE` removes the entry of each of
  them, whatever its own `Accept-Encoding` and `Accept` say; it used to remove
  only the one matching its own headers, which for a plain `curl -X PURGE` is
  the uncompressed entry no browser asks for.
- The origin's `Vary` response header is honoured: each combination of the
  request headers it names is stored as its own variant under the same key, and
  `Vary: *` makes the response uncacheable. `vary_headers` limits which headers
  may do that, since `Vary: Cookie` or `Vary: User-Agent` would mean a variant
  per client. `PURGE` removes the primary slot; the variants behind it become
  unreachable and are reclaimed by eviction or the inactive sweep.
- `lock` makes concurrent misses for the same key wait for the first one instead
  of all hitting the origin.
- `Cache-Control: stale-while-revalidate=<seconds>` from origin is honoured;
  entries without this directive are not served stale during revalidation.
  After freshness expires, pingap serves stale content inside that window while
  one lock holder revalidates against origin in background. Responses outside
  the window wait for or perform normal revalidation. SWR requires a non-zero
  `lock`; `lock = "0s"` disables it. `max_ttl` caps freshness only, not the
  SWR window. Background revalidation passes through the normal request
  pipeline, creates an access-log entry, updates metrics, and runs request-step
  plugins again.
- Cache read/write counts are recorded into the request context and are available
  in access logs as `{:cache_lookup_time}` / `{:cache_lock_time}`.

## Usage notes

- **`PURGE` no longer goes by `X-Forwarded-For` unless `basic.trusted_proxies`
  is set.** Up to 0.15.0 the header was believed from anyone. A purge that
  worked through a proxy not listed there is answered `403` after the upgrade;
  list the proxy, see [who may purge](#who-may-purge).
- **Upgrading from 0.15.0 or earlier empties the cache.** Up to that version
  the host was part of the key for HTTP/2 requests only; over HTTP/1.1 two
  sites behind one `cache` plugin shared their entries. Entries written by
  those versions are not found under the present key: the cache starts cold
  after the upgrade, and the old entries of a file cache stay on disk until
  the inactive sweep removes them.
- **`eviction` and `predictor` go by their value.** They used to be on whenever
  the key was present, so `eviction = false` — what the admin form saves for
  "No" — enabled it. A config that has `false` there to mean "on" has to say
  `true`.
- **A request with only some of the `headers` gets a new key.** With
  `headers = ["X-A", "X-B"]` the values used to be joined without their place,
  so `X-A: 1` alone and `X-B: 1` alone shared one entry. Each header now keeps
  its place. Requests that carry all of the listed headers, or none, keep the
  key they had; entries stored for requests with only some of them are not
  found again and age out. The same goes for entries whose header value
  holds a `:` or a `%` (an `Origin`, for one): those characters are now
  escaped in the key.
- **`example.com.` is cached apart from `example.com`.** A host with its root
  label written out is routed like the plain name, but the request goes to
  the upstream with the `Host` it came with, so its response is kept under a
  key of its own.
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
