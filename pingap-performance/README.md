# Pingap Performance

Metrics and process introspection for [Pingap](https://github.com/vicanso/pingap).

This crate collects two kinds of data:

- **Request metrics** — counters, gauges and histograms describing traffic,
  latency, upstream behaviour and caching, exported in Prometheus format.
- **Process metrics** — memory, CPU count, thread count, file descriptors and
  TCP connection counts, used by the [`stats`](../pingap-plugin/docs/stats.md)
  plugin and the admin UI, and also to size the memory cache budget.

## Enabling Prometheus

Metrics require the `tracing` cargo feature (included in `full`).

### Pull mode

Expose an endpoint on a server:

```toml
[servers.main]
addr = "0.0.0.0:6188"
locations = ["app"]
prometheus_metrics = "/metrics"
```

```bash
curl http://127.0.0.1:6188/metrics
```

The endpoint has no authentication of its own. It is a path of the server like
any other, so the request plugins of the location that matches it run first:
with a catch-all location that has `basic_auth` or `ip_restriction`, `/metrics`
is behind them too (it used to be served ahead of every plugin). A plugin of
that location that answers requests itself (`directory`, `mock`, `redirect`)
answers this path as well, in place of the metrics. To expose the endpoint
differently from the application, give the path a location of its own on that
server, with the plugins it should have. A request that matches no location at
all (another `Host`, when every location names one) gets the metrics without
any plugin, so that location should not be bound to a host.

### Push mode

Give a URL instead of a path and Pingap pushes to a Pushgateway:

```toml
[servers.main]
prometheus_metrics = "http://user:pass@pushgateway:9091/job/pingap?interval=1m"
```

The push runs as a task of the shared background service, which ticks once a
minute, so `interval` is rounded down to a whole number of minutes and never
goes below one. A value that does not survive that rounding is logged with the
interval actually used, so `?interval=15s` does not silently become a minute.

## Exported metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `pingap_http_requests_total` | counter | location | Requests accepted |
| `pingap_http_requests_current` | gauge | location | Requests in flight |
| `pingap_http_responses_codes` | counter | location, code | Responses by status class (`2xx`, `5xx`, …) |
| `pingap_http_responses_status` | counter | location, status | Responses by exact status code (`200`, `404`, `429`, …); a series appears with the first response of that status. A code outside `100`–`599` is only counted in its class |
| `pingap_http_response_time` | histogram | location | End-to-end response time (s) |
| `pingap_http_received` / `pingap_http_received_bytes` | histogram / counter | location | Request payload size |
| `pingap_http_sent` / `pingap_http_sent_bytes` | histogram / counter | location | Response payload size |
| `pingap_connection_reuses` | counter | — | Reused downstream connections |
| `pingap_tls_handshake_time` | histogram | — | Downstream TLS handshake (s) |
| `pingap_upstream_connections` | gauge | upstream | Established upstream connections; only exported for an upstream with `enable_tracer = true`, which is what counts them |
| `pingap_upstream_connections_current` | gauge | upstream | Upstream connections in use |
| `pingap_upstream_reuses` | counter | upstream | Reused upstream connections |
| `pingap_upstream_errors` | counter | upstream | Requests that failed because of their upstream: it could not be connected to, or the connection broke or timed out. A `5xx` the upstream itself answered is a response, not an error |
| `pingap_upstream_retries` | counter | upstream | Times a request was sent to an upstream again after a failed connection (`max_retries` of the location) |
| `pingap_upstream_tcp_connect_time` | histogram | upstream | Upstream TCP connect (s) |
| `pingap_upstream_tls_handshake_time` | histogram | upstream | Upstream TLS handshake (s) |
| `pingap_upstream_processing_time` | histogram | upstream | Upstream processing (s) |
| `pingap_upstream_response_time` | histogram | upstream | Upstream response (s) |
| `pingap_upstream_backend_failure_rate` | gauge | upstream, backend | Sliding-window failure rate percent (0–100) |
| `pingap_upstream_backend_requests` | gauge | upstream, backend | Sliding-window request count |
| `pingap_upstream_backend_circuit_state` | gauge | upstream, backend | Circuit state: 0 closed, 1 open, 2 half-open |
| `pingap_upstream_discovery_time` | gauge | upstream | Service discovery time of the latest backend refresh (s) |
| `pingap_upstream_selector_build_time` | gauge | upstream | Selector build time of the latest backend refresh (s) |
| `pingap_upstream_pool_eviction_idle_time` | histogram | — | Idle time of upstream connections when the keep-alive pool evicted them to make room (s); the count is the eviction count, a sign `upstream_keepalive_pool_size` is too small |
| `pingap_cache_lookup_time` | histogram | — | Cache lookup (s) |
| `pingap_cache_lock_time` | histogram | — | Time waiting on a cache lock (s) |
| `pingap_cache_reading` / `pingap_cache_writing` | gauge | — | Concurrent cache reads / writes |
| `pingap_cache_responses` | counter | location, status | Requests a `cache` plugin was asked about, by what came of it: `hit`, `miss`, `expired`, `stale`, `revalidated`, `bypass`, and `uncacheable` for a miss whose response was not one to keep (no `Cache-Control` that allows it, a status that is not cached, a body over the limit). Requests no cache looked at are not counted |
| `pingap_cache_memory_evictions` | counter | — | Objects the memory cache evicted to stay within its size. One that keeps growing says the cache is smaller than what is asked of it |
| `pingap_access_log_dropped` | counter | — | Access log lines dropped because the logger was behind and its channel full |
| `pingap_config_reloads` | counter | result | Reloads of the configuration: `success` for a change that was applied, `failure` for one that was refused and left the running configuration in place, or of which a part did not go through |
| `pingap_config_last_reload_successful` | gauge | — | `1` when the last reload was applied (or there was none yet), `0` when it was refused or went through in part |
| `pingap_config_last_reload_success_timestamp_seconds` | gauge | — | Unix time the configuration was last loaded or reloaded |
| `pingap_build_info` | gauge | version, rustc_version | Always `1`; the labels say which build is running |
| `pingap_start_time_seconds` | gauge | — | Unix time this server was started |
| `pingap_compression_ratio` | histogram | — | Compression ratio achieved |
| `pingap_memory` | gauge | — | Process memory (MB) |
| `pingap_fd_count` | gauge | — | Open file descriptors |
| `pingap_tcp_count` / `pingap_tcp6_count` | gauge | — | IPv4 / IPv6 TCP sockets in the process's **network namespace**, not only Pingap's own: the source is `/proc/<pid>/net/tcp`, so on a host without a separate namespace it counts every process's sockets (Linux only) |

`pingap_upstream_processing_time` and `pingap_upstream_response_time` only
count the phases that finished. A response without a body (a `HEAD`, a `204`,
a `304`) has no response phase to time, and an upstream that never answers no
processing time, so such requests add nothing to these two histograms; their
count can be lower than the request count of the upstream.

Because most latency metrics are labelled per location or per upstream, a
dashboard can attribute a regression to a specific route or backend without
extra instrumentation.

Some things to ask of the newer series:

```promql
# cache hit ratio of a location
sum(rate(pingap_cache_responses{location="static",status="hit"}[5m]))
  / sum(rate(pingap_cache_responses{location="static"}[5m]))

# requests that are being throttled
sum(rate(pingap_http_responses_status{location="",status="429"}[5m]))

# the last change of the configuration was refused
pingap_config_last_reload_successful == 0
```

A reload is a change that was found and tried. A refused configuration is
tried again every minute for as long as it stays the same, and each try is a
`failure`. Not counted: a check that finds nothing changed, a storage that
could not be read, and what only a restart applies - with `--autorestart` the
replacement process shows in `pingap_start_time_seconds`, with `--autoreload`
such a change waits for a restart and no series says so.

The evictions of the memory cache and the reloads are counted for the process,
and every server with metrics reports the same number: take `max`, not `sum`,
over servers.

The memory cache does not report how many objects it holds or how large they
are: the structure behind it (TinyUFO) does not say, and a count kept next to
it would drift. Its evictions are counted, which is what says whether it is
large enough.

The empty `location` label is the total, and it really is every request: one
that matched no location (a `404`), an admin endpoint, an ACME challenge and a
scrape of this very endpoint all count towards it. Only requests that were
routed somewhere also carry a named `location`.

Series that describe current state — the per-backend failure rate, request
count and circuit state, and the per-upstream discovery and selector build
times — are rebuilt from scratch on every scrape, so a backend that has gone
away stops being exported instead of lingering with its last value. The same
happens to the per-upstream series of an upstream removed from the
configuration. This matters most with DNS and Docker discovery, where backend
addresses churn and would otherwise accumulate as dead time series.

## Process information

```rust
use pingap_performance::get_process_system_info;

let info = get_process_system_info();
println!("{} MB, {} threads, {} fds", info.memory_mb, info.threads, info.fd_count);
```

`get_processing_accepted()` returns the global in-flight and accepted request
counters. Both are what the `stats` plugin serialises.

A snapshot is cached for one second. Collecting one reads several `/proc`
files, and three consumers ask for it independently — a Prometheus scrape, the
`stats` plugin on every request to its path, and the metrics log task — so the
cache bounds that to one collection per second however often it is asked for.
The socket tables are counted rather than parsed, and the fields that cannot
change (architecture, CPU counts, kernel version) are read once per process.

At startup the binary feeds `pingap_cache::update_available_memory()` with the
memory that is available, bounded by the container's limit, so the memory cache
sizes itself against where it runs instead of a fixed default.

## License

Apache-2.0.
