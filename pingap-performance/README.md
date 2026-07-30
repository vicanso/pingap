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

### Push mode

Give a URL instead of a path and Pingap pushes to a Pushgateway:

```toml
[servers.main]
prometheus_metrics = "http://user:pass@pushgateway:9091/job/pingap?interval=15s"
```

## Exported metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `pingap_http_requests_total` | counter | location | Requests accepted |
| `pingap_http_requests_current` | gauge | — | Requests in flight |
| `pingap_http_responses_codes` | counter | location, status | Responses by status |
| `pingap_http_response_time` | histogram | location | End-to-end response time (s) |
| `pingap_http_received` / `pingap_http_received_bytes` | counter / histogram | location | Request payload size |
| `pingap_http_sent` / `pingap_http_sent_bytes` | counter / histogram | location | Response payload size |
| `pingap_connection_reuses` | counter | — | Reused downstream connections |
| `pingap_tls_handshake_time` | histogram | — | Downstream TLS handshake (s) |
| `pingap_upstream_connections` | gauge | upstream | Established upstream connections |
| `pingap_upstream_connections_current` | gauge | upstream | Upstream connections in use |
| `pingap_upstream_reuses` | counter | upstream | Reused upstream connections |
| `pingap_upstream_tcp_connect_time` | histogram | upstream | Upstream TCP connect (s) |
| `pingap_upstream_tls_handshake_time` | histogram | upstream | Upstream TLS handshake (s) |
| `pingap_upstream_processing_time` | histogram | upstream | Upstream processing (s) |
| `pingap_upstream_response_time` | histogram | upstream | Upstream response (s) |
| `pingap_upstream_backend_failure_rate` | gauge | upstream, backend | Sliding-window failure rate percent (0–100) |
| `pingap_upstream_backend_requests` | gauge | upstream, backend | Sliding-window request count |
| `pingap_upstream_backend_circuit_state` | gauge | upstream, backend | Circuit state: 0 closed, 1 open, 2 half-open |
| `pingap_cache_lookup_time` | histogram | — | Cache lookup (s) |
| `pingap_cache_lock_time` | histogram | — | Time waiting on a cache lock (s) |
| `pingap_cache_reading` / `pingap_cache_writing` | gauge | — | Concurrent cache reads / writes |
| `pingap_compression_ratio` | histogram | — | Compression ratio achieved |
| `pingap_memory` | gauge | — | Process memory (MB) |
| `pingap_fd_count` | gauge | — | Open file descriptors |
| `pingap_tcp_count` / `pingap_tcp6_count` | gauge | — | IPv4 / IPv6 TCP connections |

Because most latency metrics are labelled per location or per upstream, a
dashboard can attribute a regression to a specific route or backend without
extra instrumentation.

## Process information

```rust
use pingap_performance::get_process_system_info;

let info = get_process_system_info();
println!("{} MB, {} threads, {} fds", info.memory_mb, info.threads, info.fd_count);
```

`get_processing_accepted()` returns the global in-flight and accepted request
counters. Both are what the `stats` plugin serialises.

The collector also feeds `pingap_cache::update_available_memory()`, so the
memory cache sizes itself against the real machine or container limit instead of
a fixed default.

## License

Apache-2.0.
