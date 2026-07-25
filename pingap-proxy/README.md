# Pingap Proxy

The HTTP proxy engine of [Pingap](https://github.com/vicanso/pingap). This crate
implements pingora's `ProxyHttp` trait and is where routing, plugin dispatch,
upstream selection, caching, tracing and access logging are actually wired
together. Every other `pingap-*` crate feeds into it; the `pingap` binary is a
thin shell that builds the configuration and hands it to this crate.

## Responsibilities

- Turn a `PingapConfig` into concrete listeners (`ServerConf`), including TLS
  parameters, HTTP/2, TCP keepalive, `SO_REUSEPORT` and TCP Fast Open.
- Match each request to a `Location` and, through it, to an `Upstream`.
- Run plugins at the right lifecycle step and honour their decisions.
- Own the per-request `Ctx`: timings, connection details, upstream state, cache
  state and log variables.
- Produce access logs, `Server-Timing` headers, Prometheus metrics and OpenTelemetry
  spans.
- Render error pages from a configurable HTML template.

## Request lifecycle

`server.rs` maps pingora's callbacks onto Pingap's `PluginStep` values:

```
                  ┌──────────────────────────────────────────┐
   client ───────▶│ early_request_filter                     │  PluginStep::EarlyRequest
                  ├──────────────────────────────────────────┤
                  │ request_filter        (location matched) │  PluginStep::Request
                  ├──────────────────────────────────────────┤
                  │ proxy_upstream_filter                    │  PluginStep::ProxyUpstream
                  ├──────────────────────────────────────────┤
                  │ upstream_peer         (backend selected) │
                  │ upstream_request_filter                  │
                  ├──────────────────────────────────────────┤
                  │ upstream_response_filter                 │  PluginStep::UpstreamResponse
                  ├──────────────────────────────────────────┤
                  │ response_filter / response_body_filter   │  PluginStep::Response
                  ├──────────────────────────────────────────┤
   client ◀───────│ logging                                  │
                  └──────────────────────────────────────────┘
```

Additional hooks that are not plugin steps but matter operationally:

| Callback | Role |
| --- | --- |
| `upstream_peer` | Chooses the backend and applies the location's retry budget (`max_retries`, `max_retry_window`) |
| `connected_to_upstream` | Records reuse, TCP connect and TLS handshake timings |
| `request_body_filter` | Enforces the location's `client_max_body_size` |
| `fail_to_proxy` | Renders the error page from the configured template |

A plugin runs at **exactly one** request step. Configuring a step a plugin does
not implement is a silent no-op — see
[pingap-plugin](../pingap-plugin/README.md#lifecycle-steps).

## Routing

Locations attached to a server are sorted once, by descending weight, and the
first one whose host, path and match conditions all hold wins. Weight is either
the explicit `weight` in `LocationConf` or derived:

| Component | Weight |
| --- | --- |
| Exact path (`=/api`) | 1024 |
| Prefix path (`/api`) | 512 |
| Regex path (`~^/api`) | 256 |
| Path length | + up to 64 |
| Exact host | + 128 |
| Regex host | + host string length |

So `=/api/health` beats `/api` beats `~^/api/.*`, and a host-qualified location
beats an otherwise identical one without a host.

When nothing matches, the request fails with `No matching location, host:<host>`.

## Server configuration

```toml
[servers.main]
addr = "0.0.0.0:443,[::]:443"
locations = ["api", "web"]
threads = 4
global_certificates = true
enabled_h2 = true
access_log = "combined"
enable_server_timing = true
tls_min_version = "TLSv1.2"
tls_max_version = "TLSv1.3"
tls_cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
tls_ciphersuites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
prometheus_metrics = "/metrics"
otlp_exporter = "http://otel-collector:4317/pingap"
reuse_port = true
tcp_fastopen = 4096
tcp_idle = "2m"
tcp_interval = "1m"
tcp_probe_count = 9
downstream_read_timeout = "30s"
downstream_write_timeout = "30s"
modules = ["grpc-web"]
```

Notes on a few of these:

- `addr` accepts several comma-separated listen addresses for one logical server.
- `global_certificates = true` switches the listener to TLS using the dynamic,
  SNI-driven certificate store from
  [pingap-certificate](../pingap-certificate/README.md). Without it the listener
  is plain HTTP, and `enabled_h2` then means h2c.
- `prometheus_metrics` exposes the pull endpoint on this server; a URL value
  instead configures push mode.
- `enable_server_timing` adds a `Server-Timing` response header built from the
  request's timing breakdown — useful when diagnosing where latency comes from.
- `error_template` (under `[basic]`) replaces the built-in `error.html`.

## Per-request context

`Ctx` carries everything the request accumulated and is what access log
variables and `$`-substitutions read from. Timings recorded include upstream TCP
connect, TLS handshake, upstream processing and response, cache lookup and lock,
compression, and total service time. See
[pingap-core](../pingap-core/README.md) and the access log tag table in
[pingap-logger](../pingap-logger/README.md).

## Features

| Feature | Effect |
| --- | --- |
| `tracing` | Enables the OpenTelemetry span integration in `tracing.rs` and cache metrics |

## License

Apache-2.0.
