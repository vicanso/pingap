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
| `request_body_filter` | Enforces the location's `client_max_body_size`. After a `101` the client's half of the tunnel is not a request body and is not held to the limit: a websocket can send any amount |
| `fail_to_proxy` | Classifies the failure and renders the error page from the configured template (see [Error responses](#error-responses)) |

A plugin runs at **exactly one** request step. Configuring a step a plugin does
not implement is a silent no-op — see
[pingap-plugin](../pingap-plugin/README.md#lifecycle-steps).

A plugin that answers at `EarlyRequest` ends the request there. pingora only
lets a request stop at `request_filter`, so that step recognises the response
already sent and nothing later runs on top of it.

Before anything reads the request, `early_request_filter` joins the cookies of
a request into one `Cookie` field. HTTP/2 lets a client send them as several
fields (RFC 9113 8.2.3), and a reader that looks at the first field alone —
`jwt` with `cookie`, `csrf`, a sticky cookie, `match_cookies`, the `{~name}` of
the access log — would miss the rest. The upstream gets the single field too.

`X-Request-Id` (and the `X-Trace-Id` / `X-Span-Id` of the tracing feature) is
set in `response_filter`, on what goes to the client. It is not part of what
the cache stores, so a cache hit carries the ids of the request it answers.

A response a plugin answers with ends with its header when it has no body by
definition: a `HEAD`, a `204`, a `304`. Those two statuses carry no generated
`Content-Length` either.

`$proxy_add_x_forwarded_for` (also what `enable_reverse_proxy_headers` sets)
is every `X-Forwarded-For` line of the request, in order, followed by the
address of the peer. A proxy in front that adds its entry as a line of its own
is carried over like one that appends to the existing line.

An interim response from the upstream, such as `103 Early Hints`, is passed on
to the client as it is. The response plugins, the status in the access log and
the metrics, and the upstream timings all belong to the final response; `101`
counts as final, since it ends the HTTP exchange.

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

When nothing matches, the request is answered with `404` and the error `No matching location, host:<host>`.

A matched location counts the request against its `max_processing` limit only
after the `client_max_body_size` check has passed, and every request it counted
is uncounted when it completes, a `429` included; a request rejected with `413`
never touches the count.

## Error responses

`fail_to_proxy` turns a pingora error into a status and, when there is still
someone to send it to, a page rendered from the error template:

| Failure | Status | Page written |
| --- | --- | --- |
| A location or plugin rejected the request with a status | that status | yes |
| Upstream timeout: connecting, the TLS handshake, a read or a write | 504 | yes |
| Any other upstream failure: refused or reset connection, a response that cannot be parsed | 502 | yes |
| Downstream read timeout (`downstream_read_timeout`) | 408 | yes |
| Malformed request header | 400 | yes |
| Client closed the connection, the socket failed on a read or write, or a write timed out | 499 | no |
| Anything else | 500 | yes |

`499` is nginx's code for a client that went away. It is recorded for the
access log and the metrics, but nothing is written to a connection that is dead
or stuck, and the event is logged at `info` rather than `error` because there
is nothing to fix on this side. Once a final response header has gone out, a
later failure (an upstream dropping mid-body, say) keeps the status the client
saw and appends nothing to the body, the same rule pingora's own error response
follows.

A `HEAD` gets the header of the page, its `Content-Length` included, and no
body.

Each failure is logged once, by pingap, with the client address, method, host
and path, the pingora error type and the status; pingora's own line for the
same error is suppressed. A `5xx` is logged at `error`. A `4xx` - no location
for the host, a body over the limit, a location at its `max_processing` - is
the request's doing and is logged at `info` (`request refused`): at `error`
it was a line per request of whoever was scanning or being throttled.

The connection stays open after the error page of a request that was refused
before it was sent anywhere - no location for the host, a plugin or a limit
that failed it - when the request had been read in full, so a client that is
refused does not come back with a new connection, and a new TLS handshake, for
every request. With some of the request body still to come it is closed, as it
is after a malformed request or a read timeout. It is closed as well after a
failure on the way to the upstream (no healthy backend, connect or read
errors, a timeout): pingora ends the connection there whatever the error page
says, so the page says `Connection: close`. The response headers for the statuses pingap raises
itself are built once and cloned.

## Server configuration

```toml
[servers.main]
addr = "0.0.0.0:443,[::]:443"
locations = ["api", "web"]
threads = 4
global_certificates = true
ja4 = true
enabled_h2 = true
access_log = "combined"
enable_server_timing = true
tls_min_version = "tlsv1.2"
tls_max_version = "tlsv1.3"
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
- `tcp_idle`, `tcp_interval`, `tcp_probe_count` and `tcp_user_timeout` (Linux
  only) turn TCP keepalive on for accepted connections as soon as one of them
  is set. Whatever is left out takes the kernel's default (7200s idle, 75s
  between probes, 9 probes), so `tcp_user_timeout` can be set on its own. The
  idle time and the interval are whole seconds of at least `1s` and the probe
  count is at least 1; smaller values are refused by the config check, as the
  kernel would refuse them on every connection.
- `global_certificates = true` switches the listener to TLS using the dynamic,
  SNI-driven certificate store from
  [pingap-certificate](../pingap-certificate/README.md). Without it the listener
  is plain HTTP, and `enabled_h2` then means h2c.
- `tls_min_version` / `tls_max_version` / `tls_cipher_list` /
  `tls_ciphersuites` apply only on an **OpenSSL** build. Version names are
  `tlsv1.1` / `tlsv1.2` / `tlsv1.3` (case-insensitive, so `TLSv1.2` also
  works). A `tls-rustls` build always offers TLS 1.2/1.3 with rustls' default
  cipher suites; setting any of those fields fails config validation at
  startup / `--test` / auto-restart (see
  [pingap-certificate](../pingap-certificate/README.md)). The admin UI disables
  the matching form fields on a rustls binary.
- `h2_max_concurrent_streams`, `h2_max_header_list_size`,
  `h2_initial_window_size`, `h2_initial_connection_window_size` and
  `h2_idle_timeout` tune the downstream HTTP/2 SETTINGS of a listener. Unset
  keeps pingora's bounded defaults (100 streams, 64 KiB header list), which cap
  the memory one client connection can pin; raise them deliberately for gRPC
  fan-in or large-header clients rather than removing the bound.
- `ja4 = true` computes the JA4 TLS fingerprint of every client; see
  [JA4 fingerprint](#ja4-fingerprint). It needs `global_certificates = true`,
  which config validation checks.
- `prometheus_metrics` exposes the pull endpoint on this server; a URL value
  instead configures push mode. The pull endpoint is a path of the server like
  any other: the request plugins of the location that matches it (by host and
  path) run first, so `/metrics` under a location with `basic_auth` or
  `ip_restriction` is behind them, and a plugin there that answers requests
  itself (`directory`, `mock`, `redirect`) answers this path too. It has no
  authentication of its own: a request that matches no location of the server
  gets the metrics unguarded. When every location names a `host`, that is any
  request with another `Host`, so give the path a location without a host if
  the endpoint is to be guarded for all of them.
- `enable_server_timing` adds a `Server-Timing` response header built from the
  request's timing breakdown — useful when diagnosing where latency comes from.
- `error_template` (under `[basic]`) replaces the built-in `error.html`. The
  template is parsed once when the server starts, and three placeholders are
  filled in per error:

  ```text
  {{version}}     the pingap version
  {{error_type}}  the pingora error type, also sent as X-Pingap-EType
  {{content}}     the message for the client
  ```

  Any other name in double braces is left as literal text, and a template
  whose first character is `{` is served as `application/json`.

  `{{content}}` is what the client may know. For a `4xx` that pingap or a
  plugin raised it is the reason: the route that did not match, the limit that
  was exceeded. For everything else, an upstream failure or a `5xx`, it is
  only the status text, `Bad Gateway` for instance: the error itself names
  upstream addresses and other internals, and goes to the log, not the page.
  The values are escaped for the page, as HTML or as the inside of a JSON
  string, since the reason can quote the request's host and path.

## JA4 fingerprint

With `ja4 = true` on a TLS server, pingap computes the
[JA4](https://github.com/FoxIO-LLC/ja4) fingerprint of each client from its
ClientHello. The fingerprint identifies the client's TLS stack, whatever its
`User-Agent` claims:

```toml
[servers.main]
addr = "0.0.0.0:443"
global_certificates = true
ja4 = true
access_log = "{client_ip} {status} {:ja4}"

[locations.api]
upstream = "api"
proxy_set_headers = ["X-JA4: $ja4"]
```

| Where | Name | Value |
| --- | --- | --- |
| Request and response headers | `$ja4` (or `:ja4`) | `JA4`, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| Access log | `{:ja4}` | `JA4` |
| Access log | `{:ja4_r}` | `JA4_r`: the sorted lists instead of their hashes |
| Access log | `{:ja4_o}` | `JA4_o`: hashed over the lists in the order the client sent them |
| Access log | `{:ja4_ro}` | `JA4_ro`: the lists in the order sent, unhashed |

How it works:

- It follows FoxIO's JA4 specification, the TLS client fingerprint, which is
  BSD 3-Clause licensed. The specification's own examples are the unit tests
  for all four forms. The other JA4+ fingerprints are not implemented.
- The ClientHello is read from the TCP stream before the TLS handshake, in code
  pingora shares between its TLS backends. OpenSSL and rustls builds therefore
  compute the same value for the same client. Every byte read is put back for
  the handshake.
- It never delays or rejects a connection beyond reading the ClientHello the
  handshake needs anyway. A client with no complete ClientHello within 5
  seconds, one larger than 16 KiB, or a malformed one simply has no
  fingerprint. Plain HTTP connections never have one. Without a fingerprint
  the access log field is empty, and a header set from `$ja4` falls back to
  the literal text, like every other variable that cannot be resolved.
- A ClientHello split over several TLS records is reassembled first. With
  Encrypted Client Hello, the outer ClientHello is the one on the wire and the
  one fingerprinted.
- The fingerprint belongs to the connection. Every request on a keep-alive or
  HTTP/2 connection carries it, and it is dropped when the connection closes.
- The cost is one ClientHello parse and two SHA-256 hashes per new TLS
  connection, plus one lookup per request. It is off by default.

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
| `openssl` (default) | Terminate downstream TLS via pingora OpenSSL; honour per-server version/cipher settings |
| `tls-rustls` | Terminate downstream TLS via pingora rustls; the `tls_*` fields above are rejected at config validation |
| `tracing` | Enables the OpenTelemetry span integration in `tracing.rs` and cache metrics |

## License

Apache-2.0.
