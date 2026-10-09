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
| `upstream_peer` | Chooses the backend and applies the location's retry budget (`max_retries`, `max_retry_window`) and its timeouts (`connection_timeout`, `read_timeout`, `write_timeout`, each in place of the upstream's) |
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

`enable_reverse_proxy_headers` sets the five headers the way nginx is usually
set up, by the same variables: `X-Real-IP: $remote_addr`,
`X-Forwarded-For: $proxy_add_x_forwarded_for`, `X-Forwarded-Proto: $scheme`,
`X-Forwarded-Host: $host` and `X-Forwarded-Port: $server_port`. Each is what
this connection has.

### Behind a load balancer

With a load balancer in front that ends TLS, the connection Pingap sees is the
balancer's: `$remote_addr` is its address and `$scheme` is `http`, and an
upstream told so answers with redirects to `https` that never end. List the
balancer in `basic.trusted_proxies` and set the client's own values on the
location, as one would in nginx with `$http_x_forwarded_proto`:

```toml
[basic]
trusted_proxies = ["10.0.0.0/8"]

[locations.app]
upstream = "app"
enable_reverse_proxy_headers = true
proxy_set_headers = [
    "X-Real-IP: $client_ip",
    "X-Forwarded-Proto: $forwarded_proto",
    "X-Forwarded-Port: $forwarded_port",
]
```

`proxy_set_headers` comes after the defaults and replaces them.

| Variable | Value |
| --- | --- |
| `$client_ip` | The address of the client: what a trusted proxy says of it, and the peer's own otherwise |
| `$forwarded_proto` | `http` or `https` from the proxy's `X-Forwarded-Proto`; the scheme of this connection otherwise |
| `$forwarded_port` | The proxy's `X-Forwarded-Port`, or else the default port of the scheme it names (`443`, `80`); the port of this listener otherwise |
| `$forwarded_host` | The proxy's `X-Forwarded-Host`, when it reads as a host name; the host of this request otherwise |

A request that did not come through a trusted proxy - or any request, without
`trusted_proxies` - gets the values of the connection: a forwarded header is
then only what the request claims.

- Of a header that has several entries (`https, http`) the first is taken,
  the client's end of a chain of proxies. The proxy nearest to the client has
  to **write** the header itself; one that passes the client's on, or only
  appends to it, hands on the client's word under its own name.
- Use `$forwarded_host` only for a proxy that does write `X-Forwarded-Host`.
  Few do, and one that does not passes on whatever the client sent - to an
  upstream that may build its links, a password reset among them, from it.

The variables can be used in the header plugins as well.

### PROXY protocol

A load balancer that works on connections - a cloud NLB, HAProxy in TCP mode -
writes no `X-Forwarded-For`. It says who the client is in a header of its own
ahead of everything the client sends, TLS included. A server with
`proxy_protocol = true` reads it:

```toml
[basic]
trusted_proxies = ["10.0.0.0/8"]      # where the load balancer connects from

[servers.web]
addr = "0.0.0.0:443"
global_certificates = true
proxy_protocol = true
```

- The address in the header becomes the address of the connection:
  `$remote_addr`, `{remote}` in the access log, `$client_ip`, and what the
  address checks and limits of the plugins go by. Nothing else has to be
  configured for it.
- Versions 1 (text) and 2 (binary) are read, on listeners with and without
  TLS, for HTTP/1.1 and HTTP/2. A `LOCAL` header of version 2 and `UNKNOWN`
  of version 1 - the load balancer's own connection, a health check - leave
  the connection its address.
- The header is read from the addresses of `basic.trusted_proxies` and from
  nobody else: whoever may send one is whoever they say. The option without
  that list is a configuration error. A client that connects directly and
  sends a header gets what a server that reads none gives it: a `400`, or on
  a TLS listener a handshake that fails.
- A trusted proxy that sends no header is served as it is, under its own
  address, so a health check that does not speak the protocol still passes.
  A header that starts as one and is none ends the connection.
- The connection of a trusted proxy is judged by its first bytes, whenever
  they come: some balancers send the header only together with the first
  bytes of the client, on a connection the client may have opened well ahead
  of its request. One on which nothing arrives for a minute is closed.
- It is read once, at the start of the connection. On a connection that is
  kept, a second one in front of a later request is not a header but a
  broken request.
- The address the client connected to (the destination in the header) is not
  used: `$server_addr` and `$server_port` are those of this listener.
- With `proxy_protocol` on a listener **without** TLS, the metric of how long
  evicted upstream connections had been idle is not reported for that server.
  The header is not sent on to upstreams.

### Client certificates (mutual TLS)

A server with `tls_client_ca` asks every client for a certificate and verifies
it against that CA, in the TLS handshake:

```toml
[servers.devices]
addr = "0.0.0.0:8443"
global_certificates = true
tls_client_ca = "/etc/pingap/device-ca.pem"   # a path, base64 or the PEM itself
# tls_client_auth = "optional"                # default: "require"
locations = ["devices"]

[locations.devices]
upstream = "devices"
proxy_set_headers = [
    "X-Client-Subject: $tls_client_subject",
    "X-Client-Fingerprint: $tls_client_fingerprint",
    "X-Client-Verified: $tls_client_verified",
]
```

| `tls_client_auth` | A client without a certificate | A certificate that does not verify |
| --- | --- | --- |
| `require` (default) | handshake fails | handshake fails |
| `optional` | let in, `$tls_client_verified` is `false` | handshake fails |

A certificate that was not issued by the CA, has expired or is not yet valid
never gets as far as a request. With `optional` it is for a location or a
plugin to tell the two kinds of client apart; nothing of the proxy does on
its own.

| Variable | Access log | Value |
| --- | --- | --- |
| `$tls_client_subject` | `{:tls_client_subject}` | The subject of the certificate, in the order the certificate has it: `O=Example, CN=device-42`. A `,`, `+`, `"`, `` \ ``, `<`, `>`, `;` or `=` inside a value is written with a `` \ `` in front of it, as RFC 4514 does, so a value can not pass for another part of the name |
| `$tls_client_fingerprint` | `{:tls_client_fingerprint}` | The SHA-256 of the certificate, in lower case hex |
| `$tls_client_serial` | `{:tls_client_serial}` | Its serial number, in lower case hex: what `openssl x509 -noout -serial` prints, in lower case |
| `$tls_client_verified` | `{:tls_client_verified}` | `true` when the client showed a certificate, `false` when it showed none |

- As header values the first three are **empty** for a client without a
  certificate, and the header is set all the same: what the client sent under
  that name is replaced, never passed on as if the proxy had vouched for it.
  That holds for `proxy_set_headers` and for `set_headers` of a
  `request_headers` plugin, on every location of the server whose upstream
  reads them. `proxy_add_headers`, `add_headers` and `set_headers_not_exists`
  keep what the client sent, so they are not the ones to use here.
- The certificate is the connection's: every request on it, and every stream
  of an HTTP/2 connection, has the same one.
- The CA is read when the server starts. A changed `tls_client_ca` is a change
  of the server, which takes a restart (`--autorestart`), like its other TLS
  settings. Revocation lists are not checked: to shut a certificate out before
  it expires, refuse its fingerprint or serial in the upstream or a plugin.
- Both TLS backends do this. `pingap -t` reads the CA and reports one that
  does not parse.

An interim response from the upstream, such as `103 Early Hints`, is passed on
to the client as it is. The response plugins, the status in the access log and
the metrics, and the upstream timings all belong to the final response; `101`
counts as final, since it ends the HTTP exchange.

## Routing

A request is routed by the path of its target. A target that is none of the
forms HTTP has for one - a path (`/a?b=1`), a url (`http://host/a`) or `*` -
is answered with `400` before that. `GET robots.txt HTTP/1.1`, without the
slash, used to be routed, run through plugins and cached as `/` while the
upstream was asked for `robots.txt`: `GET secret/report` went around the
plugins of a location for `/secret`, and a `404` for such a target could
become the cached front page.

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
otlp_exporter = "http://otel-collector:4317"
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
