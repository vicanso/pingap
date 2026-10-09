# Pingap Upstream

[![Crates.io](https://img.shields.io/crates/v/pingap-upstream.svg)](https://crates.io/crates/pingap-upstream)
[![License](https://img.shields.io/crates/l/pingap-upstream.svg)](https://github.com/vicanso/pingap/blob/main/LICENSE)
[![Docs.rs](https://docs.rs/pingap-upstream/badge.svg)](https://docs.rs/pingap-upstream)

`pingap-upstream` is a core crate within the [Pingap](https://github.com/vicanso/pingap) project, providing robust and flexible upstream management for backend services. Built on top of the [Pingora](https://github.com/cloudflare/pingora) framework, it handles service discovery, load balancing, and health checking.

## Core Features

-   **Multiple Load Balancing Strategies**: Choose the best algorithm for your needs.
    -   **Round Robin**: Distributes requests evenly across all healthy backends.
    -   **Least Connections** (`algo = "least_conn"`): the backend with the fewest requests in flight for its weight - a backend of weight 2 is given twice as many as one of weight 1 before it counts as busier. Backends that are level are given requests by the weighted round robin, so an upstream that is not busy behaves as with `round_robin`, weights included. `least_conn` takes no parameter. A request is counted from the moment it is given a backend until it ends, whichever way; the counts are this process's own and start at zero after a reload of the upstream. Use it where requests differ much in how long they take (long polls, uploads, slow queries): round robin hands a backend that is stuck with slow ones as many new requests as the others.
    -   **Sticky sessions** (`algo = "sticky:<cookie>"`): a client stays on the backend it was given first, by a cookie of that name which the proxy hands out itself - the application need not set one, as it has to for `hash:cookie`. A request without the cookie gets a backend by round robin and `Set-Cookie: <cookie>=<id>; Path=/; HttpOnly; SameSite=Lax` (and `Secure` over https) on its response; with it, that backend. The id is a number made of the backend's address, the same in every instance that serves the upstream, and not the address. When the backend the cookie names is gone, unhealthy, held back by its circuit breaker or has just failed the request, the client is given another and a new cookie: sticking never makes a request fail. With `fail_open` and no backend that can take the request, a client stays on the backend of its cookie (unless that one has just failed the request) instead of being moved with every request. The cookie goes on the response of a request that was given a backend, so a response served from the cache without asking the upstream sets none, and neither does an error page of the proxy; an attempt that failed sets none for its backend either. Its attributes are fixed: `Path=/` makes it one cookie per host, so two `sticky` upstreams behind the same host need different cookie names, or each overwrites the other's and the clients are moved back and forth; `SameSite=Lax` keeps it off requests that another site makes from a page of its own (a cross-site `fetch` or form post), which then get a backend by round robin. The cookie name is everything after `sticky:`: letters, digits, `-`, `_` and `.`, with no further parameter. The `Set-Cookie` goes onto whatever response the client's first request gets, also one the origin marked as cacheable by anyone: a CDN or another shared cache in front of pingap either stops caching such a response or stores the cookie and hands it to every visitor, who then all land on one backend. Behind such a cache, have it leave `Set-Cookie` responses alone, or use `hash:ip` / `hash:cookie` instead.
    -   A backend that is unhealthy or held back by its circuit breaker is passed over, and the selection goes on until every backend has been looked at: a request gets `503` only when none of them can take it.
    -   **Retries go elsewhere**: an attempt that the backend failed and that is tried again (a connection that could not be made, with the location's `max_retries`) goes to another backend than the ones that have just failed this request, with every algorithm. It used to be chosen like a first attempt: by a hash that is the backend that has just refused the connection, every time. When there is no other backend that can take it, it goes to one of those again, so an upstream of a single backend is still retried. A retry that only replaces a connection - a kept one the backend had closed in the meantime, an HTTP/2 one it is retiring - stays with the backend: nothing is wrong with it, and by a hash it is where the client belongs.
    -   **`fail_open`**: with `fail_open = true`, a request for which no backend is left - all of them unhealthy by the health check, or held back by their circuit breakers - is sent to one all the same instead of being answered with `503`. For health checks that can fail for every backend at once without the backends being down (a dependency of the check, a slip in its configuration): serving through a backend that may work is then better than serving nothing. Off by default.
    -   **Consistent Hashing**: Provides sticky sessions by hashing request attributes to a specific backend.
    -   **Transparent**: Acts as a direct passthrough proxy without load balancing, forwarding requests to the original host.

-   **Flexible Consistent Hashing Keys**: When using consistent hashing, you can define the key based on various request attributes:
    -   Client IP Address
    -   URL Path, Query, or full URL (`hash:url` is the path and query, without scheme or host, so the same url picks the same backend over HTTP/1.1 and HTTP/2)
    -   HTTP Header value
    -   Cookie value

-   **Dynamic Service Discovery**: Automatically discover and update backend servers from different sources:
    -   **Static**: A fixed list of backend addresses.
    -   **DNS**: by the address records of a name (`discovery = "dns"`) or by its SRV records, which also give ports and weights (`discovery = "srv"`).
    -   **Docker**: Discover backends from Docker container labels.

-   **Active Health Checking**: Periodically probes backend servers to ensure they are healthy. Unhealthy backends are automatically and temporarily removed from the load balancing pool.
    -   pingora starts every backend healthy and offers no way to change that, so an upstream's **first round of checks is decisive**: one failed check marks a backend unhealthy, whatever `failure` is set to. After a round that checked at least one backend, `failure` applies again. A success is unaffected, since a backend that passes its first check was already healthy.
    -   When a config change adds or modifies an upstream, that first round runs **before** pingap switches to it, so a backend that is down is out of the pool from the first request. It used to go live anyway: one failed check only brought it to 1 of the default 2 failures.
    -   At startup the first round runs as soon as the background health check starts, alongside the first requests. Until it completes, every backend is still treated as healthy.
    -   A round with nothing to check, because discovery has not found any backend yet, does not count as the first round.

-   **Advanced Configuration**:
    -   **TLS & SNI**: Secure connections to backends with configurable TLS and Server Name Indication. A private CA bundle (`ca`, as a PEM file path, base64 or raw PEM) can replace the system trust store for one upstream, so self-signed or internal-PKI backends keep `verify_cert` on; pooled connections are keyed by that bundle, so upstreams with different CAs never share one. With the rustls backend the backend's own certificate must be a real leaf (no `CA:TRUE`), which webpki enforces and OpenSSL does not. `sni = "$host"` asks the backend for the host the client asked the proxy for, on any upstream (it used to work for a transparent one only, and sent the text `$host` anywhere else): one upstream then serves many names, and each certificate is verified against its own. On an upstream with backends of its own the name is the request's host in lower case, without the port, and a request that has none to give (no `Host`, or an IP address) is refused with `503` rather than sent over a handshake without a name, which OpenSSL would not verify. (A transparent upstream connects to that host and names it as the request does, as before.) The client chooses that name, and so which of the backend's certificates is accepted: use such an upstream from locations that are limited to the hosts it is meant for (`host = "a.example.com,b.example.com"`).
    -   **Mutual TLS**: `client_cert` and `client_key` (each a PEM file path, base64 or raw PEM; the certificate first, then what leads from it to its CA) are presented to a backend that asks its clients for a certificate. Both are read when the upstream is built, so a key that is not the certificate's is an error of `pingap -t` and of a reload, not a handshake that fails per request; so is a `client_cert` on an upstream without `sni`, which makes no TLS connection to present it on. A path is read at that point too: a renewed file takes a reload of the upstream. Pooled connections are keyed by the certificate, so two upstreams with different certificates never share one, and an `https://` health check presents it too: without it such a backend would refuse the check and never be healthy. A `grpc` or `wss` check does not present it.
    -   **HTTP/2 & ALPN**: Supports ALPN for negotiating HTTP/1.1 or HTTP/2 with backends, with per-upstream flow-control windows (`h2_stream_window_size`, `h2_connection_window_size`) for large responses over high-latency links.
    -   **Connection Timeouts**: Fine-grained control over connection, read, write, and idle timeouts.
    -   **TCP Control**: Advanced options for TCP keepalives, buffer sizes, and TCP Fast Open. Keepalive is on as soon as one of `tcp_idle`, `tcp_interval`, `tcp_probe_count` or `tcp_user_timeout` (Linux only) is set, and what is left out takes the kernel's default (7200s, 75s, 9 probes), so `tcp_user_timeout` works on its own. The idle time and the interval must be at least `1s` and the probe count between 1 and 16.
    -   **Request Header Policy**: By default hop-by-hop and `Connection`-nominated request headers are stripped before a request reaches the backend and only WebSocket upgrades are forwarded, as RFC 9110 asks. Each rule can be relaxed per upstream (`strip_hop_by_hop`, `strip_connection_nominated`, `reject_malformed_connection_nominations`, `h1_upgrade`) for a backend that still depends on the old passthrough behaviour, such as Docker `attach`/`exec` or h2c upgrades.

-   **Circuit Breaking**: With `enable_backend_stats` on, each backend's responses are counted (`backend_failure_status_code` decides what counts as a failure; by default every 5xx does, and a connection that could not be made always does). `circuit_break_max_consecutive_failures` and `circuit_break_max_failure_percent` (the latter only once `circuit_break_min_requests_threshold` requests were seen in the stats window; `0` disables either rule) trip the breaker. The stats window is the last `backend_stats_interval` (at least `1ms`), as a sliding estimate: the requests of the interval in progress plus those of the one before it, weighted by how much of it still falls inside the window. The rule therefore acts on failures as they happen (it used to read the last completed interval only, so it tripped up to one interval late and never within the first), and a backend that has recovered is not reopened by a single failure once its bad interval has moved out of the window. When tripped: the backend is **open** and skipped for `circuit_break_open_duration`, then **half-open**, where up to `circuit_break_half_open_consecutive_success_threshold` probe requests are let through; that many consecutive successes close it again, one failure reopens it. A request the backend accepts and then fails to answer (a read timeout, a connection closed before the response) counts as a failure like a refused connection does; a pooled connection the backend had already closed does not. Probes that never report an outcome, because the client went away first for example, are given up on after another `circuit_break_open_duration` and a new round of probes starts, so a backend does not stay half-open. The state is exported as `pingap_upstream_backend_circuit_state` (0 closed, 1 open, 2 half-open).

-   **Runtime Management**:
    -   Upstreams can be dynamically added, updated, or removed at runtime without service interruption.
    -   Exposes health and connection metrics for monitoring and observability.
    -   `algo` (`round_robin`, `least_conn`, `sticky:<cookie>`, or `hash`, `hash:<ip|url|path|header|cookie|query>[:<key>]`) and `alpn` (`h1`, `h2`, `h2h1`) are validated when the upstream is built; an unknown value is an error instead of silently the default.

## Core Concepts

### `Upstream`

The `Upstream` struct is the central component, representing a logical group of backend servers. It encapsulates the configuration for load balancing, health checks, TLS, timeouts, and service discovery for that group.

### `SelectionLb`

This enum represents the configured load balancing strategy for an `Upstream`:
-   `RoundRobin(LoadBalancer<RoundRobin>)`
-   `Consistent { lb: LoadBalancer<Consistent>, hash: HashStrategy }`
-   `Transparent`

A transparent upstream builds the peer from the request's authority (`:authority` for HTTP/2, the `Host` header for HTTP/1) on every request. A port in it is honoured (`Host: backend:8080` connects to port 8080; without one, 80 or 443 by `sni`), the host is resolved asynchronously (an IP literal needs no lookup; `ipv4_only` restricts a name to its IPv4 addresses, as it does for the other discovery modes), and a host that does not resolve is a `503` for that request rather than a failed lookup inside the peer constructor, which used to panic.

The `HealthCheckTask` logs each backend refresh and health check at `debug`; only failures are `error`.

### `HealthCheckTask`

A background service that runs periodically for all configured upstreams. It is responsible for:
1.  Triggering service discovery updates (e.g., re-resolving DNS).
2.  Executing health checks against each backend.
3.  Sending notifications when an upstream's health status changes (e.g., all backends become unhealthy).

## Usage

This crate is primarily used within the `pingap` proxy application. The general workflow is as follows:

1.  Define upstream configurations (e.g., in a YAML file).
2.  The `pingap` application parses these configurations into `UpstreamConf` structs.
3.  An `Upstream` instance is created for each configuration.
4.  The `HealthCheckTask` is started to monitor all upstreams.
5.  When a request arrives, the proxy selects the appropriate `Upstream` and calls `new_http_peer()` to get a healthy, configured backend connection.


### Conceptual Code Example

```rust
use pingap_upstream::{Upstream, UpstreamConf};
use std::sync::Arc;
use std::collections::HashMap;

fn main() {
    // Configuration would typically be loaded from a file
    let mut conf = UpstreamConf::default();
    conf.addrs = vec!["127.0.0.1:8080".to_string()];
    conf.algo = Some("round_robin".to_string());

    // Create a new Upstream
    let upstream = Upstream::new("my_service", &conf, None).unwrap();
    let upstream = Arc::new(upstream);

    // In a request handling context, a peer would be created.
    // This is a simplified representation.
    // let http_peer = upstream.new_http_peer(&session, &mut client_ip, true).await;
    
    println!("Upstream '{}' created successfully.", upstream.name);
}
```

## License

This project is licensed under the [Apache-2.0 License](https://github.com/vicanso/pingap/blob/main/LICENSE).