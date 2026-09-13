# Pingap Upstream

[![Crates.io](https://img.shields.io/crates/v/pingap-upstream.svg)](https://crates.io/crates/pingap-upstream)
[![License](https://img.shields.io/crates/l/pingap-upstream.svg)](https://github.com/vicanso/pingap/blob/main/LICENSE)
[![Docs.rs](https://docs.rs/pingap-upstream/badge.svg)](https://docs.rs/pingap-upstream)

`pingap-upstream` is a core crate within the [Pingap](https://github.com/vicanso/pingap) project, providing robust and flexible upstream management for backend services. Built on top of the [Pingora](https://github.com/cloudflare/pingora) framework, it handles service discovery, load balancing, and health checking.

## Core Features

-   **Multiple Load Balancing Strategies**: Choose the best algorithm for your needs.
    -   **Round Robin**: Distributes requests evenly across all healthy backends.
    -   **Consistent Hashing**: Provides sticky sessions by hashing request attributes to a specific backend.
    -   **Transparent**: Acts as a direct passthrough proxy without load balancing, forwarding requests to the original host.

-   **Flexible Consistent Hashing Keys**: When using consistent hashing, you can define the key based on various request attributes:
    -   Client IP Address
    -   URL Path, Query, or full URL
    -   HTTP Header value
    -   Cookie value

-   **Dynamic Service Discovery**: Automatically discover and update backend servers from different sources:
    -   **Static**: A fixed list of backend addresses.
    -   **DNS**: A-record or SRV-record based discovery.
    -   **Docker**: Discover backends from Docker container labels.

-   **Active Health Checking**: Periodically probes backend servers to ensure they are healthy. Unhealthy backends are automatically and temporarily removed from the load balancing pool.

-   **Advanced Configuration**:
    -   **TLS & SNI**: Secure connections to backends with configurable TLS and Server Name Indication. A private CA bundle (`ca`, as a PEM file path, base64 or raw PEM) can replace the system trust store for one upstream, so self-signed or internal-PKI backends keep `verify_cert` on; pooled connections are keyed by that bundle, so upstreams with different CAs never share one. With the rustls backend the backend's own certificate must be a real leaf (no `CA:TRUE`), which webpki enforces and OpenSSL does not.
    -   **HTTP/2 & ALPN**: Supports ALPN for negotiating HTTP/1.1 or HTTP/2 with backends, with per-upstream flow-control windows (`h2_stream_window_size`, `h2_connection_window_size`) for large responses over high-latency links.
    -   **Connection Timeouts**: Fine-grained control over connection, read, write, and idle timeouts.
    -   **TCP Control**: Advanced options for TCP keepalives, buffer sizes, and TCP Fast Open.
    -   **Request Header Policy**: By default hop-by-hop and `Connection`-nominated request headers are stripped before a request reaches the backend and only WebSocket upgrades are forwarded, as RFC 9110 asks. Each rule can be relaxed per upstream (`strip_hop_by_hop`, `strip_connection_nominated`, `reject_malformed_connection_nominations`, `h1_upgrade`) for a backend that still depends on the old passthrough behaviour, such as Docker `attach`/`exec` or h2c upgrades.

-   **Circuit Breaking**: With `enable_backend_stats` on, each backend's responses are counted (`backend_failure_status_code` decides what counts as a failure; by default every 5xx does, and a connection that could not be made always does). `circuit_break_max_consecutive_failures` and `circuit_break_max_failure_percent` (the latter only once `circuit_break_min_requests_threshold` requests were seen in the stats window; `0` disables either rule) trip the breaker: the backend is **open** and skipped for `circuit_break_open_duration`, then **half-open**, where up to `circuit_break_half_open_consecutive_success_threshold` probe requests are let through; that many consecutive successes close it again, one failure reopens it. The state is exported as `pingap_upstream_backend_circuit_state` (0 closed, 1 open, 2 half-open).

-   **Runtime Management**:
    -   Upstreams can be dynamically added, updated, or removed at runtime without service interruption.
    -   Exposes health and connection metrics for monitoring and observability.
    -   `algo` (`round_robin`, or `hash`, `hash:<ip|url|path|header|cookie|query>[:<key>]`) and `alpn` (`h1`, `h2`, `h2h1`) are validated when the upstream is built; an unknown value is an error instead of silently the default.

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