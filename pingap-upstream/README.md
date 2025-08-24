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
    -   **TLS & SNI**: Secure connections to backends with configurable TLS and Server Name Indication.
    -   **HTTP/2 & ALPN**: Supports ALPN for negotiating HTTP/1.1 or HTTP/2 with backends.
    -   **Connection Timeouts**: Fine-grained control over connection, read, write, and idle timeouts.
    -   **TCP Control**: Advanced options for TCP keepalives, buffer sizes, and TCP Fast Open.

-   **Runtime Management**:
    -   Upstreams can be dynamically added, updated, or removed at runtime without service interruption.
    -   Exposes health and connection metrics for monitoring and observability.

## Core Concepts

### `Upstream`

The `Upstream` struct is the central component, representing a logical group of backend servers. It encapsulates the configuration for load balancing, health checks, TLS, timeouts, and service discovery for that group.

### `SelectionLb`

This enum represents the configured load balancing strategy for an `Upstream`:
-   `RoundRobin(LoadBalancer<RoundRobin>)`
-   `Consistent { lb: LoadBalancer<Consistent>, hash: HashStrategy }`
-   `Transparent`

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
    // let http_peer = upstream.new_http_peer(&session, &client_ip);
    
    println!("Upstream '{}' created successfully.", upstream.name);
}
```

## License

This project is licensed under the [Apache-2.0 License](https://github.com/vicanso/pingap/blob/main/LICENSE).