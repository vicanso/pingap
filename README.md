# pingap

Before the pingap version is stable, no pull requests will be accepted. If you have any questions, please raise an issue.

![Pingap Logo](./asset/pingap-logo.png)

## Overview

Pingap is a high-performance reverse proxy built on [pingora](https://github.com/cloudflare/pingora), offering a simpler and more efficient alternative to nginx. It includes optional Sentry and OpenTelemetry support in its full-featured version.

[中文说明](./README_zh.md) | [Examples](./examples/README.md) | [Documentation](http://pingap.io/pingap-en/)

```mermaid
flowchart LR
  internet("Internet") -- request --> pingap["Pingap"]
  pingap -- proxy:pingap.io/api/* --> apiUpstream["10.1.1.1,10.1.1.2"]
  pingap -- proxy:cdn.pingap.io --> cdnUpstream["10.1.2.1,10.1.2.2"]
  pingap -- proxy:pingap.io --> upstream["10.1.3.1,10.1.3.2"]
```

## Key Features

- **Multi-Location Support**: Configure multiple locations with host/path filtering and weighted routing
- **Advanced Proxy Features**:
  - Path rewriting with regex support
  - Transparent proxy
  - HTTP/1.1 and HTTP/2 support (including h2c)
  - gRPC-web reverse proxy
- **Service Discovery**: Static, DNS, and Docker label support
- **Monitoring & Observability**:
  - 10+ Prometheus metrics (pull/push)
  - OpenTelemetry with W3C context and Jaeger trace support
  - Detailed access logging with 30+ configurable attributes
- **Configuration**:
  - TOML-based configuration
  - File and etcd storage support
  - Hot reload support (10-second activation)
  - Web UI for easy management
- **Security & Performance**:
  - Let's Encrypt integration
  - Multi-domain TLS support with automatic certificate selection
  - HTTP plugin system (caching, compression, auth, rate limiting)
  - Detailed performance metrics

## Quick Start

Pingap can be started with either a configuration directory or a single TOML file:

```bash
# Using a config directory
RUST_LOG=INFO pingap -c=/opt/pingap/conf -d --log=/opt/pingap/pingap.log

# Using a single TOML file
RUST_LOG=INFO pingap -c=/opt/pingap/pingap.toml -d --log=/opt/pingap/pingap.log
```

Key flags:
- `-c`: Path to config directory or TOML file
- `-d`: Run in daemon/background mode
- `--log`: Path to log file (logs are appended)
- `RUST_LOG=INFO`: Set logging level (DEBUG, INFO, WARN, ERROR)

## Graceful Restart

Performs a zero-downtime restart of Pingap by following these steps:
1. Validates the new configuration
2. Gracefully shuts down the existing process
3. Starts a new process to handle incoming requests

```bash
# Graceful restart command
RUST_LOG=INFO pingap -c=/opt/pingap/conf -t \
  && pkill -SIGQUIT pingap \
  && RUST_LOG=INFO pingap -c=/opt/pingap/conf -d -u --log=/opt/pingap/pingap.log
```

Key flags:
- `-t`: Test/validate configuration before restart
- `-u`: Upgrade mode (ensures smooth handover from old process)
- `-d`: Run in daemon mode
- `SIGQUIT`: Signal for graceful shutdown

## Auto Restart

Automatically monitors configuration files and handles changes in two ways:
- **Full Restart**: When core configurations change, performs a graceful restart
- **Hot Reload**: When only upstream or location configurations change, updates take effect within ~10 seconds without restart

```bash
# Enable auto-restart and hot reload
RUST_LOG=INFO pingap -c=/opt/pingap/conf \
  -a -d --autoreload --log=/opt/pingap/pingap.log
```

Key flags:
- `-a`: Enable auto-restart on configuration changes
- `--autoreload`: Enable hot reload for upstream/location changes
- `-d`: Run in daemon mode
- `-c`: Path to configuration directory

## Docker

Run Pingap in a Docker container with auto-restart and admin interface enabled:

```bash
docker run -it -d --restart=always \
  -v $PWD/pingap:/opt/pingap \
  -p 3018:3018 \
  vicanso/pingap -c /opt/pingap/conf \
  --autoreload \
  --admin=pingap:123123@0.0.0.0:3018
```

Key options:
- `-it`: Interactive terminal (allows input/output)
- `-d`: Run container in detached/background mode
- `--restart=always`: Automatically restart container if it stops
- `-v $PWD/pingap:/opt/pingap`: Mount local config directory into container
- `-p 3018:3018`: Expose admin interface port
- `--autoreload`: Enable hot reload for configuration changes
- `--admin=user:pass@host:port`: Enable admin interface with credentials

Note: Remember to change the default admin credentials (`pingap:123123`) in production environments.

## Dev

```bash
make dev
```

If you need a web admin, you should install nodejs and build web asssets.

```bash
# generate admin web asset
cd web
yarn install
cd ..
make build-web
```


## Config

```toml
[upstreams.charts]
addrs = ["127.0.0.1:5000"]

[locations.lo]
upstream = "charts"
path = "/"

[servers.test]
addr = "0.0.0.0:6188"
locations = ["lo"]
```

All toml configurations are as follows [pingap.toml](./conf/pingap.toml).

## Proxy step

```mermaid
graph TD;
  server["HTTP Server"];
  locationA["Location A"];
  locationB["Location B"];
  locationPluginListA["Proxy Plugin List A"];
  locationPluginListB["Proxy Plugin List B"];
  upstreamA1["Upstream A1"];
  upstreamA2["Upstream A2"];
  upstreamB1["Upstream B1"];
  upstreamB2["Upstream B2"];
  locationResponsePluginListA["Response Plugin List A"];
  locationResponsePluginListB["Response Plugin List B"];

  start("New Request") --> server

  server -- "host:HostA, Path:/api/*" --> locationA

  server -- "Path:/rest/*"--> locationB

  locationA -- "Exec Proxy Plugins" --> locationPluginListA

  locationB -- "Exec Proxy Plugins" --> locationPluginListB

  locationPluginListA -- "proxy pass: 10.0.0.1:8001" --> upstreamA1

  locationPluginListA -- "proxy pass: 10.0.0.2:8001" --> upstreamA2

  locationPluginListA -- "done" --> response

  locationPluginListB -- "proxy pass: 10.0.0.1:8002" --> upstreamB1

  locationPluginListB -- "proxy pass: 10.0.0.2:8002" --> upstreamB2

  locationPluginListB -- "done" --> response

  upstreamA1 -- "Exec Response Plugins" --> locationResponsePluginListA
  upstreamA2 -- "Exec Response Plugins" --> locationResponsePluginListA

  upstreamB1 -- "Exec Response Plugins" --> locationResponsePluginListB
  upstreamB2 -- "Exec Response Plugins" --> locationResponsePluginListB

  locationResponsePluginListA --> response
  locationResponsePluginListB --> response

  response["HTTP Response"] --> stop("Logging");
```

## Performance

CPU: M4 Pro, Thread: 1

### Ping no access log:

```bash
wrk 'http://127.0.0.1:6100/ping' --latency

Running 10s test @ http://127.0.0.1:6100/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    59.87us   20.27us   1.00ms   81.00%
    Req/Sec    82.12k     3.04k   85.77k    90.59%
  Latency Distribution
     50%   63.00us
     75%   69.00us
     90%   76.00us
     99%   97.00us
  1650275 requests in 10.10s, 215.61MB read
Requests/sec: 163396.17
Transfer/sec:     21.35MB
```

## Rust version

Our current MSRV is 1.74

# License

This project is Licensed under [Apache License, Version 2.0](./LICENSE).
