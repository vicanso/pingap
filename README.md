# pingap

## What is Pingap

A reverse proxy like nginx, built on [pingora](https://github.com/cloudflare/pingora), simple and efficient.

[中文说明](./README_zh.md)

## Feature

- Filter location by host and path
- Path rewrite with regexp
- HTTP 1/2 end to end proxy
- TOML base configuration, file or etcd storage
- Graceful reload and auto restart after the configuration is changed
- Template for http access log
- Admin Web UI configuration
- Genrate TLS certificates from let's encrypt
- Notification events: `lets_encrypt`, `backend_unhealthy`, `diff_config`, `restart`, etc.
- Http proxy plugins: `compression`, `static serve`, `limit`, `stats`, `mock`, etc.

## Start

Loads all configurations from `/opt/proxy` and run in the background. Log appends to `/opt/proxy/pingap.log`.

```bash
RUST_LOG=INFO pingap -c=/opt/proxy -d --log=/opt/proxy/pingap.log
```

## Graceful restart

Validate the configurations, send quit signal to pingap, then start a new process to handle all requests.

```bash
RUST_LOG=INFO pingap -c=/opt/proxy -t \
  && pkill -SIGQUIT pingap \
  && RUST_LOG=INFO pingap -c=/opt/proxy -d -u --log=/opt/proxy/pingap.log
```

## Config

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

CPU: M2, Thread: 1

### Ping no accces log:

```bash
wrk 'http://127.0.0.1:6188/ping' --latency

Running 10s test @ http://127.0.0.1:6188/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    67.10us   67.52us   4.63ms   99.53%
    Req/Sec    74.82k     2.57k   85.56k    92.57%
  Latency Distribution
     50%   69.00us
     75%   76.00us
     90%   83.00us
     99%  105.00us
  1504165 requests in 10.10s, 196.52MB read
Requests/sec: 148928.76
Transfer/sec:     19.46MB
```

### Static serve 8kb html

```bash
wrk 'http://127.0.0.1:6188/downloads/index.html' --latency

Running 10s test @ http://127.0.0.1:6188/downloads/index.html
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   225.84us   59.47us   1.83ms   78.04%
    Req/Sec    22.17k     1.94k   25.25k    87.13%
  Latency Distribution
     50%  222.00us
     75%  247.00us
     90%  286.00us
     99%  418.00us
  445764 requests in 10.10s, 3.16GB read
Requests/sec:  44134.06
Transfer/sec:    320.01MB
```

### Compression

TODO

### Cache

TODO

## Rust version

Our current MSRV is 1.74

# License

This project is Licensed under [Apache License, Version 2.0](./LICENSE).
