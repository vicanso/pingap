# pingap

## What is Pingap

A reverse proxy like nginx, built on [pingora](https://github.com/cloudflare/pingora), simple and efficient.

[中文说明](./READMD_zh.md)

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
    start("New Request")-->server("HTTP Server");

    server -- "host:HostA, Path:/api/*" --> locationA("Location A")

    server -- "Path:/rest/*"--> locationB("Location B")

    locationA -- "Exec Plugins" --> locationPluginListA("Plugin List A")

    locationB -- "Exec Plugins" --> locationPluginListB("Plugin List B")

    locationPluginListA -- "proxy pass: 10.0.0.1:8001" --> upstreamA1("Upstream A1") --> response

    locationPluginListA -- "proxy pass: 10.0.0.2:8001" --> upstreamA2("Upstream A2") --> response

    locationPluginListA -- "done" --> response

    locationPluginListB -- "proxy pass: 10.0.0.1:8002" --> upstreamB1("Upstream B1") --> response

    locationPluginListB -- "proxy pass: 10.0.0.2:8002" --> upstreamB2("Upstream B2") --> response

    locationPluginListB -- "done" --> response

    response("HTTP Response") --> stop("Logging");
```

## Performance

CPU: M2, Thread: 1

```bash
wrk 'http://127.0.0.1:6188/stats' --latency
Running 10s test @ http://127.0.0.1:6188/stats
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    87.92us   60.91us   3.69ms   89.97%
    Req/Sec    57.32k     2.17k   69.69k    91.09%
  Latency Distribution
     50%   93.00us
     75%  100.00us
     90%  106.00us
     99%  133.00us
  1151171 requests in 10.10s, 320.61MB read
Requests/sec: 113977.63
Transfer/sec:     31.74MB
```

## Rust version

Our current MSRV is 1.74

# License

This project is Licensed under [Apache License, Version 2.0](./LICENSE).
