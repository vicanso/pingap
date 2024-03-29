# pingap

## What is Pingap

A reverse proxy like nginx, built on [pingora](https://github.com/cloudflare/pingora), simple and efficient.

## Feature

- Filter location by host and path
- HTTP 1/2 end to end proxy
- Graceful reload
- Template for http access log
- TOML base configuration

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
    start("new request")-->server;

    server -- "host:HostA, Path:/api/*" --> locationA

    server -- "Path:/rest/*"--> locationB

    locationA -- "10.0.0.1:8001" --> upstreamA1

    locationA -- "10.0.0.2:8001" --> upstreamA2

    locationB -- "10.0.0.1:8002" --> upstreamB1

    locationB -- "10.0.0.2:8002" --> upstreamB2
```

# License

This project is Licensed under [Apache License, Version 2.0](./LICENSE).
