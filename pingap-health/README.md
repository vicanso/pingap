# Pingap Health Check

This crate provides health check functionalities for the Pingap project. It supports TCP, HTTP/S, gRPC and WebSocket health checks, which can be configured via a URL-like string.

## Usage

The main entry point is the `new_health_check` function, which takes a name for the upstream, a configuration string, and an optional callback for when the health status changes. It returns a `HealthCheckConf` and a boxed `HealthCheck` trait object.

```rust
use pingap_health::{new_health_check, HealthCheckConf};
use pingora::lb::health_check::HealthCheck;

let (conf, hc): (HealthCheckConf, Box<dyn HealthCheck + Send + Sync + 'static>) =
    new_health_check("my_upstream", "https://example.com/health", None).unwrap();
```

### Configuration

The health check is configured using a URL-like string. The schema of the URL determines the type of health check to be performed.

- `tcp://<host>`: TCP health check.
- `http://<host>/<path>`: HTTP health check.
- `https://<host>/<path>`: HTTPS health check.
- `grpc://<host>`: gRPC health check.
- `ws://<host>/<path>`: WebSocket health check, an upgrade handshake that must be answered with `101 Switching Protocols` and a matching `Sec-WebSocket-Accept`.
- `wss://<host>/<path>`: the same over TLS.

The following query parameters can be used to configure the health check:

- `connection_timeout`: The connection timeout (e.g., `3s`, `100ms`). Default: `3s`.
- `read_timeout`: The read timeout. Default: `3s`.
- `check_frequency`: The interval between health checks. Default: `10s`. Checks are driven by a 10s timer, and the interval is rounded up to a whole number of its ticks: `25s` checks every 30s, and anything up to `10s` checks every 10s. Each upstream is checked on its own: one whose backends all run into the timeout does not delay the checks or the service discovery of the others. Its own next round waits until the running one is done, so a tick that comes in between is skipped for it.
- `success`: The number of consecutive successful checks to mark the backend as healthy. Default: `1`.
- `failure`: The number of consecutive failed checks to mark the backend as unhealthy. Default: `2`. It does not apply to an upstream's first round of checks, where one failure is enough; see [pingap-upstream](../pingap-upstream/README.md).
- `reuse`: If present, an HTTP/S check keeps its connection in pingora's pool between checks instead of connecting afresh each time.
- `tls`: If present, a gRPC check uses TLS, with the URL host as SNI. Certificates are not verified, the same as for `https://` and `wss://`.
- `service`: The service name for gRPC health checks.
- `parallel`: If present, health checks will be performed in parallel.
- `expect_status`: The statuses an HTTP/S check takes for healthy, in place of `200` alone: single ones and ranges with both ends included, separated by commas (`200-399`, `200,204,301-302`).
- `check_port`: The port an HTTP/S check goes to, where the backend answers its health check on another port than its service. The address is still the backend's own.
- `expect_body`: Text the body of the answer to an HTTP/S check has to have in it, for a backend that answers `200` and says in the body how it is: `expect_body=%22status%22%3A%22ok%22` for `"status":"ok"`. The text as it is, case and all, not a pattern; it is a parameter of a URL, so what has a meaning there is percent-encoded, and a `+` stands for a space (`%2B` for a plus). The first 64 KiB of the body are looked at.

An HTTP/S check passes on status `200` and nothing else unless `expect_status` says otherwise: a `204`, a redirect or a `401` from a path that wants credentials all count as failures. Only the status is looked at, not the body, unless `expect_body` is given: then the status has to be right and the body has to have the text. The connection of every kind of check is made to the backend's own address and port, from `addrs`; the host of the URL is what is sent as `Host` (and as SNI over TLS), and a port written after it is ignored - `check_port` is how an HTTP/S check is sent to another port. These three parameters are for HTTP/S checks; on a `tcp://`, `grpc://` or `ws://` check they are a configuration error. Any other parameter of the URL is sent to the backend as part of the request, as before.

A value that does not parse is a configuration error rather than a silent fallback to the default: a duration without a unit (`check_frequency=5`), a zero duration, `success=0` or `failure=0` are all rejected when the upstream is created, so `pingap -t` reports them.

An upstream without a `health_check` gets `tcp://` with the defaults above: a backend is unhealthy after two failed connects and healthy again after one success.

The checks of an upstream with `send_proxy_protocol` start their connections with a PROXY protocol header as the upstream does, in the same version: its backends wait for one on every connection and take a check without it for a broken client. The header of a check names no client (`LOCAL` in version 2, `UNKNOWN` in version 1). An HTTP/S check with `check_port` sends none, since what answers on another port is not the service; a backend whose check port reads the header as well is checked without `check_port`.

Every backend starts out healthy: pingora sets it that way and gives no means to change it. The first round of checks of an upstream is therefore decisive, so a backend that is down when its upstream is created is taken out by that first check instead of after `failure` rounds.

### Examples

#### TCP Health Check

```
tcp://my-backend:8080?connection_timeout=1s&failure=3
```

This will perform a TCP health check on `my-backend:8080` with a 1-second connection timeout. The backend will be marked as unhealthy after 3 consecutive failures.

#### HTTP Health Check

```
http://my-api/healthz?check_frequency=5s&success=2
```

This will send a GET request to `http://my-api/healthz` every 5 seconds. The backend will be marked as healthy after 2 consecutive successful checks.

#### gRPC Health Check

```
grpc://my-grpc-service:50051?service=my.service.v1.MyService&tls
```

This will perform a gRPC health check on `my-grpc-service:50051` using the service name `my.service.v1.MyService`. The connection will use TLS.

The check is the `grpc.health.v1.Health/Check` call, made over pingora's own HTTP/2 client (h2 in the clear, or TLS with `tls`) with the connection and read timeouts above; the request and response are encoded in the crate, so no gRPC library is involved at runtime. The backend must answer `SERVING` for the service (`service` left out asks for the overall server health). `NOT_SERVING`, a service the server does not know, a call that fails, or a backend that does not speak gRPC at all each fail the check. The HTTP/2 connection to a backend stays open and later checks reuse it.

#### WebSocket Health Check

```
ws://my-chat/ws?connection_timeout=1s&failure=3
```

This sends a WebSocket upgrade request (`Connection: Upgrade`, `Upgrade: websocket`, a random `Sec-WebSocket-Key`) to `/ws` and expects `101 Switching Protocols` with `Upgrade: websocket` and the `Sec-WebSocket-Accept` derived from that key; anything else, including the `400`/`426` a WebSocket server gives a plain GET, counts as a failure. The connection is closed right after the handshake. Use `wss://` for a TLS backend.

## Development

This crate is part of the [Pingap](https://github.com/vicanso/pingap) project. Please refer to the main project for contribution guidelines.