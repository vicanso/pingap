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
- `check_frequency`: The interval between health checks. Default: `10s`.
- `success`: The number of consecutive successful checks to mark the backend as healthy. Default: `1`.
- `failure`: The number of consecutive failed checks to mark the backend as unhealthy. Default: `2`.
- `reuse`: If present, an HTTP/S check keeps its connection in pingora's pool between checks instead of connecting afresh each time.
- `tls`: If present, a gRPC check uses TLS, with the URL host as SNI. Certificates are not verified, the same as for `https://` and `wss://`.
- `service`: The service name for gRPC health checks.
- `parallel`: If present, health checks will be performed in parallel.

A value that does not parse is a configuration error rather than a silent fallback to the default: a duration without a unit (`check_frequency=5`), a zero duration, `success=0` or `failure=0` are all rejected when the upstream is created, so `pingap -t` reports them.

An upstream without a `health_check` gets `tcp://` with the defaults above: a backend is unhealthy after two failed connects and healthy again after one success.

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