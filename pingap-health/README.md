# Pingap Health Check

This crate provides health check functionalities for the Pingap project. It supports TCP, HTTP/S, and gRPC health checks, which can be configured via a URL-like string.

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

The following query parameters can be used to configure the health check:

- `connection_timeout`: The connection timeout (e.g., `3s`, `100ms`). Default: `3s`.
- `read_timeout`: The read timeout. Default: `3s`.
- `check_frequency`: The interval between health checks. Default: `10s`.
- `success`: The number of consecutive successful checks to mark the backend as healthy. Default: `1`.
- `failure`: The number of consecutive failed checks to mark the backend as unhealthy. Default: `2`.
- `reuse`: If present, the connection will be reused.
- `tls`: If present, TLS will be enabled for gRPC.
- `service`: The service name for gRPC health checks.
- `parallel`: If present, health checks will be performed in parallel.

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

## Development

This crate is part of the [Pingap](https://github.com/vicanso/pingap) project. Please refer to the main project for contribution guidelines.