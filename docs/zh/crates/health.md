# Pingap 健康检查

本 crate 为 Pingap 提供健康检查能力。支持 TCP、HTTP/S 与 gRPC 健康检查，通过类 URL 字符串配置。

## 用法

主入口是 `new_health_check`：接收上游名称、配置字符串，以及健康状态变化时的可选回调。返回 `HealthCheckConf` 与装箱的 `HealthCheck` trait 对象。

```rust
use pingap_health::{new_health_check, HealthCheckConf};
use pingora::lb::health_check::HealthCheck;

let (conf, hc): (HealthCheckConf, Box<dyn HealthCheck + Send + Sync + 'static>) =
    new_health_check("my_upstream", "https://example.com/health", None).unwrap();
```

### 配置

健康检查用类 URL 字符串配置。URL scheme 决定检查类型：

- `tcp://<host>`：TCP 健康检查。
- `http://<host>/<path>`：HTTP 健康检查。
- `https://<host>/<path>`：HTTPS 健康检查。
- `grpc://<host>`：gRPC 健康检查。

可用查询参数：

- `connection_timeout`：连接超时（如 `3s`、`100ms`）。默认：`3s`。
- `read_timeout`：读超时。默认：`3s`。
- `check_frequency`：检查间隔。默认：`10s`。
- `success`：连续成功次数后标记健康。默认：`1`。
- `failure`：连续失败次数后标记不健康。默认：`2`。
- `reuse`：存在则复用连接。
- `tls`：存在则为 gRPC 启用 TLS。
- `service`：gRPC 健康检查的服务名。
- `parallel`：存在则并行执行健康检查。

### 示例

#### TCP 健康检查

```
tcp://my-backend:8080?connection_timeout=1s&failure=3
```

对 `my-backend:8080` 做 TCP 检查，连接超时 1 秒。连续 3 次失败后标记不健康。

#### HTTP 健康检查

```
http://my-api/healthz?check_frequency=5s&success=2
```

每 5 秒对 `http://my-api/healthz` 发 GET。连续 2 次成功后标记健康。

#### gRPC 健康检查

```
grpc://my-grpc-service:50051?service=my.service.v1.MyService&tls
```

对 `my-grpc-service:50051` 做 gRPC 健康检查，服务名为 `my.service.v1.MyService`，使用 TLS。

## 开发

本 crate 是 [Pingap](https://github.com/vicanso/pingap) 项目的一部分。贡献指南请见主项目。
