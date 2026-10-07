# Pingap 健康检查

本 crate 为 Pingap 提供健康检查能力。支持 TCP、HTTP/S、gRPC 与 WebSocket 健康检查，通过类 URL 字符串配置。

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
- `ws://<host>/<path>`：WebSocket 健康检查，发起升级握手，后端必须回 `101 Switching Protocols` 且 `Sec-WebSocket-Accept` 正确。
- `wss://<host>/<path>`：同上，走 TLS。

可用查询参数：

- `connection_timeout`：连接超时（如 `3s`、`100ms`）。默认：`3s`。
- `read_timeout`：读超时。默认：`3s`。
- `check_frequency`：检查间隔。默认：`10s`。检查由一个 10s 的定时器驱动，间隔向上取整到定时器周期的整数倍：`25s` 表示每 30s 检查一次，不超过 `10s` 的值都是每 10s 检查一次。每个 upstream 各自检查：某个 upstream 的后端全部超时，不会拖慢其他 upstream 的检查和服务发现。它自己的下一轮要等正在进行的这一轮结束，中间到点的那几次会被跳过。
- `success`：连续成功次数后标记健康。默认：`1`。
- `failure`：连续失败次数后标记不健康。默认：`2`。upstream 的第一轮检查不受它约束，失败一次即标记不健康，见 [pingap-upstream](upstream.md)。
- `reuse`：存在则 HTTP/S 检查把连接保留在 pingora 的连接池中供下次检查复用，而不是每次重新连接。
- `tls`：存在则 gRPC 检查使用 TLS，SNI 为 URL 中的主机名。不校验证书，与 `https://`、`wss://` 一致。
- `service`：gRPC 健康检查的服务名。
- `parallel`：存在则并行执行健康检查。
- `expect_status`：HTTP/S 检查认为健康的状态码，替代默认的只认 `200`：单个状态码或闭区间，用逗号分隔（`200-399`、`200,204,301-302`）。
- `check_port`：HTTP/S 检查访问的端口，用于后端在另一个端口上提供健康检查的情况。地址仍然是后端自己的地址。

HTTP/S 检查只认状态码 `200`，除非用 `expect_status` 另行指定：`204`、重定向、需要凭据的路径返回的 `401` 都算失败。只看状态码，不看响应内容。各类检查的连接都发往后端自己的地址和端口（取自 `addrs`）；URL 里的主机名只用作 `Host`（TLS 下也用作 SNI），写在它后面的端口会被忽略——要让 HTTP/S 检查访问另一个端口，用 `check_port`。这两个参数只用于 HTTP/S 检查，写在 `tcp://`、`grpc://`、`ws://` 的检查上是配置错误。URL 上的其他参数和以前一样，会作为请求的一部分发给后端。

无法解析的值是配置错误，不会静默回退到默认值：没有单位的时长（`check_frequency=5`）、为零的时长、`success=0` 或 `failure=0` 都会在创建 upstream 时被拒绝，`pingap -t` 会报告出来。

没有配置 `health_check` 的 upstream 等同于不带参数的 `tcp://`，使用上述默认值：连续两次连接失败标记不健康，一次成功即恢复。

每个后端一开始都是健康的：pingora 固定如此，也没有提供修改的方法。因此 upstream 的第一轮检查是决定性的，创建 upstream 时已经挂掉的后端会在第一次检查就被剔除，而不必等 `failure` 轮。

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

检查即 `grpc.health.v1.Health/Check` 调用，通过 pingora 自身的 HTTP/2 客户端发出（明文 h2，或带 `tls` 时走 TLS），沿用上面的连接与读超时；请求和响应由本 crate 自行编解码，运行时不依赖任何 gRPC 库。后端必须对该服务回复 `SERVING`（不填 `service` 表示询问整个服务器的健康状态）。`NOT_SERVING`、服务器不认识的服务、调用失败或后端根本不说 gRPC，都算检查失败。到每个后端的 HTTP/2 连接会保持打开，后续检查复用它。

#### WebSocket 健康检查

```
ws://my-chat/ws?connection_timeout=1s&failure=3
```

向 `/ws` 发送 WebSocket 升级请求（`Connection: Upgrade`、`Upgrade: websocket`、随机 `Sec-WebSocket-Key`），期望 `101 Switching Protocols`、`Upgrade: websocket` 以及由该 key 推导出的 `Sec-WebSocket-Accept`；其他响应，包括 WebSocket 服务对普通 GET 返回的 `400`/`426`，都算失败。握手完成后立即关闭连接。TLS 后端用 `wss://`。

## 开发

本 crate 是 [Pingap](https://github.com/vicanso/pingap) 项目的一部分。贡献指南请见主项目。
