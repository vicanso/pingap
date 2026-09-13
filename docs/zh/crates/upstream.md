# Pingap Upstream

[![Crates.io](https://img.shields.io/crates/v/pingap-upstream.svg)](https://crates.io/crates/pingap-upstream)
[![License](https://img.shields.io/crates/l/pingap-upstream.svg)](https://github.com/vicanso/pingap/blob/main/LICENSE)
[![Docs.rs](https://docs.rs/pingap-upstream/badge.svg)](https://docs.rs/pingap-upstream)

`pingap-upstream` 是 [Pingap](https://github.com/vicanso/pingap) 中的核心 crate，为后端服务提供稳健、灵活的上游管理。基于 [Pingora](https://github.com/cloudflare/pingora)，处理服务发现、负载均衡与健康检查。

## 核心特性

- **多种负载均衡策略**：按需选择算法。
  - **Round Robin**：在健康后端间均匀分配请求。
  - **Consistent Hashing**：按请求属性哈希到固定后端，提供粘性会话。
  - **Transparent**：无负载均衡的透传代理，转发到原始主机。

- **灵活的一致性哈希键**：一致性哈希时可基于：
  - 客户端 IP
  - URL 路径、查询串或完整 URL
  - HTTP 头值
  - Cookie 值

- **动态服务发现**：从不同来源自动发现并更新后端：
  - **Static**：固定后端地址列表。
  - **DNS**：基于 A 记录或 SRV 记录。
  - **Docker**：从 Docker 容器标签发现。

- **主动健康检查**：周期性探测后端；不健康后端会自动、临时地从负载均衡池移除。

- **高级配置**：
  - **TLS & SNI**：可配置 TLS 与 SNI 的安全后端连接。可为单个上游指定私有 CA（`ca`，支持 PEM 文件路径、base64 或原始 PEM）替代系统信任库，使自签名或内部 PKI 的后端也能保持 `verify_cert` 开启；连接池同时按该 CA 分组，不同 CA 的上游不会复用同一条连接。rustls 后端下，后端自身的证书必须是真正的叶子证书（不能带 `CA:TRUE`），这是 webpki 的要求，OpenSSL 则不检查。
  - **HTTP/2 & ALPN**：支持 ALPN 协商 HTTP/1.1 或 HTTP/2，并可按上游设置流控窗口（`h2_stream_window_size`、`h2_connection_window_size`），适合高延迟链路上的大响应。
  - **连接超时**：连接、读、写与空闲超时的细粒度控制。
  - **TCP 控制**：TCP keepalive、缓冲区大小与 TCP Fast Open 等高级选项。
  - **请求头策略**：默认按 RFC 9110 的要求，在请求到达后端前剥离 hop-by-hop 头与 `Connection` 提名的头，且只转发 WebSocket 升级。每条规则都可按上游单独放宽（`strip_hop_by_hop`、`strip_connection_nominated`、`reject_malformed_connection_nominations`、`h1_upgrade`），供仍依赖旧透传行为的后端使用，例如 Docker `attach`/`exec` 或 h2c 升级。

- **熔断**：开启 `enable_backend_stats` 后统计每个后端的响应（`backend_failure_status_code` 决定哪些状态码算失败，默认所有 5xx；连接不上的请求总是算失败）。`circuit_break_max_consecutive_failures` 与 `circuit_break_max_failure_percent`（后者要在统计窗口内累计到 `circuit_break_min_requests_threshold` 个请求后才生效；两者填 `0` 即关闭该规则）任一触发即熔断：后端进入**打开**状态，在 `circuit_break_open_duration` 内被跳过，之后进入**半开**，最多放行 `circuit_break_half_open_consecutive_success_threshold` 个探测请求；连续成功这么多次则关闭熔断，失败一次则重新打开。状态通过 `pingap_upstream_backend_circuit_state` 导出（0 关闭、1 打开、2 半开）。

- **运行时管理**：
  - 可在运行时动态增删改上游，无服务中断。
  - 暴露健康与连接指标，便于监控与可观测。
  - `algo`（`round_robin`，或 `hash`、`hash:<ip|url|path|header|cookie|query>[:<key>]`）与 `alpn`（`h1`、`h2`、`h2h1`）在构建上游时校验，未知值报错而不是静默用默认值。

## 核心概念

### `Upstream`

`Upstream` 是中心组件，表示一组逻辑后端服务器。封装该组的负载均衡、健康检查、TLS、超时与服务发现配置。

### `SelectionLb`

表示 `Upstream` 配置的负载均衡策略：
- `RoundRobin(LoadBalancer<RoundRobin>)`
- `Consistent { lb: LoadBalancer<Consistent>, hash: HashStrategy }`
- `Transparent`

透明上游按每个请求的 authority（HTTP/2 的 `:authority`，HTTP/1 的 `Host` 头）构建 peer。其中的端口会被采用（`Host: backend:8080` 连到 8080；没有端口时按 `sni` 取 80 或 443），主机名异步解析（IP 字面量不需要查询；`ipv4_only` 会像其他发现方式一样只取名字的 IPv4 地址），解析不到的主机对该请求返回 `503`，而不是在 peer 构造函数里解析失败——那以前会直接 panic。

`HealthCheckTask` 每次后端刷新与健康检查以 `debug` 级别记录；只有失败才是 `error`。

### `HealthCheckTask`

对所有已配置上游周期运行的后台服务。负责：
1. 触发服务发现更新（如重新解析 DNS）。
2. 对每个后端执行健康检查。
3. 上游健康状态变化时发送通知（如全部后端不健康）。

## 用法

本 crate 主要在 `pingap` 代理应用中使用。一般流程：

1. 定义上游配置（例如 YAML 文件）。
2. `pingap` 应用解析为 `UpstreamConf` 结构体。
3. 为每个配置创建 `Upstream` 实例。
4. 启动 `HealthCheckTask` 监控所有上游。
5. 请求到达时，代理选择合适的 `Upstream` 并调用 `new_http_peer()` 获取健康、已配置的后端连接。

### 概念代码示例

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
    // let http_peer = upstream.new_http_peer(&session, &mut client_ip, true).await;
    
    println!("Upstream '{}' created successfully.", upstream.name);
}
```

## 许可证

本项目采用 [Apache-2.0 许可证](https://github.com/vicanso/pingap/blob/main/LICENSE)。
