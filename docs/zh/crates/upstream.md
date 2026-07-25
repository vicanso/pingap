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
  - **TLS & SNI**：可配置 TLS 与 SNI 的安全后端连接。
  - **HTTP/2 & ALPN**：支持 ALPN 协商 HTTP/1.1 或 HTTP/2。
  - **连接超时**：连接、读、写与空闲超时的细粒度控制。
  - **TCP 控制**：TCP keepalive、缓冲区大小与 TCP Fast Open 等高级选项。

- **运行时管理**：
  - 可在运行时动态增删改上游，无服务中断。
  - 暴露健康与连接指标，便于监控与可观测。

## 核心概念

### `Upstream`

`Upstream` 是中心组件，表示一组逻辑后端服务器。封装该组的负载均衡、健康检查、TLS、超时与服务发现配置。

### `SelectionLb`

表示 `Upstream` 配置的负载均衡策略：
- `RoundRobin(LoadBalancer<RoundRobin>)`
- `Consistent { lb: LoadBalancer<Consistent>, hash: HashStrategy }`
- `Transparent`

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
    // let http_peer = upstream.new_http_peer(&session, &client_ip);
    
    println!("Upstream '{}' created successfully.", upstream.name);
}
```

## 许可证

本项目采用 [Apache-2.0 许可证](https://github.com/vicanso/pingap/blob/main/LICENSE)。
