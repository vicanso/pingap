# Pingap Performance

[Pingap](https://github.com/vicanso/pingap) 的指标与进程内省。

本 crate 收集两类数据：

- **请求指标** — 描述流量、延迟、上游行为与缓存的计数器、仪表与直方图，以 Prometheus 格式导出。
- **进程指标** — 内存、CPU 数、线程数、文件描述符与 TCP 连接数，供 [`stats`](../plugins/stats.md) 插件与管理 UI 使用，也用于确定内存缓存预算。

## 启用 Prometheus

指标需要 `tracing` cargo feature（包含在 `full` 中）。

### Pull 模式

在 server 上暴露端点：

```toml
[servers.main]
addr = "0.0.0.0:6188"
locations = ["app"]
prometheus_metrics = "/metrics"
```

```bash
curl http://127.0.0.1:6188/metrics
```

### Push 模式

给 URL 而非路径，Pingap 推送到 Pushgateway：

```toml
[servers.main]
prometheus_metrics = "http://user:pass@pushgateway:9091/job/pingap?interval=15s"
```

## 导出的指标

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `pingap_http_requests_total` | counter | location | 已接受请求 |
| `pingap_http_requests_current` | gauge | — | 在途请求 |
| `pingap_http_responses_codes` | counter | location, status | 按状态的响应 |
| `pingap_http_response_time` | histogram | location | 端到端响应时间（秒） |
| `pingap_http_received` / `pingap_http_received_bytes` | counter / histogram | location | 请求载荷大小 |
| `pingap_http_sent` / `pingap_http_sent_bytes` | counter / histogram | location | 响应载荷大小 |
| `pingap_connection_reuses` | counter | — | 复用的下游连接 |
| `pingap_tls_handshake_time` | histogram | — | 下游 TLS 握手（秒） |
| `pingap_upstream_connections` | gauge | upstream | 已建立的上游连接 |
| `pingap_upstream_connections_current` | gauge | upstream | 使用中的上游连接 |
| `pingap_upstream_reuses` | counter | upstream | 复用的上游连接 |
| `pingap_upstream_tcp_connect_time` | histogram | upstream | 上游 TCP 连接（秒） |
| `pingap_upstream_tls_handshake_time` | histogram | upstream | 上游 TLS 握手（秒） |
| `pingap_upstream_processing_time` | histogram | upstream | 上游处理（秒） |
| `pingap_upstream_response_time` | histogram | upstream | 上游响应（秒） |
| `pingap_cache_lookup_time` | histogram | — | 缓存查找（秒） |
| `pingap_cache_lock_time` | histogram | — | 等待缓存锁的时间（秒） |
| `pingap_cache_reading` / `pingap_cache_writing` | gauge | — | 并发缓存读 / 写 |
| `pingap_compression_ratio` | histogram | — | 达到的压缩比 |
| `pingap_memory` | gauge | — | 进程内存（MB） |
| `pingap_fd_count` | gauge | — | 打开的文件描述符 |
| `pingap_tcp_count` / `pingap_tcp6_count` | gauge | — | IPv4 / IPv6 TCP 连接 |

多数延迟指标按 location 或 upstream 打标签，仪表盘可在无额外埋点的情况下把回归归因到具体路由或后端。

## 进程信息

```rust
use pingap_performance::get_process_system_info;

let info = get_process_system_info();
println!("{} MB, {} threads, {} fds", info.memory_mb, info.threads, info.fd_count);
```

`get_processing_accepted()` 返回全局在途与已接受请求计数器。二者正是 `stats` 插件序列化的内容。

收集器还向 `pingap_cache::update_available_memory()` 供数，使内存缓存按真实机器或容器限制自定大小，而非固定默认。

## 许可证

Apache-2.0。
