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
prometheus_metrics = "http://user:pass@pushgateway:9091/job/pingap?interval=1m"
```

推送作为共享后台服务的一个任务运行，该服务每分钟一跳，因此 `interval` 会向下取整到整分钟，且不低于一分钟。取整后与配置不符时会打印实际生效的间隔，`?interval=15s` 不会再被静默当成一分钟。

## 导出的指标

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `pingap_http_requests_total` | counter | location | 已接受请求 |
| `pingap_http_requests_current` | gauge | location | 在途请求 |
| `pingap_http_responses_codes` | counter | location, code | 按状态类别（`2xx`、`5xx`…）的响应 |
| `pingap_http_response_time` | histogram | location | 端到端响应时间（秒） |
| `pingap_http_received` / `pingap_http_received_bytes` | histogram / counter | location | 请求载荷大小 |
| `pingap_http_sent` / `pingap_http_sent_bytes` | histogram / counter | location | 响应载荷大小 |
| `pingap_connection_reuses` | counter | — | 复用的下游连接 |
| `pingap_tls_handshake_time` | histogram | — | 下游 TLS 握手（秒） |
| `pingap_upstream_connections` | gauge | upstream | 已建立的上游连接；只有开启 `enable_tracer = true` 的上游才会导出，计数由它产生 |
| `pingap_upstream_connections_current` | gauge | upstream | 使用中的上游连接 |
| `pingap_upstream_reuses` | counter | upstream | 复用的上游连接 |
| `pingap_upstream_tcp_connect_time` | histogram | upstream | 上游 TCP 连接（秒） |
| `pingap_upstream_tls_handshake_time` | histogram | upstream | 上游 TLS 握手（秒） |
| `pingap_upstream_processing_time` | histogram | upstream | 上游处理（秒） |
| `pingap_upstream_response_time` | histogram | upstream | 上游响应（秒） |
| `pingap_upstream_backend_failure_rate` | gauge | upstream, backend | 滑动窗口失败率百分比（0–100） |
| `pingap_upstream_backend_requests` | gauge | upstream, backend | 滑动窗口内的请求数 |
| `pingap_upstream_backend_circuit_state` | gauge | upstream, backend | 熔断状态：0 关闭、1 打开、2 半开 |
| `pingap_upstream_discovery_time` | gauge | upstream | 最近一次后端刷新的服务发现耗时（秒） |
| `pingap_upstream_selector_build_time` | gauge | upstream | 最近一次后端刷新的选择器构建耗时（秒） |
| `pingap_upstream_pool_eviction_idle_time` | histogram | — | 上游连接被 keep-alive 连接池腾位淘汰时的空闲时长（秒）；count 即淘汰次数，持续增长说明 `upstream_keepalive_pool_size` 偏小 |
| `pingap_cache_lookup_time` | histogram | — | 缓存查找（秒） |
| `pingap_cache_lock_time` | histogram | — | 等待缓存锁的时间（秒） |
| `pingap_cache_reading` / `pingap_cache_writing` | gauge | — | 并发缓存读 / 写 |
| `pingap_compression_ratio` | histogram | — | 达到的压缩比 |
| `pingap_memory` | gauge | — | 进程内存（MB） |
| `pingap_fd_count` | gauge | — | 打开的文件描述符 |
| `pingap_tcp_count` / `pingap_tcp6_count` | gauge | — | 进程所在**网络命名空间**中的 IPv4 / IPv6 TCP 套接字，不只是 Pingap 自己的：数据源是 `/proc/<pid>/net/tcp`，因此在没有独立命名空间的宿主机上会把其他进程的套接字一并计入（仅 Linux）|

多数延迟指标按 location 或 upstream 打标签，仪表盘可在无额外埋点的情况下把回归归因到具体路由或后端。

空 `location` 标签即总量，而且确实是全部请求：未匹配任何 location 的请求（404）、admin 端点、ACME challenge，以及对该指标端点自身的抓取都计入其中。只有被路由到某处的请求才另外带上具体的 `location`。

描述当前状态的序列——每个 backend 的失败率、请求数与熔断状态，以及每个 upstream 的服务发现与选择器构建耗时——在每次抓取时整体重建，因此消失的 backend 会停止导出，而不是带着最后一次的值一直留着。从配置中删除的 upstream，其按 upstream 打标的序列同样会被清掉。这在 DNS 与 Docker 发现下最关键：backend 地址不断变化，否则会积累成永不消失的死序列。

## 进程信息

```rust
use pingap_performance::get_process_system_info;

let info = get_process_system_info();
println!("{} MB, {} threads, {} fds", info.memory_mb, info.threads, info.fd_count);
```

`get_processing_accepted()` 返回全局在途与已接受请求计数器。二者正是 `stats` 插件序列化的内容。

快照会缓存一秒。采集一次要读若干 `/proc` 文件，而有三个消费者各自独立索取——Prometheus 抓取、`stats` 插件对其路径的每个请求，以及指标日志任务——缓存把开销限制在每秒最多一次采集，无论被索取多频繁。套接字表只数行数而不解析，架构、CPU 数、内核版本这些不会变的字段每个进程只读一次。

收集器还向 `pingap_cache::update_available_memory()` 供数，使内存缓存按真实机器或容器限制自定大小，而非固定默认。

## 许可证

Apache-2.0。
