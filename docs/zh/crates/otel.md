# Pingap OpenTelemetry

通过 OpenTelemetry 为 [Pingap](https://github.com/vicanso/pingap) 提供分布式追踪。

启用后，Pingap 为每个请求创建 span、加入入站 trace 上下文，并经 OTLP 导出到收集器——从而可从代理一路跟到其后服务，定位慢请求。

## 启用

需要 `tracing` cargo feature（包含在 `full` 中）：

```bash
cargo build --features=tracing
```

然后按 server 配置导出器：

```toml
[servers.main]
addr = "0.0.0.0:6188"
locations = ["app"]
otlp_exporter = "http://otel-collector:4317/pingap"
```

URL 的路径组件成为服务名，因此同一进程中的多个 server 可用不同名称上报。URL 上的查询参数配置导出器（超时、压缩、协议）。

## 追踪内容

每个请求成为一个 span，携带 location、upstream、状态以及 Pingap 已收集的时序分解——上游连接、TLS 握手、上游处理、缓存查找。入站 trace 上下文用 `HeaderExtractor` 读取，因此 Pingap 延续已有 trace，而非新开。

## 收集器

任何兼容 OTLP 的收集器均可——OpenTelemetry Collector、Jaeger、Tempo、Honeycomb、Datadog。最小收集器配置：

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  otlphttp:
    endpoint: https://tempo:4318

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp]
```

## 再导出

本 crate 再导出 [pingap-proxy](proxy.md) 所需的 OpenTelemetry API 片段，使工作区其余部分不直接依赖 `opentelemetry`：

```rust
pub use opentelemetry::{global, trace, KeyValue};
pub use opentelemetry_http::HeaderExtractor;
```

## 成本

追踪不是免费的：每个请求分配 span，导出在后台进行。高流量监听器宜在收集器侧采样而非全量导出，不需要的 server 不要设 `otlp_exporter`。

## 许可证

Apache-2.0。
