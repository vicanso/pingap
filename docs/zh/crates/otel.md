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
otlp_exporter = "http://otel-collector:4317"
```

服务名是 `pingap:` 加 server 的名字（这里是 `pingap:main`），因此同一进程中的多个 server 以不同名称上报。URL 原样作为采集端的地址，它的路径并不是服务名（本文档以前是这么写的）。URL 上的查询参数配置导出器：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `protocol` | `grpc` | `grpc`（OTLP/gRPC，惯例端口 4317，只支持 `http://`）或 `http`（OTLP/HTTP，protobuf 正文，端口 4318，`http://` 和 `https://` 都可以）。 |
| `sampler` | `always_on` | 追踪哪些请求：`always_on`、`always_off`、`traceidratio`、`parentbased_always_on`、`parentbased_always_off`、`parentbased_traceidratio`。 |
| `sample_ratio` | `1` | 按比例采样时的比例，`0` 到 `1`。只能和 `traceidratio` 或 `parentbased_traceidratio` 一起用。 |
| `header` | — | 每次导出带的请求头，`Name:Value`；需要多个时重复这个参数。 |
| `timeout` | `3s` | 一次导出最多花多长时间。 |
| `compression` | — | `gzip` 或 `zstd`，用于 gRPC。 |
| `max_queue_size` | `2048` | 最多有多少 span 等待导出，超出的丢弃。 |
| `scheduled_delay` | `5s` | 每隔多久导出一次。 |
| `max_export_batch_size` | `512` | 一次导出最多多少 span。 |
| `max_attributes`、`max_events` | `16` | 每个 span 保留的属性和事件数。 |
| `jaeger`、`baggage` | — | 同时接受并传递这些传播格式。 |

```toml
# 十分之一的请求（调用方已有决定时听调用方的），走 HTTP，带 token
otlp_exporter = "https://otlp.example.com?protocol=http&sampler=parentbased_traceidratio&sample_ratio=0.1&header=Authorization:Bearer%20abc123"
```

- **`protocol=http`** 按 URL 原样发送；URL 没有写路径时发到 `/v1/traces`。用于采集端前面有不转发 gRPC 的设备、只接受 OTLP over HTTP 的服务，以及所有需要通过 TLS 访问的采集端：gRPC 导出器没有编译 TLS 支持，`https://` 的 URL 不加 `protocol=http` 时导出器启动会失败（日志里是 `opentelemetry init fail`，server 照常运行但没有追踪）。
- **`sampler`**：默认的 `always_on` 追踪并导出每个请求。`traceidratio` 按 trace id 选出 `sample_ratio` 比例的请求。`parentbased_` 开头的采样器在请求自带 trace（`traceparent`）时听调用方的：调用方采样了就采样，否则不采样；没有自带 trace 的请求按后面那个采样器决定。
- **`header`** 用来给需要 token 的采集端传凭据。值和其他参数一样要做 URL 编码：空格写 `%20`，`+` 写 `%2B`（否则会被读成空格，base64 的凭据里常有）。带了请求头的 URL 就是凭据：写进日志、发给 webhook 的配置差异里，它的参数显示为校验和；导出器的日志行里显示的是不带参数的 URL。admin 里是原样显示。
- `sampler`、`sample_ratio`、`protocol`、`header` 随配置一起校验：不是上面列出的值，或者写了 `sample_ratio` 却没有用按比例的采样器，会被 `-t`、启动和 admin 拒绝。如果当作没写，一个拼错的采样器就等于追踪所有请求。原有的参数仍按原来的方式读取，解析不了的保持默认值。
- `max_export_timeout` 可以写但不起作用：一次导出的时间上限是 `timeout`。设置它会在启动时打一条警告。

只要构建时带 `tracing` 特性，导出器就会启动。以前只有 `full` 构建才会启动：带 `tracing` 而不带 `imageoptim` 的构建把它编译进去了，却从不运行。

## 追踪内容

每个请求成为一个 span，携带 location、upstream、状态以及 Pingap 已收集的时序分解——上游连接、TLS 握手、上游处理、缓存查找。入站 trace 上下文用 `HeaderExtractor` 读取，因此 Pingap 延续已有 trace，而非新开。

发往上游的请求带上 Pingap 为这次上游访问建立的 span 的上下文（`traceparent`，以及开启 Jaeger 格式时的对应头），所以上游的 span 挂在代理的 span 之下。以前是把客户端的 `traceparent` 原样转给上游，上游的 span 就和代理的 span 并列，而不是它的子节点。是否采样仍然由客户端决定：默认的采样器下 Pingap 自己的 span 全部采样，但延续客户端的 trace 时会把客户端的采样标记传下去，所以按“父节点采样才采样”的上游不会因此多记录。（用 `parentbased_` 采样器时，Pingap 自己的 span 也跟随客户端。）如果采样器丢弃了 Pingap 为一个自带 trace 的请求建立的 span，上游收到的是客户端原来的 `traceparent`，这样上游的 span 挂在客户端的 span 下面，而不是挂在一个不会被导出的 span 下面。在这里开始的 trace 之外，客户端的采样决定是从 `traceparent` 读的：开启 `jaeger` 格式时，只发 Jaeger 头且没有采样的客户端，在默认采样器下仍会被当成已采样传给上游。在这里开始的 trace，传给上游的是 Pingap 采样器的决定。`tracestate` 和 `baggage` 是客户端的，原样透传。用 location 的 `proxy_set_headers` 设置的 `traceparent` 仍然优先。

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

追踪不是免费的：每个请求分配 span，导出在后台进行。高流量监听器请设置 `sampler`，只记录和导出一部分请求；不需要的 server 不要设 `otlp_exporter`。

## 许可证

Apache-2.0。
