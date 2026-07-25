# Pingap Proxy

[Pingap](https://github.com/vicanso/pingap) 的 HTTP 代理引擎。本 crate 实现 pingora 的 `ProxyHttp` trait，是路由、插件分发、上游选择、缓存、追踪与访问日志真正接线的地方。其他 `pingap-*` crate 都汇入此处；`pingap` 二进制是构建配置并交给本 crate 的薄壳。

## 职责

- 把 `PingapConfig` 变成具体监听器（`ServerConf`），含 TLS 参数、HTTP/2、TCP keepalive、`SO_REUSEPORT` 与 TCP Fast Open。
- 将每个请求匹配到 `Location`，再经其匹配到 `Upstream`。
- 在正确的生命周期步骤运行插件并尊重其决策。
- 拥有每请求 `Ctx`：时序、连接细节、上游状态、缓存状态与日志变量。
- 产出访问日志、`Server-Timing` 头、Prometheus 指标与 OpenTelemetry span。
- 用可配置 HTML 模板渲染错误页。

## 请求生命周期

`server.rs` 将 pingora 回调映射到 Pingap 的 `PluginStep`：

```
                  ┌──────────────────────────────────────────┐
   client ───────▶│ early_request_filter                     │  PluginStep::EarlyRequest
                  ├──────────────────────────────────────────┤
                  │ request_filter        (location matched) │  PluginStep::Request
                  ├──────────────────────────────────────────┤
                  │ proxy_upstream_filter                    │  PluginStep::ProxyUpstream
                  ├──────────────────────────────────────────┤
                  │ upstream_peer         (backend selected) │
                  │ upstream_request_filter                  │
                  ├──────────────────────────────────────────┤
                  │ upstream_response_filter                 │  PluginStep::UpstreamResponse
                  ├──────────────────────────────────────────┤
                  │ response_filter / response_body_filter   │  PluginStep::Response
                  ├──────────────────────────────────────────┤
   client ◀───────│ logging                                  │
                  └──────────────────────────────────────────┘
```

不是插件步骤但运维上重要的额外钩子：

| Callback | Role |
| --- | --- |
| `upstream_peer` | 选择后端并应用 location 的重试预算（`max_retries`、`max_retry_window`） |
| `connected_to_upstream` | 记录复用、TCP 连接与 TLS 握手时序 |
| `request_body_filter` | 强制 location 的 `client_max_body_size` |
| `fail_to_proxy` | 用配置的模板渲染错误页 |

插件在请求的**恰好一个**步骤运行。配置插件未实现的步骤是静默空操作——见 [pingap-plugin](../plugins/#生命周期步骤)。

## 路由

挂到 server 的 location 按权重降序排序一次，主机、路径与匹配条件全部成立的第一个获胜。权重为 `LocationConf` 中显式 `weight` 或推导值：

| Component | Weight |
| --- | --- |
| 精确路径（`=/api`） | 1024 |
| 前缀路径（`/api`） | 512 |
| 正则路径（`~^/api`） | 256 |
| 路径长度 | + 最多 64 |
| 精确主机 | + 128 |
| 正则主机 | + 主机字符串长度 |

因此 `=/api/health` 胜过 `/api` 胜过 `~^/api/.*`，带主机限定的 location 胜过其他相同但不带主机的。

无匹配时请求失败，信息为 `No matching location, host:<host>`。

## Server 配置

```toml
[servers.main]
addr = "0.0.0.0:443,[::]:443"
locations = ["api", "web"]
threads = 4
global_certificates = true
enabled_h2 = true
access_log = "combined"
enable_server_timing = true
tls_min_version = "TLSv1.2"
tls_max_version = "TLSv1.3"
tls_cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
tls_ciphersuites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
prometheus_metrics = "/metrics"
otlp_exporter = "http://otel-collector:4317/pingap"
reuse_port = true
tcp_fastopen = 4096
tcp_idle = "2m"
tcp_interval = "1m"
tcp_probe_count = 9
downstream_read_timeout = "30s"
downstream_write_timeout = "30s"
modules = ["grpc-web"]
```

部分说明：

- `addr` 可接受逗号分隔的多个监听地址，对应一个逻辑 server。
- `global_certificates = true` 用 [pingap-certificate](certificate.md) 的动态 SNI 证书存储把监听器切到 TLS。否则为明文 HTTP，此时 `enabled_h2` 表示 h2c。
- `prometheus_metrics` 在本 server 上暴露 pull 端点；URL 值则配置 push 模式。
- `enable_server_timing` 添加由请求时序分解构建的 `Server-Timing` 响应头——便于诊断延迟来源。
- `error_template`（在 `[basic]` 下）替换内置 `error.html`。

## 每请求上下文

`Ctx` 携带请求累积的一切，是访问日志变量与 `$` 替换的读取源。记录的时序包括上游 TCP 连接、TLS 握手、上游处理与响应、缓存查找与锁、压缩与总服务时间。见 [pingap-core](core.md) 与 [pingap-logger](logger.md) 中的访问日志标签表。

## Features

| Feature | Effect |
| --- | --- |
| `tracing` | 启用 `tracing.rs` 中的 OpenTelemetry span 集成与缓存指标 |

## 许可证

Apache-2.0。
