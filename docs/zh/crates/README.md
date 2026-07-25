# Crates / 模块

每个工作区 crate 的 README 描述职责、配置及其在依赖图中的位置。以下为中文维护文档。

| Crate | 职责 |
| --- | --- |
| [pingap-util](util.md) | 加解密、IP 规则、PEM/base64、路径与格式化辅助 |
| [pingap-core](core.md) | `Ctx`、`HttpResponse`、`Plugin` trait、后台服务、粗粒度时钟 |
| [pingap-config](config.md) | 配置模型、存储后端、TOML/HCL/KDL |
| [pingap-discovery](discovery.md) | 静态 / DNS / Docker / 透明后端发现 |
| [pingap-health](health.md) | TCP、HTTP(S) 与 gRPC 健康检查 |
| [pingap-upstream](upstream.md) | 负载均衡、熔断、上游连接选项 |
| [pingap-location](location.md) | 主机/路径匹配、改写、按 location 限制 |
| [pingap-certificate](certificate.md) | 基于 SNI 的动态 TLS 证书存储 |
| [pingap-acme](acme.md) | Let's Encrypt HTTP-01 与 DNS-01 自动化 |
| [pingap-cache](cache.md) | 内存（TinyUFO）与文件缓存后端 |
| [pingap-plugin](plugin.md) | 内置插件 — 见 [插件索引](../plugins/) |
| [pingap-imageoptim](imageoptim.md) | PNG/JPEG → WebP/AVIF 转换 |
| [pingap-logger](logger.md) | 访问日志、文件/syslog 写出器、轮转与压缩 |
| [pingap-performance](performance.md) | Prometheus 指标与进程内省 |
| [pingap-otel](otel.md) | OpenTelemetry 分布式追踪 |
| [pingap-sentry](sentry.md) | Sentry 错误上报 |
| [pingap-pyroscope](pyroscope.md) | 持续 CPU 剖析 |
| [pingap-webhook](webhook.md) | 运维通知到企业微信 / 钉钉 / HTTP |
| [pingap-proxy](proxy.md) | 代理引擎：生命周期、路由、server 配置 |

另见 [架构](../guide/modules.md)。
