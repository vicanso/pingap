# Pingap Discovery

[Pingap](https://github.com/vicanso/pingap) 上游的后端发现。

上游需要一组后端地址。本 crate 产出该集合——来自静态列表、DNS 或 Docker 容器标签——并保持更新，使扩缩容无需改配置。

结果是 pingora `Backends` 对象，由 [pingap-upstream](upstream.md) 包成负载均衡器，并由 [pingap-health](health.md) 探测。

## 机制

由 `UpstreamConf` 中的 `discovery` 选择：

| Value | Behaviour |
| --- | --- |
| `static` *(默认)* | 启动时解析一次 `addrs` 并保持 |
| `dns` | 周期性重新解析 `addrs`，DNS 变更生效 |
| `docker` | 经 Docker API 按标签查找容器 |
| `transparent` | 无发现 — 转发到请求自身的地址 |

`update_frequency` 控制 `dns` 与 `docker` 的刷新频率。

### Static

```toml
[upstreams.api]
addrs = ["10.0.0.1:8080", "10.0.0.2:8080 5"]
```

地址可带尾部权重（`host:port weight`），负载均衡器会遵守。主机名仅在启动时解析一次：名称背后地址会变时用 `dns`。

### DNS

```toml
[upstreams.api]
addrs = ["api.internal:8080"]
discovery = "dns"
update_frequency = "30s"
dns_server = "10.0.0.53:53"
dns_domain = "svc.cluster.local"
dns_search = "default.svc.cluster.local"
ipv4_only = true
```

| Key | Description |
| --- | --- |
| `dns_server` | 查询的解析器。未设置用系统解析器。 |
| `dns_domain` | 追加到非限定名的域名 |
| `dns_search` | 非限定名的搜索列表 |
| `ipv4_only` | 忽略 AAAA 记录 |

每个解析到的 A/AAAA 成为后端，因此覆盖无头 Kubernetes 服务与轮询 DNS。

### Docker

```toml
[upstreams.api]
addrs = ["pingap-api:8080"]
discovery = "docker"
update_frequency = "10s"
```

每项为 `label[:port] [weight]`。按 Docker 标签匹配容器，其发布地址成为后端，因此 `docker compose up --scale api=5` 会在下次刷新时被发现。通过 `DOCKER_HOST` 连接 Docker 守护进程，否则回退默认套接字。

### Transparent

```toml
[upstreams.passthrough]
addrs = []
discovery = "transparent"
```

完全没有后端列表：使用请求自身的目标。`transparent-proxy` 示例即以此转发任意主机——见 [examples/transparent-proxy](https://github.com/vicanso/pingap/tree/main/examples/transparent-proxy)。

## 通知

`Discovery::with_sender` 附加通知发送器，发现失败（DNS 停答、Docker 套接字消失）可通过 [pingap-webhook](webhook.md) 告警，而不只落在日志里。

## 用法

```rust
use pingap_discovery::{Discovery, DNS_DISCOVERY};

let discovery = Discovery::new(vec!["api.internal:8080".to_string()])
    .with_ipv4_only(true)
    .with_dns_server("10.0.0.53:53".to_string());

let backends = pingap_discovery::new_dns_discover_backends(&discovery)?;
```

## 许可证

Apache-2.0。
