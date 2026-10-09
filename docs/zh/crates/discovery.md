# Pingap Discovery

[Pingap](https://github.com/vicanso/pingap) 上游的后端发现。

上游需要一组后端地址。本 crate 产出该集合——来自静态列表、DNS 或 Docker 容器标签——并保持更新，使扩缩容无需改配置。

结果是 pingora `Backends` 对象，由 [pingap-upstream](upstream.md) 包成负载均衡器，并由 [pingap-health](health.md) 探测。

## 机制

由 `UpstreamConf` 中的 `discovery` 选择：

| Value | Behaviour |
| --- | --- |
| `static` | 启动时解析一次 `addrs` 并保持。地址全是 IP 时的默认值 |
| `dns` | 周期性重新解析 `addrs`，DNS 变更生效。地址里有域名时的默认值 |
| `srv` | 周期性查询 `addrs` 里各个名字的 `SRV` 记录：记录给出主机、端口和权重 |
| `docker` | 经 Docker API 按标签查找容器 |
| `transparent` | 无发现 — 转发到请求自身的地址 |

`update_frequency` 控制 `dns`、`srv` 与 `docker` 的刷新频率（默认 `1m`）。刷新和健康检查共用一个 10s 的定时器，所以这个值向上取整到定时器周期的整数倍，不超过 `10s` 的值都是每 10s 刷新一次。对这几种发现方式它必须大于 0：`0s` 以前的效果是“只解析一次，之后不再更新”，现在是配置错误。

`discovery` 只能是上表的五个值之一，大小写不敏感（`DNS` 等同于 `dns`）。其他值是配置错误；以前会被接受并当作 `static`，写错成 `dsn` 时域名只在启动时解析一次。

### Static

```toml
[upstreams.api]
addrs = ["10.0.0.1:8080", "10.0.0.2:8080 5"]
```

地址可带尾部权重（`host:port weight`），负载均衡器会遵守；带端口的 IPv6 字面量写作 `[::1]:8080`。端口和权重在加载配置时就会检查：无法解析的端口或为 `0` 的权重（这样的后端永远不会被选中）会直接报错，而不是被静默丢弃。显式设置 `discovery = "static"` 时，主机名只在启动时解析一次；不设置时，地址里有主机名的 upstream 按 `dns` 处理，会跟随域名的变化。

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
| `dns_server` | 查询的解析器，多个用逗号分隔：IP 地址，可带端口（`10.0.0.53`、`10.0.0.53:5353`、`[fd00::53]:53`）。其他写法是配置错误。未设置用系统解析器。 |
| `dns_domain` | 追加到非限定名的域名 |
| `dns_search` | 非限定名的搜索列表 |
| `ipv4_only` | 忽略 AAAA 记录 |

每个解析到的 A/AAAA 成为后端，因此覆盖无头 Kubernetes 服务与轮询 DNS。解析结果会沿用到最短记录 TTL 到期；解析失败只在发生时通知一次，之后命中缓存的刷新不会重复通知，成功日志也只在后端集合真正变化时打印。

配了多个域名时，某个域名的查询没有得到应答会保留它上一次的后端（真的下线了会被健康检查摘掉），最多保留 10 分钟，并在 5 秒后重新解析，而不是等其他域名的记录到期。以前一次解析失败就会让这个域名的后端全部消失，最长持续 5 分钟。应答明确是“域名不存在”时，它的后端立即移除。两种情况都只在失败开始时通知一次，不会每一轮重复。

### SRV

```toml
[upstreams.api]
addrs = ["_http._tcp.api.service.consul"]
discovery = "srv"
update_frequency = "30s"
dns_server = "10.0.0.53:8600"
```

`addrs` 里的每一项是一个要查询 `SRV` 记录的名字。一条记录给出主机、端口和权重，这台主机的每个地址都成为一个后端，使用记录里的端口和权重：Consul、Nomad，以及带命名端口的 Kubernetes 无头服务，都是这样发布端口各不相同的实例的。`addrs` 里写在名字后面的端口和权重不起作用，默认端口也不使用。

- **优先级。** 只有优先级数值最小的那些记录成为后端。按 RFC 2782，其余的是在它们不可用时才用的；upstream 没有“备用后端”的概念，一起加进来的话它们会照常分到请求。
- **权重。** 用记录里的权重，`0` 按 `1` 算：权重为 `0` 的后端永远不会被选中。同一个名字下的权重按相互之间的比例使用：先除以公约数（`10` 和 `30` 就是 `1` 和 `3`），再按比例缩小到最大值不超过 `256`。注册中心给每个实例相同的权重时，不论具体数值是多少（CoreDNS 给 `n` 个 Pod 每个写 `100 / n`），得到的都是权重为 `1` 的后端，实例增减时原有的后端保持不变。权重是后端身份的一部分，所以权重变了的后端在健康状态上是一个新的后端：在下一次健康检查之前算作健康。权重不相等时，没有变化的记录也可能受影响——另一条记录改变了它们的公约数的时候（`10` 和 `10` 是 `1` 和 `1`；再加一条 `15`，就成了 `2`、`2` 和 `3`）。
- 目标是 `.` 表示这个名字下不提供该服务，不产生后端。
- 记录里的主机名使用和 `dns` 发现相同的 `dns_server` 和 `ipv4_only` 解析。`dns_domain` 和 `dns_search` 只作用于 `addrs` 里的名字：记录里的主机名是完整的域名。解析不了的主机会被略过并写日志，其他的照常服务。如果是根本没有得到应答（超时），这一轮的结果只保留 5 秒，而不是保留到它的记录过期：在那之后的下一个 `update_frequency` 就会重新查询这个名字。
- 缓存和查询失败时的处理与 `dns` 相同：结果沿用到 `SRV` 记录和地址记录里最短的 TTL 到期。`addrs` 里有多个名字时，没有得到应答的名字保留原有后端最多 10 分钟；应答是“名字不存在”（或者没有可用的记录）的名字立即失去它的后端。
- `addrs` 里只有一个名字，或者所有名字都失败时，不论应答是什么，upstream 都一直保留原有的后端：不会因为注册中心的问题把 upstream 清空，下线的后端由健康检查摘除。失败的每一轮都会写日志并发通知（`service_discover_fail`），间隔是 `update_frequency`——注册中心只是表示“当前没有可用实例”时也是如此。

### Docker

```toml
[upstreams.api]
addrs = ["pingap-api:8080"]
discovery = "docker"
update_frequency = "10s"
```

每项为 `label[:port] [weight]`。按 Docker 标签匹配容器，其发布地址成为后端，因此 `docker compose up --scale api=5` 会在下次刷新时被发现。通过 unix 套接字连接 Docker 守护进程：`DOCKER_HOST` 是 `unix://` 路径时用它指定的套接字，否则用默认的；`tcp://` 形式的 `DOCKER_HOST` 不会被使用。后台任务跟随容器事件即时刷新列表；每次重连守护进程后都会重新列举容器，上游因重载被替换时该任务随之停止。守护进程连不上时只在开始连不上（或第一次尝试）的那一次报告，之后的每次重试不再重复通知。

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
