# stats

在路径上暴露进程与请求统计的 JSON 快照。位于 `pingap` 二进制（`src/plugin/stats.rs`），因为需要进程启动时间与全局计数器。

- **步骤：** `request`（默认）或 `proxy_upstream` — 可配置
- **注册名：** `stats`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `stats`。 |
| `path` | string | `""` | 应答的精确路径。 |
| `step` | string | `request` | `request` 或 `proxy_upstream`。其他值为配置错误。 |

## 示例

```toml
[plugins.stats]
category = "stats"
path = "/stats"

[plugins.statsAcl]
category = "ip_restriction"
type = "allow"
ip_list = ["127.0.0.1", "10.0.0.0/8"]

[locations.app]
upstream = "app"
path = "/"
plugins = ["statsAcl", "stats"]
```

```bash
curl -s http://127.0.0.1:6188/stats | jq
```

## 响应

```json
{
  "processing": 3,
  "accepted": 152340,
  "location_processing": 1,
  "location_accepted": 98211,
  "hostname": "gateway-1",
  "version": "0.13.4",
  "rustc_version": "1.88.0",
  "start_time": 1753400000,
  "uptime": "3days 4h 12m",
  "memory_mb": 84,
  "memory": "84.1 MB",
  "total_memory": "16.0 GB",
  "used_memory": "9.2 GB",
  "arch": "aarch64",
  "cpus": 12,
  "physical_cpus": 12,
  "threads": 14,
  "fd_count": 96,
  "tcp_count": 41,
  "tcp6_count": 3
}
```

| Field group | Meaning |
| --- | --- |
| `processing` / `accepted` | 全进程在途与自启动以来已接受的请求数 |
| `location_processing` / `location_accepted` | 同上，限定于服务本请求的 location |
| `hostname`, `version`, `rustc_version` | 构建与主机标识 |
| `start_time`, `uptime` | Unix 启动时间与可读时长 |
| `memory*`, `arch`, `cpus`, `physical_cpus`, `threads` | 进程与主机资源 |
| `fd_count`, `tcp_count`, `tcp6_count` | 打开的文件描述符与 TCP 连接 |

## 使用说明

- 响应暴露主机细节（主机名、CPU 数、内存、连接数）。请限制访问——在 `plugins` 中把 [`ip_restriction`](ip_restriction.md) 或 [`basic_auth`](basic_auth.md) 列在 `stats` **之前**，因为先响应的插件获胜。
- 时序数据请优先用 Prometheus 端点（`servers.<name>.prometheus_metrics`），见 [`pingap-performance`](../crates/performance.md)；`stats` 是面向人与快速检查的瞬时快照。
- `path` 精确相等匹配，任意 HTTP 方法。
