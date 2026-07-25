# stats

Exposes a JSON snapshot of process and request statistics on a path. Lives in the
`pingap` binary (`src/plugin/stats.rs`) because it needs access to the process
start time and the global counters.

- **Step:** `request` (default) or `proxy_upstream` — configurable
- **Registered as:** `stats`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `stats`. |
| `path` | string | `""` | Exact path to answer on. |
| `step` | string | `request` | `request` or `proxy_upstream`. Any other value is a configuration error. |

## Example

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

## Response

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
| `processing` / `accepted` | Requests in flight and accepted since start, across the whole process |
| `location_processing` / `location_accepted` | The same, scoped to the location that served this request |
| `hostname`, `version`, `rustc_version` | Build and host identification |
| `start_time`, `uptime` | Unix start time and a human-readable duration |
| `memory*`, `arch`, `cpus`, `physical_cpus`, `threads` | Process and host resources |
| `fd_count`, `tcp_count`, `tcp6_count` | Open file descriptors and TCP connections |

## Usage notes

- The response exposes host details (hostname, CPU count, memory, connection
  counts). Restrict it — list [`ip_restriction`](ip_restriction.md) or
  [`basic_auth`](basic_auth.md) **before** `stats` in `plugins`, since the first
  plugin to respond wins.
- For time series, prefer the Prometheus endpoint
  (`servers.<name>.prometheus_metrics`) from
  [`pingap-performance`](../../pingap-performance/README.md); `stats` is a
  point-in-time snapshot meant for humans and quick checks.
- `path` is matched for exact equality, on any HTTP method.
