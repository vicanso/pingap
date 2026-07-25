# ping

存活探测端点。对 `path` 的请求得到 `200 pong`；其余原样放行。

- **步骤：** `request`（固定）
- **注册名：** `ping`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `ping`。 |
| `path` | string | `""` | 应答的精确路径。 |

## 示例

```toml
[plugins.pingPath]
category = "ping"
path = "/ping"

[locations.app]
upstream = "app"
path = "/"
plugins = ["pingPath"]
```

```bash
curl -i http://127.0.0.1:6188/ping
# HTTP/1.1 200 OK
# pong
```

Kubernetes：

```yaml
livenessProbe:
  httpGet:
    path: /ping
    port: 6188
  periodSeconds: 10
```

## 行为

`path` 精确相等比较。插件对任意 HTTP 方法应答。`path` 为空时永不匹配正常请求，插件为空操作。

## 使用说明

- 这检查 Pingap 进程是否在接受并应答请求。不反映上游健康——上游健康请暴露 [`stats`](stats.md)，或在 upstream 上配置 `health_check` 并观察 Prometheus 指标。
- 响应是共享静态值，端点几乎零成本，可频繁探测。
- 把插件挂在路径前缀包含探测路径的 location 上，并放在任何认证插件之前，以免探针被挑战。
