# request_id

确保每个请求带有唯一标识。若入站请求已有，则保留（跨服务边界稳定）；否则生成新 ID，写入请求头并放入请求上下文供日志使用。

- **步骤：** `request`（默认）或 `proxy_upstream` — 可配置
- **注册名：** `request_id`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `request_id`。 |
| `algorithm` | string | `uuid` | `nanoid` 生成短 URL 安全 ID；其他表示 UUID v7。 |
| `size` | int | `8` | 生成的 nanoid 长度。UUID 忽略。 |
| `header_name` | string | `X-Request-Id` | 读写的头名。 |
| `step` | string | `request` | `request` 或 `proxy_upstream`。其他值为配置错误。 |

## 示例

UUID v7 — 按时间有序，利于日志排序与索引局部性：

```toml
[plugins.requestId]
category = "request_id"
algorithm = "uuid"
```

短 ID，自定义头：

```toml
[plugins.requestId]
category = "request_id"
algorithm = "nanoid"
size = 12
header_name = "X-Trace-Id"
```

在访问日志中引用并回显给客户端：

```toml
[servers.test]
access_log = "{when_utc_iso} {request_id} {method} {uri} {status} {latency_human}"

[plugins.echoId]
category = "response_headers"
set_headers = ["X-Request-Id: $http_x_request_id"]
```

## 行为

| Situation | Result |
| --- | --- |
| 请求上已有 `header_name` | 值复制到上下文；头保持不变 |
| 无 `header_name` | 生成新 ID，写入请求头与上下文 |

ID 在访问日志中为 `{request_id}`，对其他插件为 `ctx.state.request_id`。

## 使用说明

- 已有头会原样信任，客户端可自选请求 ID——包括与他人冲突的值。若 ID 必须可信，请在边缘剥离该头（`response_headers` 的 `mode = "upstream"` 帮不上忙；在入站侧删除或先在受信任代理终止）。
- `nanoid` 且 `size = 8` 约 47 bit 熵——足以关联日志，不适合安全敏感场景。高流量系统用更大 size 或 UUID v7。
- 把本插件放在 location `plugins` 列表最前，以便后续插件与错误响应都已有可记录的 ID。
