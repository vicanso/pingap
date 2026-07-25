# traffic_splitting

将已匹配 location 的一部分流量导向另一 upstream。是金丝雀发布、蓝绿切换与 A/B 测试的基础能力。路由不变——仅所选后端池不同。

- **步骤：** `request`（固定）
- **注册名：** `traffic_splitting`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `traffic_splitting`。 |
| `upstream` | string | — | **必填。** 被选中时切换到的 upstream。 |
| `weight` | int | `0` | 0–100。导向 `upstream` 的流量百分比。 |
| `stickiness` | bool | `false` | 是否按客户端做确定性决策（而非随机）。 |
| `sticky_cookie` | string | — | 驱动粘性决策的 Cookie 名。 |
| `sticky_header` | string | — | 驱动粘性决策的头名。仅在未设 `sticky_cookie` 时使用。 |
| `matcher` | string | — | 粘性值上的正则。匹配的值始终导向 `upstream`。 |

`stickiness = true` 时，`sticky_cookie` / `sticky_header` 至少设置其一，否则配置失败。

## 选择逻辑

在 `0..100` 上掷骰，与 `weight` 比较；当 `roll < weight` 时切换 upstream。

| Mode | Roll |
| --- | --- |
| `stickiness = false` | 均匀随机 |
| `stickiness = true`，无 `matcher` | `crc32(sticky value) % 100` — 同一客户端同一结果 |
| `stickiness = true`，设了 `matcher` | 正则匹配时为 `0`，否则 `255` |
| 粘性值缺失 | `255` — 永不选中 |

## 示例

随机 10% 金丝雀：

```toml
[plugins.canary]
category = "traffic_splitting"
upstream = "app-v2"
weight = 10

[locations.app]
upstream = "app-v1"
path = "/"
plugins = ["canary"]
```

粘性 20% 金丝雀——给定 `deviceId` 始终同一版本，用户不会在请求间翻版本：

```toml
[plugins.canary]
category = "traffic_splitting"
upstream = "app-v2"
weight = 20
stickiness = true
sticky_cookie = "deviceId"
```

按请求头显式 opt-in——仅内部测试者看 v2：

```toml
[plugins.betaUsers]
category = "traffic_splitting"
upstream = "app-v2"
weight = 100
stickiness = true
sticky_header = "X-User-Group"
matcher = "^(beta|internal)$"
```

## 使用说明

- 使用 `matcher` 时 `weight` 仍须大于 `0`——匹配只产生 `0` 的 roll，仍需小于 `weight`。纯 opt-in 规则用 `weight = 100`。
- 没有粘性 Cookie/头的客户端永不选中。依赖粘性模式前请确保值已设置（例如边缘分配 `deviceId`）。
- 插件只改用哪个 upstream；location 自身的 `upstream` 仍是其余流量的默认。
- 同一 location 上多个 `traffic_splitting` 按顺序执行，最后一次选中的生效。
