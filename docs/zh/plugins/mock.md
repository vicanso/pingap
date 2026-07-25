# mock

返回固定响应而不代理，可选延迟。适合桩未就绪端点、维护页、无需上游的 `/robots.txt`，或测试客户端超时处理。

- **步骤：** `request`（固定）
- **注册名：** `mock`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `mock`。 |
| `path` | string | `""` | 要 mock 的精确路径。空则匹配 location 内**所有**路径。 |
| `status` | int | `200` | 响应状态。非法码回退为 `200`。 |
| `headers` | string[] | — | 响应头，格式 `Name: value`。 |
| `data` | string | `""` | 响应正文。 |
| `delay` | duration | 无 | 应答前休眠。 |

## 示例

桩 API 端点：

```toml
[plugins.mockUsers]
category = "mock"
path = "/api/users"
status = 200
headers = ["Content-Type: application/json"]
data = '{"users":[{"id":1,"name":"pingap"}]}'
```

整 location 维护页：

```toml
[plugins.maintenance]
category = "mock"
status = 503
headers = ["Content-Type: text/html; charset=utf-8", "Retry-After: 600"]
data = "<h1>Back shortly</h1>"

[locations.app]
upstream = "app"
path = "/"
plugins = ["maintenance"]
```

模拟慢后端：

```toml
[plugins.slowEndpoint]
category = "mock"
path = "/api/slow"
delay = "5s"
data = "ok"
```

无上游提供 `robots.txt`：

```toml
[plugins.robots]
category = "mock"
path = "/robots.txt"
headers = ["Content-Type: text/plain"]
data = """
User-agent: *
Disallow: /admin
"""
```

## 行为

`path` 精确相等比较——无前缀或正则。不匹配则跳过插件，请求正常继续。匹配时永不联系上游。

## 使用说明

- `path` 为空会短路整个 location。维护页正需要如此；若本意是桩单个端点则绝不要留空。
- `delay` 在持续时间内占用请求任务。大延迟叠加真实流量会堆积连接；在线上实验时请配合 [`limit`](limit.md)。
- 因在 `request` 运行，也会短路缓存与链中更后面的插件。
