# mock

返回固定响应而不代理，可选延迟。适合桩未就绪端点、维护页、无需上游的 `/robots.txt`，或测试客户端超时处理。

- **步骤：** `request`（固定）
- **注册名：** `mock`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `mock`。 |
| `path` | string | `""` | 要 mock 的精确路径。空则匹配 location 内**所有**路径。 |
| `status` | int | `200` | 响应状态。不在 `200`–`999` 范围内的码是配置错误：`1xx` 是临时状态而不是最终响应，客户端会一直等不到响应。 |
| `headers` | string[] | — | 响应头，格式 `Name: value`。非法的名称或值是配置错误。 |
| `data` | string | `""` | 响应正文。 |
| `delay` | duration | 无 | 应答前休眠。 |
| `percentage` | int | `100` | 匹配的请求里有多大比例得到 mock 的响应，`0` 到 `100`；其余请求照常处理，就像没有这个插件。 |
| `delay_only` | bool | `false` | 等待 `delay` 之后请求继续发往上游，拿到真实的响应。需要同时配置 `delay`。 |

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

让一部分流量失败或变慢，观察客户端的表现（故障注入）：

```toml
# 十个请求里有一个不经过上游，直接返回 503
[plugins.flaky]
category = "mock"
status = 503
percentage = 10

# 五个里有一个先等两秒，然后照常处理
[plugins.sluggish]
category = "mock"
delay = "2s"
delay_only = true
percentage = 20
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

`path` 精确相等比较——无前缀或正则。不匹配则跳过插件，请求正常继续。匹配并且由 mock 应答的请求不会到达上游。有两种情况请求仍会继续发往上游：没有被 `percentage` 选中的那部分，以及开了 `delay_only` 时等待结束后的所有请求。

## 使用说明

- `path` 为空会短路整个 location。维护页正需要如此；若本意是桩单个端点则绝不要留空。
- `percentage` 是逐个请求按概率决定的：`10` 是大量请求里的十分之一，不是每第十个。`0` 相当于关掉插件而不用把它从配置里删掉。`0`–`100` 之外的值是配置错误。
- `delay` 在持续时间内占用请求任务。大延迟叠加真实流量会堆积连接；在线上实验时请配合 [`limit`](limit.md)。
- 在 `request` 步骤由 mock 应答的请求，也会短路缓存与链中更后面的插件。没有被应答的请求（没被 `percentage` 选中，或者 `delay_only` 只是延迟）照常经过缓存和后面的插件。
- `delay` 为 `0` 等于没有延迟，此时配 `delay_only` 和不配 `delay` 一样是配置错误。
