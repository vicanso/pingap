# health

在一个路径上回答“这个实例后面的 upstream 能不能接请求”：给负载均衡器或 Kubernetes 用的就绪探针。

[`ping`](ping.md) 插件只要进程在就返回 `pong`，它说明的是代理本身活着，说明不了它后面的东西。

- **步骤：** `request`（固定）
- **注册名：** `health`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `health`。 |
| `path` | string | — | **必填。**应答的路径，精确相等比较。 |
| `upstreams` | string[] | *(全部)* | 要检查的 upstream 名称。为空则检查所有 upstream。 |
| `min_healthy` | int | `1` | 每个 upstream 需要的健康后端数，至少为 `1`。 |

## 示例

```toml
[plugins.ready]
category = "health"
path = "/ready"
upstreams = ["api", "auth"]

[locations.app]
upstream = "api"
plugins = ["ready"]
```

```bash
curl -i http://127.0.0.1:6188/ready
# HTTP/1.1 200 OK
# {"ready":true,"upstreams":{"api":{"healthy":2,"total":2,"ready":true},"auth":{"healthy":1,"total":1,"ready":true}}}
```

`api` 的后端全部不可用时：

```
HTTP/1.1 503 Service Unavailable
{"ready":false,"upstreams":{"api":{"healthy":0,"total":2,"ready":false,"unhealthy_backends":["10.0.0.1:8080","10.0.0.2:8080"]},"auth":{"healthy":1,"total":1,"ready":true}}}
```

## 行为

| Situation | Result |
| --- | --- |
| 路径不是 `path` | 跳过插件 |
| 被检查的每个 upstream 都有 `min_healthy` 个健康后端 | `200` |
| 其中某个不足 | `503`，正文里列出这个 upstream 和它不健康的后端 |
| `upstreams` 里写了不存在的 upstream | `503`，`"reason":"no such upstream"` |

后端是否健康以它的健康检查结果为准。熔断器不在判断之内：被熔断器暂时挡住的后端仍然算健康。upstream 的第一轮健康检查跑完之前，所有后端都算健康。

## 使用说明

- 透明代理的 upstream 没有自己的后端可查：检查全部 upstream 时会跳过它，被点名时算就绪。
- 回答说的是 upstream 的情况，和插件挂在哪个 location 上无关：请写上这个实例离不开的那几个。`upstreams` 留空时，一个已经没人用的 upstream 出问题也会让整个实例被摘出去。
- 响应里有 upstream 的名字和后端地址。请把它放在外部访问不到的监听或 location 上，或者前面加 [`ip_restriction`](ip_restriction.md)。
- 存活探针（进程在不在）用 `ping`，就绪探针用这个。
