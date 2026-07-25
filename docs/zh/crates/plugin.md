# Pingap Plugin

[Pingap](https://github.com/vicanso/pingap) 的内置插件 crate。

插件是自包含的请求/响应逻辑单元，在代理生命周期的明确阶段执行。插件声明一次后可挂到任意多个 location。

完整的插件索引、生命周期说明与每个插件的配置文档见 **[插件文档](../plugins/)**。

## 配置方式

在 `[plugins.<name>]` 下声明；`category` 选择实现：

```toml
[plugins.pingPath]
category = "ping"
path = "/ping"

[locations.api]
upstream = "api"
path = "/api"
plugins = ["pingPath"]
```

## 生命周期步骤

| 步骤 | 运行时机 | 典型用途 |
| --- | --- | --- |
| `early_request` | 读完请求行与头之后、路由之前 | 协商压缩 / `Accept-Encoding` |
| `request` | 已匹配 location | 认证、限流、缓存、mock、静态文件 |
| `proxy_upstream` | location 已解析、尚未选后端 | 不应在缓存命中时执行的检查 |
| `upstream_response` | 上游响应头到达时 | 改写上游头、响应体变换 |
| `response` | 响应头即将发往下游时 | 添加响应头、正文替换 |

## Features

- `geo` — 启用 `geo_restriction` 插件（内嵌 Tor GeoIP 数据库）。

## 许可证

Apache-2.0。
