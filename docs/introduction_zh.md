---
description: Pingap 简述
---

Pingap是基于[pingora](https://github.com/cloudflare/pingora)开发的，pingora提供了各类模块便于rust开发者使用，但并不方便非rust开发者使用，因此pingap提供了以toml的形式配置简单易用的反向代理，实现支持多location代理转发。特性如下：

- 支持多location配置，可通过请求的路径与域名筛选
- 支持HTTP1与HTTP2两种协议
- 无中断请求的配置更新，方便实时更新应用配置
- 模板式的请求日志输出，可按模板指定各种输出
- 提供Web界面式的配置，简化操作
- 支持各种插件形式，根据需要灵活配置各种特性：如静态文件目录、服务性能指标、WEB后台配置应用等

[Pingap处理流程](./phase_chart_zh.md)

## 请求筛选

Pingap支持以下的服务类型，以及常规的反向代理服务，具体如下：

- `Stats`: 获取Server所对应的性能指标
- `Admin`: 根据启动时指定的admin地址或者配置的`admin path`转发至对应的管理后台服务
- `Directory`: 根据指定的静态目录提供静态文件服务
- `其它`: 常规的反向代理服务，根据域名与路径选择对应的转发节点

```mermaid
graph TD;
    start("新的请求")-->ServiceFilter{{请求服务筛选}};
    ServiceFilter--是否匹配stats-->stats的处理;
    ServiceFilter--是否匹配admin-->admin的处理;
    ServiceFilter--是否匹配静态文件目录-->静态文件的处理;
    ServiceFilter--根据host与path选择对应的Location-->Location筛选处理;
```

## Location的处理逻辑

该Server下的所有location在初始化时根据权重按高至低排序，接受到请求时按顺序一个个匹配到符合的location为止，若无符合的则返回出错。根据符合的location重写path(若无则不需要)，添加请求头(若无则不需要)，成功响应时添加响应头(若无则不需要)。

```rust
let header = session.req_header_mut();
let path = header.uri.path();
let host = header.uri.host().unwrap_or_default();

let (location_index, lo) = self
    .locations
    .iter()
    .enumerate()
    .find(|(_, item)| item.matched(host, path))
    .ok_or_else(|| pingora::Error::new_str(LOCATION_NOT_FOUND))?;
```

[Location的详细说明](./location_zh.md)

## Upstream的处理逻辑

Upstream现支持三种类型，包括`静态目录`，`Mock响应`以及常规的`反向代理节点`。upstream的处理比较简单，大概如下：

- `静态目录`: 读取对应的静态文件响应，需要注意静态文件是以chunked的形式返回
- `Mock响应`: 用于针对部分响应临时mock处理，主要用于临时的应急处理或测试
- `反向代理节点`: 根据各节点的健康情况以及选择算法，选择对应的节点转发请求

[Upstream的详细说明](./upstream_zh.md)

## 访问日志格式化

[日志格式化详细说明](./log_zh.md)
