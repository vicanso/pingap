---
description: Pingap 简述
---

Pingap是基于[pingora](https://github.com/cloudflare/pingora)开发的，pingora提供了各类模块便于rust开发者使用，但并不方便非rust开发者使用，因此pingap提供了以toml的形式配置简单易用的反向代理，单服务支持多location转发，通过插件的形式支持更多的需求场景。特性如下：

- 支持多location配置，可通过请求的路径与域名匹配
- 支持HTTP1与HTTP2两种协议
- 无中断请求的配置更新，方便实时更新应用配置
- 模板式的请求日志输出，可按模板指定各种输出
- 提供Web界面式的配置，简化操作
- 支持各种插件形式，根据需要灵活配置各种特性：如静态文件目录、服务性能指标、WEB后台配置应用等

[Pingap处理流程](./phase_chart_zh.md)

## Location的处理逻辑

该Server下的所有location在初始化时根据权重按高至低排序，接收到请求时按顺序一个个匹配到符合的location为止，若无符合的则返回出错。在选择对应的location之后，判断是否有配置重写path(若无则不需要)，添加请求头(若无则不需要)。

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
if let Some(mut new_path) = lo.rewrite(path) {
    if let Some(query) = header.uri.query() {
        new_path = format!("{new_path}?{query}");
    }
    // TODO parse error
    let _ = new_path.parse::<http::Uri>().map(|uri| header.set_uri(uri));
}
```

[Location的详细说明](./location_zh.md)

## 插件体系

[插件体系](./plugin_zh.md)

## Upstream的处理逻辑

Upstream的逻辑比较简单，在匹配location后，根据该location配置的upstream节点列表，按算法选择可用节点，并将请求转发至该节点即可。需要注意，插件也可配置在`proxy_upstream_filter`转发至upstream之前执行，可按需配置对应的插件。

[Upstream的详细说明](./upstream_zh.md)

## 访问日志格式化

[日志格式化详细说明](./log_zh.md)

## 应用配置

[应用配置详细说明](./config_zh.md)
