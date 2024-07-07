---
description: Pingap 简述
---

Pingap是基于[pingora](https://github.com/cloudflare/pingora)开发的，pingora提供了各类模块便于rust开发者使用，但并不方便非rust开发者，因此pingap提供了以toml的形式配置简单易用的反向代理，单服务支持多location转发，通过插件的形式支持更多的需求场景。已预编译好各架构上使用的可执行文件，在[releases](https://github.com/vicanso/pingap/releases)下载即可。特性如下：

- 服务支持配置多个Location，通过host与path筛选对应的location，按权重逐一匹配选择
- 支持正则形式配置重写Path，方便应用按前缀区分转发
- HTTP 1/2 的全链路支持，包括h2c
- 基于TOML格式的配置，配置方式非常简洁，可保存至文件或etcd
- 频繁更新的Upstream与Location相关配置调整准实时生效(30秒)，其它应用配置更新后，无中断式的优雅重启程序
- 访问日志的模板化配置，已支30多个相关属性的配置，可按需指定输出各种参数与指标
- WEB形式的管理后台界面，无需学习，简单易用
- 开箱即用的`let's encrypt`tls证书，仅需配置对应域名即可
- 不同域名的tls证书可使用在同一服务端口中，按servername自动选择匹配证书
- 支持各种事件的推送：`lets_encrypt`, `backend_status`, `diff_config`, `restart`等等
- 丰富的http插件：`compression`, `static serve`, `limit`, `stats`, `mock`, 等等
- 提供了不同阶段的统计数据，如`upstream_connect_time`, `upstream_processing_time`, `compression_time`, `cache_lookup_time` 与 `cache_lock_time`等

[Pingap处理流程](./phase_chart_zh.md)

## Location的处理逻辑

该Server下的所有location在初始化时根据权重按高至低排序，接收到请求时按顺序一个个匹配到符合的location为止，若无符合的则返回出错。在选择对应的location之后，判断是否有配置重写path(若无则不需要)，添加请求头(若无则不需要)。

```rust
let mut location = None;
// locations not found
let Some(locations) = get_server_locations(&self.name) else {
    return Ok(());
};
let header = session.req_header_mut();
let host = util::get_host(header).unwrap_or_default();
let path = header.uri.path();
for name in locations.iter() {
    if let Some(lo) = get_location(name) {
        if lo.matched(host, path) {
            ctx.location = name.to_string();
            location = Some(lo);
            break;
        }
    }
}
```

[Location的详细说明](./location_zh.md)

## 插件体系

Pingap的插件主要分为两类，请求前或响应后的处理，提供压缩、缓存、认证、流控等各种不同场景的应用需求。插件是添加至location的，可根据不同需求参数配置各种不同的插件后，在location添加对应的插件，实现不同的功能组合。注意不同的插件是按顺序执行的，因此需要按需调整其顺序。

[插件体系](./plugin_zh.md)

## Upstream的处理逻辑

Upstream的逻辑比较简单，在匹配location后，根据该location配置的upstream节点列表，按算法选择可用节点，并将请求转发至该节点即可。upstream有各种超时以及tcp相关的配置，建议按需配置而非使用默认值。

[Upstream的详细说明](./upstream_zh.md)

## 访问日志格式化

现在日志是按server来配置，因此该server下的所有location共用，已支持各种不同的占位符，按需配置不同的访问日志输出。

[日志格式化详细说明](./log_zh.md)

## 应用配置

[应用配置详细说明](./config_zh.md)
