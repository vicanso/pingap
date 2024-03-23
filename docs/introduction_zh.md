---
description: Pingap 简述
---

Pingap是基于[pingora](https://github.com/cloudflare/pingora)开发的，pingora提供了各类模块便于rust开发者使用，但并不方便非rust开发者使用，因此pingap提供了以toml的形式配置简单易用的反向代理，在以下流程中接入调整，实现支持多location代理转发。特性如下：

- 可通过请求的路径与域名筛选对应的location
- 支持HTTP1与HTTP2
- 无中断请求的配置更新
- 模板式的请求日志输出

TODO 接入http缓存的逻辑

```mermaid
graph TD;
    start("新的请求")-->upstream_peer;

    upstream_peer("选择upstream")--根据请求的host与path选择对应的upstream-->Connect{{IO: 连接至对应upstream}};

    Connect--连接成功-->connected_to_upstream("已连接至upstream");
    Connect--连接失败-->fail_to_proxy;

    connected_to_upstream--响应成功-->upstream_response_filter;
    connected_to_upstream--响应失败-->fail_to_proxy;

    upstream_response_filter("从upstream中获取到数据") --> logging
    fail_to_proxy("转发失败") --> logging

    logging("记录请求的相关日志") --> endreq("请求结束")
```
