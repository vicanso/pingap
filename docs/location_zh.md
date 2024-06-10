---
description: Location的详细介绍
---

## Location

Location主要配置请求的匹配、请求头响应头的插入，以及各种插件的关联，是整个流程中的最重要组成部分。下面是相关参数的详细说明：

- `upstream`: 配置该location对应的upstream，若该location所有的处理均由插件完成，则可不配置。如针对http重定向至https的逻辑，则只需要添加中间件即可
- `path`: 匹配的路径，具体使用方法后续内容细说
- `host`: 匹配的域名，如果是多个域名则使用`,`分隔
- `proxy_set_headers`: 转发至upstream时设置的请求头，若该请求头已存在则覆盖
- `proxy_add_headers`: 转发至upstream时添加的请求头
- `rewrite`: 请求路径的重写规则
- `weight`: 自定义的权重，可以调整该location的权重，例如mock为服务不可用后，再调整该权重最高，则可禁用所有请求
- `plugins`: 添加至该location的插件列表，按顺序执行
- `client_max_body_size`: 客户端请求的body最大长度

Location支持配置对应host(支持多个）与path规则，path支持以下的规则，权重由高至低：

- 全等模式，配置以`=`开始，如`=/api`表示匹配path等于`/api`的请求
- 正则模式，配置以`~`开始，如`~^/(api|rest)`表示匹配path以`/api`或`/rest`开始请求
- 前缀模式，如`/api`表示匹配path为`/api`开始的请求

在server中会根据所添加的所有location列表，计算对应的权重重新排序，也可自定义权重，location的计算权限逻辑如下：

```rust
pub fn get_weight(&self) -> u16 {
    if let Some(weight) = self.weight {
        return weight;
    }
    // path starts with
    // = 1024
    // prefix(default) 512
    // ~ 256
    // host exist 128
    let mut weight: u16 = 0;
    if let Some(path) = &self.path {
        if path.starts_with('=') {
            weight += 1024;
        } else if path.starts_with('~') {
            weight += 256;
        } else {
            weight += 512;
        }
        weight += path.len().min(64) as u16;
    };
    if self.host.is_some() {
        weight += 128;
    }
    weight
}
```

一般而言，权重均无需自定义，由规则计算即可。有时可定义一个用于禁用服务的location，其匹配规则为无`host`与`path`限制并指定最高的权重`2048`，在平时并不添加此location，仅在有时需要禁用该Server下所有请求时添加使用。

### 添加请求头

可按需配置该location对应的请求头，两个配置的方式均比较简单一种是直接添加，一种是设置（若已存在则覆盖），需要注意的是，有些`upstream`是需要匹配对应的`Host`的，有此要求的则需要在请求头中设置对应的配置`Host:xxx`(使用设置而非添加)。

### 重写请求路径

可按需配置请求路径重写规则，支持正则匹配处理(与nginx类似)，仅支持配置一个重写规则，若逻辑过于复杂建议可配置多个location来分开实现。配置通过空格分隔为前后两部分，处理逻辑则是按正则匹配将前部分替换为后部分，下面是常用的一些例如：

- `^/api/ /`: 表示将请求前缀的`/api/`替换为`/`
- `^/(\S*?)/ /api/$1/`: 表示在请求路径添加前缀`/api`
- `^/(\S*?)/api/ /$1`: 表示将请求路径中的`/api`部分删除

### 插件

Location可根据需要添加对应的插件，需要注意插件是按顺序执行的，因此要配置时要保证其顺序(若在web上配置则勾选后调整顺序即可)，通过插件可支持各种不同的应用场景，具体查看[细说插件体系](./plugin_zh.md)。
