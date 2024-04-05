---
description: Location的详细介绍
---

## Location

Location支持配置对应的多个host与path规则，path支持以下的规则，权重由高至低：

- 全等模式，配置以`=`开始，如`=/api`表示匹配path等于`/api`的请求
- 正则模式，配置以`~`开始，如`~^/(api|rest)`表示匹配path以`/api`或`/rest`开始请求
- 前缀模式，如`/api`表示匹配path为`/api`开始的请求
- 空模式，若未指定path则表示所有的path均匹配，一般建议配置一个`/`的前缀模式即可，无需使用空模式

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

一般而言，权重均无需自定义，由规则计算即可。有时可定义一个用于禁用服务的location，其匹配规则为无`host`与`path`限制并指定最高的权重`2048`，在平时并不添加此location，仅在有时需要禁用所有服务时才添加使用。

### 添加请求头与响应头

可按需配置该location对应的请求头与响应头，两个配置的方式均比较简单，需要注意的是，有些`upstream`是需要匹配对应的`Host`的，因此有此要求的则需要在请求头中设置对应的配置`Host:xxx`。

### 重写请求路径

可按需配置请求路径重写规则，支持正则匹配处理，如`^/api/ /`表示将请求前缀的`/api/`替换为`/`，仅支持配置一个重写规则，若逻辑过于复杂建议可配置多个location来分开实现。
