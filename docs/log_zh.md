---
description: Pingap 请求日志格式化
---

Pingap格式化可以使用以下几种默认形式`combined`，`common`，`short`以及`tiny`。也可自定义完整的日志格式化输出，具体参数说明如下：

- `{host}`: 请求的host属性
- `{method}`: 请求的method
- `{path}`: 请求的路径
- `{proto}`: 协议类型，`HTTP/1.1`或`HTTP/2.0`
- `{query}`: 请求的querystring
- `{remote}`: 请求的源ip
- `{client-ip}`: 客户ip，根据`x-forwarded-for`中获取
- `{scheme}`:
- `{uri}`: 请求的完整地址
- `{referer}`: 请求头中的referer
- `{user-agent}`: 请求的user-agent
- `{when}`: 日志的输出时间
- `{when-utc-iso}`: 日志的输出的utc时间
- `{when-unix}`: 日志的输出时间，格式为时间戳
- `{size}`: 响应数据的字节数
- `{size-human}`: 响应数据的大小，按数据大小格式化字符串
- `{status}`: 响应状态码
- `{latency}`: 响应时间的ms
- `{latency-human}`: 响应时间，按时间格式化
- `{payload-size}`: 请求数据的字节大小
- `{payload-size-human}`: 请求数据的大小，按数据大小格式化字符串
- `{~cookiename}`: 从cookie中获取对应的值
- `{>request_header_name}`: 请求头中获取对应的值
- `{<response_header_name}`: 响应头中获取对应的值
- `{:context_ame}`: 从context中获取对应的值，暂时仅支持以下属性：`reused`, `upstream-address`, `processing`
- `{$env_name}`: 从环境变量中获取对应的值，仅启动时获取
