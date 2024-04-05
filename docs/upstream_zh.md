---
description: Upstream的详细介绍
---

## Upstream

Upstream现支持三种类型，包括`静态目录`，`Mock响应`以及常规的`反向代理节点`，下面一下详细讲解各类型的使用场景。

### 静态目录

upstream地址配置以`file://目录路径?chunk_size=8192&max_age=3600&private&index=index.html`的方式指定访问目录，暂仅支持单路径服务，其querystring部分均为可选，参数说明如下：

- `chunk_size`: 静态文件以chunk的形式读取，此参数指定每次读取的分块大小，默认为8192
- `max_age`: 指定静态文件的缓存时长，单位为秒。需要注意，对于`text/html`默认设置为不可缓存
- `private`: 指定缓存是否为私有的，若指定为私有的，则只允许客户端缓存，中间的缓存中间件不缓存该数据

- `index`: 指定默认路径对应的文件，无默认值

### Mock响应

Mock响应的配置形式为`mock://{"status":500,"headers":["Content-Type: application/json"],"data":"{\"message\":\"Mock Service Unavailable\"}"}`配置响应，配置形式为json形式，用于应急或测试使用，参数说明如下：

- `status`: 响应状态码
- `headers`: 响应头列表
- `data`: 响应数据，可根据需要是html或者json等数据

### 反向代理节点

此种形式为最常用形式，配置为节点地址列表，需要注意此节点会使用默认的tcp health check的形式检测节点是否可用，不过建议配置为http health chech。下面针对相关参数详细说明：

- `addrs`: 节点地址列表，地址为`ip:port weight`的形式，`weight`权重可不指定，默认为1
- `health_check`: 节点健康检测配置，支持http与tcp形式
- `algo`: 节点的选择算法，支持`hash`与`round_robin`两种形式，如`hash:ip`表示按ip hash选择节点。默认为`round_robin`
- `connection_timeout`: tcp连接超时，默认为无
- `total_connection_timeout`: 连接超时，对于https包括tls握手部分，默认为无
- `read_timeout`: 读取超时，默认为无
- `write_timeout`: 写超时，默认为无
- `idle_timeout`: 空闲超时，指定连接空闲多久后会自动回收，如果设置为0，则连接不复用，需要注意有些网络设备对于无数据的tcp连接会过期自动关闭，因此可根据需要设置对应的值。默认为无

### 节点健康检测

- `health_check`: 建议配置为health check的形式，根据服务的检测路径配置为`http://upstream名称/路径`，如对于upstream为charts的服务，其检测路径为`/ping`，即可设置为`http://charts/ping`

- `TCP`: tcp://upstreamname?connection_timeout=3s&success=2&failure=1&check_frequency=10s
- `HTTP`: http(s): http://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s

健康检测参数说明：

- `connection_timeout`: 连接超时，默认为3秒
- `read_timeout`: 读取超时，默认为3少
- `check_frequency`: 检测间隔，默认为10秒
- `success`: 成功次数多少次为成功，默认为1次
- `failure`: 失败次数多少次为失败，默认为2次
- `reuse`: 检测时是否复用连接，默认为否
