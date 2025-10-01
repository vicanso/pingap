# api gateway

API网关是微服务架构中的重要组成部分，它负责将客户端的请求路由到不同的后端微服务。


```bash
pingap -c ~/github/pingap/examples/api-gateway --admin=127.0.0.1:3018 --autoreload
```

## 配置简述

- `charts`: 图表服务，请求为`/api/charts/`前缀的所有请求转发至该服务，并将请求前缀删除
- `orders`: 订单服务，请求为`/api/orders/`前缀的所有请求转发至该服务，并将请求前缀删除
- `common`: 公共服务，不符合以上规则的所有请求转发至该服务，一般用于前端静态html等静态资源服务

所有服务的upstream均配置了http的健康检查，pingap会定时检测上游节点是否可用（若不配置则默认使用tcp:port形式检测)，当一个server关联多个location时，会根据配置的规则计算匹配权重，权重高的location优先匹配。

## 插件

- `charts`: 图表服务提供接口生成svg图表，程序本身已支持将`Accept-Encoding`返回压缩后的数据，所以这里只配置了`userBasicAuth`插件用于认证，`requestId`插件用于生成请求id
- `orders`: 订单服务提供接口查询订单，程序本身未支持压缩，因此配置了`compressionUpstream`插件用于压缩接收到的响应数据，并配置了`appKeyAuth`插件用于认证。需要注意压缩插件会占用更多的cpu资源，如果是对外的接口建议启用，而内部服务则建议根据网络与cpu的资源综合考虑
- `common`: 公共服务提供前端静态html等静态资源服务，静态资源用于对客户端展示，程序本身未支持压缩，静态资源也不常更新，因此配置了`commonCache`插件用于缓存，`compressionUpstream`插件用于压缩接收到的响应数据。缓存+压缩是一种很好的组合插件使用，使用`compressionUpstream`会自动将相应的encoding添加至缓存key，保证支持不同压缩算法的客户端使用不同的缓存，而缓存压缩数据也避免了每次都重复压缩，极大的提升性能