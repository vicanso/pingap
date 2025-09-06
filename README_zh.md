# pingap

Pingap在发布稳定版本之前，暂时不接受 pull requests，如果有问题可以先提issue，会及时处理。

Pingap是一个基于[pingora](https://github.com/cloudflare/pingora)构建的高性能反向代理服务器。

可选择性地集成Sentry和OpenTelemetry功能。

[使用示例](./examples/README.md) | [详细文档](http://pingap.io/pingap-zh/)


```mermaid
flowchart LR
  internet("互联网") -- 客户端请求 --> pingap["Pingap"]
  pingap -- 转发:pingap.io/api/* --> apiUpstream["10.1.1.1,10.1.1.2"]
  pingap -- 转发:cdn.pingap.io --> cdnUpstream["10.1.2.1,10.1.2.2"]
  pingap -- 转发:pingap.io --> upstream["10.1.3.1,10.1.3.2"]
```

## 核心功能

- **支持多Location配置**: 配置多个Location，支持主机/路径过滤和权重路由
- **高级代理功能**:
  - 支持正则表达式的路径重写
  - 透明代理
  - HTTP/1.1 和 HTTP/2 支持（包括 h2c）
  - gRPC-web 反向代理
- **服务发现**: 支持静态、DNS 和 Docker 标签
- **监控与可观测性**:
  - 10+ Prometheus 指标（拉取/推送）
  - OpenTelemetry 支持，包含 W3C 上下文和 Jaeger 追踪
  - 详细的访问日志，含 30+ 可配置属性
- **配置管理**:
  - 基于 TOML 的配置
  - 支持文件和 etcd 存储
  - 热重载支持（10秒内生效）
  - 便捷的 Web 管理界面
- **安全性与性能**:
  - Let's Encrypt 集成
  - 多域名 TLS 支持，自动证书选择
  - HTTP 插件系统（缓存、压缩、认证、限流）
  - 详细的性能指标：包括upstream连接时间、处理时间、压缩时间、缓存查询时间等

## 启动服务

使用以下命令从指定配置目录启动 Pingap 服务：

```bash
RUST_LOG=INFO pingap -c=/opt/pingap/conf -d --log=/opt/pingap/pingap.log
```

参数说明：
- `-c`: 指定配置文件目录
- `-d`: 以守护进程（后台）模式运行
- `--log`: 指定日志文件路径

## 优雅重启

执行以下命令可实现零停机重启：

```bash
RUST_LOG=INFO pingap -c=/opt/pingap/conf -t \
  && pkill -SIGQUIT pingap \
  && RUST_LOG=INFO pingap -c=/opt/pingap/conf -d -u --log=/opt/pingap/pingap.log
```

执行步骤：
1. 验证配置文件正确性 (`-t`)
2. 向现有进程发送退出信号
3. 启动新进程接管现有连接 (`-u`)

## 配置热重载

启用配置自动重载功能：

```bash
RUST_LOG=INFO pingap -c=/opt/pingap/conf \
  -a -d --autoreload --log=/opt/pingap/pingap.log
```

特性：
- `-a`: 启用配置变更监听
- `--autoreload`: 支持 upstream 和 location 配置的热重载（10秒内生效）
- 配置变更时自动应用，无需手动重启


## Docker

使用docker启动程序，并支持自动更新配置(仅location与upstream支持)以及管理后台：


```bash
docker run -d --restart=always \
  -v $PWD/pingap:/opt/pingap \
  -p 3018:3018 \
  -e PINGAP_ADMIN_ADDR=0.0.0.0:3018 \
  -e PINGAP_ADMIN_USER=pingap \
  -e PINGAP_ADMIN_PASSWORD=123123 \
  -e PINGAP_AUTORELOAD=true \
  vicanso/pingap -c /opt/pingap/conf
```


## 应用配置

```toml
[upstreams.charts]
addrs = ["127.0.0.1:5000"]

[locations.lo]
upstream = "charts"
path = "/"

[servers.test]
addr = "0.0.0.0:6188"
locations = ["lo"]
```

所有的应用配置可查阅说明： [pingap.toml](./conf/pingap.toml)。

## 请求处理流程

```mermaid
graph TD;
    server["HTTP服务"];
    locationA["Location A"];
    locationB["Location B"];
    locationPluginListA["转发插件列表A"];
    locationPluginListB["转发插件列表B"];
    upstreamA1["上游服务A1"];
    upstreamA2["上游服务A2"];
    upstreamB1["上游服务B1"];
    upstreamB2["上游服务B2"];
    locationResponsePluginListA["响应插件列表A"];
    locationResponsePluginListB["响应插件列表B"];

    start("新的请求") --> server

    server -- "host:HostA, Path:/api/*" --> locationA

    server -- "Path:/rest/*"--> locationB

    locationA -- "顺序执行转发插件" --> locationPluginListA

    locationB -- "顺序执行转发插件" --> locationPluginListB

    locationPluginListA -- "转发至: 10.0.0.1:8001" --> upstreamA1

    locationPluginListA -- "转发至: 10.0.0.2:8001" --> upstreamA2

    locationPluginListA -- "处理完成" --> response

    locationPluginListB -- "转发至: 10.0.0.1:8002" --> upstreamB1

    locationPluginListB -- "转发至: 10.0.0.2:8002" --> upstreamB2

    locationPluginListB -- "处理完成" --> response

    upstreamA1 -- "顺序执行响应插件" --> locationResponsePluginListA
    upstreamA2 -- "顺序执行响应插件" --> locationResponsePluginListA

    upstreamB1 -- "顺序执行响应插件" --> locationResponsePluginListB
    upstreamB2 -- "顺序执行响应插件" --> locationResponsePluginListB

    locationResponsePluginListA --> response
    locationResponsePluginListB --> response

    response["HTTP响应"] --> stop("日志记录");
```

## 性能测试

CPU: M4 Pro, Thread: 1

```bash
wrk 'http://127.0.0.1:6100/ping' --latency

Running 10s test @ http://127.0.0.1:6100/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    59.87us   20.27us   1.00ms   81.00%
    Req/Sec    82.12k     3.04k   85.77k    90.59%
  Latency Distribution
     50%   63.00us
     75%   69.00us
     90%   76.00us
     99%   97.00us
  1650275 requests in 10.10s, 215.61MB read
Requests/sec: 163396.17
Transfer/sec:     21.35MB
```

## 最低支持rust版本

最低支持的rust版本为1.74

# 开源协议

This project is Licensed under [Apache License, Version 2.0](./LICENSE).
