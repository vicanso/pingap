---
description: Pingap 配置说明
---

Pingap使用toml来配置相关参数，具体参数说明如下：

## 基本配置

- `name`: 实例名称，默认为`Pingap`
- `error_template`: 参数可选，异常出错时的html模板，可自定义出错的html模板，在出错时会替换模板中的`{{version}}`为pingap的版本号，`{{content}}`为出错的具体信息
- `pid_file`: 参数可选，默认为`/tmp/pingap.pid`，此参数配置进程id的记录文件
- `upgrade_sock`: 参数可选，默认为`/tmp/pingap_upgrade.sock`，此参数配置程序无中断式更新时的socket路径，用于新的pingap进程与旧进程之间切换时使用
- `user`: 参数可选，默认为空，用于设置守护进程的执行用户
- `group`: 参数可选，默认为空，与`user`类似
- `threads`: 参数可选，默认为1，用于设置每个服务(如server监控的tcp连接)使用的线程数，如果设置为0，则使用cpu或cgroup限制核数
- `work_stealing`: 参数可选，默认为`true`，是否允许同服务中的不同线程的抢占工作
- `grace_period`: 设置优雅退出的等待周期，默认为5分钟
- `graceful_shutdown_timeout`: 设置优雅退出关闭超时时长，默认为5秒
- `upstream_keepalive_pool_size`: 设置upstream保持连接的连接池大小，默认为`128`
- `webhook`: Webhook的请求路径
- `webhook_type`: Webhook的类型，支持普通的http形式、`webcom`与`dingtalk`三种类型
- `webhook_notifications`: Webhook通知的类型，有`backend_status`，`lets_encrypt`，`diff_config`，`restart`，`restart_fail`以及`tls_validity`
- `log_level`: 应用日志的输出级别
- `log_capacity`: 日志缓存区字节大小，设置后会以`BufWriter`的形式写入日志
- `sentry`: Sentry的DSN配置
- `pyroscope`: Pyroscope连接地址，需要注意默认版本并未编译支持pyroscpe，需要使用perf的版本
- `auto_restart_check_interval`: 检测配置更新的间隔，默认为每90秒检测一次，若配置为小于1秒的值，则不检测
- `cache_max_size`: 缓存空间的最大限制，缓存是程序中所有服务共用
- `certificate_file`: https证书文件保存，对于使用`let's encrypt`自动生成证书时建议配置

## upstreams

Upstream的相关配置说明可查看[Upstream的详细说明](./upstream_zh.md)

## Location

Location的相关配置说明可查看[Location的详细说明](./location_zh.md)

## Server

- `server.x`: server的配置，其中`x`为server的名称，需要注意名称不要相同，相同名称的配置会被覆盖。
- `addr`: 监控的端口地址，地址格式为`ip:port`的形式，若需要监听多地址则以`,`分隔
- `access_log`: 可选，默认为不输出访问日志。请求日志格式化，指定输出访问日志的形式。提供了以下几种常用的日志输出格式`combined`, `common`, `short`, `tiny`
- `locations`: location的列表，指定该server使用的所有location
- `threads`: 设置服务默认的线程数，设置为0则等于cpu核数，默认为1
- `tls_cert`: tls证书的cert，pem格式，如果是https的形式才需要添加
- `tls_key`: tls证书的key，pem格式，如果是https的形式才需要添加
- `lets_encrypt`: 指定通过let's encrypt生成https证书的域名地址列表，多个域名用`,`分隔
- `enabled_h2`: 是否启用http2，默认为不启用，需要注意只有https下才有效
- `tcp_idle`: tcp连接keepalive空闲回收时长
- `tcp_interval`: tcp连接keepavlie检测时长
- `tcp_probe_count`: tcp连接keepalvie探针检测次数
- `tcp_fastopen`: 启用tcp快速启动，并设置backlog的大小
