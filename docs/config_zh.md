---
description: Pingap 配置说明
---

Pingap使用toml来配置相关参数，具体参数说明如下：

## 基本配置

- `error_template`: 参数可选，出错时的html模板，可自定义出错的html模板，在出错时会替换模板中的`{{version}}`为pingap的版本号，`{{content}}`为出错的具体信息
- `pid_file`: 参数可选，默认为`/tmp/pingap.pid`，此参数配置进程id的记录文件
- `upgrade_sock`: 参数可选，默认为`/tmp/pingap_upgrade.sock`，此参数配置程序无中断式更新时的socket路径，用于新的pingap进程与旧进程之间切换时使用
- `user`: 参数可选，默认为空，用于设置守护进程的执行用户
- `group`: 参数可选，默认为空，与`user`类似
- `threads`: 参数可选，默认为1，用于设置每个服务(如server监控的tcp连接)使用的线程数，如果设置为0，则使用cpu或cgroup限制核数
- `work_stealing`: 参数可选，默认为`true`，是否允许同服务中的不同线程的抢占工作
- `grace_period`: 设置优雅退出的时间周期
- `graceful_shutdown_timeout`: 设置优雅退出关闭超时时长
- `upstream_keepalive_pool_size`: 设置upstream保持连接的连接池大小
- `webhook_type`: Webhook的类型，支持普通的http形式、`webcom`与`dingtalk`三种类型
- `webhook`: Webhook的请求路径
- `log_level`: 应用日志的输出级别
- `sentry`: Sentry的DSN配置

## upstreams

Upstream的相关配置说明可查看[Upstream的详细说明](./upstream_zh.md)

## Location

Location的相关配置说明可查看[Location的详细说明](./location_zh.md)

## Server

- `server.x`: server的配置，其中`x`为server的名称，需要注意名称不要相同，相同名称的配置会被覆盖。
- `addr`: 监控的端口地址。
- `access_log`: 可选，默认为不输出访问日志。请求日志格式化，指定输出访问日志的形式。
- `locations`: location的列表，指定该server使用的所有location。
- `threads`: 设置服务默认的线程数，设置为0则等于cpu核数，默认为1
- `tls_cert`: tls证书的cert，base64格式，如果是https的形式才需要添加。
- `tls_key`: tls证书的key，base64格式，如果是https的形式才需要添加。
