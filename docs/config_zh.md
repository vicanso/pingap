---
description: Pingap 配置说明
---

Pingap使用toml来配置相关参数，具体参数说明如下：

## 基本配置

- `error_template`: 参数可选，出错时的html模板，可自定义出错的html模板，在出错时会替换模板中的`{{version}}`为pingap的版本号，`{{content}}`为出错的具体信息。
- `pid_file`: 参数可选，默认为`/tmp/pingap.pid`，此参数配置进程id的记录文件。
- `upgrade_sock`: 参数可选，默认为`/tmp/pingap.sock`，此参数配置程序无中断式更新时的socket路径，用于新的pingap进程与旧进程之间切换时使用。
- `user`: 参数可选，默认为空，用于设置守护进程的执行用户
- `group`: 参数可选，默认为空，与`user`类似
- `threads`: 参数可选，默认为1，用于设置每个服务(如server监控的tcp连接)使用的线程数，如果设置为0，则使用cpu或cgroup限制核数
- `work_stealing`: 参数可选，默认为`true`，是否允许同服务中的不同线程的抢占工作。

## upstreams

- `upstreams.x`: upstream配置，其中`x`为upstream的名称，需要注意名称不要相同，相同名称的配置会被覆盖。
- `addrs`: 该upstream的服务地址列表，格式为`ip:port`的形式，如果要指定权重则可通过此形式指定`ip:port weight`。
- `algo`: 参数可选，默认为`round_robin`。upstream各节点的选择方法，支持`hash`与`round_robin`两种形式。
- `health_check`: 参数可选，默认为`tcp`形式。upstream节点的健康检查方式，支持`tcp`与`http`方式。`tcp://upstreamname?connection_timeout=3s&success=2&failure=1&check_frequency=10s`表示使用tcp的形式，连接超时为3秒，成功2次则成功或失败1次则失败，检测间隔为10秒。`http://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s`表示使用http的形式检测，路径为`/ping`，连接超时为3少，读取超时为1秒，成功2次则成功或失败1次则失败，检测间隔为10秒。
- `connection_timeout`: 参数可选，默认为无超时，表示tcp连接建立的超时时间为多少秒。
- `total_connection_timeout` 参数可选，默认为无超时，表示连接建立的超时时间为多少秒，包括tcp与tls。
- `read_timeout`: 参数可选，默认为无超时，表示读取的超时时间。
- `write_timeout`: 参数可选，默认为无超时，表示写的超时时间。
- `idle_timeout`: 参数可选，默认为无，表示空闲连接不关闭。若设置为0秒表示禁用连接池。

## Location

- `locations.x`: locations配置，其中`x`为locations的名称，需要注意名称不要相同，相同名称的配置会被覆盖。
- `upstream`: 该location使用的upstream。
- `host`: 参数可选，默认无。表示该location匹配请求的`host`。
- `path`: 参数可选，默认无。表示该location匹配的请求`path`，支持以下几种模式，`~/api`表示正则形式匹配；`=/api`表示全等模式匹配，需要path等于`/api`才算匹配；`/api`则表示前缀匹配，需要path以`/api`开头的请求。
- `proxy_headers`: 设置发送至`upstream`时添加的请求头列表，格式为`name:value`的形式。
- `headers`: 设置响应时添加的响应头列表，格式为`name:value`的形式。
- `rewrite`: 请求替换规则，`^/api/ /`如表示将请求的path前缀的`/api/`表示为`/。

## Server

- `server.x`: server的配置，其中`x`为server的名称，需要注意名称不要相同，相同名称的配置会被覆盖。
- `addr`: 监控的端口地址。
- `tls_cert`: tls证书的cert，base64格式，如果是https的形式才需要添加。
- `tls_key`: tls证书的key，base64格式，如果是https的形式才需要添加。
- `access_log`: 可选，默认为不输出访问日志。请求日志格式化，指定输出访问日志的形式。
- `locations`: location的列表，指定该server使用的所有location。
- `stats_path`: 可选，默认无。指定返回server的stats的路由。
- `admin_path`: 可选，默认无。指定用于转发至admin管理后台的路由。
