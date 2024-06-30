---
description: Pingap 配置说明
---

Pingap的大部分参数均是配置toml配置文件来指定，而有一些参数则是需要在启动程序时指定的，具体如下：

- `conf`或者`c`: 默认为当前目录，指定配置文件或配置文件目录，建议使用目录的形式，便于配置按类型管理
- `daemon`或者`d`: 可选，是否指定以后台服务的形式启用，若需要使用upgrade的形式无中断式加载新配置，则需要使用此模式
- `upgrade`或`u`: 可选，以更新程序模式启用，此模式下新的程序会通过unix socket接收原有的程序的请求，避免请求中断。此模式只允许在`daemon`下有效
- `test`或`t`: 可选，仅测试配置是否正确
- `log`: 可选，指定日志输入目录
- `admin`: 可选，配置admin的监听地址，形式为`base64(user:pass)@ip:port`，其中认证部分是basic auth，若不配置则不校验，建议配置
- `cp`: 可选，是否为控制面板节点，对于使用etcd存储配置的部署使用，设置后此节点只用于配置参数，避免配置有误导致节点无法启动，其它节点则加载对应配置运行。
- `autorestart`或`a`: 可选，是否在配置有更新时自动重启，建议使用此方式达到准实时更新配置的效果(需要在daemon模式下)
- `autoreload`: 可选，是否自动更新配置，仅适用于upstream与location的配置变更


## 配置以文件形式的启用命令

配置目录保存在`/opt/pingap/conf`，配置变更时自动重启程序，启动命令如下：

```bash
RUST_LOG=INFO pingap \
  -c=/opt/pingap/conf -d \
  --log=/opt/pingap/pingap.log \
  --autorestart -d
```

## 配置保存在etcd

一般如果是多节点部署，也有现成etcd，建议使用管理节点与应用节点分离的形式。

管理节点：

```bash
RUST_LOG=INFO pingap \
  -c="etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s&user=pingap&password=123123" \
  --cp \
  --admin=cGluZ2FwOjEyMzEyMw==@127.0.0.1:3018
```

etcd的连接参数：`etcd://ip1:port1,ip2:port2/path?user=xx&password=xx`的形式，需要注意`/path`部分按需要对应不同的应用配置。
admin的配置参数：`cGluZ2FwOjEyMzEyMw==`对应base64(pingap:123123)，指定后访问管理后台会使用basic auth校验，若不配置则无需校验，建议配置。

应用节点：

```bash
RUST_LOG=INFO pingap \
  -c="etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s&user=pingap&password=123123" \
  -d --log=/opt/pingap/pingap.log \
  --autorestart
```
