---
description: 从零开始使用Pingap反向代理
---

本章节介绍从零开始如何创建反向代理，由于pingora的热更新重启会关闭当前进程，暂时pingap也只能使用此方式，因此以下的示例均是以后台进程的形式运行。

## 选择存储目录

pingap支持etcd方式存储配置，而文件与etcd的形式仅是启动参数上的差异，因此示例选择使用文件方式存储，方便大家尝试。

pingaap保存文件配置中，若指定的是目录则会按类别生成不同的toml配置，若指定的是文件，则所有配置均保存至该文件中，建议使用目录的形式。

```bash
RUST_LOG=INFO pingap -c /opt/pingap/conf
```

选择该目录后，默认会加载该目录下的所有toml配置，由于当前目录为空，暂时无任何实际的效果。

## 启用WEB管理后台配置

toml的相关配置可以查阅[应用配置详细说明](./config_zh.md)，建议可以使用WEB管理后台的方式来匹配。WEB管理后台支持basic auth的方式鉴权（可选），下面通过127.0.0.1:3018端口提供管理后台服务，账号为：pingap，密码为：123123，`cGluZ2FwOjEyMzEyMw==`为base64("pingap:123123")。

```bash
RUST_LOG=INFO pingap -c /opt/pingap/conf --admin=cGluZ2FwOjEyMzEyMw==@127.0.0.1:3018
```

<p align="center">
    <img src="../asset/pingap-zh.jpg" alt="pingap">
</p>

启动成功后访问`http://127.0.0.1:3018/`可以看到，该界面支持了各类属性配置，后续将一个个讲解。

## 基础配置

基础配置中一般不需要如何调整，若在同一机器运行多个pingap，则需要设置`进程id文件`与`upgrade sock`这两个配置，避免冲突。

<p align="center">
    <img src="../asset/basic-info-zh.jpg" alt="basic config">
</p>

## 上游服务配置

由于配置中有依赖关系，因此先配置上游服务。点击添加上游服务配置，界面如下：

<p align="center">
    <img src="../asset/upstream-add-zh.jpg" alt="upstream config">
</p>

地址配置的是`ip:端口`的形式，无需指定协议，默认为http，对于使用https的填充`sni`即可。

需要注意，对于各超时的配置建议按需配置，默认值无超时不建议使用。`Sni`与`是否校验证书`用于该upstream的节点使用https时设置，若非https忽略即可。健康检查的`http://charts/ping`其中charts为该upstream的名称，在检测时会替换为该节点对应的地址。

<p align="center">
    <img src="../asset/upstream-detail-zh.jpg" alt="upstream detail">
</p>

## Location配置

Location主要配置其对应的host与path，以及选择关联对应的上游服务，界面如下：

<p align="center">
    <img src="../asset/location-detail-zh.jpg" alt="location config">
</p>

host一般不需要设置，path则是因为一般会基于不同的前缀转发至不同的服务，因此会设置对应的path匹配规则（更多的规则可查询location的详细说明），此处选择了自带的`pingap:requestId`插件，用于生成请求id。

## 服务配置

服务配置主要配置该服务监听的端口，https相关证书(非https无需设置)，关联对应的location服务，访问日志格式，以及线程数，界面如下：

<p align="center">
    <img src="../asset/server-detail-zh.jpg" alt="server detail">
</p>

## 程序后台运行及自动重启

程序的配置均已完成，由于此时程序加载的配置非最新版本，因此需要重启程序加载新的配置。Pingap也支持判断配置是否有更新，若有更新则自动触发upgrade的操作，拉起新的实例并关闭当前实例。

最后调整后的程序启动命令为包括以下方面：

- 程序以后台服务运行
- 程序自动检测配置是否更新，若有更新则重启
- 日志写入至/opt/pingap/pingap.log

```bash
RUST_LOG=INFO pingap -c /opt/pingap/conf \
  -d --log=/opt/pingap/pingap.log \
  --autorestart \
  --admin=cGluZ2FwOjEyMzEyMw==@127.0.0.1:3018
```

至此反向代理服务已完成配置，浏览器打开`http://127.0.0.1:6188/charts/`可正常访问，截图如下：

<p align="center">
    <img src="../asset/demo-zh.jpg" alt="pingap">
</p>

接着来调整相应的配置，看看实例是否正常重启并生效，将`location`中的path由`/charts`调整为`/pingap`，以及`rewrite`配置，查看日志看看效果如何：

```
INFO 2024-05-03T13:30:05.087916836+08:00 Auto restart background service, should restart:true
INFO 2024-05-03T13:30:05.088470907+08:00 Webhook notification, category:diff_config, message:location:charts
-path = "/charts"
+path = "/pingap"
-rewrite = "^/charts/ /"
+rewrite = "^/pingap/ /"
```

需要注意，因为避免频繁更新配置时导致重复的重启，因此配置检测只会定时运行(现默认为90秒)，而程序重启也会避免过于频繁，因此需要配置更新后，大概需要等待2分钟才会真正触发upgrade操作。完成后打`http://127.0.0.1:6188/charts/`，需要注意在linux才可正常的触发upgrade的更新切换。
