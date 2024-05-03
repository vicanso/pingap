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
    <img src="../asset/pingap.jpg" alt="pingap">
</p>

启动成功后访问`http://127.0.0.1:3018/`可以看到，该界面支持了各类属性配置，后续将一个个讲解。

## 基础配置
