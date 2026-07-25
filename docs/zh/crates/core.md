# Pingap Core

Pingap Core 是 Pingap 项目的基础库，提供一组核心组件与工具，用于在 Rust 中构建高性能、可扩展的代理与网络应用。

## 概述

本库提供模块化工具包，覆盖 HTTP 请求与响应的完整生命周期。包含强大的请求上下文、灵活的插件架构、高效的 HTTP 头与响应处理、后台任务管理等。构建于 `pingora` 框架之上，并扩展专用能力。

## 核心特性

- **请求上下文（`Ctx`）**：跟踪每个请求的状态，包括时序指标、连接细节、上游信息、缓存状态与自定义变量。并提供生成详细日志与 `Server-Timing` 头的工具。
- **插件系统**：可扩展架构，允许挂接到请求/响应生命周期的各阶段（`PluginStep`），实现认证、限流、改头等自定义逻辑。
- **HTTP 辅助**：
  - **头操作**：解析、创建与修改 HTTP 头，支持动态值替换（如 `$hostname`、`$remote_addr`、`$http_user_agent`）。
  - **响应构建器**：流畅的 `HttpResponseBuilder`，便于构造完整 HTTP 响应，含 JSON、HTML、文本与重定向等常用类型。
  - **流式响应**：`HttpChunkResponse` 支持分块，高效流式发送大正文。
- **后台任务服务**：通用 `BackgroundTaskService`，用于周期任务，如健康检查、数据同步或清理。
- **限流**：基于 TTL 的高效 LRU 缓存（`TtlLruLimit`），实现时间窗口内最大请求数限制。
- **通知服务**：可扩展的简单 trait（`Notification`），通过多种渠道发送告警与通知。
- **高性能工具**：粗粒度时间缓存等工具，减少热路径系统调用。

## 模块

- `ctx`：请求生命周期状态管理的核心 `Ctx`。
- `http_header`：HTTP 请求头解析与操作辅助。
- `http_response`：创建 HTTP 响应的构建器与结构体。
- `plugin`：定义 `Plugin` trait 与 `PluginStep` 枚举。
- `service`：运行后台任务的 `BackgroundTaskService`。
- `ttl_lru_limit`：基于 TTL 的 LRU 限流器。
- `notification`：发送通知的 trait。
- `util`：杂项工具，含时间缓存与主机名获取。

## 许可证

本项目采用 Apache-2.0 许可证。
