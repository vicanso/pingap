# pingap-logger

[![Crates.io](https://img.shields.io/crates/v/pingap-logger.svg)](https://crates.io/crates/pingap-logger)
[![Docs.rs](https://docs.rs/pingap-logger/badge.svg)](https://docs.rs/pingap-logger)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

为 Pingap 项目构建的灵活、强大的日志库，基于 `tracing` 生态。

## 概述

`pingap-logger` 提供稳健的日志方案，注重性能与灵活性。功能包括可定制访问日志、多种日志写出器（文件、syslog、stdout/stderr）、自动轮转与日志压缩。

## 功能

- **可定制访问日志：** 使用丰富标签轻松创建自定义访问日志格式。
- **多种写出器：** 写入文件、syslog 或标准输出/错误。
- **日志轮转：** 按日、时或分自动轮转日志文件。
- **日志压缩：** 用 `gzip` 或 `zstd` 压缩已轮转文件以节省磁盘。
- **结构化日志：** 以 JSON 输出，便于解析与分析。
- **面向性能：** 为高性能应用设计，支持缓冲写入等特性。

## 安装

在 `Cargo.toml` 中加入 `pingap-logger`：

```toml
[dependencies]
pingap-logger = "0.12.0"
```

## 用法

### 初始化日志器

用期望的 `LoggerParams` 调用 `logger_try_init`：

```rust
use pingap_logger::{logger_try_init, LoggerParams};

fn main() {
    let params = LoggerParams {
        log: "/tmp/pingap-test.log?rolling=daily&compression=gzip".to_string(),
        level: "info".to_string(),
        capacity: 4096,
        json: true,
    };
    let _ = logger_try_init(params);
}
```

### 访问日志

可用格式字符串配置访问日志。预定义格式：`combined`、`common`、`short`、`tiny`。

也可自定义格式：

```rust
use pingap_logger::Parser;
use pingora::proxy::Session;
use pingap_core::Ctx;

// Example of a custom format
let format = "{client_ip} - {method} {uri} {proto} {status} {latency_human}";
let parser = Parser::from(format);

// In your request handling logic
// let log_line = parser.format(&session, &ctx);
// println!("{}", log_line);
```

#### 可用标签

| Tag                    | Description                                            |
| ---------------------- | ------------------------------------------------------ |
| `{host}`               | 服务器主机名。                                       |
| `{method}`             | HTTP 方法（如 GET、POST）。                         |
| `{path}`               | 请求路径。                                          |
| `{proto}`              | 协议版本（如 HTTP/1.1）。                     |
| `{query}`              | 查询参数。                                          |
| `{remote}`             | 远端地址。                                        |
| `{client_ip}`          | 客户端 IP。                                     |
| `{scheme}`             | URL scheme（http 或 https）。                            |
| `{uri}`                | 请求 URI。                                           |
| `{referer}`            | Referer 头。                                        |
| `{user_agent}`         | User-Agent 头。                                     |
| `{when}`               | 请求时间，RFC3339。                        |
| `{when_utc_iso}`       | 请求时间，UTC ISO。                        |
| `{when_unix}`          | 请求时间，Unix 时间戳（毫秒）。         |
| `{size}`               | 响应大小（字节）。                                |
| `{size_human}`         | 响应大小可读格式（如 1.2 KB）。 |
| `{status}`             | 响应状态码。                                  |
| `{latency}`            | 请求延迟（毫秒）。                       |
| `{latency_human}`      | 请求延迟可读格式（如 1.2s）。 |
| `{payload_size}`       | 载荷大小（字节）。                                 |
| `{payload_size_human}` | 载荷大小可读格式。                 |
| `{request_id}`         | 请求 ID。                                            |
| `{~<cookie_name>}`     | Cookie 值。                                     |
| `{><header_name>}`     | 请求头值。                             |
| `{<<header_name>}`     | 响应头值。                            |
| `{:<context_key>}`     | 上下文中的值。                                |

## 配置

日志器通过 `LoggerParams` 的 `log` 字段中的类 URI 字符串配置。

- **文件日志：** `"/path/to/file.log?rolling=daily&compression=gzip"`
  - `rolling`：`daily`（默认）、`hourly`、`minutely`、`never`。
  - `compression`：`gzip` 或 `zstd`。
  - `level`：压缩级别。
  - `days_ago`：保留已压缩日志的天数。
  - `time_point_hour`：运行压缩任务的小时。

- **Syslog（仅 Unix）：** `"syslog:///?format=3164"`
  - `format`：`3164`（默认）或 `5424`。
  - `process`：syslog 消息中的进程名。
  - `facility`：syslog facility。

- **标准 I/O：** `""`（空字符串）表示 stderr。

## 基准

本库面向高性能。详细基准结果见源码中的 `benches` 目录。

## 贡献

欢迎贡献！请提交 pull request 或 issue。

## 许可证

本项目采用 Apache-2.0 许可证。
