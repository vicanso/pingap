# pingap-logger

[![Crates.io](https://img.shields.io/crates/v/pingap-logger.svg)](https://crates.io/crates/pingap-logger)
[![Docs.rs](https://docs.rs/pingap-logger/badge.svg)](https://docs.rs/pingap-logger)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

为 Pingap 项目构建的灵活、强大的日志库，基于 `tracing` 生态。

## 概述

`pingap-logger` 提供稳健的日志方案，注重性能与灵活性。功能包括可定制访问日志、多种日志写出器（文件、syslog、stdout/stderr）、自动轮转与日志压缩。

## 功能

- **可定制访问日志：** 使用丰富标签轻松创建自定义访问日志格式。
- **多种写出器：** 写入文件、标准输出/错误，或 syslog（本机，或经 UDP/TCP 发往远程服务器）。
- **日志轮转：** 按日、时或分自动轮转日志文件。
- **日志压缩：** 用 `gzip` 或 `zstd` 压缩已轮转文件以节省磁盘。
- **结构化日志：** 应用日志可输出 JSON，访问日志有 JSON 格式，值会被转义并带类型。
- **面向性能：** 为高性能应用设计，支持缓冲写入等特性。
- **`log` crate 桥接：** 通过 `log` crate 输出的记录同样会被采集，不会被静默丢弃。

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

### 来自 `log` crate 的记录

`logger_try_init` 同时会装上 `tracing-log` 桥接，使通过 `log` crate 输出的记录进入与 `tracing` 事件相同的 subscriber。这一点很关键：Pingora 用的是 `log`，没有桥接就没有任何 `log::Log` 实现被安装，它的诊断信息——包括那条解释热升级为何没能接管监听套接字的 bootstrap 失败——会被直接丢弃。

有两点需要留意：

- `log::max_level` 保持在 `Trace`，`EnvFilter` 是唯一的过滤点。因此通过 reload handle 在运行时修改日志级别，会立即对桥接过来的记录生效。
- 对 `EnvFilter` 指令而言，桥接记录的 target 是 `log` 而非产生它的模块。要整体提升级别请用 `log=debug`；输出的日志行中仍然带有原始 target（如 `pingora_core::server`）。

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

占位符由 `{`、名字（字母、数字和 `_ - < > ~ : $`）和 `}` 组成；后面不是这种形式的 `{` 是普通文本。缺失的值——不存在的请求头或 cookie、尚无状态码——输出为 `-`；没有值的上下文字段不输出任何内容。名字不对应任何标签的占位符会被丢弃。

#### 上下文键

`{:<context_key>}` 输出 pingap 处理请求时记录的值。同样的键也能以 `:<context_key>` 的形式用在请求头的值里，例如 `proxy_set_headers = ["X-Upstream: :upstream_addr"]`。

| 键 | 值 |
| --- | --- |
| `connection_id` | 下游连接的 ID |
| `connection_reused` | 下游连接已处理过之前的请求时为 `true` |
| `connection_time` | 下游连接已存在的时长 |
| `processing` | 该请求到达时 server 正在处理的请求数，含它自己 |
| `location` | 匹配到的 location 名称 |
| `tls_version` | 下游 TLS 版本：OpenSSL 构建为 `TLSv1.3`，rustls 构建为 `TLSv1_3` |
| `tls_cipher` | 下游 TLS 密码套件 |
| `tls_handshake_time` | 下游 TLS 握手耗时，仅连接上的第一个请求有 |
| `ja4` | 客户端的 [JA4 指纹](proxy.md#ja4-指纹)，如 `t13d1516h2_8daaf6152771_e5627efa2ab1`；需要 server 设置 `ja4 = true` |
| `ja4_r` | `JA4_r`：排序后的密码套件与扩展列表本身，而非哈希 |
| `ja4_o` | `JA4_o`：按客户端发送顺序的列表计算哈希 |
| `ja4_ro` | `JA4_ro`：按发送顺序的列表，不做哈希；其他形式都能由它算出 |
| `upstream_addr` | 上游后端地址 |
| `upstream_status` | 上游返回的状态码，没有时为 `-` |
| `upstream_reused` | 上游连接来自 keep-alive 连接池时为 `true` |
| `upstream_connected` | 到该上游的已建立连接数；需要上游开启 `enable_tracer` |
| `upstream_connect_time` | 获取上游连接的耗时，复用或新建 |
| `upstream_tcp_connect_time` | 与上游的 TCP 连接耗时 |
| `upstream_tls_handshake_time` | 与上游的 TLS 握手耗时 |
| `upstream_connect_offload_wait_time` | 连接前等待卸载线程的时长；仅在开启 `basic.upstream_connect_offload_*` 时有 |
| `upstream_connection_time` | 上游连接已存在的时长 |
| `upstream_processing_time` | 从拿到上游连接到收到上游响应头 |
| `upstream_response_time` | 从收到上游响应头到响应体结束 |
| `compression_time` | 压缩响应的耗时 |
| `compression_ratio` | 输入字节数除以输出字节数，保留一位小数 |
| `cache_lookup_time` | 缓存查找耗时 |
| `cache_lock_time` | 等待缓存锁的耗时 |
| `service_time` | 从请求开始到写日志 |

时间单位为毫秒。每个以 `_time` 结尾的键都有对应的 `_human` 版本，以可读形式输出同一时间，例如 `{:upstream_response_time_human}` 输出 `12ms` 或 `1.2s`。从未记录过的值不输出任何内容，比如未走缓存的请求的缓存耗时，或明文 HTTP 连接上的 `ja4`。

#### 配置 server 的访问日志

server 的 `access_log` 是一个格式，前面可以加上输出目标和一个空格：

| 值 | 含义 |
| --- | --- |
| `tiny` | 预定义格式，写入应用日志 |
| `{client_ip} {status} {:ja4}` | 自定义格式，写入应用日志；以 `{` 开头 |
| `/var/log/pingap/access.log {client_ip} {status}` | 文件，再接预定义格式名或自定义格式 |
| `stdout json` | 标准输出；`stderr` 为标准错误 |
| `syslog://10.0.0.5?protocol=tcp combined` | syslog 服务器，每行一条消息 |

预定义格式如下：

```text
combined  {remote} "{method} {uri} {proto}" {status} {size_human} "{referer}" "{user_agent}"
common    {remote} "{method} {uri} {proto}" {status} {size_human}
short     {remote} {method} {uri} {proto} {status} {size_human} - {latency}ms
tiny      {method} {uri} {status} {size_human} - {latency}ms
json      {"when":{when},"remote":{remote},"client_ip":{client_ip},"host":{host},
          "method":{method},"uri":{uri},"proto":{proto},"status":{status},
          "size":{size},"latency":{latency},"referer":{referer},
          "user_agent":{user_agent},"request_id":{request_id}}
```

（`json` 实际是一行，这里为了排版折行。）

输出目标可以是：

- **文件**，支持下文“文件日志”的参数，如 `rolling`、`compression`：`/var/log/pingap/access.log?rolling=hourly {client_ip} {status}`。
- **`stdout` 或 `stderr`**，适合由容器收集标准输出的场景。`/dev/stdout` 与 `/dev/stderr` 含义相同；若当作文件路径，它们会被加上轮转后缀。
- **`syslog://` URL**，本机或远程，参数见下文[配置](#配置)。每行是一条消息，因此 JSON 格式会以每条消息一个对象的形式到达。

它们都支持 `channel_buffer`（排队等待写出的行数，满了之后新的行会被丢弃，默认 1000）与 `flush_timeout`（默认 `10s`）：日志由后台任务写出，文件按这个间隔刷盘，标准输出与标准错误则每写完一批就刷新，便于实时查看。

第一个词后面跟着格式时，这个词总会被当作输出目标：`ACCESS {status}` 会写入名为 `ACCESS` 的文件。要写入应用日志，自定义格式请以标签开头。

#### JSON 格式

以 `{"` 开头的格式是一个 JSON 对象，每个值都会被处理成合法的 JSON。字符串内的占位符会被转义后写进该字符串；单独出现的占位符则自成一个 JSON 值：

```toml
[servers.main]
addr = "0.0.0.0:80"
locations = ["api"]
access_log = 'stdout {"time":{when},"request":"{method} {uri}","status":{status},"latency":{latency},"ua":{user_agent},"upstream":{:upstream_addr},"ja4":{:ja4}}'
```

```json
{"time":"2026-10-02T10:04:05.006+08:00","request":"GET /api/items?page=2","status":200,"latency":12,"ua":"curl/8.7.1","upstream":"10.0.0.7:8080","ja4":null}
```

| 占位符 | 输出 |
| --- | --- |
| 在引号内，如 `"{method} {uri}"` | 转义后的文本：`"` 与 `\` 前加反斜杠，控制字符写作 `\u00XX`，非法 UTF-8 替换为 U+FFFD。没有值时为空 |
| 单独出现的数值标签：`{status}`、`{size}`、`{payload_size}`、`{latency}`、`{when_unix}`，以及上下文键 `connection_id`、`processing`、`upstream_connected`、`upstream_status`、`compression_ratio` 和所有 `_time` 键（毫秒；对应的 `_human` 版本是字符串） | 数字 |
| 单独出现的 `{:upstream_reused}` 或 `{:connection_reused}` | `true` 或 `false` |
| 单独出现的其他标签 | 加引号并转义的字符串 |
| 单独出现且没有值 | `null`；输出的不是数字的数值标签也是 `null`，例如没有上游响应时 `upstream_status` 的 `-` |

字段的类型由标签决定，与值无关，所以同一字段在每一行的类型都相同：名为 `404` 的 location 仍是字符串 `"404"`。与其他格式一样，不是标签的占位符会被丢弃，这会让 JSON 缺少值，请检查标签名。

写入应用日志的 JSON 格式会嵌在应用日志的那一行里（开启 `log_format_json` 时还会被再次转义）；要得到每行一个对象，请给它单独的输出目标。

#### 输出 JA4 指纹

在 TLS server 上开启 `ja4`，并在格式中加入 `{:ja4}`：

```toml
[servers.main]
addr = "0.0.0.0:443"
global_certificates = true
ja4 = true
access_log = "/var/log/pingap/access.log {client_ip} {method} {uri} {status} {latency}ms {:tls_version} {:ja4}"
```

每行末尾就是客户端的指纹：

```text
203.0.113.7 GET /api/items 200 12ms TLSv1.3 t13d1516h2_8daaf6152771_e5627efa2ab1
```

`{:ja4}` 用于分组与匹配。哈希无法反推原始值，如需留存供日后分析，可再加上 `{:ja4_ro}`。没有指纹的连接（明文 HTTP，或 ClientHello 无法读取）该字段为空。同一个值可以通过 `proxy_set_headers = ["X-JA4: $ja4"]` 发给上游，见 [pingap-proxy](proxy.md#ja4-指纹)。

`format` 直接写入一个预估大小的缓冲区：时间戳逐位写出而不经过中间 `String`，每行的开销只剩字段本身。

## 配置

日志器通过 `LoggerParams` 的 `log` 字段中的类 URI 字符串配置。

- **文件日志：** `"/path/to/file.log?rolling=daily&compression=gzip"`
  - `rolling`：`daily`（默认）、`hourly`、`minutely`、`never`，其他值会被拒绝。轮转边界与文件名后缀（`file.log.YYYY-MM-DD[-HH[-MM]]`）使用 **UTC**，不是机器所在时区：UTC+8 的机器上 daily 文件在本地 08:00 切换，本地 18:00 写入的日志落在 `-10` 的小时文件里。这是 `tracing-appender` 的行为，它没有时区选项；日志行内的时间戳仍是本地时间。
  - `compression`：`gzip` 或 `zstd`。
  - `level`：压缩级别。
  - `days_ago`：已轮转文件超过这么多天未被**修改**后压缩（默认 7 天），压缩后删除原文件。
  - `time_point_hour`：运行压缩任务的小时。压缩在阻塞线程池上执行，压大文件不会拖住其他后台任务。
  - `capacity`（`LoggerParams`，pingap 里对应 `basic.log_buffered_size`）：不小于 4096 字节时文件经该大小的缓冲区写入。缓冲日志由 `new_log_flush_service()` 返回的任务（pingap 中每分钟一次）和 `flush_application_log()` 刷盘，后者 pingap 在退出前调用；否则安静的服务器上最后几行会一直留在缓冲区，退出前的几行则会丢失。

  无法解析的参数（`rolling=monthly`、访问日志的 `flush_timeout=soon`、未知的 syslog `facility`）在启动时报错，而不是静默使用默认值。

- **Syslog（仅 Unix）：** `syslog://` URL。每个事件或每行访问日志是一条消息，级别为 info。

  | URL | 服务器 |
  | --- | --- |
  | `syslog://` 或 `syslog:///` | 本机 syslog，依次尝试 `/dev/log`、`/var/run/syslog`、`/var/run/log` |
  | `syslog:///run/rsyslog/dev.sock` | 指定 socket 路径的本机 syslog |
  | `syslog://10.0.0.5` | 经 UDP 的远程服务器，端口 514 |
  | `syslog://logs.example.com:1514?protocol=tcp` | 经 TCP 的远程服务器；IPv6 地址加方括号，如 `syslog://[fd00::5]` |

  - `format`：`3164`（默认）或 `5424`。
  - `process`：syslog 消息中的进程名（默认 `pingap`）。
  - `facility`：syslog facility，如 `LOG_LOCAL0`（默认 `LOG_USER`）。
  - `protocol`：`udp`（默认）或 `tcp`，仅用于远程服务器。

  远程主机名在启动时解析，写错会在启动时报错。UDP 下每条消息是一个数据报，发出后不等待任何回应。TCP 下消息以换行分帧（RFC 6587；消息内部的换行会被替换为空格）。连接在第一条消息时才建立，因此服务器宕机不会阻止 pingap 启动。连接与写入的超时都是一秒；失败后五秒内的消息会被丢弃，之后再重新连接，每次失败都会输出到 stderr。

- **标准 I/O：** `stdout` 或 `stderr`；`""`（空字符串）表示 stderr。

## 基准

本库面向高性能。详细基准结果见源码中的 `benches` 目录。

## 贡献

欢迎贡献！请提交 pull request 或 issue。

## 许可证

本项目采用 Apache-2.0 许可证。
