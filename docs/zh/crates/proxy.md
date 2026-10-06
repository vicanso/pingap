# Pingap Proxy

[Pingap](https://github.com/vicanso/pingap) 的 HTTP 代理引擎。本 crate 实现 pingora 的 `ProxyHttp` trait，是路由、插件分发、上游选择、缓存、追踪与访问日志真正接线的地方。其他 `pingap-*` crate 都汇入此处；`pingap` 二进制是构建配置并交给本 crate 的薄壳。

## 职责

- 把 `PingapConfig` 变成具体监听器（`ServerConf`），含 TLS 参数、HTTP/2、TCP keepalive、`SO_REUSEPORT` 与 TCP Fast Open。
- 将每个请求匹配到 `Location`，再经其匹配到 `Upstream`。
- 在正确的生命周期步骤运行插件并尊重其决策。
- 拥有每请求 `Ctx`：时序、连接细节、上游状态、缓存状态与日志变量。
- 产出访问日志、`Server-Timing` 头、Prometheus 指标与 OpenTelemetry span。
- 用可配置 HTML 模板渲染错误页。

## 请求生命周期

`server.rs` 将 pingora 回调映射到 Pingap 的 `PluginStep`：

```
                  ┌──────────────────────────────────────────┐
   client ───────▶│ early_request_filter                     │  PluginStep::EarlyRequest
                  ├──────────────────────────────────────────┤
                  │ request_filter        (location matched) │  PluginStep::Request
                  ├──────────────────────────────────────────┤
                  │ proxy_upstream_filter                    │  PluginStep::ProxyUpstream
                  ├──────────────────────────────────────────┤
                  │ upstream_peer         (backend selected) │
                  │ upstream_request_filter                  │
                  ├──────────────────────────────────────────┤
                  │ upstream_response_filter                 │  PluginStep::UpstreamResponse
                  ├──────────────────────────────────────────┤
                  │ response_filter / response_body_filter   │  PluginStep::Response
                  ├──────────────────────────────────────────┤
   client ◀───────│ logging                                  │
                  └──────────────────────────────────────────┘
```

不是插件步骤但运维上重要的额外钩子：

| Callback | Role |
| --- | --- |
| `upstream_peer` | 选择后端并应用 location 的重试预算（`max_retries`、`max_retry_window`） |
| `connected_to_upstream` | 记录复用、TCP 连接与 TLS 握手时序 |
| `request_body_filter` | 强制 location 的 `client_max_body_size`。`101` 之后客户端发来的是隧道数据而不是请求体，不受这个上限约束：WebSocket 可以发送任意多的数据 |
| `fail_to_proxy` | 对失败分类，并用配置的模板渲染错误页（见[错误响应](#错误响应)） |

插件在请求的**恰好一个**步骤运行。配置插件未实现的步骤是静默空操作——见 [pingap-plugin](../plugins/#生命周期步骤)。

在 `EarlyRequest` 步骤直接应答的插件会在此结束请求。pingora 只允许请求在 `request_filter` 处停止，因此该步骤会识别已经发出的响应，后续步骤不会再叠加执行。

在任何读取发生之前，`early_request_filter` 会把请求的多个 `Cookie` 头合并成一个。HTTP/2 允许客户端把 Cookie 拆成多个头字段发送（RFC 9113 8.2.3），只看第一个字段的读取方（`cookie` 方式的 `jwt`、`csrf`、粘性 Cookie、`match_cookies`、访问日志的 `{~name}`）会漏掉其余的。转发给上游的也是合并后的单个字段。

`X-Request-Id`（以及 tracing 特性的 `X-Trace-Id` / `X-Span-Id`）在 `response_filter` 里写到发给客户端的响应上，不属于缓存保存的内容，所以命中缓存的响应带的是当前请求的 ID。

插件直接返回的响应，如果按定义没有响应体（`HEAD`、`204`、`304`），写完响应头就结束。后两个状态码也不会带自动生成的 `Content-Length`。

`$proxy_add_x_forwarded_for`（`enable_reverse_proxy_headers` 设置的也是它）是请求里所有 `X-Forwarded-For` 行按顺序拼接，再加上对端地址。前置代理把自己的条目单独写成一行，与追加到已有行的效果相同。

上游的中间响应（如 `103 Early Hints`）会原样转发给客户端。响应阶段的插件、访问日志与指标里的状态码、上游耗时都以最终响应为准；`101` 视为最终响应，因为它结束了 HTTP 交互。

## 路由

挂到 server 的 location 按权重降序排序一次，主机、路径与匹配条件全部成立的第一个获胜。权重为 `LocationConf` 中显式 `weight` 或推导值：

| Component | Weight |
| --- | --- |
| 精确路径（`=/api`） | 1024 |
| 前缀路径（`/api`） | 512 |
| 正则路径（`~^/api`） | 256 |
| 路径长度 | + 最多 64 |
| 精确主机 | + 128 |
| 正则主机 | + 主机字符串长度 |

因此 `=/api/health` 胜过 `/api` 胜过 `~^/api/.*`，带主机限定的 location 胜过其他相同但不带主机的。

无匹配时请求以 `404` 结束，错误信息为 `No matching location, host:<host>`。

匹配到的 location 只有在通过 `client_max_body_size` 检查之后才把请求计入 `max_processing` 限制，计入的每个请求在结束时都会扣回（`429` 也一样）；被 `413` 拒绝的请求不会触碰计数。

## 错误响应

`fail_to_proxy` 把 pingora 错误转成状态码，并在客户端仍在时用错误模板渲染页面：

| 失败 | 状态码 | 是否写页面 |
| --- | --- | --- |
| location 或插件以某状态码拒绝请求 | 该状态码 | 是 |
| 上游连接、读或写失败 | 502 | 是 |
| 下游读超时（`downstream_read_timeout`） | 408 | 是 |
| 请求头格式错误 | 400 | 是 |
| 客户端关闭连接、socket 读写失败或写超时 | 499 | 否 |
| 其他 | 500 | 是 |

`499` 是 nginx 表示客户端已离开的状态码。它会记录到访问日志与指标中，但不会向已断开或卡住的连接写任何内容，事件以 `info` 而非 `error` 级别记录，因为服务端无需修复什么。一旦最终响应头已发出，之后的失败（例如上游在响应体中途断开）保留客户端实际看到的状态码，且不会向响应体追加任何内容，与 pingora 自身错误响应的规则一致。

`HEAD` 请求只收到错误页的响应头（含 `Content-Length`），不带响应体。

每次失败只由 pingap 记录一条日志，包含客户端地址、方法、主机与路径、pingora 错误类型和状态码；pingora 对同一错误的日志被抑制。pingap 自身产生的状态码对应的响应头只构建一次然后克隆。

## Server 配置

```toml
[servers.main]
addr = "0.0.0.0:443,[::]:443"
locations = ["api", "web"]
threads = 4
global_certificates = true
ja4 = true
enabled_h2 = true
access_log = "combined"
enable_server_timing = true
tls_min_version = "tlsv1.2"
tls_max_version = "tlsv1.3"
tls_cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
tls_ciphersuites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
prometheus_metrics = "/metrics"
otlp_exporter = "http://otel-collector:4317/pingap"
reuse_port = true
tcp_fastopen = 4096
tcp_idle = "2m"
tcp_interval = "1m"
tcp_probe_count = 9
downstream_read_timeout = "30s"
downstream_write_timeout = "30s"
modules = ["grpc-web"]
```

部分说明：

- `addr` 可接受逗号分隔的多个监听地址，对应一个逻辑 server。
- `tcp_idle`、`tcp_interval`、`tcp_probe_count`、`tcp_user_timeout`（仅 Linux）四项只要配置了其中一项，就会对接入的连接开启 TCP keepalive。没有配置的项取内核默认值（空闲 7200s、探测间隔 75s、探测 9 次），所以 `tcp_user_timeout` 可以单独设置。空闲时间和间隔按整秒生效，至少 `1s`；探测次数至少为 1。更小的值在配置校验时被拒绝，因为内核会在每个连接上拒绝它们。
- `global_certificates = true` 用 [pingap-certificate](certificate.md) 的动态 SNI 证书存储把监听器切到 TLS。否则为明文 HTTP，此时 `enabled_h2` 表示 h2c。
- `tls_min_version` / `tls_max_version` / `tls_cipher_list` / `tls_ciphersuites` 仅在 **OpenSSL** 构建下生效。版本名接受 `tlsv1.1` / `tlsv1.2` / `tlsv1.3`（大小写不敏感，`TLSv1.2` 亦可）。`tls-rustls` 构建固定提供 TLS 1.2/1.3 与 rustls 默认密码套件；配置了这些字段会在启动 / `--test` / auto-restart 的配置校验阶段失败（见 [pingap-certificate](certificate.md)）。Admin UI 在 rustls 二进制上会禁用对应表单项。
- `h2_max_concurrent_streams`、`h2_max_header_list_size`、`h2_initial_window_size`、`h2_initial_connection_window_size` 与 `h2_idle_timeout` 调整监听器面向客户端的 HTTP/2 SETTINGS。不设置即沿用 pingora 的有界默认值（100 个并发流、64 KiB 请求头列表），它们限制单个客户端连接能占用的内存；gRPC 汇聚或大请求头的场景应有意识地调高，而不是去掉上限。
- `ja4 = true` 为每个客户端计算 JA4 TLS 指纹，见 [JA4 指纹](#ja4-指纹)。需要 `global_certificates = true`，配置校验会检查。
- `prometheus_metrics` 在本 server 上暴露 pull 端点；URL 值则配置 push 模式。
- `enable_server_timing` 添加由请求时序分解构建的 `Server-Timing` 响应头——便于诊断延迟来源。
- `error_template`（在 `[basic]` 下）替换内置 `error.html`。模板在 server 启动时解析一次，每次出错填入三个占位符：

  ```text
  {{version}}     pingap 版本
  {{error_type}}  pingora 的错误类型，同时作为 X-Pingap-EType 响应头发送
  {{content}}     给客户端的说明
  ```

  其他双花括号名称按字面文本保留；首字符为 `{` 的模板按 `application/json` 返回。

  `{{content}}` 只包含可以让客户端知道的内容。pingap 或插件主动返回的 `4xx`，内容是原因：哪个路由没有匹配、超过了哪项限制。其他情况（上游失败或 `5xx`）只给出状态码对应的文本，例如 `Bad Gateway`：错误本身带有上游地址等内部信息，只写入日志，不出现在页面上。各个值会按页面类型转义（HTML，或 JSON 字符串内部），因为原因里可能引用请求的 host 与路径。

## JA4 指纹

在 TLS server 上设置 `ja4 = true`，pingap 会根据客户端的 ClientHello 计算 [JA4](https://github.com/FoxIO-LLC/ja4) 指纹。指纹识别的是客户端的 TLS 实现，不受它声称的 `User-Agent` 影响：

```toml
[servers.main]
addr = "0.0.0.0:443"
global_certificates = true
ja4 = true
access_log = "{client_ip} {status} {:ja4}"

[locations.api]
upstream = "api"
proxy_set_headers = ["X-JA4: $ja4"]
```

| 位置 | 名称 | 值 |
| --- | --- | --- |
| 请求头与响应头 | `$ja4`（或 `:ja4`） | `JA4`，如 `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| 访问日志 | `{:ja4}` | `JA4` |
| 访问日志 | `{:ja4_r}` | `JA4_r`：排序后的列表本身而非哈希 |
| 访问日志 | `{:ja4_o}` | `JA4_o`：按客户端发送顺序的列表计算哈希 |
| 访问日志 | `{:ja4_ro}` | `JA4_ro`：按发送顺序的列表，不做哈希 |

实现说明：

- 按 FoxIO 的 JA4 规范实现（TLS 客户端指纹，BSD 3-Clause 许可）。规范自带的样例就是四种形式的单元测试。JA4+ 的其他指纹未实现。
- ClientHello 在 TLS 握手之前从 TCP 流读取，这段代码由 pingora 的各个 TLS 后端共用，因此 OpenSSL 与 rustls 构建对同一客户端算出的值相同。读取的每个字节都会放回给握手使用。
- 除了读取握手本来就需要的 ClientHello，不会延迟或拒绝任何连接。5 秒内没有发完 ClientHello、超过 16 KiB 或格式错误的客户端只是没有指纹；明文 HTTP 连接永远没有指纹。没有指纹时访问日志字段为空，用 `$ja4` 设置的请求头会回退为字面文本，与其他无法解析的变量一致。
- 被拆进多个 TLS 记录的 ClientHello 会先重组。使用 Encrypted Client Hello 时，线路上的是外层 ClientHello，指纹也按它计算。
- 指纹属于连接：keep-alive 或 HTTP/2 连接上的每个请求都带有它，连接关闭时释放。
- 开销是每个新 TLS 连接一次 ClientHello 解析和两次 SHA-256，外加每个请求一次查表。默认关闭。

## 每请求上下文

`Ctx` 携带请求累积的一切，是访问日志变量与 `$` 替换的读取源。记录的时序包括上游 TCP 连接、TLS 握手、上游处理与响应、缓存查找与锁、压缩与总服务时间。见 [pingap-core](core.md) 与 [pingap-logger](logger.md) 中的访问日志标签表。

## Features

| Feature | Effect |
| --- | --- |
| `openssl`（默认） | 经 pingora OpenSSL 终止下游 TLS；生效 server 级版本/密码套件 |
| `tls-rustls` | 经 pingora rustls 终止下游 TLS；上述 `tls_*` 字段在配置校验时拒绝 |
| `tracing` | 启用 `tracing.rs` 中的 OpenTelemetry span 集成与缓存指标 |

## 许可证

Apache-2.0。
