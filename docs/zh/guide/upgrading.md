# 升级说明

用新版本替换旧版本、配置保持不变时会发生哪些变化。新增功能见
[更新日志](https://github.com/vicanso/pingap/blob/main/CHANGELOG.md)；这一页只讲可能出问题或让人意外的地方。

## 0.16 之后

已经在 `main` 上、还没有发布的变化。

### 插件

- **`image_optim` 输出的 png 不再是原来的字节。** png 的调色板原来由 `imagequant` 生成，现在由 `color_quant`（NeuQuant）生成，颜色的统计、抖动以及用多少种颜色由 Pingap 自己完成。在用来对比的六张图片上，默认 `png_quality` 下有五张的体积在小 14% 到大 8% 之间，另一张（`imagequant` 只用了 20 种颜色的图标）大了一半；信噪比有五张相差在 2 dB 以内，一张高 4 dB。`png_quality` 的取值范围和方向不变，含义是对调色板误差的限制：见 [image_optim](../plugins/image_optim.md#png)。颜色不超过 256 种的图片在任何取值下都保留全部颜色，而 `imagequant` 在取值较低时会减少颜色。缓存里已有的内容是旧编码器写的，到期之前不会变。
- **`image_optim` 重新编码没有收益时发送原图**：png 仍以 png 返回、jpeg 仍以 jpeg 返回，而结果并不更小的情况。以前会发出重新编码后的结果，比原图还大。

- **`br` 响应现在是完整的 brotli 流。** pingora 0.9.0 压缩的每个流都漏掉了最后一个块，`compression` 的两种模式都受影响：浏览器能正常显示，严格的解码器（Node 的 `fetch`、`brotli -t`）会拒绝（[#256](https://github.com/vicanso/pingap/issues/256)）。上游模式之前存进缓存的仍是不完整的流，直到过期：请 purge。上游模式下，`Content-Length: 0` 的响应也不再在零个字节上标 `Content-Encoding`。

### 许可证

- 所有构建都不再链接 copyleft 许可证的代码。`imagequant`（GPL-3.0-or-later）原来在 `-full`、`-rustls-full` 压缩包以及 `:full`、`:rustls-full` 镜像里；`option-ext`（MPL-2.0，经 `dirs` 引入）原来在每一个构建里。
- 去掉 `dirs` 之后，路径开头的 `~/` 用标准库的 home 目录展开，在 Linux 和 macOS 上与原来相同：`HOME`，没有设置或设置为空时取系统里该用户的记录。

### 通知

- **崩溃后的启动会报出来。** 进程启动时发现上一次运行没有结束——崩溃、panic，或者因内存不足被结束——会以 error 级别写日志，并发出 `Error` 级别的 `abnormal_exit` 通知，管理后台首页也会显示。配置了 `webhook_notifications = ["*"]` 的部署不用改配置就会收到；不想要的话请逐项列出类别。为此进程会在 pid 文件所在目录留下一个小文件 `pingap-<hash>.state`：见[异常退出](../crates/webhook.md#异常退出)。

### 使用这些 crate 的开发者

- **pingap-util**：新增 `home_dir()`，`resolve_path` 展开 `~` 用的就是它。
- **pingap-proxy**：服务器的压缩模块换成了 `pingap_core::ResponseCompression`（它会补全 brotli 流，[#256](https://github.com/vicanso/pingap/issues/256)），不再是 pingora 的。自己写的插件如果要调整压缩，得按这个类型取：`downstream_modules_ctx.get_mut::<pingap_core::ResponseCompression>()`。按 pingora 的 `ResponseCompression` 取会拿到空，插件也就静默地不再调整压缩，不会报错。它 deref 到 pingora 的 `ResponseCompressionCtx`，上面的调用不用改。
- **tokio 低于 1.54**：这里用到 tokio 的 crate 现在都要求 `tokio = ">=1.53.3, <1.54"`。pingora 0.9.0 给每个连接建的缓冲区容量为 0，tokio 1.54 不再接受，第一个连接就会 panic（[cloudflare/pingora#1059](https://github.com/cloudflare/pingora/issues/1059)）。要求 tokio 1.54 及以上的项目，在 pingora 修复之前用不了这些 crate。

## 从 0.15 升级到 0.16

0.16 改动很大，其中很大一部分是“变严格”：0.15 接受了、但实际上没有生效的配置，现在会被拒绝；一些原来相信客户端所发内容的判断，现在不再相信。

### 升级之前

1. **用新版本的二进制对正在使用的配置执行 `pingap -t`**。`-t` 现在会像启动时一样构建每个 upstream、location、插件、证书和 server，所以启动时会报的错它都会报。systemd unit 一直把它作为 `ExecStartPre`：检查变严格之后，0.15 能启动（只是打了一条 error 日志）的配置，现在会让 unit 启动失败。
2. **如果客户端和 Pingap 之间还有别的东西（CDN、负载均衡），配置 `basic.trusted_proxies`**。不配的话，按地址做的规则不再读取 `X-Forwarded-For`，见[客户端地址](#客户端地址)。
3. **缓存会从空开始**：缓存键变了，0.15 存下的内容都找不到。见[缓存](#缓存)。
4. **有按 `502` 告警的吗？** 上游超时现在返回 `504`。
5. 留着旧版本的二进制。`install.sh` 可以用 `PINGAP_VERSION=0.15.0` 安装指定版本，见[回退](#回退)。

### 现在会被拒绝的配置

被拒绝的表现是：启动和 `-t` 报错；重载不生效（保持运行中的配置）；admin 返回 `400`。

| 情况 | 0.15 | 0.16 |
| --- | --- | --- |
| location 引用了不存在的插件、插件的 `category` 不认识、插件构建失败 | 打日志；location 在**没有**这个插件的情况下提供服务 | 启动失败，例如 `plugin(<name>) of location(<location>) is not found` |
| 插件选项的类型不对（`status = "503"`、`max = "100"`、`lock = 2`） | 悄悄用默认值 | `<key> must be an integer, got string "503"` |
| `access_log` 里没有任何请求字段（`access_log = "/var/log/pingap/access.log"`） | 每个请求把这段文字原样打印一次 | 拒绝；写成 `"<路径> combined"` 或带 `{...}` 的格式 |
| upstream 的 `discovery` 不是 `static`、`dns`、`srv`、`docker`、`transparent` 之一 | 当成静态地址 | 拒绝；大写的 `DNS` 现在就是 DNS 发现 |
| `dns`、`srv`、`docker` 发现配了 `update_frequency = "0s"` | 只解析一次，之后不再更新 | 拒绝 |
| `tcp_idle` / `tcp_interval` 小于 1 秒、`tcp_probe_count = 0` | 接受，然后每条连接都失败 | 拒绝 |
| `dns_server` 不是 `ip` 或 `ip:port` | 悄悄丢弃 | 拒绝 |
| `directory` 插件没有 `path` | 以工作目录作为根目录 | 拒绝：`path is required` |
| 在没有 `geo` 特性的构建（发布的二进制都是）里，location 用了 `geo_restriction` | 不做限制地提供服务 | 拒绝 |
| `--admin=user@addr`（没有密码）、格式不对的 `authorizations` 条目 | admin **无认证**运行 | 拒绝 |
| 证书和私钥不配对 | 校验通过 | `-t` 和 admin 保存时拒绝 |
| `log_compress_algorithm` 不是 `gzip` 或 `zstd`、`circuit_break_max_failure_percent` 大于 100、`auto_restart_check_interval` 小于 1 秒 | 接受 | 拒绝 |
| `webhook_type = "ntfy"`，而 `webhook` 不是 topic 的地址（没有路径，或者最后一段不是 ntfy 能接受的 topic 名：`/hook.php`） | 和 0.15 不认识的其他类型一样，向这个地址发通用 JSON | 拒绝：`the url of ntfy names no topic`。想保留通用 JSON 的话，把类型改成别的名字 |

**Pingap 不读取的键**（`trusted_proxy` 这类拼写错误，或从来不存在的键，比如 `basic.cache_directory`、server 上的 `tcp_fast_open`）以前被悄悄丢弃。现在在启动、`-t` 和重载时给出警告：`basic: unknown key "trusted_proxy", did you mean "trusted_proxies"?`。加上 `--strict`（或设置 `PINGAP_STRICT`）之后是错误。插件内部的键不做检查。

**整个值写成 `$ENV:NAME` 或 `$FILE:/path`** 时，现在在所有文本字段里都会被替换成环境变量或文件的内容；0.15 把它们当成字面文本（`dns_service_url` 除外）。变量没有设置、文件读不到都是错误。

### 客户端地址

按客户端地址做判断的规则——`ip_restriction`、按 ip 的 `limit`、`geo_restriction`、`combined_auth` 的 `ip_list`、`basic_auth` 和 admin 的失败锁定、缓存 `PURGE` 的白名单——以前会取任何人发来的 `X-Forwarded-For` 的第一项。客户端想写什么地址都可以。

- **没有配 `basic.trusted_proxies` 时**，现在按连接的对端地址来。如果前面有一层没有列出的代理，这个地址就是代理的地址：白名单要么放行所有人、要么谁都不放行，所有客户端共用一个限流额度，输错几次密码会把所有人都锁住。
- **配了 `basic.trusted_proxies` 时**，客户端是 `X-Forwarded-For` 里从右往左第一个不是可信代理的地址；0.15 取的是最左边那一项，而那一项是客户端自己写的。要把每一跳都列出来：CDN 在负载均衡前面、只列了负载均衡时，客户端地址就是 CDN 的地址。

没有配可信代理时，访问日志的 `{client_ip}`、`hash:ip` 和 `forward_auth` 发出的地址仍然读取任何人发来的 `X-Forwarded-For`。配了 `basic.trusted_proxies` 之后，它们和上面一样取从右往左第一个不是可信代理的地址，而以前取的是最左边那一项。

### 缓存

- **缓存键变了**（键里有了 host，HTTP/1.1 和 HTTP/2 下的键也一致了），所以缓存从空开始。0.15 的文件留在磁盘上，直到被淘汰或清理（`inactive`，默认 48 小时）；想马上腾出空间就清空目录。
- **`PURGE` 按 host 生效**：发给 `127.0.0.1` 的清除请求要带 `-H 'Host: <站点>'`。
- **存什么**：带 `Set-Cookie` 的响应不再存；带 `Authorization` 的请求的响应只有在源站声明 `public`、`s-maxage` 或 `must-revalidate` 时才存；默认的 1 秒有效期只用于默认可缓存的状态码，不再用于 `302`、`401`、`502`。
- **`headers`**（进缓存键的请求头）在生成缓存键时读取，也就是所有 request 插件运行完之后：键里放的是发给上游的内容。别的插件设置的头在键里，被插件删掉的头不在；见 [cache](../plugins/cache.md)。
- 带 `Upgrade` 头的请求（WebSocket 握手）不查缓存，也不保存。
- `eviction = false` 和 `predictor = false` 现在表示关闭；以前只要写了这个键就是开启。

### 路由与请求

- **location 按规范化之后的路径匹配**：解一次百分号编码、处理 `.` 和 `..`、合并 `//`、去掉 `;参数`、把 `\` 当成 `/`。以前换一种写法就会落到兜底 location 的请求，现在会经过它本来所属 location 的插件。按编码后的写法写的正则（`~^/a%20b`）不再匹配。请求仍然按客户端发来的样子转发。
- 请求目标既不是路径也不是 url 时返回 `400`。
- **上游超时返回 `504`**；上游的其他失败仍然是 `502`。
- 低于 `500` 的错误以 `info` 级别记录为 `request refused`，不再以 `error` 级别记录为 `fail to proxy`；错误页不再显示上游地址和错误链。
- 访问日志的 `{status}` 和状态码指标记录的是客户端实际收到的状态：缓存的重新验证不再记成 `304`。
- 重试会换一个后端，不再回到刚刚失败的那个。
- `basic.threads = 0` 表示每个核一个线程，和文档一致；0.15 里它表示一个线程。

### 插件

- **`limit`** 的 rate 模式：`max` 是任意一个 `interval` 内允许的请求数，按滑动窗口计算。0.15 在第一个 `429` 之前会放过大约两倍的请求，而且一直重试的客户端会一直被拒绝。`weight` 不再使用，配了会有警告。
- **`jwt`** 使用 `secret` 时：没有 `exp` 的令牌被拒绝（`401`），`require_exp = false` 恢复原来的行为。上游返回的声明里没有 `exp` 时，`auth_path` 不签发令牌。过期判断现在有 60 秒的 `leeway`。
- **`directory`**：名字以点开头的文件和目录返回 `404`（`hidden = true` 可以放开，`.well-known` 始终可以访问）；`GET`、`HEAD` 之外的方法返回 `405`；目录路径不带结尾的斜杠时重定向。
- **`compression`**：编码按 zstd、brotli、gzip 的顺序选择，和客户端列出的顺序无关；`min_length` 在默认模式下也生效；`text/event-stream`、`Cache-Control: no-transform` 和部分内容（`206`）不压缩。`mode = "upstream"` 时，同一 location 上别的插件要读取响应体的响应也不压缩：[`sub_filter`](../plugins/sub_filter.md) 要改写的内容（按它的 `path` 和 `types`），以及 `jwt` 在 `auth_path` 上要签名的声明。
- **`redirect`**：只有 `http_to_https = true` 才会改变协议。以前 TLS 监听上只配了 `prefix` 的插件会把所有请求重定向到 `http://`。
- **按路径提供的 Prometheus 指标**（`prometheus_metrics = "/metrics"`）：匹配到的 location 的 request 插件会先运行，所以带认证的 location 后面的采集器需要带凭据，或者给这个路径单独配一个 location。
- 应该是列表的选项写成了一个字符串（`ip_list = "1.2.3.4"`）时，按只有一项的列表处理；以前是空列表。

### 健康检查、定时任务、日志

- 以前小于 1 秒的检查周期只会运行一次；现在是 10 秒，也就是定时器的一个节拍（所有周期都向上取整到它的整数倍）。
- `health_check` 的 url 里的 `expect_status`、`check_port`、`expect_body` 现在是检查的设置；0.15 把它们当成查询参数发给后端。
- `tcp_idle`、`tcp_interval`、`tcp_probe_count` 只要配了其中一项就开启 TCP keepalive；0.15 要三项都配（或者配 `tcp_user_timeout`）。
- **ACME**：没有配 `buffer_days` 的证书在到期前 14 天续期（以前是 2 天；最多不超过有效期的三分之一），所以剩余时间不足 14 天的证书会在升级后的第一次检查时全部申请。
- **日志输出位置**：`--log stdout` 和 `access_log = "stdout ..."` 是标准输出（`stderr` 同理）；0.15 会写到名为 `stdout.<日期>` 的文件里。`syslog://<host>` 现在是远程服务器，以前 host 被忽略。
- **压缩后的日志归档**按它包含的文件命名（`access.log.2026-10-05.zst`），而且只压缩和删除这份日志自己滚动出来的文件；0.15 会遍历整个目录。
- 文本格式的访问日志会转义请求所提供内容里的引号、反斜杠和控制字符。不含这些字符的行没有变化。
- **Webhook**：通知的发送方是 `basic.name`。以前不管它设成什么，通知里都写 `pingap`，所以配置里有自己名称的，现在会显示出来：聊天消息的第一行、JSON 里的 `name`。JSON 里还多了 `version` 和 `labels`，聊天消息多了一行 `version`。
- **访问日志**：`{$name}` 是 `basic.name`，`{$label:<键>}` 是这套部署的一个标签。`{$name}` 以前读的是名为 `name` 的环境变量。
- **链路追踪**：资源属性里多了 `service.version`、这套部署的标签，以及 `service.namespace`（设置了 `basic.name` 时）；`OTEL_RESOURCE_ATTRIBUTES` 里已经有的不会被覆盖。
- `basic.name` 只能是一行，最长 64 字节，否则会被拒绝。
- **Webhook**：`webhook_type = "ntfy"` 现在是一个独立的类型，对应 [ntfy](https://ntfy.sh/) 的 topic。0.15 把它和其他不认识的名字一样，当成发往 `webhook` 的通用 JSON POST。碰巧用了这个名字的配置，现在发送的是 ntfy 的 JSON，并且发到去掉最后一段（topic）之后的地址；`webhook` 不是 topic 地址时会被[拒绝](#现在会被拒绝的配置)。

### 重载、重启与配置文件

- 重载要么全部生效，要么全部不生效：先构建 upstream、location 和插件，任何一个失败，这次改动都不应用。
- `-t`、`--to-hcl`、`--to-kdl`、`--sync` 不再改写配置目录的布局；配置加载失败时它们会报错，以前会带着空配置继续执行。
- `--sync` 和 admin 的导入，在目标是 etcd 或带 `?separation` 的目录时，会**删除**目标里有而来源里没有的条目。
- 配置历史每个条目只保留最新的 100 个版本；升级后的第一次保存会删掉更早的。
- 同一个条目在目录的两个文件里都有定义时报错，并指出是哪两个文件。
- `--autoreload` 下，只有重启才能生效的变更（server 的 `addr`、`[basic]` 的大部分键）现在会说出来：日志里一条 warning，外加一条 `reload_config_fail` 通知。以前是不声不响地略过。
- 存储里的配置新增了一个绑不上的监听地址时，重启会被拒绝，运行中的进程继续服务。以前会照常重启，最后没有进程在服务。
- 改了 `basic.upgrade_sock` 要等 pingap 停止再启动之后才生效。重启时沿用正在使用的路径；以前这样的重启会让服务中断。
- **重启需要守护进程**（`-d`，Linux）。在前台运行时（容器、不带 `-d` 的 unit、终端），admin 的重启和 `--autorestart` 以前会把监听套接字交给一个守护进程，然后让原来启动的进程退出：容器在几分钟后结束，接替的进程也一起没了。现在 admin 会拒绝并说明原因；`--autorestart` 和 `--autoreload` 一样只做热更新，并报告哪些变更在等重启。要让这些变更生效，请重启容器或服务。
- 没有 `tracing` 的构建会对 `prometheus_metrics`、`otlp_exporter`、`basic.sentry` 给出 warning，没有 `pyro` 的构建会对 `basic.pyroscope` 给出 warning：这些键在这样的构建里和以前一样不起作用。加了 `--strict` 时它们是错误。前三个请使用 `-full` 构建。

### Admin

- **不带 `/api` 的接口路径**（`/configs/...`、`/basic`、`/restart`）返回 `404`。`GET /api/certificates` 不再返回证书和私钥。
- **没有配凭据的 admin** 会拒绝从本机发来、但 host 不是 `localhost` 或 ip 地址的 API 请求，也会拒绝来自其他站点的写请求。前面有一层本机的反向代理、并且把公网域名作为 host 传过来时，页面能打开，但所有 API 调用都是 `403`：给 admin 配上凭据。
- `--admin` 里的密码会做百分号解码：`p%40ss` 表示 `p@ss`。
- 保存时按 `-t` 的标准校验“保存之后的配置”，失败返回 `400` 和原因（以前返回 `500`，或者存下一份再也加载不了的配置）。先创建 upstream，再创建引用它的 location。
- 新增：只读账号和 API 令牌（`readonly_authorizations`、`tokens`、`readonly_tokens`），每次修改在日志里留一条审计记录。

### Docker、安装包与 systemd unit

- 镜像改为基于 `debian:trixie-slim`（以前是 `ubuntu:24.04`）；entrypoint、命令和路径不变。每个 tag 都有对应的 `-distroless` 版本，里面没有 shell，也没有 entrypoint 脚本。
- `:latest`、`:full`、`:rustls-full` 镜像在该提交的测试通过之后才推送；以前是和测试同时推送的。
- `pingap.service` 由 systemd 自己发 `SIGTERM` 停止。
- `pingap.service` 改为 `Type=forking`（以前是 `Type=simple`，它不适合用 `-d` 启动的守护进程：pid 文件还没写好时，服务可能被当成已经结束）。已经安装的 unit 不会随新的二进制更新：手工改这一行，或者重新安装 unit（`install.sh` 加 `PINGAP_SERVICE=1`），然后执行 `systemctl daemon-reload`。
- 构建需要的 Rust 版本（1.96）和两种 TLS 后端都没有变化。

### 回退

0.15 读取 0.16 的配置时有下面这些差异，它都不会报错：

- 0.16 新增的键被忽略，它们的作用也就没有了。其中有些是保护措施：没有 `tls_client_ca`，监听不再向客户端要证书；没有 `proxy_protocol`，仍在发送这个头的负载均衡器发来的头会被当成格式错误的请求。其余的有 `send_proxy_protocol`、`fail_open`、`client_cert`、location 的超时、`acme_*`、`ocsp_stapling`、`labels`，以及 webhook 的 `webhook_min_level`、`webhook_headers`、`webhook_secret`、`webhook_template`、`webhook_retries`。
- **只配了令牌作为凭据的 admin**（`tokens`，或 `--admin` 上的 `?token=`）会在**没有认证**的情况下运行：0.15 不认识它们。
- 用了 0.16 新增插件（`oidc`、`hmac_auth`、`uri_block`、`maintenance` 等）的 location 会在**没有**这个插件的情况下提供服务。回退前先把这些 location 下线。
- `discovery = "srv"` 被当成静态地址。
- `$ENV:` 和 `$FILE:` 的值被当成字面文本使用。
- `webhook_notifications = ["*"]` 会被当成一个并不存在的类别：不发送任何通知。`webhook_type = "ntfy"` 又变回通用 JSON，直接发到 topic 的地址，订阅者看到的是一段原始 JSON。
- 缓存再次从空开始。

### 使用这些 crate 的开发者

公开的结构体没有标 `#[non_exhaustive]`，所以新增了字段的结构体，用字面量构造的代码会编译不过。除了新增字段之外的变化：

- **pingap-core**：`get_cache_key` 的参数从 `Uri` 改成 `RequestHeader`；`RequestState.guard` 改成 `guards: Vec<Guard>`；`LocationInstance::rewrite` 返回 `pingora::Result<bool>`；`HttpChunkResponse` 多了 `status` 和 `pace`；`get_client_ip` 取从右往左第一个不可信的地址。
- **pingap-upstream**：`PeerAttempt` 多了 `location`。
- **pingap-proxy**：`ServerServices.lb` 是 `Box<dyn ServiceWithDependents>`，用 `add_boxed_service` 添加。
- **pingap-logger**：`AsyncLoggerTask::get_dir()` 去掉了（改用 `get_log_files()`）；`LogCompressParams::new` 的参数是 `Vec<LogFiles>`；`logger_try_init` 返回 `Option<LogFiles>`。
- **pingap-plugin**：`get_*_conf` 这组函数遇到类型不对的值会返回错误，使用它们的自定义插件同样受影响。
- **pingap-health**：`HealthCheckConf` 多了 `expect_status`、`check_port`、`expect_body`；`new_health_check_with_peer` 接收检查从它的 upstream 继承的内容。
