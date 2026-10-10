# Pingap Upstream

[![Crates.io](https://img.shields.io/crates/v/pingap-upstream.svg)](https://crates.io/crates/pingap-upstream)
[![License](https://img.shields.io/crates/l/pingap-upstream.svg)](https://github.com/vicanso/pingap/blob/main/LICENSE)
[![Docs.rs](https://docs.rs/pingap-upstream/badge.svg)](https://docs.rs/pingap-upstream)

`pingap-upstream` 是 [Pingap](https://github.com/vicanso/pingap) 中的核心 crate，为后端服务提供稳健、灵活的上游管理。基于 [Pingora](https://github.com/cloudflare/pingora)，处理服务发现、负载均衡与健康检查。

## 核心特性

- **多种负载均衡策略**：按需选择算法。
  - **Round Robin**：在健康后端间均匀分配请求。
  - **最少连接**（`algo = "least_conn"`）：选按权重折算后在途请求最少的后端——权重 2 的后端要拿到权重 1 的两倍才算一样忙。一样忙的后端之间按加权轮询分配，所以不忙的 upstream 表现和 `round_robin` 相同，权重照样起作用。`least_conn` 不带参数。请求从分到后端起计数，到它结束为止（不论怎么结束）；计数是本进程自己的，upstream 重载后从零开始。适合各请求耗时差别很大的场景（长轮询、上传、慢查询）：轮询会给一个被慢请求占住的后端分配和其他后端一样多的新请求。
  - **粘性会话**（`algo = "sticky:<cookie>"`）：客户端一直留在它第一次分到的后端上，靠的是代理自己下发的这个名字的 cookie——不像 `hash:cookie` 那样需要应用来设置。没有这个 cookie 的请求按轮询分配后端，响应里带上 `Set-Cookie: <cookie>=<id>; Path=/; HttpOnly; SameSite=Lax`（https 下加 `Secure`）；带着它的请求去对应的后端。id 是由后端地址算出来的一个数，服务同一个 upstream 的所有实例算出来都一样，但它不是地址本身。cookie 指向的后端不在了、不健康、被熔断器挡住或者刚让这个请求失败时，客户端会被换到另一个后端并拿到新的 cookie：粘性不会让请求失败。开了 `fail_open` 且没有后端能接请求时，客户端留在 cookie 指向的后端上（除非它刚让这个请求失败），而不是每个请求都换一个后端。cookie 加在分配过后端的请求的响应上，所以没有询问上游、直接由缓存应答的响应不会设置 cookie，代理自己的错误页也不会；失败的那次尝试也不会为它的后端设置 cookie。cookie 的属性是固定的：`Path=/` 意味着每个 host 只有一个 cookie，同一个 host 后面有两个 `sticky` upstream 时必须用不同的 cookie 名，否则互相覆盖，客户端会被来回切换；`SameSite=Lax` 使得其他站点从自己的页面发起的请求（跨站 `fetch`、表单提交）不带这个 cookie，这类请求按轮询分配后端。cookie 名称是 `sticky:` 之后的全部内容：只能用字母、数字、`-`、`_`、`.`，后面不能再带参数。`Set-Cookie` 会加在客户端第一个请求拿到的响应上，不管它是什么响应，包括源站标记为任何人都可缓存的：pingap 前面如果还有 CDN 或其他共享缓存，它要么不再缓存这类响应，要么把 cookie 一起存下来发给所有访问者，结果是大家都落到同一个后端。前面有这类缓存时，让它不缓存带 `Set-Cookie` 的响应，或者改用 `hash:ip` / `hash:cookie`。
  - 不健康或被熔断器挡住的后端会被跳过，选择过程会一直进行到所有后端都被检查过：只有全部后端都无法接收请求时才返回 `503`。
  - **重试换后端**：因为后端本身失败而被重试的请求（连接建不起来，配了 location 的 `max_retries`）会发给本次请求刚失败过的后端之外的另一个，各种算法都一样。以前重试和第一次尝试的选法相同：按哈希选时每次都是刚拒绝连接的那个后端。没有别的后端可用时仍会发给失败过的后端，所以只有一个后端的 upstream 照样会重试。只是换一条连接的重试——长连接已被后端关闭、后端正在收回的 HTTP/2 连接——仍然发给原来的后端：它没有问题，按哈希选时客户端本来就该去它那里。
  - **`fail_open`**：配了 `fail_open = true` 时，没有后端可用的请求（全部被健康检查判为不健康，或全部被熔断器挡住）仍然发给其中一个，而不是返回 `503`。用于健康检查可能在后端并没有宕机的情况下同时全部失败的场景（检查依赖的服务出了问题、检查本身配错了）：这时通过一个也许能用的后端提供服务，好过什么都不提供。默认关闭。
  - **Consistent Hashing**：按请求属性哈希到固定后端，提供粘性会话。
  - **Transparent**：无负载均衡的透传代理，转发到原始主机。

- **灵活的一致性哈希键**：一致性哈希时可基于：
  - 客户端 IP
  - URL 路径、查询串或完整 URL（`hash:url` 取路径加查询串，不含协议和域名，所以同一个 URL 在 HTTP/1.1 和 HTTP/2 下选到同一个后端）
  - HTTP 头值
  - Cookie 值

- **动态服务发现**：从不同来源自动发现并更新后端：
  - **Static**：固定后端地址列表。
  - **DNS**：按名字的地址记录（`discovery = "dns"`），或者按它的 SRV 记录（`discovery = "srv"`，记录同时给出端口和权重）。
  - **Docker**：从 Docker 容器标签发现。

- **主动健康检查**：周期性探测后端；不健康后端会自动、临时地从负载均衡池移除。
  - pingora 让每个后端一开始都是健康的，且无法修改，因此 upstream 的**第一轮检查是决定性的**：无论 `failure` 设为多少，失败一次即标记不健康。某一轮检查过至少一个后端之后，恢复按 `failure` 判定。成功不受影响，因为通过第一次检查的后端本来就是健康的。
  - 配置变更新增或修改 upstream 时，第一轮检查在 pingap 切换到它**之前**执行，挂掉的后端从第一个请求起就不在池中。此前它照样会上线：一次失败只让计数到默认阈值 2 中的 1。
  - 启动时，第一轮检查在后台健康检查启动后立即执行，与最初的请求同时进行；完成之前，所有后端仍视为健康。
  - 没有任何后端可检查的一轮（服务发现尚未找到后端）不算第一轮。

- **高级配置**：
  - **TLS & SNI**：可配置 TLS 与 SNI 的安全后端连接。可为单个上游指定私有 CA（`ca`，支持 PEM 文件路径、base64 或原始 PEM）替代系统信任库，使自签名或内部 PKI 的后端也能保持 `verify_cert` 开启；连接池同时按该 CA 分组，不同 CA 的上游不会复用同一条连接。`sni = "$host"` 用客户端请求代理时的域名作为向后端发起握手的名字，任何上游都适用（以前只对透明上游有效，其他上游发出去的是 `$host` 这串字）：一个上游可以对应多个域名，各自的证书按各自的名字校验。有自己后端的上游，名字取请求的 host，转成小写、不带端口；给不出名字的请求（没有 `Host`，或者是 IP 地址）直接返回 `503`，不会发起一个不带名字的握手——那样的握手 OpenSSL 是不校验证书的。（透明上游连的就是这个 host，名字按请求里的原样，和以前一样。）名字由客户端决定，也就决定了后端的哪张证书会被接受：请只在限定了 host 的 location（`host = "a.example.com,b.example.com"`）上使用这样的上游。rustls 后端下，后端自身的证书必须是真正的叶子证书（不能带 `CA:TRUE`），这是 webpki 的要求，OpenSSL 则不检查。
  - **双向 TLS**：`client_cert` 和 `client_key`（各自可以是 PEM 文件路径、base64 或原始 PEM；证书在前，其后是通往 CA 的中间证书）会出示给要求客户端证书的后端。两者在构建上游时读取，所以私钥和证书不配对是 `pingap -t` 和重载时的错误，而不是每个请求握手失败；没有配 `sni` 的上游配了 `client_cert` 同样报错，因为它不建立 TLS 连接，证书无处出示。文件路径也是在这时读取的：证书文件更新后需要重载这个上游。连接池按证书区分，证书不同的两个上游不会复用同一条连接；`https://` 健康检查同样会出示它，否则这类后端会拒绝检查、永远不健康。`grpc` 和 `wss` 的检查不会出示。
  - **HTTP/2 & ALPN**：支持 ALPN 协商 HTTP/1.1 或 HTTP/2，并可按上游设置流控窗口（`h2_stream_window_size`、`h2_connection_window_size`），适合高延迟链路上的大响应。
  - **连接超时**：连接、读、写与空闲超时的细粒度控制。
  - **TCP 控制**：TCP keepalive、缓冲区大小与 TCP Fast Open 等高级选项。`tcp_idle`、`tcp_interval`、`tcp_probe_count`、`tcp_user_timeout`（仅 Linux）只要配置了其中一项就开启 keepalive，没有配置的项取内核默认值（7200s、75s、探测 9 次），所以 `tcp_user_timeout` 可以单独使用。空闲时间和间隔至少 `1s`，探测次数在 1 到 16 之间。
  - **请求头策略**：默认按 RFC 9110 的要求，在请求到达后端前剥离 hop-by-hop 头与 `Connection` 提名的头，且只转发 WebSocket 升级。每条规则都可按上游单独放宽（`strip_hop_by_hop`、`strip_connection_nominated`、`reject_malformed_connection_nominations`、`h1_upgrade`），供仍依赖旧透传行为的后端使用，例如 Docker `attach`/`exec` 或 h2c 升级。
  - **向后端发送 PROXY protocol**：`send_proxy_protocol = "v1"`（一行文本）或 `"v2"`（二进制）让发往后端的每条连接都以 PROXY protocol 头开始，说明这条连接是替哪个客户端建立的：客户端从哪里来，连到了本代理的哪个地址。用于会读这个头的后端（nginx 的 `listen 8080 proxy_protocol;`、HAProxy 的 `bind ... accept-proxy`、另一个开了 `proxy_protocol = true` 的 pingap），它们从连接本身得到客户端地址，不需要信任 `X-Forwarded-For`。不读这个头的后端会把它当成格式错误的请求，所以两边要么都开，要么都不开。不配置则不发送。
    - 头在连接上所有内容之前，包括配了 `sni` 的上游的 TLS 握手；HTTP/1.1 和 HTTP/2 的后端都会发送。
    - 源地址是请求所在连接的对端地址，也就是 `$remote_addr`，不会取 `X-Forwarded-For` 或 `X-Real-IP` 里的地址：前面有 CDN 时，后端得到的是 CDN 的地址。在开了 `proxy_protocol = true` 的 server 上，它是负载均衡器在头里给出的地址，所以客户端地址可以经过两层一路传下去。目的地址是连接到达的本代理地址，不是 server 读到的头里的目的地址。
    - 一个 pingap 接在另一个后面时：接收的一方（`proxy_protocol = true`）要把发送方的地址写进自己的 `basic.trusted_proxies`，否则它会把这个头当成格式错误的请求：返回 `400`，在 TLS 监听上则是握手失败。
    - 一条连接只在开头说明一次它属于谁。因此保持的连接只会复用给同一条客户端连接上的请求，不会交给别的客户端；到后端的 HTTP/2 连接上的各个流也都属于同一条客户端连接。客户端断开之后，它还会在连接池里停留 `idle_timeout`（默认 60s），期间占用 `basic.upstream_keepalive_pool_size` 的名额。这个连接池是一个 server 的所有上游共用的，池满之后再放入连接会挤掉等待最久的那条，不管它属于哪个上游：客户端短连接很多时，把这类上游的 `idle_timeout` 调小，或者调大连接池。
    - `alpn = "h2h1"` 时，如果后端先同意 HTTP/2、之后又要求改用 HTTP/1.1，这个情况在其他上游上是按后端记住的，在这类上游上每条客户端连接都要重新发现一次。把 `alpn` 设成后端实际支持的协议。
    - 该上游的健康检查同样发送这个头，但不带客户端信息（`LOCAL` 或 `UNKNOWN`），否则后端会把每次检查都当成错误的客户端。带 `check_port` 的 HTTP 检查不发送：在另一个端口上应答的不是这个服务本身。
    - `connection_timeout`（上游的，或者 location 自己设置的那个）覆盖建立连接和发送头的时间；`tcp_recv_buf`、`tcp_fast_open` 和 keepalive 设置照常生效。

- **熔断**：开启 `enable_backend_stats` 后统计每个后端的响应（`backend_failure_status_code` 决定哪些状态码算失败，默认所有 5xx；连接不上的请求总是算失败）。`circuit_break_max_consecutive_failures` 与 `circuit_break_max_failure_percent`（后者要在统计窗口内累计到 `circuit_break_min_requests_threshold` 个请求后才生效；两者填 `0` 即关闭该规则）任一触发即熔断。统计窗口是最近一个 `backend_stats_interval`（不能小于 `1ms`），按滑动窗口估算：当前周期内的请求，加上上一个周期里仍落在窗口内的那部分（按比例折算）。所以规则对正在发生的失败立即起作用（以前只读上一个已结束的周期，熔断最多晚一个周期才触发，第一个周期内永远不触发），后端恢复之后，等坏的那个周期移出窗口，一次失败也不会再把它重新打开。触发后：后端进入**打开**状态，在 `circuit_break_open_duration` 内被跳过，之后进入**半开**，最多放行 `circuit_break_half_open_consecutive_success_threshold` 个探测请求；连续成功这么多次则关闭熔断，失败一次则重新打开。后端接受了连接却没有给出响应的请求（读超时、响应前连接被关闭）和连接被拒绝一样算作失败；连接池里已经被后端关闭的旧连接不算。探测请求如果一直没有报告结果（例如客户端先断开了），再过一个 `circuit_break_open_duration` 就放弃它们并开始新一轮探测，后端不会一直停在半开状态。状态通过 `pingap_upstream_backend_circuit_state` 导出（0 关闭、1 打开、2 半开）。

- **运行时管理**：
  - 可在运行时动态增删改上游，无服务中断。
  - 暴露健康与连接指标，便于监控与可观测。
  - `algo`（`round_robin`、`least_conn`、`sticky:<cookie>`，或 `hash`、`hash:<ip|url|path|header|cookie|query>[:<key>]`）与 `alpn`（`h1`、`h2`、`h2h1`）在构建上游时校验，未知值报错而不是静默用默认值。

## 核心概念

### `Upstream`

`Upstream` 是中心组件，表示一组逻辑后端服务器。封装该组的负载均衡、健康检查、TLS、超时与服务发现配置。

### `SelectionLb`

表示 `Upstream` 配置的负载均衡策略：
- `RoundRobin(LoadBalancer<RoundRobin>)`
- `Consistent { lb: LoadBalancer<Consistent>, hash: HashStrategy }`
- `Transparent`

透明上游按每个请求的 authority（HTTP/2 的 `:authority`，HTTP/1 的 `Host` 头）构建 peer。其中的端口会被采用（`Host: backend:8080` 连到 8080；没有端口时按 `sni` 取 80 或 443），主机名异步解析（IP 字面量不需要查询；`ipv4_only` 会像其他发现方式一样只取名字的 IPv4 地址），解析不到的主机对该请求返回 `503`，而不是在 peer 构造函数里解析失败——那以前会直接 panic。

`HealthCheckTask` 每次后端刷新与健康检查以 `debug` 级别记录；只有失败才是 `error`。

### `HealthCheckTask`

对所有已配置上游周期运行的后台服务。负责：
1. 触发服务发现更新（如重新解析 DNS）。
2. 对每个后端执行健康检查。
3. 上游健康状态变化时发送通知（如全部后端不健康）。

## 用法

本 crate 主要在 `pingap` 代理应用中使用。一般流程：

1. 定义上游配置（例如 YAML 文件）。
2. `pingap` 应用解析为 `UpstreamConf` 结构体。
3. 为每个配置创建 `Upstream` 实例。
4. 启动 `HealthCheckTask` 监控所有上游。
5. 请求到达时，代理选择合适的 `Upstream` 并调用 `new_http_peer()` 获取健康、已配置的后端连接。

### 概念代码示例

```rust
use pingap_upstream::{Upstream, UpstreamConf};
use std::sync::Arc;
use std::collections::HashMap;

fn main() {
    // Configuration would typically be loaded from a file
    let mut conf = UpstreamConf::default();
    conf.addrs = vec!["127.0.0.1:8080".to_string()];
    conf.algo = Some("round_robin".to_string());

    // Create a new Upstream
    let upstream = Upstream::new("my_service", &conf, None).unwrap();
    let upstream = Arc::new(upstream);

    // In a request handling context, a peer would be created.
    // This is a simplified representation.
    // let http_peer = upstream.new_http_peer(&session, &mut client_ip, true).await;
    
    println!("Upstream '{}' created successfully.", upstream.name);
}
```

## 许可证

本项目采用 [Apache-2.0 许可证](https://github.com/vicanso/pingap/blob/main/LICENSE)。
