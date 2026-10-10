# Pingap

Pingap 是一款由 [`Cloudflare Pingora`](https://github.com/cloudflare/pingora) 框架驱动的高性能反向代理。它通过简洁的 TOML 文件和直观的 Web 管理界面，实现了动态、零停机的配置热更新，极大地简化了运维管理。

其核心优势在于强大的插件体系，提供了三十多种开箱即用的插件，涵盖认证 (JWT, Key Auth, OIDC)、安全 (CSRF, IP/Referer/UA 限制)、流量控制 (限流、缓存)、内容修改 (重定向、内容替换) 和可观测性 (请求 ID)。

这使得 Pingap 不仅仅是一个代理，更是一个灵活且可扩展的应用网关，旨在轻松应对从 API 保护到现代化 Web 应用部署的各类复杂场景。


[详细文档](https://pingap.io/zh/) · [English](https://pingap.io/) | [使用示例](./examples/README.md) | [插件](./pingap-plugin/README.md) | [组件](./docs/README.md)


![来自互联网的请求经 Pingap 按域名和路径转发到各组上游服务](./asset/pingap-flow-zh.svg)

## 核心特性

- 🚀 高性能与高可靠性
  - 基于 `Rust` 构建，确保内存安全与顶尖性能。
  - 由 `Cloudflare Pingora` 驱动，一个经过实战考验的异步网络库。
  - 支持 HTTP/1.1、HTTP/2、WebSocket 和 gRPC-web 代理，监听端口支持 PROXY protocol。

- 🔧 动态化与易用性
  - 通过热更新实现零停机的配置变更。
  - 简单且人类可读的 TOML 配置文件（也可以读取 HCL 和 KDL）。
  - 功能齐全的 Web UI，提供直观的实时管理。
  - 同时支持文件和 etcd 作为配置后端。
  - 支持配置变更历史记录功能，可一键恢复到历史版本。

- 🧩 强大的可扩展性
  - 丰富的插件体系，用于处理常见的网关任务。
  - 支持基于主机、路径和正则表达式的高级路由。
  - 内置通过静态列表、DNS（A/AAAA 与 SRV 记录）或 Docker 标签的服务发现机制。
  - 负载均衡支持轮询、最少连接、一致性哈希和会话保持，并带有主动健康检查、重试和熔断。
  - 通过 Let's Encrypt 或其他 ACME CA 实现自动化 HTTPS（支持 HTTP-01 和 DNS-01 两种质询方式），可同时提供 RSA 与 ECDSA 证书，支持 OCSP stapling。

- 📊 现代化的可观测性
  - 原生的 Prometheus 指标监控（支持 pull 和 push 模式）。
  - 集成 OpenTelemetry，支持分布式追踪。
  - 超过 30 种变量的高度可定制的访问日志。
  - JA4 TLS 客户端指纹（访问日志中的 `{:ja4}`、上游请求头中的 `$ja4`），按 TLS 实现区分客户端，OpenSSL 与 rustls 构建均支持。
  - 包含上游连接、处理时间等详细的性能指标。

## 🚀 快速入门

上手 `Pingap` 最简单的方式是使用 `Docker Compose`。

1. 创建一个 `docker-compose.yml` 文件：

```yaml
# docker-compose.yml
services:
  pingap:
    image: vicanso/pingap:latest # 生产环境建议使用具体的版本号，如 vicanso/pingap:0.15.0-full
    container_name: pingap-instance
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      # 挂载本地目录以持久化所有配置和数据
      - ./pingap_data:/opt/pingap
    environment:
      # 使用环境变量进行配置
      - PINGAP_CONF=/opt/pingap/conf
      - PINGAP_ADMIN_ADDR=0.0.0.0:80/pingap
      - PINGAP_ADMIN_USER=pingap
      - PINGAP_ADMIN_PASSWORD=<YourSecurePassword> # 修改此密码！
    command:
      # 启动 pingap 并启用热更新
      - pingap
      - --autoreload
```

2. 创建一个数据目录并运行：

```bash
mkdir pingap_data
docker compose up -d
```

3. 访问管理后台：

您的 Pingap 实例现已运行！您可以使用您设置的凭证，通过 http://localhost/pingap 访问 Web 管理界面。

0.15.0 之后构建的镜像都有对应的 distroless 变体，在标签后加上 `-distroless` 即可，如 `latest-distroless`、`full-distroless`、`rustls-full-distroless`，发布版本则为 `<版本>-distroless` 等。二进制与对应的普通镜像完全相同，只是基础镜像换成了 `gcr.io/distroless/cc-debian13`，其中没有 shell 和包管理器，因此 `command` 必须以 `pingap` 开头（如上例所示）。


### 通过 curl 安装二进制

Linux 与 macOS 用户可以用一条命令将最新的预编译二进制安装到 `/usr/local/bin/pingap`：

```bash
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | sh
```

可选环境变量：

- `PINGAP_FULL=1` —— 安装 `-full` 构建（启用所有可选特性）
- `PINGAP_LIBC=gnu` —— Linux 上使用 glibc 构建（默认是静态链接的 musl 构建）
- `PINGAP_TLS=rustls` —— Linux 上安装 `-rustls-full` 构建（rustls TLS 后端，启用所有可选特性，不含 OpenSSL），见 [TLS 后端](#tls-后端)
- `PINGAP_SERVICE=1` —— 在有 systemd 的 Linux 上同时安装 `pingap` 服务：unit 文件 `/etc/systemd/system/pingap.service`，并在 `/etc/pingap/conf` 为空时放入一份初始的 `basic.toml`。服务不会被启用或启动，因为此时还没有可运行的 server

```bash
# 安装完整特性版本
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | PINGAP_FULL=1 sh

# 同时安装 systemd 服务：先把 server 配置放到 /etc/pingap/conf，再启动
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | PINGAP_SERVICE=1 sh
sudo systemctl enable --now pingap
```

支持的平台：`Linux x86_64/arm64`、`Darwin x86_64/arm64`。所有可用的构建产物见 [releases 页面](https://github.com/vicanso/pingap/releases)。

要了解更多详细说明，包括如何通过二进制文件运行，请查阅我们的[文档](https://pingap.io/zh/)。



### 不写配置文件直接启动代理

一条命令即可把一个域名以 https 对外提供，并转发到后端：

```bash
# 证书向 Let's Encrypt 申请
pingap --domain=pingap.io --upstream=192.168.1.1:3000

# 或使用自己的证书
pingap --domain=pingap.io --upstream=192.168.1.1:3000 --cert=/etc/ssl/pingap.io
```

不带 `--cert` 时，Pingap 通过 HTTP-01 质询向 Let's Encrypt 申请证书，因此 `pingap.io` 必须解析到本机，且 80 端口可从公网访问。签发的证书保存在 `~/.pingap/acme/<domains>.toml`，重启时复用——申请有速率限制，请勿删除。其余一切仍来自命令行：改动 `--upstream` 在下次启动时生效，不影响证书。

`--cert` 接受证书文件本身或其所在目录——常见的 `fullchain.pem` / `privkey.pem`、`cert.pem` / `key.pem` 与 `tls.crt` / `tls.key` 布局会自动识别，其他命名用 `--key` 指定。有证书时监听默认为 `0.0.0.0:443`，既无证书也无域名时为 `0.0.0.0:80`，`--addr` 可覆盖。`--upstream` 为逗号分隔的后端列表，`--domain` 为逗号分隔的主机名（省略则以明文 http 服务所有主机），未列出的主机的请求返回 404。

配置在每次启动时生成，因此不能通过管理界面修改：超出单个 server 的需求请使用 `--conf`，它不能与这些参数同时使用。

## 动态配置

Pingap 的设计旨在无需停机即可适应配置变更。

热更新 (--autoreload)：对于大多数变更——如更新上游服务、路由、插件或证书——Pingap 无需重启即可应用新配置：文件存储在 10 秒内生效，etcd 在变更写入后立即生效。这是容器化环境的推荐模式。

平滑重启 (-a 或 --autorestart)：对于基础性变更（如修改服务器监听端口），此模式会执行一次完整的、零停机的重启，确保不丢失任何请求。

严格模式 (--strict)：Pingap 不认识的键或分段，默认只打一条告警然后忽略。加上 `--strict` 后它是错误：`pingap -t --strict` 会因此失败（建议在 CI 里使用），运行中的 Pingap 也不会接受带有这种键的重载。

检查与预览 (-t、--diff)：`pingap -c conf -t` 会走到启动流程里开始服务之前的那一步，构建每个 upstream、location、插件、证书和 server（包括 TLS 设置），不绑定端口。`pingap -c conf --diff new-conf` 输出用 `new-conf` 替换 `conf` 后会发生的变化，密钥显示为校验值。

从环境变量和文件读取密钥：配置里任何文本值都可以整体写成 `$ENV:NAME` 或 `$FILE:/path`，在加载运行用的配置时被替换；admin、`--to-hcl`、`--sync` 保留原样。详见[配置文档](https://pingap.io/zh/crates/config)。

交接以“就绪”而不是计时为准：新进程以 `-d -u` 拉起，一旦准备好接管监听就通过升级 socket 旁边的一个 unix socket 回报，旧进程此时才向自己发送 SIGQUIT。若新进程退出、其守护进程死亡，或先到了 `basic.restart_ready_timeout`（默认 1m），本次重启作废，旧进程继续服务。新进程在最初那个进程的启动目录下拉起，并带上同样的 `--autoreload` / `--autorestart`，所以相对路径（`--log=logs/pingap.log`、配置里的路径）的含义不变。


## 🔧 开发

```bash
# 需要 bacon：cargo install bacon
make dev
```

`make dev` 以 `full` 特性集构建，用 `~/tmp/pingap` 里的配置并带 `--autoreload` 运行 Pingap，管理界面在 `127.0.0.1:3018`（`pingap` / `123123`），源码有改动时自动重新构建。

管理界面是从 `dist/` 嵌入二进制的。修改 `web/` 下的内容后需要重新构建（需要 Node.js）：

```bash
make build-web
```

提交改动之前：

```bash
make fmt     # cargo fmt
make lint    # typos + clippy（警告视为错误）
make test    # 整个 workspace 的测试
```

### TLS 后端

默认构建使用 OpenSSL 终止 TLS（由 `openssl` crate 从源码编译）。若想改用 rustls（不再从源码编译 OpenSSL；但仍需要 C 编译器，rustls 的密码学库 ring 与 aws-lc-rs 含 C 和汇编代码）：

```bash
cargo build --release --no-default-features --features tls-rustls
# 连同可选特性一起
cargo build --release --no-default-features --features tls-rustls,full
```

rustls 构建会在配置校验阶段（启动、`--test`、auto-restart）拒绝 server 级的 `tls_min_version`、`tls_max_version`、`tls_cipher_list` 与 `tls_ciphersuites`：它固定提供 TLS 1.2 与 1.3，使用 rustls 默认密码套件。Admin UI 在当前二进制为 rustls 构建时会禁用这些字段。其余能力，包括按 SNI 动态选证书、自签名 CA 签发、ACME 与上游 `ca`，行为一致。预构建镜像也提供同一变体：`vicanso/pingap:rustls-full`（发布版本为 `:<版本>-rustls-full`），与 `:latest`、`:full` 并列。校验上游时有一点差异需要知道：rustls（webpki）会拒绝带 `CA:TRUE` 的服务端证书，而 OpenSSL 接受，所以后端若用 `openssl req -x509` 随手生成的自签名证书，需要换成由 CA 签发的叶子证书（或不带 CA 标记的自签名叶子），上游 `ca` 选项才能信任它。`--version` 长格式、启动日志与 Admin 首页都会标明二进制使用的后端。

## 📝 应用配置

```toml
[upstreams.charts]
addrs = ["127.0.0.1:5000"]

[locations.lo]
upstream = "charts"
path = "/"

[servers.test]
addr = "0.0.0.0:6188"
locations = ["lo"]
```

所有的 TOML 配置可以查阅：[https://pingap.io/zh/crates/config](https://pingap.io/zh/crates/config)。


## 🔄 请求处理流程

![请求依次经过 server、location 及其请求插件到达上游服务；响应经响应插件返回并记录日志](./asset/pingap-steps-zh.svg)

1. **server** 接受连接（TLS、HTTP/1.1 或 HTTP/2），并选出主机名和路径最匹配的 **location**。没有任何 location 匹配的请求返回 `404`。
2. location 的**插件**按列出的顺序执行，各自在自己的阶段运行：请求方向是 `early_request`、`request` 或 `proxy_upstream`，响应方向是 `upstream_response` 或 `response`。插件可以直接应答请求——缓存命中、认证失败、重定向、静态文件——这时不会再请求上游。
3. 否则由 location 的 **upstream** 选出一个健康的后端并转发请求。location 配置了 `max_retries` 时，连接失败的请求会换一个后端重试。
4. 响应经响应插件返回客户端，随后**记录**这次请求：访问日志、指标和链路追踪。

## 📊 性能测试

CPU: M4 Pro, Thread: 1

### Ping (无访问日志)

```bash
wrk 'http://127.0.0.1:6118/ping' --latency

Running 10s test @ http://127.0.0.1:6118/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    66.41us   23.67us   1.11ms   76.54%
    Req/Sec    73.99k     2.88k   79.77k    68.81%
  Latency Distribution
     50%   67.00us
     75%   80.00us
     90%   91.00us
     99%  116.00us
  1487330 requests in 10.10s, 194.32MB read
Requests/sec: 147260.15
Transfer/sec:     19.24MB
```




## 📦 最低支持rust版本

最低支持的rust版本为1.96

## 🤝 参与贡献

欢迎提交 pull request。

- 新功能请先提 issue 讨论，再动手写代码。
- 请不要只为修正个别错别字或注释格式而提交 pull request，这类问题会集中处理。
- 提交前请运行 `make fmt`、`make lint` 和 `make test`，CI 会对每个 pull request 执行同样的检查。
- 贡献以[贡献者许可协议](./CLA.md)为前提，在 pull request 模板里勾选对应选项即表示接受：代码仍归你所有，并按项目的开源协议授权给项目使用。

## 📄 开源协议

本项目采用 [Apache License, Version 2.0](./LICENSE) 开源协议。
