# Pingap

基于 [Cloudflare Pingora](https://github.com/cloudflare/pingora) 的反向代理和应用网关。通过 TOML 文件或内置在二进制里的 Web 管理后台配置，配置变更不需要重启，自带三十多个插件。

[English](./README.md) | [详细文档](https://pingap.io/zh/) · [Documentation](https://pingap.io/) | [使用示例](./examples/README.md) | [插件](./pingap-plugin/README.md) | [组件](./docs/README.md) | [升级说明](https://pingap.io/zh/guide/upgrading)

![来自互联网的请求经 Pingap 按域名和路径转发到各组上游服务](./asset/pingap-flow-zh.svg)

## 特色

- **管理后台内置在二进制里。** 每一项配置都有表单。保存前按 `pingap -t` 的标准校验，可以保留历史版本并恢复，支持只读账号和 API 令牌。
- **变更不停机。** upstream、location、插件和证书在运行中的进程里直接替换（`--autoreload`）。需要重新监听的变更通过交接监听套接字的重启来完成（`--autorestart`，Linux）；新进程起不来时，旧进程继续服务。
- **三十多个插件**，按 location 配置，按列出的顺序执行：认证（JWT、OIDC、Key、Basic、HMAC、forward auth）、访问控制（IP、Referer、User-Agent、路径屏蔽）、流量（限流、限速、缓存、流量镜像、流量切分）、内容（压缩、内容替换、重定向、静态文件、图片优化）、运维（维护模式、健康检查端点、错误页）。[全部插件](./pingap-plugin/README.md)
- **证书自动管理。** Let's Encrypt 或其他 ACME CA，支持 HTTP-01 和 DNS-01（阿里云、Cloudflare、腾讯云、华为云），RSA 与 ECDSA 证书并存，OCSP stapling，面向客户端和面向上游的双向 TLS。
- **配置在生效前检查。** `-t` 会把启动时要构建的东西全部构建一遍，`--strict` 拒绝不认识的键，`--diff` 预览一次变更的影响。支持 TOML、HCL、KDL，存放在文件或 etcd 里，密钥可以取自环境变量或文件。
- **便于观测。** Prometheus 指标（pull 和 push）、OpenTelemetry 链路追踪、三十多个字段的文本或 JSON 访问日志、客户端的 JA4 TLS 指纹。

反向代理该有的其余能力也都有：HTTP/1.1、HTTP/2、WebSocket 和 gRPC-web；按主机名、路径和正则路由；轮询、最少连接、一致性哈希和会话保持，带健康检查、重试和熔断；从 DNS（A/AAAA、SRV）或 Docker 标签发现后端；监听端和上游连接都支持 PROXY protocol；OpenSSL 或 rustls。

指标、链路追踪和图片优化在 `-full` 构建里。

## 🚀 快速入门

### Docker Compose

```yaml
# docker-compose.yml
services:
  pingap:
    image: vicanso/pingap:latest # 生产环境请固定版本：vicanso/pingap:<版本>-full
    container_name: pingap-instance
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      # Pingap 保存的所有内容：配置、证书、缓存
      - ./pingap_data:/opt/pingap
    environment:
      - PINGAP_CONF=/opt/pingap/conf
      - PINGAP_ADMIN_ADDR=0.0.0.0:80/pingap
      - PINGAP_ADMIN_USER=pingap
      - PINGAP_ADMIN_PASSWORD=<YourSecurePassword> # 修改此密码
    command:
      - pingap
      - --autoreload
```

```bash
mkdir pingap_data
docker compose up -d
```

管理后台在 http://localhost/pingap。镜像标签有 `latest`、`full`、`rustls-full`，发布版本为 `<版本>`、`<版本>-full`、`<版本>-rustls-full`。每个标签都有对应的 `-distroless` 版本，里面没有 shell，`command` 必须像上面那样以 `pingap` 开头。

### 二进制

```bash
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | sh
```

把最新版本安装到 `/usr/local/bin/pingap`，支持 Linux 和 macOS（x86_64 与 arm64）。在 `sh` 前面加变量可以选择安装内容：

| 变量 | 作用 |
| --- | --- |
| `PINGAP_FULL=1` | `-full` 构建，包含所有可选特性 |
| `PINGAP_TLS=rustls` | Linux：`-rustls-full` 构建，不含 OpenSSL（见 [TLS 后端](#tls-后端)） |
| `PINGAP_LIBC=gnu` | Linux：glibc 构建，默认是静态链接的 musl 构建 |
| `PINGAP_SERVICE=1` | 有 systemd 的 Linux：同时安装 `pingap` 服务，并在 `/etc/pingap/conf` 放一份初始配置；不会启用或启动服务 |
| `PINGAP_VERSION=0.15.0` | 安装指定版本，而不是最新版本 |

所有构建产物见 [releases 页面](https://github.com/vicanso/pingap/releases)。

### 一条命令启动，不写配置文件

```bash
# 证书向 Let's Encrypt 申请
pingap --domain=pingap.io --upstream=192.168.1.1:3000

# 或使用自己的证书
pingap --domain=pingap.io --upstream=192.168.1.1:3000 --cert=/etc/ssl/pingap.io
```

- 不带 `--cert` 时通过 HTTP-01 申请证书：域名必须解析到本机，且 80 端口可从公网访问。证书保存在 `~/.pingap/acme/<domains>.toml`，下次启动时复用。申请有速率限制，请勿删除。
- `--cert` 可以是证书文件或它所在的目录（自动识别 `fullchain.pem` / `privkey.pem`、`cert.pem` / `key.pem`、`tls.crt` / `tls.key`，其他命名用 `--key` 指定）。`--upstream` 和 `--domain` 是逗号分隔的列表，`--addr` 指定监听地址。
- 配置在每次启动时重新生成，所以不能通过管理后台修改。超过一个 server 的需求请使用 `--conf`，它不能和这些参数同时使用。

## 📝 配置

```toml
[upstreams.api]
addrs = ["api.github.com:443"]
discovery = "dns"
sni = "api.github.com"

[plugins.staticServe]
category = "directory"
path = "~/Downloads"

[locations.github-api]
upstream = "api"
path = "/api"
proxy_set_headers = ["Host:api.github.com"]
rewrite = "^/api/(?<path>.+)$ /$1"

[locations.static]
plugins = ["staticServe"]

[servers.test]
addr = "127.0.0.1:6118"
locations = ["github-api", "static"]
```

同样的配置也可以用 HCL 或 KDL 书写。每个配置项的说明见[配置文档](https://pingap.io/zh/crates/config)。

| | |
| --- | --- |
| `--autoreload` | 变更无需重启即可生效：文件存储在 10 秒内，etcd 立即生效。需要重启的变更会给出提示，并等到重启时生效。容器环境推荐使用 |
| `-a`、`--autorestart` | 同上；热更新改不了的内容（比如监听地址）通过不丢请求的重启来生效 |
| `-t` | 像启动时一样构建每个 upstream、location、插件、证书和 server，但不绑定端口 |
| `--strict` | Pingap 不认识的键、当前构建没有对应 feature 的键是错误，否则只是告警。适合在 CI 里和 `-t` 一起用 |
| `--diff <other>` | 输出用 `<other>` 替换当前配置后会发生的变化，密钥显示为校验值 |
| `$ENV:NAME`、`$FILE:/path` | 作为整个值：加载配置时替换成环境变量或文件的内容 |

## 🔄 请求处理流程

![请求依次经过 server、location 及其请求插件到达上游服务；响应经响应插件返回并记录日志](./asset/pingap-steps-zh.svg)

1. **server** 接受连接，并选出主机名和路径最匹配的 **location**。没有任何 location 匹配的请求返回 `404`。
2. location 的**插件**按列出的顺序执行，各自在自己的阶段运行：请求方向或响应方向。插件可以直接应答请求——缓存命中、认证失败、重定向、静态文件——这时不会再请求上游。
3. 否则由 location 的 **upstream** 选出一个健康的后端并转发请求。配置了 `max_retries` 时，连接失败的请求会换一个后端重试。
4. 响应经响应插件返回客户端，随后**记录**这次请求：访问日志、指标和链路追踪。

## 📊 性能

M4 Pro 单线程下 `/ping` 约每秒 14.7 万个请求，99 分位延迟 116µs（`wrk`，10 个连接，不写访问日志）。

<details>
<summary>测试输出</summary>

```
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

</details>

## 🔧 开发

```bash
make dev         # 需要 bacon：cargo install bacon
make build-web   # 修改 web/ 下的内容之后执行，需要 Node.js
make fmt && make lint && make test
```

`make dev` 以 `full` 特性集构建，用 `~/tmp/pingap` 里的配置并带 `--autoreload` 运行 Pingap，管理后台在 `127.0.0.1:3018`（`pingap` / `123123`），源码有改动时自动重新构建。管理后台是从 `dist/` 嵌入二进制的，`make build-web` 负责生成它。最低支持的 Rust 版本是 1.96。

### TLS 后端

默认构建使用 OpenSSL（从源码编译）。改用 rustls：

```bash
cargo build --release --no-default-features --features tls-rustls,full
```

rustls 构建固定提供 TLS 1.2 和 1.3，使用 rustls 自己的密码套件，所以 server 级的 `tls_min_version`、`tls_max_version`、`tls_cipher_list`、`tls_ciphersuites` 会在检查配置时被拒绝。其余行为一致，差异列在 [certificate 文档](https://pingap.io/zh/crates/certificate)里。`pingap --version` 会标明二进制使用的后端。

## 🤝 参与贡献

欢迎提交 pull request。

- 新功能请先提 issue 讨论，再动手写代码。
- 请不要只为修正个别错别字或注释格式而提交 pull request，这类问题会集中处理。
- 提交前请运行 `make fmt`、`make lint` 和 `make test`，CI 会对每个 pull request 执行同样的检查。
- 贡献以[贡献者许可协议](./CLA.md)为前提，在 pull request 模板里勾选对应选项即表示接受：代码仍归你所有，并按项目的开源协议授权给项目使用。

## 📄 开源协议

[Apache License, Version 2.0](./LICENSE)。
