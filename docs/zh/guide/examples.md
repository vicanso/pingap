# 示例

在仓库根目录执行。已安装的二进制把 `cargo run --` 换成 `pingap`。`-c` 可以是单个 TOML，也可以是含多份 `*.toml` 的目录。

- [static-serve](https://github.com/vicanso/pingap/tree/main/examples/static-serve)
- [api-gateway](https://github.com/vicanso/pingap/tree/main/examples/api-gateway)
- [web-socket](https://github.com/vicanso/pingap/tree/main/examples/web-socket)
- [grpc-web](https://github.com/vicanso/pingap/tree/main/examples/grpc-web)
- [transparent-proxy](https://github.com/vicanso/pingap/tree/main/examples/transparent-proxy)

## static-serve

静态文件，挂了缓存和压缩。配置是目录里的多份 TOML，上游示例是本机 `127.0.0.1:8080`。

```bash
cargo run -- -c=examples/static-serve --admin=127.0.0.1:3018 --autoreload
```

## api-gateway

按路径把请求分到三个上游：`/api/charts/`、`/api/orders/`，其余走公共服务。每个 location 带自己的认证、压缩或缓存插件。

```bash
cargo run -- -c=examples/api-gateway --admin=127.0.0.1:3018 --autoreload
```

## web-socket

`wssUpstream` 用 DNS 发现 `ws.postman-echo.com`，并设置 SNI。`/raw` 转到这条上游，其余转到 `static`（`127.0.0.1:8080`）。服务监听 `127.0.0.1:6118`。

```bash
cargo run -- -c=examples/web-socket --admin=127.0.0.1:3018 --autoreload
```

用客户端连 `ws://127.0.0.1:6118/raw`。

## grpc-web

- 上游是未加密的 gRPC（`127.0.0.1:9090`）
- `[upstreams.grpc-server]` 的 `alpn` 为 `H2`
- `[servers.grpc-web]` 打开 `enabled_h2`，`modules` 含 `grpc-web`
- `[locations.grpc-server]` 打开 `grpc_web`
- `[plugins.grpc-web-static]` 是 `directory`，`path` 写的是 `~/tmp/grpc/commonjs-example`，换成自己的静态文件目录

文件里的开发证书 notAfter 是 2025-12-24。本地再跑时换成自己的证书。

```bash
cargo run -- -c=examples/grpc-web/grpc-web.toml --admin=127.0.0.1:3018
```

## transparent-proxy

- 上游 `discovery` 为 `transparent`，地址写 `127.0.0.1`（只用来占位）
- HTTPS 时 `sni` 为 `$host`
- 证书 `is_default = true`，作为所有域名的默认证书
- 监听 `127.0.0.1:443`

文件里的开发证书 notAfter 同样是 2025-12-24，本地再跑时换成自己的证书。

```bash
sudo cargo run -- -c=examples/transparent-proxy/transparent-proxy.toml --admin=127.0.0.1:3018
```

```bash
curl -kv --resolve '*:443:127.0.0.1' 'https://cn.bing.com/'
```
