# Pingap

A reverse proxy and application gateway built on [Cloudflare Pingora](https://github.com/cloudflare/pingora). It is configured through TOML files or a web admin that is part of the binary, takes changes without a restart, and comes with more than thirty plugins.

[中文说明](./README_zh.md) | [Documentation](https://pingap.io/) · [中文文档](https://pingap.io/zh/) | [Examples](./examples/README.md) | [Plugins](./pingap-plugin/README.md) | [Crates](./docs/README.md) | [Upgrading](https://pingap.io/guide/upgrading)

![Requests from the internet pass through Pingap, which routes them by host and path to groups of upstream servers](./asset/pingap-flow.svg)

## What sets it apart

- **A web admin in the binary.** Every setting has a form. A change is checked the way `pingap -t` checks it before it is stored, earlier versions can be kept and restored, and there are read-only accounts and API tokens.
- **Changes without downtime.** Upstreams, locations, plugins and certificates are replaced in the running process (`--autoreload`). What needs new listeners is applied by a restart that hands the sockets over (`--autorestart`, Linux), and the running process keeps serving if its replacement does not come up.
- **Over thirty plugins**, per location and in the order you list them: authentication (JWT, OIDC, key, basic, HMAC, forward auth), access rules (IP, referer, user agent, blocked paths), traffic (rate and bandwidth limits, cache, mirroring, traffic splitting), content (compression, body substitution, redirects, static files, image optimisation) and operations (maintenance mode, health endpoint, error pages). [All plugins](./pingap-plugin/README.md)
- **Certificates without a cron job.** Let's Encrypt or any other ACME CA, by HTTP-01 or DNS-01 (Alibaba Cloud, Cloudflare, Tencent Cloud, Huawei Cloud), RSA and ECDSA side by side, OCSP stapling, and mutual TLS towards clients and towards upstreams.
- **Configuration that is checked before it runs.** `-t` builds everything a start would, `--strict` refuses keys it does not know, `--diff` shows what a change would do. TOML, HCL or KDL, in files or in etcd, with secrets taken from the environment or from files.
- **Made to be watched.** Prometheus metrics (pull and push), OpenTelemetry traces, access logs as text or JSON with more than thirty fields, and JA4 TLS fingerprints of the clients.

The rest of what a reverse proxy does is there too: HTTP/1.1, HTTP/2, WebSocket and gRPC-web; routing by host, path and regular expression; round robin, least connections, consistent hashing and sticky sessions, with health checks, retries and a circuit breaker; backends from DNS (A/AAAA, SRV) or Docker labels; the PROXY protocol on listeners and towards upstreams; OpenSSL or rustls.

Metrics, tracing and image optimisation are in the `-full` builds.

## 🚀 Getting Started

### Docker Compose

```yaml
# docker-compose.yml
services:
  pingap:
    image: vicanso/pingap:latest # for production, pin a release: vicanso/pingap:<version>-full
    container_name: pingap-instance
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      # everything Pingap keeps: configuration, certificates, cache
      - ./pingap_data:/opt/pingap
    environment:
      - PINGAP_CONF=/opt/pingap/conf
      - PINGAP_ADMIN_ADDR=0.0.0.0:80/pingap
      - PINGAP_ADMIN_USER=pingap
      - PINGAP_ADMIN_PASSWORD=<YourSecurePassword> # change this
    command:
      - pingap
      - --autoreload
```

```bash
mkdir pingap_data
docker compose up -d
```

The admin is at http://localhost/pingap. Images are tagged `latest`, `full` and `rustls-full`, and `<version>`, `<version>-full`, `<version>-rustls-full` for a release. Each also has a `-distroless` twin without a shell, where `command` has to start with `pingap` as it does above.

### Binary

```bash
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | sh
```

installs the latest release to `/usr/local/bin/pingap` on Linux and macOS (x86_64 and arm64). Variables in front of `sh` choose what is installed:

| Variable | Effect |
| --- | --- |
| `PINGAP_FULL=1` | The `-full` build, with every optional feature |
| `PINGAP_TLS=rustls` | Linux: the `-rustls-full` build, without OpenSSL (see [TLS backend](#tls-backend)) |
| `PINGAP_LIBC=gnu` | Linux: the glibc build in place of the static musl one |
| `PINGAP_SERVICE=1` | Linux with systemd: also the `pingap` service and a starter configuration in `/etc/pingap/conf`; it is not enabled or started |
| `PINGAP_VERSION=0.15.0` | That release in place of the latest |

All assets are on the [releases page](https://github.com/vicanso/pingap/releases).

### One command, no configuration file

```bash
# the certificate comes from Let's Encrypt
pingap --domain=pingap.io --upstream=192.168.1.1:3000

# or bring your own
pingap --domain=pingap.io --upstream=192.168.1.1:3000 --cert=/etc/ssl/pingap.io
```

- Without `--cert` the certificate is ordered by HTTP-01: the domain has to resolve to this host, with port 80 reachable. It is kept in `~/.pingap/acme/<domains>.toml` and used again at the next start. Do not delete it, issuing is rate limited.
- `--cert` is the certificate or the directory it is in (`fullchain.pem` / `privkey.pem`, `cert.pem` / `key.pem` and `tls.crt` / `tls.key` are found; `--key` names anything else). `--upstream` and `--domain` take lists separated by commas, `--addr` the address to listen on.
- The configuration is made anew at every start, so the admin cannot edit it. For more than one server use `--conf`, which these flags cannot be combined with.

## 📝 Configuration

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

The same can be written in HCL or KDL. Every key is described in the [configuration reference](https://pingap.io/crates/config).

| | |
| --- | --- |
| `--autoreload` | A change is applied without a restart: within ten seconds from files, at once from etcd. What takes a restart is reported, and waits for one. The mode for containers |
| `-a`, `--autorestart` | The same, and a restart that drops no request for what a reload cannot change, a listen address for one |
| `-t` | Builds every upstream, location, plugin, certificate and server as a start does, and binds nothing |
| `--strict` | A key Pingap does not know, or one this build has no feature for, is an error, where it is otherwise a warning. For `-t` in CI |
| `--diff <other>` | Prints what would change if `<other>` took the place of the configuration, credentials shown as checksums |
| `$ENV:NAME`, `$FILE:/path` | As a whole value: replaced by the variable or the file when the configuration is loaded |

## 🔄 How a request is handled

![A request passes the server, the location and its request plugins to an upstream; the response comes back through the response plugins and is logged](./asset/pingap-steps.svg)

1. The **server** accepts the connection and picks the **location** whose host and path match best. A request that matches none is answered with `404`.
2. The location's **plugins** run in the order they are listed, each at its own step: on the way in, or on the way back. A plugin can answer the request itself - a cache hit, a failed authentication, a redirect, a static file - and the upstream is then never asked.
3. Otherwise the **upstream** of the location picks a healthy backend and the request is forwarded. With `max_retries`, a connection that cannot be made is tried on another backend.
4. The response goes back through the response plugins to the client, and the request is **logged**: access log, metrics and traces.

## 📊 Performance

About 147,000 requests a second for `/ping` on one thread of an M4 Pro, with a 99th percentile of 116µs (`wrk`, 10 connections, no access log).

<details>
<summary>The run</summary>

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

## 🔧 Development

```bash
make dev         # needs bacon: cargo install bacon
make build-web   # after a change under web/, needs Node.js
make fmt && make lint && make test
```

`make dev` builds with the `full` features, runs Pingap on the configuration in `~/tmp/pingap` with `--autoreload`, serves the admin on `127.0.0.1:3018` (`pingap` / `123123`) and rebuilds when the sources change. The admin is embedded into the binary from `dist/`, which `make build-web` fills. The minimum supported Rust version is 1.96.

### TLS backend

The default build uses OpenSSL, compiled from source. For rustls:

```bash
cargo build --release --no-default-features --features tls-rustls,full
```

A rustls build always offers TLS 1.2 and 1.3 with rustls' own cipher suites, so the per-server `tls_min_version`, `tls_max_version`, `tls_cipher_list` and `tls_ciphersuites` are refused when the configuration is checked. Everything else behaves the same; the differences are listed with the [certificate crate](https://pingap.io/crates/certificate). `pingap --version` says which backend a binary has.

## 🤝 Contributing

Pull requests are welcome.

- For a new feature, please open an issue first, so that it can be discussed before any code is written.
- Please do not open a pull request only to fix a typo or the formatting of a comment; these are fixed in batches.
- Run `make fmt`, `make lint` and `make test` before pushing. CI runs the same checks on every pull request.
- A contribution is made under the [Contributor License Agreement](./CLA.md), which is accepted by ticking its box in the pull request template: the work stays yours, and is licensed to the project under its license.

## 📄 License

[Apache License, Version 2.0](./LICENSE).
