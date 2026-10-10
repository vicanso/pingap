# pingap

![Pingap Logo](./asset/pingap-logo.png)

## Overview

Pingap is a high-performance reverse proxy powered by the [`Cloudflare Pingora`](https://github.com/cloudflare/pingora) . It simplifies operational management by enabling dynamic, zero-downtime configuration hot-reloading through concise TOML files and an intuitive web admin interface.

Its core strength lies in a powerful plugin system, offering over thirty out-of-the-box plugins for Authentication (JWT, Key Auth, OIDC), Security (CSRF, IP/Referer/UA Restrictions), Traffic Control (Rate Limiting, Caching), Content Modification (Redirects, Content Substitution), and Observability (Request ID). This makes `Pingap` not just a proxy, but a flexible and extensible application gateway, engineered to effortlessly handle complex scenarios from API protection to modern web application deployments.


[中文说明](./README_zh.md) | [Documentation](https://pingap.io/) · [中文文档](https://pingap.io/zh/) | [Examples](./examples/README.md) | [Plugins](./pingap-plugin/README.md) | [Crates](./docs/README.md)

![Requests from the internet pass through Pingap, which routes them by host and path to groups of upstream servers](./asset/pingap-flow.svg)

## Key Features

- 🚀 High Performance & Reliability
  - Built with Rust for memory safety and top-tier performance.
  - Powered by Cloudflare Pingora, a battle-tested asynchronous networking library.
  - Supports HTTP/1.1, HTTP/2, WebSocket and gRPC-web proxying, and the PROXY protocol on its listeners.

- 🔧 Dynamic & Easy to Use
  - Zero-downtime configuration changes with hot-reloading.
  - Simple, human-readable TOML configuration files (HCL and KDL are read as well).
  - Full-featured Web UI for intuitive, real-time management.
  - Supports both file and etcd as configuration backends.
  - Supports configuration history record, can restore to the history version with one click.

- 🧩 Powerful Extensibility
  - A rich plugin system to handle common gateway tasks.
  - Advanced routing with host, path, and regex matching.
  - Built-in service discovery via static lists, DNS (A/AAAA and SRV records), or Docker labels.
  - Load balancing by round robin, least connections, consistent hashing or sticky sessions, with active health checks, retries and a circuit breaker.
  - Automated HTTPS with Let's Encrypt or any other ACME CA (HTTP-01 and DNS-01 challenges), RSA and ECDSA certificates side by side, and OCSP stapling.

- 📊 Modern Observability
  - Native Prometheus metrics for monitoring (pull & push modes).
  - Integrated OpenTelemetry support for distributed tracing.
  - Highly customizable access logs with over 30 variables.
  - JA4 TLS client fingerprints (`{:ja4}` in access logs, `$ja4` in upstream headers) to tell clients apart by their TLS stack, on OpenSSL and rustls builds alike.
  - Detailed performance metrics, including upstream connect time, processing time, and more.

## 🚀 Getting Started

The easiest way to get started with Pingap is by using Docker Compose.

1. Create a `docker-compose.yml` file:

```yaml
# docker-compose.yml
services:
  pingap:
    image: vicanso/pingap:latest # For production, use a specific version like vicanso/pingap:0.15.0-full
    container_name: pingap-instance
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      # Mount a local directory to persist all configurations and data
      - ./pingap_data:/opt/pingap
    environment:
      # Configure using environment variables
      - PINGAP_CONF=/opt/pingap/conf
      - PINGAP_ADMIN_ADDR=0.0.0.0:80/pingap
      - PINGAP_ADMIN_USER=pingap
      - PINGAP_ADMIN_PASSWORD=<YourSecurePassword> # Change this!
    command:
      # Start pingap and enable hot-reloading
      - pingap
      - --autoreload
```

2. Create a data directory and run:

```bash
mkdir pingap_data
docker compose up -d
```

3. Access the Admin UI:

Your Pingap instance is now running! You can access the web admin interface at http://localhost/pingap with the credentials you set.

Images built after 0.15.0 also come in a distroless variant: add `-distroless` to the tag, e.g. `latest-distroless`, `full-distroless`, `rustls-full-distroless`, or `<version>-distroless` and so on for a release. The binary is the same as in the matching regular image, on `gcr.io/distroless/cc-debian13` with no shell or package manager, so `command` must start with `pingap` as it does above.

### Install the binary via curl

For Linux and macOS, you can install the latest pre-built binary to `/usr/local/bin/pingap` with one command:

```bash
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | sh
```

Optional environment variables:

- `PINGAP_FULL=1` — install the `-full` build (all optional features enabled)
- `PINGAP_LIBC=gnu` — on Linux, use the glibc build instead of the default musl static build
- `PINGAP_TLS=rustls` — on Linux, install the `-rustls-full` build (rustls TLS backend, all optional features, no OpenSSL); see [TLS backend](#tls-backend)
- `PINGAP_SERVICE=1` — on Linux with systemd, also install a `pingap` service: the unit `/etc/systemd/system/pingap.service` and, when `/etc/pingap/conf` is empty, a starter `basic.toml` in it. The service is not enabled or started, since there is no server to run yet

```bash
# Full-featured build
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | PINGAP_FULL=1 sh

# With a systemd service: add your servers to /etc/pingap/conf, then start it
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | PINGAP_SERVICE=1 sh
sudo systemctl enable --now pingap
```

Supported targets: `Linux x86_64/arm64`, `Darwin x86_64/arm64`. See the [releases page](https://github.com/vicanso/pingap/releases) for all available assets.

For more detailed instructions, including running from a binary, check out our [Documentation](https://pingap.io/).

### Start a proxy without a config file

A single command is enough to serve a domain over https and forward it to a backend:

```bash
# certificate requested from let's encrypt
pingap --domain=pingap.io --upstream=192.168.1.1:3000

# or bring your own certificate
pingap --domain=pingap.io --upstream=192.168.1.1:3000 --cert=/etc/ssl/pingap.io
```

Without `--cert`, Pingap asks Let's Encrypt for a certificate through the
HTTP-01 challenge, so `pingap.io` must resolve to this host and port 80 must be
reachable from the internet. The issued certificate is kept in
`~/.pingap/acme/<domains>.toml` and reused on restart — issuing is rate limited,
so do not delete it. Everything else still comes from the command line: changing
`--upstream` takes effect on the next start without touching the certificate.

`--cert` accepts the certificate itself or the directory holding it — the common
`fullchain.pem` / `privkey.pem`, `cert.pem` / `key.pem` and `tls.crt` / `tls.key`
layouts are detected automatically, use `--key` for anything else. The listener
defaults to `0.0.0.0:443` when there is a certificate and `0.0.0.0:80` when there
is neither a certificate nor a domain, and `--addr` overrides it. `--upstream`
takes a comma separated list of backends, `--domain` a comma separated list of
hosts (omit it to serve every host over plain http). Requests for a host that
is not listed are answered with 404.

The configuration is generated on every start, so it cannot be edited through
the admin UI: for anything beyond a single server use `--conf`, which cannot be
combined with these flags.


## Dynamic Configuration

Pingap is designed to adapt to configuration changes without downtime.

Hot Reload (--autoreload): For most changes—like updating upstreams, locations, plugins, or certificates—Pingap applies the new configuration without a restart: within 10 seconds with a file storage, and as soon as the change is stored with etcd. This is the recommended mode for containerized environments.

Graceful Restart (-a or --autorestart): For fundamental changes (like modifying server listen ports), this mode performs a full, zero-downtime restart, ensuring no requests are dropped.

Strict mode (--strict): A key or section Pingap does not know is normally reported with a warning and otherwise ignored. With `--strict` it is an error: `pingap -t --strict` fails on it (use that in CI), and a running Pingap does not take a reload that has one.

Check and preview (-t, --diff): `pingap -c conf -t` goes as far as a start does without serving - every upstream, location, plugin, certificate and server is built, TLS settings included, and nothing is bound. `pingap -c conf --diff new-conf` prints what would change if `new-conf` replaced `conf`, with credentials shown as checksums.

Secrets from the environment and from files: any text value of the configuration can be written `$ENV:NAME` or `$FILE:/path` as a whole, and is replaced when the configuration is loaded to run. The admin, `--to-hcl` and `--sync` keep it as written. See the [config documentation](https://pingap.io/crates/config).

The hand-over is readiness-driven rather than timed: the replacement is started with `-d -u`, reports back over a unix socket next to the upgrade socket the moment it is ready to take over the listeners, and only then does the running process send itself SIGQUIT. If the replacement exits, its daemon dies, or `basic.restart_ready_timeout` (default 1m) passes first, the restart is abandoned and the running process keeps serving. The replacement is started in the directory the first process was started in, with the same `--autoreload` / `--autorestart`, so relative paths (`--log=logs/pingap.log`, paths in the config) keep meaning what they did.


## 🔧 Development

```bash
# needs bacon: cargo install bacon
make dev
```

`make dev` builds with the `full` feature set, runs Pingap on the configuration in `~/tmp/pingap` with `--autoreload`, serves the admin UI on `127.0.0.1:3018` (`pingap` / `123123`), and rebuilds when the sources change.

The admin UI is embedded into the binary from `dist/`. After a change under `web/`, rebuild it (needs Node.js):

```bash
make build-web
```

Before sending a change:

```bash
make fmt     # cargo fmt
make lint    # typos + clippy with warnings denied
make test    # the test suite of the workspace
```

### TLS backend

The default build terminates TLS with OpenSSL, compiled from source by the `openssl` crate. To build with rustls instead, which drops the OpenSSL source build (a C compiler is still needed: rustls' crypto providers, ring and aws-lc-rs, contain C and assembly):

```bash
cargo build --release --no-default-features --features tls-rustls
# with the optional features as well
cargo build --release --no-default-features --features tls-rustls,full
```

The rustls build rejects the per-server `tls_min_version`, `tls_max_version`, `tls_cipher_list` and `tls_ciphersuites` settings at config validation (startup, `--test`, auto-restart): it always offers TLS 1.2 and 1.3 with rustls' default cipher suites. The admin UI disables those fields when the running binary is a rustls build. Everything else, including dynamic SNI certificates, self-signed CA issuance, ACME and the upstream `ca` option, behaves the same. Pre-built images carry the same variant: `vicanso/pingap:rustls-full` (and `:<version>-rustls-full` for a release), alongside `:latest` and `:full`. One difference to know about when verifying upstreams: rustls (webpki) rejects a server certificate that carries `CA:TRUE`, which OpenSSL accepts, so a backend using a quick `openssl req -x509` self-signed certificate needs a proper leaf signed by a CA (or a self-signed leaf without the CA flag) before the upstream `ca` option can trust it. `--version` (long form), the startup log and the admin home page all report which backend a binary was built with.

## 📝 Configuration

```hcl
server "test" {
  addr = "127.0.0.1:6118"

  location "github-api" {
    path = "/api"
    proxy_set_headers = ["Host:api.github.com"]
    rewrite = "^/api/(?<path>.+)$ /$1"

    upstream "api" {
      addrs     = ["api.github.com:443"]
      discovery = "dns"
      sni       = "api.github.com"
    }
  }

  location "static" {
    plugin "staticServe" {
      category = "directory"
      path     = "~/Downloads"
      step     = "request"
    }
  }
}
```

```toml
[upstreams.api]
addrs = ["api.github.com:443"]
discovery = "dns"
sni = "api.github.com"

[plugins.staticServe]
category = "directory"
path = "~/Downloads"
step = "request"

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

You can find the relevant instructions here: [https://pingap.io/crates/config](https://pingap.io/crates/config).

## 🔄 How a request is handled

![A request passes the server, the location and its request plugins to an upstream; the response comes back through the response plugins and is logged](./asset/pingap-steps.svg)

1. The **server** accepts the connection (TLS, HTTP/1.1 or HTTP/2) and picks the **location** whose host and path match best. A request that matches none is answered with `404`.
2. The location's **plugins** run in the order they are listed, each at its own step: `early_request`, `request` or `proxy_upstream` on the way in, `upstream_response` or `response` on the way back. A plugin can answer the request itself - a cache hit, a failed authentication, a redirect, a static file - and the upstream is then never asked.
3. Otherwise the **upstream** of the location picks a healthy backend and the request is forwarded. With `max_retries` on the location, a connection that cannot be made is tried on another backend.
4. The response goes back through the response plugins to the client, and the request is **logged**: access log, metrics and traces.

## 📊 Performance

CPU: M4 Pro, Thread: 1

### Ping no access log

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


## 📦 Rust version

Our current MSRV is 1.96

## 🤝 Contributing

Pull requests are welcome.

- For a new feature, please open an issue first, so that it can be discussed before any code is written.
- Please do not open a pull request only to fix a typo or the formatting of a comment; these are fixed in batches.
- Run `make fmt`, `make lint` and `make test` before pushing. CI runs the same checks on every pull request.
- A contribution is made under the [Contributor License Agreement](./CLA.md), which is accepted by ticking its box in the pull request template: the work stays yours, and is licensed to the project under its license.

## 📄 License

This project is Licensed under [Apache License, Version 2.0](./LICENSE).
