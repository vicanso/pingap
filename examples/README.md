# Examples

Run these from the repository root. An installed binary replaces
`cargo run --` with `pingap`. `-c` takes one TOML file or a directory of
`*.toml` files.

- [static-serve](./static-serve/README.md)
- [api-gateway](./api-gateway/README.md)
- [web-socket](./web-socket/README.md)
- [grpc-web](./grpc-web/README.md)
- [transparent-proxy](./transparent-proxy/README.md)

## static-serve

Static files, with cache and compression. The upstream in the sample listens
on `127.0.0.1:8080`.

```bash
cargo run -- -c=examples/static-serve --admin=127.0.0.1:3018 --autoreload
```

## api-gateway

Routes by path to three upstreams: `/api/charts/`, `/api/orders/`, and
everything else. Each location has its own auth, compression or cache plugin.

```bash
cargo run -- -c=examples/api-gateway --admin=127.0.0.1:3018 --autoreload
```

## web-socket

`wssUpstream` discovers `ws.postman-echo.com` over DNS and sets the SNI.
`/raw` goes there; other paths go to `static` (`127.0.0.1:8080`). The server
listens on `127.0.0.1:6118`.

```bash
cargo run -- -c=examples/web-socket --admin=127.0.0.1:3018 --autoreload
```

Connect a client to `ws://127.0.0.1:6118/raw`.

## grpc-web

- The upstream is an insecure gRPC server on `127.0.0.1:9090`
- `[upstreams.grpc-server]` sets `alpn` to `H2`
- `[servers.grpc-web]` sets `enabled_h2` and includes `grpc-web` in `modules`
- `[locations.grpc-server]` sets `grpc_web`
- `[plugins.grpc-web-static]` is a `directory` plugin whose `path` is
  `~/tmp/grpc/commonjs-example`; point it at your own files

The development certificate in the file has notAfter 2025-12-24. Replace it
for a local run.

```bash
cargo run -- -c=examples/grpc-web/grpc-web.toml --admin=127.0.0.1:3018
```

## transparent-proxy

- Upstream `discovery` is `transparent`; `127.0.0.1` is only a placeholder
- `sni` is `$host` for HTTPS
- The certificate is `is_default = true`, so it is the default for every host
- The server listens on `127.0.0.1:443`

The development certificate in the file has the same notAfter, 2025-12-24.
Replace it for a local run.

```bash
sudo cargo run -- -c=examples/transparent-proxy/transparent-proxy.toml --admin=127.0.0.1:3018
```

```bash
curl -kv --resolve '*:443:127.0.0.1' 'https://cn.bing.com/'
```
