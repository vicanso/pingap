# Examples

- [static-serve](./static-serve/README.md)
- [api-gateway](./api-gateway/README.md)

## Grpc-Web

- Insecure grpc-server
- Commonjs example static
- Locally trusted development certificates for 127.0.0.1

The key points of configuration are as follows:

- [upstreams.grpc-server] should choose h2 alpn
- [servers.grpc-web] should select grpc-web module
- [locations.grpc-server] should enable grpc_web

```bash
cargo run -- -c=~/github/pingap/examples/grpc-web.toml --admin=127.0.0.1:3018
```

## Transparent Proxy

- Upstream discovery should be `transparent`
- Upstream sni should be `$host` for https
- Certificate should be set as default for all domains

```bash
sudo cargo run -- -c=~/github/pingap/examples/transparent-proxy.toml --admin=127.0.0.1:3018
```

```bash
curl -kv --resolve '*:443:127.0.0.1' 'https://cn.bing.com/'
```


## Web Socket

```bash
cargo run -- -c=~/github/pingap/examples/web-socket.toml --admin=127.0.0.1:3018
```