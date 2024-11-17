# examples


## Static-Server

```bash
cargo run -- -c=~/github/pingap/examples/static-serve.toml --admin=127.0.0.1:3018
```

```bash
curl http://127.0.0.1:3000/ -v
```

## Proxy-Upstream

Upstream features:

- Support comresssion: zstd, br, gzip
- Static cache: public, max-age=31536000

```bash
cargo run -- -c=~/github/pingap/examples/proxy-upstream.toml --admin=127.0.0.1:3018
```
