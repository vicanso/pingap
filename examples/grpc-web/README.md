# Grpc Web

This example shows how to use Pingap to proxy gRPC-Web requests.

## Usage

The development certificate in `grpc-web.toml` has notAfter 2025-12-24.
Replace it for a local run. `[plugins.grpc-web-static]` serves
`~/tmp/grpc/commonjs-example`; point `path` at your own files.

```bash
cargo run -- -c=examples/grpc-web/grpc-web.toml --admin=127.0.0.1:3018
```