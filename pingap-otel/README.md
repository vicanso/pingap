# Pingap OpenTelemetry

Distributed tracing for [Pingap](https://github.com/vicanso/pingap) via
OpenTelemetry.

When enabled, Pingap creates a span per request, joins any incoming trace
context, and exports spans over OTLP to a collector — so a slow request can be
followed from the proxy through the services behind it.

## Enabling

Requires the `tracing` cargo feature (included in `full`):

```bash
cargo build --features=tracing
```

Then configure an exporter per server:

```toml
[servers.main]
addr = "0.0.0.0:6188"
locations = ["app"]
otlp_exporter = "http://otel-collector:4317/pingap"
```

The path component of the URL becomes the service name, so several servers in
one process can report under distinct names. Query parameters on the URL
configure the exporter (timeout, compression, protocol).

## What is traced

Each request becomes a span carrying the location, upstream, status and the
timing breakdown Pingap already collects — upstream connect, TLS handshake,
upstream processing, cache lookup. Incoming trace context is read with
`HeaderExtractor`, so Pingap continues an existing trace rather than starting a
new one.

## Collector

Any OTLP-compatible collector works — the OpenTelemetry Collector, Jaeger,
Tempo, Honeycomb, Datadog. A minimal collector config:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  otlphttp:
    endpoint: https://tempo:4318

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp]
```

## Re-exports

The crate re-exports the pieces of the OpenTelemetry API that
[pingap-proxy](../pingap-proxy/README.md) needs, so the rest of the workspace
does not depend on `opentelemetry` directly:

```rust
pub use opentelemetry::{global, trace, KeyValue};
pub use opentelemetry_http::HeaderExtractor;
```

## Cost

Tracing is not free: every request allocates a span and export happens in the
background. For high-volume listeners, sample at the collector rather than
exporting everything, and leave `otlp_exporter` off servers that do not need it.

## License

Apache-2.0.
