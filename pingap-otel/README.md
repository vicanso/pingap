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
otlp_exporter = "http://otel-collector:4317"
```

The service name is `pingap:` followed by the name of the server
(`pingap:main` here), so several servers in one process report under distinct
names. The URL is the collector's endpoint as it is; its path is not the
service name, as this README used to say. Query parameters on the URL
configure the exporter: `timeout`, `compression` (`gzip` or `zstd`),
`max_queue_size`, `scheduled_delay`, `max_export_batch_size`,
`max_attributes`, `max_events`, and `jaeger` / `baggage` to accept those
propagation formats.

The exporter is started in any build with the `tracing` feature. It used to be
started only in a `full` build: one with `tracing` and without `imageoptim`
had it compiled in and never ran it.

## What is traced

Each request becomes a span carrying the location, upstream, status and the
timing breakdown Pingap already collects — upstream connect, TLS handshake,
upstream processing, cache lookup. Incoming trace context is read with
`HeaderExtractor`, so Pingap continues an existing trace rather than starting a
new one.

The request to the upstream carries the context of Pingap's span for it
(`traceparent`, and the Jaeger header where that format is enabled), so what
the upstream traces hangs from the proxy's span. The client's `traceparent`
used to be passed on as it was, which put the upstream's spans beside the
proxy's instead of under it. Whether the trace is sampled stays the client's
decision: Pingap samples every span of its own, but where it continues a
client's trace it passes on the client's flag, so an upstream that samples
what its parent sampled is not made to record more than before. `tracestate`
and `baggage` are the client's and go through as they came. A `traceparent`
set with the location's `proxy_set_headers` still wins.

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
