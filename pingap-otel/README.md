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
configure the exporter:

| Parameter | Default | Description |
| --- | --- | --- |
| `protocol` | `grpc` | `grpc` (OTLP/gRPC, port 4317 by convention, `http://` only) or `http` (OTLP/HTTP with a protobuf body, port 4318, `http://` or `https://`). |
| `sampler` | `always_on` | Which requests are traced: `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio`. |
| `sample_ratio` | `1` | The share a ratio sampler takes, `0` to `1`. Only with `traceidratio` or `parentbased_traceidratio`. |
| `header` | — | A header of every export, as `Name:Value`; repeat the parameter for more. |
| `timeout` | `3s` | How long one export may take. |
| `compression` | — | `gzip` or `zstd`, over gRPC. |
| `max_queue_size` | `2048` | Spans that wait for export at most; what comes beyond is dropped. |
| `scheduled_delay` | `5s` | How often the waiting spans are exported. |
| `max_export_batch_size` | `512` | Spans in one export at most. |
| `max_attributes`, `max_events` | `16` | Attributes and events a span keeps. |
| `jaeger`, `baggage` | — | Accept and pass on those propagation formats too. |

```toml
# one request in ten, unless the caller has decided, over HTTP, with a token
otlp_exporter = "https://otlp.example.com?protocol=http&sampler=parentbased_traceidratio&sample_ratio=0.1&header=Authorization:Bearer%20abc123"
```

- **`protocol=http`** posts to the url as it is written; where it names no
  path, to `/v1/traces`. Use it for a collector behind something that does
  not pass gRPC, for a service that only takes OTLP over HTTP, and for any
  collector that is reached over TLS: the gRPC exporter is built without
  TLS, and an `https://` url without `protocol=http` fails when the exporter
  starts (`opentelemetry init fail` in the log; the server runs untraced).
- **`sampler`**: with `always_on`, the default, every request is traced and
  exported. A `traceidratio` sampler traces the share `sample_ratio` says,
  chosen by the trace id. A `parentbased_` sampler goes by the caller where
  the request comes with a trace of its own (`traceparent`): sampled when
  the caller sampled, and not otherwise; a request without one is decided by
  the sampler named after it.
- **`header`** is how a collector that asks for a token gets it. The value
  is url-encoded like any parameter: `%20` for a space, and `%2B` for a `+`,
  which would otherwise be read as a space (a base64 credential has them).
  A header makes the url a credential: the configuration differences that
  are logged and sent to the webhook show its parameters as a checksum, and
  the log lines of the exporter show the url without them. The admin shows
  the url as it is.
- `sampler`, `sample_ratio`, `protocol` and `header` are checked with the
  configuration: a value that is not one of the above, or a `sample_ratio`
  without a ratio sampler to go by it, is refused by `-t`, at startup and by
  the admin. Read as if it were not there, a sampler with a typo would trace
  every request. The older parameters are read as they always were, and one
  that does not parse leaves its default in place.
- `max_export_timeout` is accepted and has no effect: the time one export
  may take is `timeout`. Setting it logs a warning at startup.

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
decision: with the default sampler Pingap samples every span of its own, but
where it continues a client's trace it passes on the client's flag, so an
upstream that samples what its parent sampled is not made to record more than
before. (With a `parentbased_` sampler Pingap's own span follows the client
as well.) Where the sampler drops Pingap's span for a request that came with
a trace, the upstream gets the client's `traceparent` as it came, so that
what it records hangs from the client's span and not from one that is never
exported. A request that starts a trace here is passed on with the decision
of Pingap's sampler. The client's decision is read from `traceparent`: with
the `jaeger` format enabled, a client that sends only the Jaeger header and
did not sample is still told on as sampled by the default sampler. `tracestate`
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
background. For high-volume listeners, set a `sampler` so that only a share of
the requests is recorded and exported, and leave `otlp_exporter` off servers
that do not need it.

## License

Apache-2.0.
