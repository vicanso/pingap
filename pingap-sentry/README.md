# Pingap Sentry

Error reporting for [Pingap](https://github.com/vicanso/pingap) via
[Sentry](https://sentry.io/).

A deliberately thin crate: it parses a DSN into `sentry_core::ClientOptions`.
The Sentry client itself is installed by pingora, which Pingap enables through
pingora's `sentry` feature, so panics and errors raised inside the proxy runtime
are captured with a stack trace rather than only appearing in the log.

## Building

Requires the `tracing` cargo feature (included in `full`):

```bash
cargo build --features=tracing
```

## Configuration

```toml
[basic]
sentry = "https://<key>@o0.ingest.sentry.io/0"
```

A missing or unparseable DSN disables reporting; the error is logged and startup
continues.

## Usage

```rust
use pingap_sentry::new_sentry_options;

let options = new_sentry_options("https://key@o0.ingest.sentry.io/0")?;
// handed to pingora's server configuration
```

## Notes

- Only the DSN is configurable here. Sample rates, environment and release
  tagging are left at the Sentry client defaults; set them on the Sentry project
  side, or via the standard `SENTRY_*` environment variables the client reads.
- A busy proxy can generate a lot of similar events. Configure rate limiting and
  grouping in the Sentry project rather than relying on volume being low.
- This is complementary to [pingap-webhook](../pingap-webhook/README.md): Sentry
  captures unexpected failures, webhooks report expected operational events such
  as certificate expiry.

## License

Apache-2.0.
