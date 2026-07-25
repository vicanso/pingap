# Pingap Pyroscope

Continuous CPU profiling for [Pingap](https://github.com/vicanso/pingap) via
[Pyroscope](https://pyroscope.io/).

The agent samples stacks in the running proxy and ships them to a Pyroscope
server, so a CPU regression can be attributed to a function — which plugin, which
compression level, which regex — rather than guessed at.

## Building

Profiling is behind a cargo feature and is paired with a profile that keeps
debug symbols (stripped binaries produce useless flame graphs):

```bash
cargo build --features=pyro
make release-perf          # features = perf (pyro + full), profile = release-perf
```

## Configuration

```toml
[basic]
pyroscope = "http://pyroscope:4040?app=pingap&sample_rate=100&tag:region=$REGION&tag:env=prod"
```

The URL is the Pyroscope server; everything else comes from query parameters:

| Parameter | Default | Description |
| --- | --- | --- |
| `app` | `pingap` | Application name shown in Pyroscope |
| `user` / `password` | — | Basic auth credentials for the server |
| `sample_rate` | `100` | Samples per second |
| `tag:<name>` | — | Arbitrary tag. A value starting with `$` is read from the environment. |

Environment interpolation makes per-instance tagging easy:

```toml
pyroscope = "http://pyroscope:4040?app=pingap&tag:host=$HOSTNAME&tag:region=$AWS_REGION"
```

## Running it

The agent is a pingora `BackgroundService`: it starts with the process and is
shut down cleanly on graceful shutdown, so profiles are flushed rather than
truncated.

```rust
use pingap_pyroscope::new_agent_service;

let service = new_agent_service("http://pyroscope:4040?app=pingap");
```

## Notes

- Sampling costs CPU. `100` Hz is a reasonable production default; raise it only
  while investigating something specific.
- Without debug information the flame graph is a wall of addresses — use the
  `release-perf` profile (`make release-perf`), which disables stripping.
- Tags are how you separate instances, regions and versions in the Pyroscope UI.
  Set at least a host tag.

## License

Apache-2.0.
