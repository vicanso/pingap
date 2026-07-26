# Pingap Cache

HTTP cache storage backends for [Pingap](https://github.com/vicanso/pingap).

This crate implements pingora's cache storage interface twice — once in memory
on top of [TinyUFO], once on disk — and exposes both through a single
`new_cache_backend(directory)` entry point. The
[`cache` plugin](../pingap-plugin/docs/cache.md) is what user-facing
configuration talks to; this crate is the storage layer underneath it.

## Backends

| `directory` value | Backend |
| --- | --- |
| `""` or `memory://…` | In-memory TinyUFO cache |
| Anything else | File cache rooted at that path |

```rust
use pingap_cache::new_cache_backend;

let memory = new_cache_backend("memory://pingap?max_size=100mb&mode=default")?;
let file   = new_cache_backend("/opt/pingap/cache?inactive=1h&reading_max=1000")?;
```

Backends are process-wide singletons: file backends are memoised per directory
string, and there is exactly **one** memory backend, created by whoever asks
first.

### Memory backend

TinyUFO is a S3-FIFO-style cache with good scan resistance and no global lock,
which makes it a better fit than an LRU for proxy workloads.

| Parameter | Default | Description |
| --- | --- | --- |
| `max_size` | 1/4 of available memory, else 256 MB, capped at 1 GB | Cache budget |
| `mode` | `default` | TinyUFO cache mode |

`max_size` accepts either form:

| Value | Meaning |
| --- | --- |
| `max_size=20` | 20 % of the memory budget — a bare number is a percentage, clamped to 100 |
| `max_size=100mb` | An absolute size — anything with a unit is taken literally, however small |

`update_available_memory()` is called by the process metrics collector so the
default budget tracks the machine (or the container limit) rather than a
hard-coded number.

### File backend

| Parameter | Default | Description |
| --- | --- | --- |
| `inactive` | none | Remove files untouched for this long, regardless of freshness |
| `reading_max` | `10000` | Maximum concurrent reads |
| `writing_max` | — | Maximum concurrent writes |
| `cache_max` | `0` | Size of an in-front TinyUFO layer for hot entries |
| `cache_file_max_weight` | 256 pages (1 MB) | Largest entry admitted to that layer |
| `levels` | — | Directory nesting levels, e.g. `levels=1:2`, to avoid huge flat directories |

`new_storage_clear_service()` returns a background service that periodically
sweeps inactive files.

## Namespaces

The `cache` plugin's `namespace` option isolates entries. With the file backend
it becomes a subdirectory, which also makes it easy to drop a whole class of
cached content by removing one directory.

## Metrics

With the `tracing` feature the crate exports Prometheus histograms:

| Metric | Meaning |
| --- | --- |
| `pingap_cache_reading_time` | Time spent reading an entry |
| `pingap_cache_writing_time` | Time spent writing an entry |

Cache read/write counts are also surfaced per request through `Ctx`, which makes
them available to access logs as `{:cache_lookup_time}` and `{:cache_lock_time}`.

## Choosing a backend

| | Memory | File |
| --- | --- | --- |
| Latency | Lowest | Disk-bound |
| Survives restart | No | Yes |
| Capacity | Bounded by RAM | Bounded by disk |
| Eviction | LRU, when the `cache` plugin enables it | Inactive-file sweep |

LRU eviction needs a backend that reports a maximum size, which the file backend
does not — file cache reclamation is the `inactive` sweep instead. Setting
`eviction` on a file cache logs an error rather than pretending to apply.

[TinyUFO]: https://github.com/cloudflare/pingora/tree/main/tinyufo

## License

Apache-2.0.
