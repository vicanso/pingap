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

Backends are process-wide singletons: there is one file backend per directory,
and exactly **one** memory backend, created by whoever asks first.

A file backend belongs to its directory. The same directory with the same
parameters is the same backend, however the path is spelled (`d`, `./d`) and
in whatever order the parameters come. Asking for the directory with other
parameters — `inactive=1h` changed to `7d` on a reload — builds a new backend
that takes the directory over: the hourly sweep goes by the new `inactive`, and the
replaced backend, still valid for requests that are using it, gives up its
in-memory layer. Two `cache` plugins that name one directory should therefore
use the same parameters; with different ones the plugin built last decides how
the directory is swept, and the other one runs without its in-memory layer.

`dry_run(|| ...)` runs a closure with the backends left as they are: inside
it `new_cache_backend` checks the setting it is given and returns the backend
that is there (or a stand-in) without creating a directory, replacing a
backend or sizing the memory cache. The admin uses it to validate a `cache`
plugin before storing it, in a process that is serving.

### Memory backend

TinyUFO is a S3-FIFO-style cache with good scan resistance and no global lock,
which makes it a better fit than an LRU for proxy workloads.

| Parameter | Default | Description |
| --- | --- | --- |
| `max_size` | 1/4 of available memory, else 256 MB, capped at 1 GB | Cache budget |
| `mode` | `normal` | TinyUFO variant: `normal` (also `default`), or `compact` for a smaller index at some speed cost |

`max_size` accepts either form:

| Value | Meaning |
| --- | --- |
| `max_size=20` | 20 % of the memory budget — a bare number is a percentage, clamped to 100 |
| `max_size=100mb` | An absolute size — anything with a unit is taken literally, however small |

`update_available_memory()` is called once at startup with the memory that is
available: what the machine reports, and no more than the container is allowed
(the memory limit of the cgroup, on Linux), so the default budget tracks where
the process runs rather than a hard-coded number. The machine's figure alone
used to be taken, which in a container limited to less than a quarter of it
sized the cache past the limit. A limit that is not the container's own, the
`MemoryMax=` of a systemd unit for example, is not seen: set `max_size` there.

An entry weighs its size in 4 KB pages, rounded up (rounded down, a cache of
small objects held up to twice its budget). One that weighs more than the
whole cache holds is not stored in memory: TinyUFO would make room for it by
evicting everything else. An object of 40 MB or more weighs the maximum, 256 MB.

Entries are weighed in 4 KB pages, so the budget in pages is also the most
entries the cache can hold, and that is the size estimate TinyUFO gets for its
index and frequency sketch: a few MB for a 256 MB cache, about 16 MB for the
1 GB cap. A parameter that does not parse (`max_size=lots`, `mode=tiny`) is an
error from `new_cache_backend`, not silently the default.

### File backend

| Parameter | Default | Description |
| --- | --- | --- |
| `inactive` | `48h` | Remove files untouched for this long, regardless of freshness |
| `reading_max` | `10000` | Maximum concurrent reads; over quota is a **miss** (origin fetch), not 5xx |
| `writing_max` | `1000` | Maximum concurrent writes; over quota **skips** the disk write |
| `cache_max` | `0` | Size, in 4 KB pages, of an in-front TinyUFO layer for hot entries |
| `cache_file_max_weight` | 256 pages (1 MB) | Largest entry admitted to that layer, whether it arrives by a write or by a read from disk |
| `levels` | — | Directory nesting, up to two levels of 1 to 3 key characters each, e.g. `levels=1:2`, to avoid huge flat directories; anything else is rejected |
| `max_size` | unlimited | Total on-disk budget (e.g. `max_size=10gb`); least-recently-accessed files are evicted to stay under it |

Staying under `max_size` costs one directory walk per write that finds the
budget exceeded (on the blocking pool, so no worker thread stalls), after which
files are deleted in access order until the new object fits. Writes that arrive
while that eviction runs go ahead without waiting. An object larger than the
whole budget is not written at all; evicting everything for it would only empty
the cache. The usage figure is a running estimate; that walk sets it back to
what is actually in the directory, so files removed by hand or two writes of one
key do not leave it off for good.

`new_storage_clear_service()` returns a background service that periodically
sweeps inactive files.

"Untouched" and "least recently accessed" go by the access time of the file,
which the cache sets itself when an object is read, about once a minute per
object and also when the read was answered from the hot layer. It does not
depend on how the file system is mounted. Left to the file system, an object
served from the hot layer was never read from disk: the more it was asked for
the older its file looked, and on a `noatime` mount `inactive` counted from the
write.

The directory can hold other data. The cache counts, evicts, sweeps and purges
only the files it wrote: the objects, whose names are their keys (32
hexadecimal digits in lower case), and the temporary file of a write
(`<key>.<pid>.<seq>.tmp`). Any other file is left where it is and does not
count towards `max_size`. A file of something else that happens to be named
like a key, by an MD5 for example, cannot be told apart and is treated as a
cached object, so a directory of such files is not one to share.

## Namespaces

The `cache` plugin's `namespace` option isolates entries. With the file backend
it becomes a subdirectory, which is what makes namespace-level purging possible:
`HttpCacheStorage::purge_namespace` walks that directory, removes every object
from disk, empties the TinyUFO hot layer, and drops the emptied directories. The
hot layer is emptied whole: it cannot be searched by namespace, and an object
whose disk write was skipped or failed (over `writing_max`, larger than
`max_size`, an i/o error) is in memory only,
with no file to find it by. Other namespaces read their objects back from disk.
The memory
backend cannot enumerate its entries, so its `purge_namespace` reports
"unsupported" (`Ok(None)`) rather than silently doing nothing. The `cache`
plugin exposes this as `PURGE /*`.

## Metrics

With the `tracing` feature the crate exports Prometheus histograms:

| Metric | Meaning |
| --- | --- |
| `pingap_cache_storage_read_time` | Time spent reading an entry from disk |
| `pingap_cache_storage_write_time` | Time spent writing an entry to disk |

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
