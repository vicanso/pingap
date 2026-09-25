# compression

Response compression with gzip, brotli and zstd. Two modes:

- **downstream mode** (default) — configures pingora's built-in compression
  module, which compresses on the way out to the client.
- **upstream mode** (`mode = "upstream"`) — Pingap compresses the upstream
  response body itself as it streams through, which lets it apply content-type
  and minimum-length rules.

- **Step:** `early_request` (fixed); upstream mode also hooks
  `upstream_response` and `upstream_response_body`
- **Registered as:** `compression`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `compression`. |
| `gzip_level` | int | `0` | 0–9. `0` disables gzip. |
| `br_level` | int | `0` | 0–11. `0` disables brotli. |
| `zstd_level` | int | `0` | 0–22. `0` disables zstd. |
| `mode` | string | `response` | `response` (downstream mode) or `upstream` for the streaming compressor. Anything else is a configuration error. |

Levels outside their range are clamped to it (a negative level is `0`).
| `min_length` | int | `0` | Upstream mode only: skip responses whose `Content-Length` is below this. |
| `decompression` | bool | absent | Presence of the key toggles decompression of compressed upstream responses. |

Algorithm priority is fixed: **zstd > brotli > gzip**. The first enabled
algorithm the client accepts wins.

## Examples

Standard downstream compression:

```toml
[plugins.compression]
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 3
```

Upstream mode with a size floor, so tiny JSON payloads are not compressed:

```toml
[plugins.compression]
category = "compression"
mode = "upstream"
gzip_level = 6
br_level = 6
min_length = 1024
```

## Upstream mode details

The response is compressed only when **all** of these hold:

1. It has a body: HEAD answers, `1xx`, `204` and `304` are left alone, since
   encoding nothing would still emit the format's header and footer.
2. It has no `Content-Encoding` yet.
3. It has a `Content-Type` that is compressible: `application/json`,
   `application/xml`, `text/html`, or any `text/*`.
4. The client accepts one of the enabled algorithms.
5. `min_length` is `0`, or `Content-Length` is present and at least `min_length`.
   A response with no `Content-Length` is always compressed.

When it does compress, `Content-Length` is removed, `Transfer-Encoding: chunked`
and `Content-Encoding` are set, and the body is encoded incrementally.

On the way out to the client, any response carrying `Content-Encoding` gets
`Vary: Accept-Encoding` unless its `Vary` already names it (or `*`), so caches
in front of Pingap keep the encodings apart. It is added at the `response` step
rather than on the upstream response, so Pingap's own cache, which already keys
on the chosen encoding, is not split further by every spelling of the request
header; a cached compressed entry gets it on every hit the same way.

Upstream mode also appends the chosen encoding to the cache key, so a cached
entry is per-encoding.

## Usage notes

- Downstream mode does not look at `Content-Type`; pingora's module applies its
  own rules. Upstream mode is the one to use when you need explicit control.
- `Accept-Encoding` is matched on token boundaries and honours `q=0`, using the
  same helper as [`accept_encoding`](accept_encoding.md), so `x-gzip` does not
  enable gzip and `gzip;q=0` is treated as "not acceptable".
- Compressing already-compressed formats (JPEG, PNG, MP4, `.gz`) wastes CPU.
  Upstream mode's content-type list handles this; in downstream mode rely on
  upstream `Content-Type` correctness.
- Brotli above level 9 and zstd above level 12 cost a lot of CPU for very little
  extra ratio on dynamic responses. 4–6 is a good default for both.
