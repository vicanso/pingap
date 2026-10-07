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
algorithm the client accepts wins, wherever the client lists it: a browser
sends `gzip, deflate, br, zstd` and gets zstd when zstd is enabled. To make
that so in `response` mode the plugin moves its choice to the front of the
request's `Accept-Encoding` (`zstd, gzip, deflate, br`), which is also what the
upstream receives; the set of encodings is unchanged.

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

## Responses that are never compressed

In both modes two kinds of response are passed on as the upstream sent them:

- `Content-Type: text/event-stream`. A compressor hands its output over when
  its buffer is full or the body ends, so the events of a stream — a few bytes
  each, sent as they happen — would all reach the client together when the
  stream closes.
- A response with `Cache-Control: no-transform`, which forbids changing the
  content coding (RFC 9111 5.2.2.6). In downstream mode that includes
  `decompression`: a response that arrives compressed is passed on compressed. An upstream that streams in another
  format (newline-delimited JSON, a chunked AI completion) can set it to keep
  its chunks flowing through a location that has compression on.

## Upstream mode details

The response is compressed only when **all** of these hold:

1. It has a body: HEAD answers, `1xx`, `204` and `304` are left alone, since
   encoding nothing would still emit the format's header and footer.
2. It has no `Content-Encoding` yet, and is not one of the responses above.
   Nor is it a part of a body: a `206`, or anything with a `Content-Range`,
   is passed on as it is. Compressed, the hundred bytes a range request asked
   for came back as the gzip of those bytes, under a `Content-Range` that
   still counted in the bytes of the original.
3. It has a `Content-Type` that is compressible: `application/json`,
   `application/xml`, `text/html`, or any `text/*`.
4. The client accepts one of the enabled algorithms.
5. `min_length` is `0`, or `Content-Length` is present and at least `min_length`.
   A response with no `Content-Length` is always compressed.

When it does compress, `Content-Length` is removed, `Transfer-Encoding: chunked`
and `Content-Encoding` are set, and the body is encoded incrementally.
`Accept-Ranges` is removed and a strong `ETag` is made a weak one (`"v1"`
becomes `W/"v1"`), as nginx and pingora's own compression do it: both are
statements about the bytes the upstream sent, which these no longer are. The
`ETag` is weakened on the way to the client, also for a response from the
cache; what the cache stores keeps the validator as the upstream gave it, so a
revalidation asks the upstream with the value it knows.

When the client accepts one of the enabled codings, the upstream is asked for
that coding and no other: `Accept-Encoding` is rewritten to it (this is also
what the access log shows). Passed on as the client sent it, an upstream that
compresses by itself answered in a coding of its own choice, `br` to a client
that takes `br` and `gzip`, and with a `cache` plugin that answer was stored
under the key of the coding chosen here and served to clients that take only
that one. When the client accepts none of them the header is passed on
untouched; an upstream that then compresses for that client gets
`Vary: Accept-Encoding` added to its response unless it says so itself, so
that the cache keeps the answers to different headers apart. With no level
enabled at all the plugin leaves requests and cache keys alone.

On the way out to the client, any response carrying `Content-Encoding` gets
`Vary: Accept-Encoding` unless its `Vary` already names it (or `*`), so caches
in front of Pingap keep the encodings apart. It is added at the `response` step
rather than on the upstream response, so Pingap's own cache, which already keys
on the chosen encoding, is not split further by every spelling of the request
header; a cached compressed entry gets it on every hit the same way.

Upstream mode also appends the chosen encoding to the cache key, so a cached
entry is per-encoding. A `PURGE` of the [`cache`](cache.md) plugin removes the
entry of every encoding.

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
