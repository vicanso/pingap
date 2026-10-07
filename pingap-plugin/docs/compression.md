# compression

Response compression with gzip, brotli and zstd. Two modes:

- **downstream mode** (default) — configures pingora's built-in compression
  module, which compresses on the way out to the client.
- **upstream mode** (`mode = "upstream"`) — Pingap compresses the upstream
  response body itself as it streams through, before the response reaches the
  [`cache`](cache.md) plugin, so what is cached is the compressed form.

`types`, `min_length` and `skip` decide which responses are compressed in both
modes.

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
| `types` | string[] | per mode | Content types to compress, each a prefix (`text/`, `application/json`); `*` for any. See [Which responses are compressed](#which-responses-are-compressed). |
| `min_length` | int | `0` | Responses whose `Content-Length` is below this are not compressed. One without a `Content-Length` is. |
| `skip` | string | — | Regular expression; a request whose path and query match is not compressed. |
| `decompression` | bool | absent | Presence of the key toggles decompression of compressed upstream responses. |

Levels outside their range are clamped to it (a negative level is `0`).

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

A static site: text is compressed, fonts and documents (`font/woff2`,
`application/pdf`) are not, and neither is anything under `/download/`:

```toml
[plugins.compression]
category = "compression"
gzip_level = 6
br_level = 6
types = [
  "text/",
  "application/json",
  "application/javascript",
  "application/xml",
  "image/svg+xml",
]
min_length = 256
skip = "^/download/"
```

## Which responses are compressed

- **`types`** — each entry is the beginning of a content type, compared
  without regard to case and without the parameters (`; charset=utf-8`):
  `text/` takes every `text/*`, `application/json` takes that and whatever
  else begins so (`application/json-seq`). `*` takes any type. A response
  with no `Content-Type` is never compressed. Without the key each mode keeps
  its own rule:

  | Mode | Without `types` | With `types` |
  | --- | --- | --- |
  | downstream | pingora's rule: `text/*`, `application/*`, `font/*`, `image/svg+xml`, the icon types and `binary/octet-stream`, unless the type has `zip` in it | the listed types, as far as pingora's rule takes them too |
  | upstream | `application/json`, `application/xml`, `text/html`, any `text/*` | the listed types and nothing else |

  An empty list is a configuration error rather than "compress nothing".
- **`min_length`** — a response that says in `Content-Length` that it is
  shorter is passed on as it is. A response without `Content-Length`
  (chunked) is compressed: its length is not known when the decision is
  made. In downstream mode pingora has a floor of its own, twenty bytes.
- **`skip`** — a regular expression that is asked about the path and query of
  the request (`/download/a.html?raw=1`), as the client sent them: a
  `rewrite` of the location does not change what it sees. A request that
  matches is treated as one from a client that takes no coding.

The list of downstream mode can only narrow pingora's rule: `image/png` in it
does not make pingora compress one. What it is for is the wide
`application/*` and `font/*` of that rule, which take in formats that are
compressed already (`font/woff2`, `application/pdf`, `application/wasm`
served precompressed) and bodies not worth the CPU (`application/octet-stream`
downloads).

In downstream mode `types` and `min_length` also cover what another plugin
answers with, the files of [`directory`](directory.md) above all: pingora
compresses those like any other response unless a list says otherwise.

Until now `min_length` was read in upstream mode only. A configuration of the
default mode that carries the key anyway has it applied from this version on.

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
3. It has a `Content-Type` that is compressible: one of `types` when that is
   set, otherwise `application/json`, `application/xml`, `text/html`, or any
   `text/*`.
4. The client accepts one of the enabled algorithms, and the request is not
   one `skip` takes out.
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

Which coding a response gets, `skip` included, is settled once, when the
request comes in, and is what goes into the cache key; the response is
compressed by that and not by the request as later steps have left it (a
location's rewrite, a parameter `key_auth` took out of the query, an
`Accept-Encoding` another plugin replaced).

Upstream mode also appends the chosen encoding to the cache key, so a cached
entry is per-encoding. A `PURGE` of the [`cache`](cache.md) plugin removes the
entry of every encoding.

## Usage notes

- Without `types`, downstream mode leaves the content type to pingora's
  module, which takes every `application/*` and `font/*` along with text. Set
  `types` to say which.
- `Accept-Encoding` is matched on token boundaries and honours `q=0`, using the
  same helper as [`accept_encoding`](accept_encoding.md), so `x-gzip` does not
  enable gzip and `gzip;q=0` is treated as "not acceptable".
- Compressing already-compressed formats (WOFF2, PDF, `.gz`) wastes CPU.
  Upstream mode's content-type list handles this; in downstream mode pingora
  leaves out images, video and anything with `zip` in its type, and `types`
  takes care of the rest.
- `Accept-Encoding: *` is not taken as accepting the enabled codings, as in
  nginx: a coding has to be named.
- Brotli above level 9 and zstd above level 12 cost a lot of CPU for very little
  extra ratio on dynamic responses. 4–6 is a good default for both.
