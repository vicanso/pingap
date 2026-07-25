# accept_encoding

Rewrites the client's `Accept-Encoding` header into a canonical form before the
request is routed, so upstreams and the cache see a small, predictable set of
values instead of whatever the browser happened to send.

Two problems this solves:

- **Cache fragmentation.** `gzip, deflate, br` and `br, gzip` are the same thing
  to an origin but different cache variants. Rewriting both to `br` collapses
  them.
- **Unwanted encodings.** An upstream that supports zstd may produce responses
  Pingap would rather compress itself, or that a middlebox cannot handle.

- **Step:** `early_request` (fixed — it must run before routing and caching)
- **Registered as:** `accept_encoding`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `accept_encoding`. |
| `encodings` | string | `""` | Comma-separated list of encodings to keep, **in priority order**. |
| `only_one_encoding` | bool | `false` | Keep only the first encoding the client actually accepts. |

The output header is built by walking `encodings` in order and keeping those the
client listed, so the resulting order is yours, not the client's. Matching is
done on comma/`;` token boundaries and honours `q=0`, so `x-gzip` does not match
`gzip` and `gzip;q=0` is treated as "not acceptable".

If the client sent no `Accept-Encoding` at all the plugin does nothing. If none
of the configured encodings are acceptable, the header is removed entirely.

## Examples

Prefer zstd, then brotli, then gzip, and forward only the best one:

```toml
[plugins.acceptEncoding]
category = "accept_encoding"
encodings = "zstd, br, gzip"
only_one_encoding = true
```

| Client sends | Forwarded |
| --- | --- |
| `gzip, deflate, br` | `br` |
| `zstd, gzip` | `zstd` |
| `deflate` | *(header removed)* |
| `br;q=0, gzip` | `gzip` |

Keep the full ordered list instead (useful when the upstream picks):

```toml
[plugins.acceptEncoding]
category = "accept_encoding"
encodings = "br, gzip"
```

`gzip, br` from the client becomes `br, gzip`.

## Usage notes

- Pair this with [`cache`](cache.md) and add `Accept-Encoding` to the cache key
  headers; the normalised value keeps the number of variants bounded.
- When [`compression`](compression.md) does the compressing, list only the
  encodings Pingap is configured to produce.
