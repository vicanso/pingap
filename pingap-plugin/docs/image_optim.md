# image_optim

Re-encodes PNG and JPEG responses into a modern format (WebP or AVIF) when the
client advertises support for it, and re-encodes them in place otherwise. Lives
in the [`pingap-imageoptim`](../../pingap-imageoptim/README.md) crate.

- **Step:** `request` (cache-key contribution), `upstream_response` and
  `upstream_response_body` (the actual conversion)
- **Registered as:** `image_optim`
- **Requires the `imageoptim` cargo feature** (included in `full`)

```bash
cargo build --features=imageoptim
```

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `image_optim`. |
| `output_types` | string | `""` | Comma-separated target formats, e.g. `avif,webp`. |
| `png_quality` | int | `90` | 1–100. Out-of-range values reset to the default. |
| `jpeg_quality` | int | `80` | 1–100. |
| `avif_quality` | int | `75` | 1–100. |
| `avif_speed` | int | `3` | 1–10. Higher is faster and larger. |

Only `image/png` and `image/jpeg` upstream responses are candidates. Everything
else passes through untouched.

## Example

```toml
[plugins.imageOptim]
category = "image_optim"
output_types = "avif,webp"
png_quality = 85
jpeg_quality = 80
avif_quality = 70
avif_speed = 4

[plugins.imageCache]
category = "cache"
directory = "/opt/pingap/cache"
max_file_size = "10mb"

[locations.images]
upstream = "images"
path = "/images"
plugins = ["imageCache", "imageOptim"]
```

## Behaviour

At `request` the plugin looks at the client's `Accept` header, collects the
configured output MIME types the client accepts, sorts them and appends them to
the cache key — so an AVIF-capable browser and an old one get separate cache
entries instead of poisoning each other.

At `upstream_response` the response is converted when the content type is
`image/png` or `image/jpeg` and the client accepts one of `output_types`. The
body is then re-encoded as it streams.

## Usage notes

- **Always pair with [`cache`](cache.md).** Re-encoding AVIF is expensive
  (`avif_speed` trades quality for CPU); doing it per request will dominate your
  CPU profile.
- Order matters: list the cache plugin before this one so hits are served without
  re-encoding.
- `avif_speed` is the main knob. `1`–`2` produce the smallest files at a cost
  that is only reasonable behind a cache; `4`–`6` is a sane live default.
- The `Accept` check is a substring test against `image/<type>`, so
  `output_types = "webp"` matches an `Accept` containing `image/webp`.
