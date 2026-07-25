# Pingap ImageOptim

On-the-fly image optimization for [Pingap](https://github.com/vicanso/pingap).

This crate provides the `image_optim` plugin: it intercepts PNG and JPEG
responses coming back from an upstream and re-encodes them — either at a lower
quality in the same format, or into a modern format (WebP or AVIF) when the
client says it accepts one.

The point is to get the bandwidth savings of modern formats without changing the
origin: the origin keeps storing PNG/JPEG, and Pingap negotiates per client.

## Building

The crate is behind a cargo feature and is not compiled by default:

```bash
cargo build --features=imageoptim     # or --features=full
```

## Supported formats

| Direction | Formats |
| --- | --- |
| Input (from upstream) | `image/png`, `image/jpeg` |
| Output (to client) | `png`, `jpeg`, `webp`, `avif` |

## Configuration

Registered as plugin category `image_optim`:

```toml
[plugins.imageOptim]
category = "image_optim"
output_types = "avif,webp"
png_quality = 85
jpeg_quality = 80
avif_quality = 70
avif_speed = 4
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `output_types` | string | `""` | Comma-separated target formats. Each becomes `image/<format>` and is matched against the client's `Accept`. |
| `png_quality` | int | `90` | 1–100; out-of-range resets to the default. |
| `jpeg_quality` | int | `80` | 1–100. |
| `avif_quality` | int | `75` | 1–100. |
| `avif_speed` | int | `3` | 1–10. Higher is faster to encode and produces larger files. |

Full plugin documentation, including the cache interaction, is in
[pingap-plugin/docs/image_optim.md](../pingap-plugin/docs/image_optim.md).

## How it works

1. **`request` step** — the client's `Accept` header is inspected. Every
   configured output MIME type the client accepts is sorted and appended to the
   cache key, so AVIF-capable and legacy clients get separate cache entries.
2. **`upstream_response` step** — if the response is PNG or JPEG and the client
   accepts one of `output_types`, a body modifier is installed and the response
   is re-framed as chunked.
3. **`upstream_response_body` step** — the body is buffered and re-encoded, and
   `Content-Type` is updated to the chosen format.

## Underlying encoders

| Format | Crate |
| --- | --- |
| PNG | `imagequant` + `lodepng` |
| JPEG | `mozjpeg` |
| WebP / AVIF | `image` (with the `webp` and `avif` features) |

Some of these compile native code, which is why the crate is optional: it makes
the default build noticeably slower and larger.

## Performance

Re-encoding is CPU-bound and, for AVIF, expensive. Always put a
[`cache`](../pingap-plugin/docs/cache.md) plugin in front so each image is
converted once per variant rather than once per request, and list the cache
plugin **before** `image_optim` in the location's `plugins`.

`avif_speed` is the main trade-off knob: `1`–`2` produce the smallest files and
are only viable behind a warm cache; `4`–`6` is a reasonable live default.

## License

Apache-2.0.
