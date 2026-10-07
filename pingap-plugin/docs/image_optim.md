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
| `output_types` | string | `""` | Comma-separated target formats in order of preference, e.g. `avif,webp`. Each is one of `avif`, `webp`, `jpeg`, `png`; anything else is a configuration error. |
| `png_quality` | int | `90` | 1–100. Unset or `0` is the default; any other value outside the range is a configuration error, for this and the three below. (They used to be cast to a byte first, so `300` passed as `44`.) |
| `jpeg_quality` | int | `80` | 1–100. |
| `avif_quality` | int | `75` | 1–100. |
| `avif_speed` | int | `3` | 1–10. Higher is faster and larger. |

Only `200` upstream responses of type `image/png` or `image/jpeg` are
candidates. Everything else passes through untouched, and so does an image
whose `Content-Length` is over 20 MB or that comes with a `Content-Encoding`.

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

At `early_request` the plugin looks at the client's `Accept` header, collects
the configured output MIME types the client accepts, sorts them and appends them
to the cache key — so an AVIF-capable browser and an old one get separate cache
entries instead of poisoning each other. A `PURGE` of the [`cache`](cache.md)
plugin removes the entry of every selection of formats. (This used to happen
at `request`, where a `cache` plugin listed first had answered the purge
before the formats were known to be a part of the key.)

A converted response loses its `Accept-Ranges`, and a strong `ETag` becomes a
weak one: both described the image the upstream sent. The `ETag` is weakened
on the way to the client, for every image of a kind the plugin reads or writes
and also when it comes from the cache; the cache keeps the upstream's own
validator to revalidate with.

At `upstream_response` the response is converted when the content type is
`image/png` or `image/jpeg` and the request has an `Accept` header. The target
is the first of `output_types` the client accepts, and the image's own format
(re-encoded at the configured quality) when it accepts none of them.
`Content-Type` is set to the target, `image/avif` for example.

The body is collected and converted once it is complete. What goes out is
always an image:

- The original is sent, as it came, when it cannot be converted: it does not
  decode, or it is larger than 16384 pixels on a side or 40 million pixels in
  all. The size is read from the image header before anything is decoded, so a
  small file describing a huge image costs nothing.
- An upstream that sends no `Content-Length` is collected up to 20 MB. Beyond
  that the body is passed on as it arrives.

In both cases the `Content-Type` has already been sent and names the target
format, while the body is the original. Browsers go by the content of an image
and display it; keep originals within the limits if something stricter reads
them.

## Usage notes

- **Always pair with [`cache`](cache.md).** Re-encoding AVIF is expensive
  (`avif_speed` trades quality for CPU); doing it per request will dominate your
  CPU profile.
- Order matters: list the cache plugin before this one so hits are served without
  re-encoding.
- The conversion runs on the worker thread that handles the request. With
  `basic.work_stealing` on (the default) the thread's other connections are
  moved to another worker for the duration; with it off they wait.
- `avif_speed` is the main knob. `1`–`2` produce the smallest files at a cost
  that is only reasonable behind a cache; `4`–`6` is a sane live default.
- The `Accept` check is a substring test against `image/<type>`, so
  `output_types = "webp"` matches an `Accept` containing `image/webp`.
