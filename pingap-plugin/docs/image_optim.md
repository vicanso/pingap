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
| `png_quality` | int | `90` | 1–100: how close to the original the palette of a png has to be, see [PNG](#png). Unset or `0` is the default; any other value outside the range is a configuration error, for this and the three below. (They used to be cast to a byte first, so `300` passed as `44`.) |
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
(re-encoded at the configured quality) when it accepts none of them. An image
that is no smaller for being written again in its own format goes out as it
came: an icon, a png that has a palette already, a jpeg of a lower quality
than the one configured.
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

### PNG

The colours of a png are reduced to a palette: 256 at most, each with its
alpha. `png_quality` is how close to the original that palette has to be.

- An image of no more than 256 colours keeps the ones it has, pixel for
  pixel, whatever the value.
- An image of more colours gets a palette from
  [NeuQuant](https://github.com/image-rs/color_quant), a net that is trained
  on its colours, and is dithered: three quarters of what a pixel is off by
  is carried on to its neighbours, which keeps a gradient from breaking into
  bands.
- At `100` the palette is as large as it can be. Below that it is halved -
  128, 64, 32 colours - for as long as the error stays within what the value
  allows: a peak signal-to-noise ratio of 44 dB at the default of `90`,
  falling evenly to 30 dB at the lowest value. That is the palette against
  the image, every pixel with the entry nearest to it; dithering comes after
  and costs a decibel or two. An illustration or a screenshot with gradients
  gets smaller with a lower value.
- A palette is not halved either while one colour of the image would be more
  than twenty times as far from its entry as that allows for the image as a
  whole.
- A colour that is so far from every entry - the mark on a chart, the pin on
  a map: what a few pixels have and nothing else is near - is given an entry
  to itself, where there is one the rest of the image loses less by giving
  up, and for no more than one entry in sixteen. This is an effort and not a
  promise: with more such colours than that, the rest come out as the
  nearest colour there is.
- An image that 256 colours cannot bring that close gets 256, whatever the
  value. For most photographs a lower value changes nothing; send those as
  `webp` or `avif`, or leave them as `jpeg`.

Colours are compared as they are seen, multiplied by their alpha. A pixel
that is fully transparent stays fully transparent and has no colour in what
goes out; one that is seen faintly keeps its colour as exactly as its alpha
tells colours apart. An image with transparent pixels has an entry of the
palette for them.

The same image gives the same bytes every time a build converts it.

Up to 0.16 the palette came from `imagequant`, which is under
GPL-3.0-or-later. `color_quant` is MIT: a `full` build no longer contains code
under a copyleft license, and the png of an image is not the bytes it used
to be.

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
