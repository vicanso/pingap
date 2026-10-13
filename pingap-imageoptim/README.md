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
| `png_quality` | int | `90` | 1–100: how close to the original the palette of a png has to be. Unset or `0` is the default, any other value outside the range is a configuration error (also for the three below). |
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

| Format | Crate | License |
| --- | --- | --- |
| PNG | `color_quant` (the palette) + `lodepng` (the file) | MIT, Zlib |
| JPEG | `mozjpeg` | IJG, Zlib, BSD-3-Clause |
| WebP / AVIF | `image` (with the `webp` and `avif` features; `ravif` and `rav1e` for AVIF) | MIT or Apache-2.0, BSD-3-Clause, BSD-2-Clause |

Some of these compile native code, which is why the crate is optional: it makes
the default build noticeably slower and larger.

None of them is under a copyleft license. The palette of a png came from
`imagequant` up to 0.16, which is GPL-3.0-or-later and made a `full` build a
work under that license.

### The palette of a png

The palette is NeuQuant's, from
[`color_quant`](https://github.com/image-rs/color_quant): a net of as many
neurons as there are to be colours. `src/quantize.rs` is what it is trained on
and what is made of it:

- **The colours are counted**, premultiplied by their alpha so that the
  colour of a pixel counts by as much as is seen of it. An image of no more
  than 256 of them keeps them as they are, without a net and whatever the
  quality: a net of fewer colours, with the grain dithering adds, is more
  often the larger file. For the others the net is trained on a sample of
  65536 pixels at most, each colour as often as its share of the image (and
  at least once, while there are no more than 32768 of them; beyond that the
  colours that share their upper bits are put together). An image of fewer
  than 16384 pixels is gone through until there are that many: a net that
  has seen each pixel of an icon once is several decibels worse.
- **The entries are settled**: each is moved to the mean of the colours it
  is the entry of. A neuron is left near that mean and seldom on it, which
  on a flat area is one step off and, dithered, a scatter of the next
  colour.
- **A colour no neuron is near gets an entry to itself**, up to one in
  sixteen. A net maps where most of the colours are; the mark on a chart has
  none of its own. The entry is taken from the pixels that lose least by
  going to the entry nearest to theirs - as a rule one two neurons share or
  no pixel has - and only where that is less than the colour gains: taking
  the only entry of another small part of the image sent a shadow out as
  opaque blue.
- **`png_quality` is a limit on the error**, measured here: the mean squared
  distance of every pixel from its entry, as a peak signal-to-noise ratio
  (44 dB at 90, 30 dB at the low end), and for the one colour that is
  furthest from its entry twenty times that distance. The palette is 256
  colours and halved, down to 32, for as long as it stays within both; at 100
  it is not halved. NeuQuant's documentation asks for 64 neurons or more
  and its code says it is not tuned for fewer than 26; a net of 32 is taken
  like any other, when its error is within the limit.
- **The pixels are given their entries here**, three quarters of the error
  of each carried on to its neighbours, every other row from right to left,
  and no more than 24 levels a channel to any one pixel.
  `image::imageops::dither` is not used: it indexes past an image that is one
  pixel wide, and a release build (`panic = "abort"`) ends on a panic.
- **A pixel that is fully transparent stays that**: it takes the clear entry,
  which the palette is given where the net has no neuron there.

## Performance

Re-encoding is CPU-bound and, for AVIF, expensive. Always put a
[`cache`](../pingap-plugin/docs/cache.md) plugin in front so each image is
converted once per variant rather than once per request, and list the cache
plugin **before** `image_optim` in the location's `plugins`.

`avif_speed` is the main trade-off knob: `1`–`2` produce the smallest files and
are only viable behind a warm cache; `4`–`6` is a reasonable live default.

## License

Apache-2.0.
