// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use image::ImageEncoder;
use image::codecs::avif;
use image::codecs::webp;
use image::{ImageFormat, ImageReader, Limits, RgbaImage};
use lodepng::Bitmap;
use rgb::{ComponentBytes, RGBA8};
use snafu::{ResultExt, Snafu};
use std::{ffi::OsStr, io::Cursor};

/// The longest side of an image that is converted.
pub(crate) const MAX_DIMENSION: u32 = 16_384;
/// The most pixels of an image that is converted: an 8K frame fits, and
/// decoded it takes 160MB at four bytes a pixel.
pub(crate) const MAX_PIXELS: u64 = 40_000_000;

#[derive(Debug, Snafu)]
pub enum ImageError {
    #[snafu(display("Image format is not supported"))]
    NotSupported,
    #[snafu(display("Image is too large, {width}x{height}"))]
    TooLarge { width: u32, height: u32 },
    #[snafu(display(
        "Handle image fail, category:{category}, message:{source}"
    ))]
    Image {
        category: String,
        source: image::ImageError,
    },
    #[snafu(display(
        "Handle image fail, category:{category}, message:{source}"
    ))]
    ImageQuant {
        category: String,
        source: imagequant::Error,
    },
    #[snafu(display(
        "Handle image fail, category:{category}, message:{source}"
    ))]
    LodePNG {
        category: String,
        source: lodepng::Error,
    },

    #[snafu(display("Io fail, {source}"))]
    Io { source: std::io::Error },
}

type Result<T, E = ImageError> = std::result::Result<T, E>;

pub struct ImageInfo {
    // rgba像素
    pub buffer: Vec<RGBA8>,
    /// Width in pixels
    pub width: usize,
    /// Height in pixels
    pub height: usize,
}

impl From<Bitmap<RGBA8>> for ImageInfo {
    fn from(info: Bitmap<RGBA8>) -> Self {
        ImageInfo {
            buffer: info.buffer,
            width: info.width,
            height: info.height,
        }
    }
}

impl From<RgbaImage> for ImageInfo {
    fn from(img: RgbaImage) -> Self {
        let width = img.width() as usize;
        let height = img.height() as usize;
        let raw_buffer: Vec<u8> = img.into_raw();
        let buffer: Vec<RGBA8> = bytemuck::cast_vec(raw_buffer);

        ImageInfo {
            buffer,
            width,
            height,
        }
    }
}

/// Decodes `data` into pixels.
///
/// The size is read from the header and checked before anything is
/// decoded. A few kilobytes of png can describe an image of gigabytes, and
/// decoding it took the memory for all of them; a side beyond what jpeg
/// can hold made the jpeg encoder give up by panicking, which a release
/// build turns into an abort of the whole process.
pub(crate) fn load_image(data: &[u8], ext: &str) -> Result<ImageInfo> {
    let format = image::guess_format(data).or_else(|_| {
        ImageFormat::from_extension(OsStr::new(ext))
            .ok_or(ImageError::NotSupported)
    })?;
    let (width, height) = ImageReader::with_format(Cursor::new(data), format)
        .into_dimensions()
        .context(ImageSnafu {
            category: "load_image",
        })?;
    if width == 0
        || height == 0
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
        || width as u64 * height as u64 > MAX_PIXELS
    {
        return Err(ImageError::TooLarge { width, height });
    }
    let mut reader = ImageReader::with_format(Cursor::new(data), format);
    // The decoder's own working memory, on top of the pixels.
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_PIXELS * 8);
    reader.limits(limits);
    let di = reader.decode().context(ImageSnafu {
        category: "load_image",
    })?;
    Ok(di.to_rgba8().into())
}

pub(crate) fn optimize_png(info: &ImageInfo, quality: u8) -> Result<Vec<u8>> {
    let mut liq = imagequant::new();
    liq.set_quality(0, quality).context(ImageQuantSnafu {
        category: "png_set_quality",
    })?;

    let width = info.width;
    let height = info.height;
    let mut img = liq
        .new_image(info.buffer.as_ref(), width, height, 0.0)
        .context(ImageQuantSnafu {
            category: "png_new_image",
        })?;

    let mut res = liq.quantize(&mut img).context(ImageQuantSnafu {
        category: "png_quantize",
    })?;

    res.set_dithering_level(1.0).context(ImageQuantSnafu {
        category: "png_set_level",
    })?;

    let (palette, pixels) =
        res.remapped(&mut img).context(ImageQuantSnafu {
            category: "png_remapped",
        })?;
    let mut enc = lodepng::Encoder::new();
    enc.set_palette(&palette).context(LodePNGSnafu {
        category: "png_encoder",
    })?;

    let buf = enc.encode(&pixels, width, height).context(LodePNGSnafu {
        category: "png_encode",
    })?;

    Ok(buf)
}

pub(crate) fn optimize_jpeg(info: &ImageInfo, quality: u8) -> Result<Vec<u8>> {
    let mut comp = mozjpeg::Compress::new(mozjpeg::ColorSpace::JCS_RGB);
    comp.set_size(info.width, info.height);
    comp.set_quality(quality as f32);
    let mut comp = comp
        .start_compress(Vec::with_capacity(info.buffer.len() * 3 / 4))
        .context(IoSnafu {})?;

    let rgb_buffer: Vec<u8> = info
        .buffer
        .iter()
        .flat_map(|rgba| [rgba.r, rgba.g, rgba.b])
        .collect();
    comp.write_scanlines(&rgb_buffer).context(IoSnafu {})?;

    let data = comp.finish().context(IoSnafu {})?;
    Ok(data)
}

pub(crate) fn optimize_avif(
    info: &ImageInfo,
    quality: u8,
    speed: u8,
) -> Result<Vec<u8>> {
    let mut w = Vec::new();
    let mut sp = speed;
    if sp == 0 {
        sp = 3;
    }

    let img = avif::AvifEncoder::new_with_speed_quality(&mut w, sp, quality);
    img.write_image(
        info.buffer.as_bytes(),
        info.width as u32,
        info.height as u32,
        image::ColorType::Rgba8.into(),
    )
    .context(ImageSnafu {
        category: "avif_encode",
    })?;

    Ok(w)
}

pub(crate) fn optimize_webp(info: &ImageInfo, _quality: u8) -> Result<Vec<u8>> {
    let mut w = Vec::new();

    let img = webp::WebPEncoder::new_lossless(&mut w);

    img.encode(
        info.buffer.as_bytes(),
        info.width as u32,
        info.height as u32,
        image::ColorType::Rgba8.into(),
    )
    .context(ImageSnafu {
        category: "webp_encode",
    })?;

    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageEncoder, RgbaImage};
    use pretty_assertions::assert_eq;

    fn sample() -> RgbaImage {
        RgbaImage::from_fn(4, 3, |x, y| {
            image::Rgba([(x * 60) as u8, (y * 80) as u8, 0, 255])
        })
    }

    /// `image` is pulled with `default-features = false`, so every decoder this
    /// crate needs has to be listed explicitly. Decoding is what breaks if one
    /// is missing, and it breaks at runtime rather than at compile time, so
    /// pin the four formats the plugin accepts.
    #[test]
    fn test_every_supported_format_decodes() {
        let img = sample();

        let mut png = Vec::new();
        image::codecs::png::PngEncoder::new(&mut png)
            .write_image(img.as_raw(), 4, 3, image::ExtendedColorType::Rgba8)
            .unwrap();

        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
            .write_image(
                image::DynamicImage::ImageRgba8(img.clone())
                    .to_rgb8()
                    .as_raw(),
                4,
                3,
                image::ExtendedColorType::Rgb8,
            )
            .unwrap();

        let mut webp = Vec::new();
        image::codecs::webp::WebPEncoder::new_lossless(&mut webp)
            .encode(img.as_raw(), 4, 3, image::ExtendedColorType::Rgba8)
            .unwrap();

        for (ext, data) in [("png", &png), ("jpeg", &jpeg), ("webp", &webp)] {
            let info = load_image(data, ext)
                .unwrap_or_else(|e| panic!("{ext} failed to decode: {e}"));
            assert_eq!(4, info.width, "{ext}");
            assert_eq!(3, info.height, "{ext}");
        }
    }

    /// Regression: the size in the header is checked before the pixels are
    /// decoded. A small file describing a huge image used to be decoded in
    /// full.
    #[test]
    fn test_oversized_image_is_refused() {
        // A png that announces 60000x60000 and has next to no data: 14GB
        // of pixels if anything went on to decode it.
        let chunk = |kind: &[u8; 4], data: &[u8]| {
            let mut body = kind.to_vec();
            body.extend_from_slice(data);
            let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
            chunk.extend_from_slice(&body);
            chunk.extend_from_slice(&crc32(&body).to_be_bytes());
            chunk
        };
        let mut ihdr = 60_000u32.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&60_000u32.to_be_bytes());
        // 8 bit rgba, default compression, filter and interlace
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        png.extend(chunk(b"IHDR", &ihdr));
        // an empty zlib stream
        png.extend(chunk(b"IDAT", &[0x78, 0x9c, 0x03, 0, 0, 0, 0, 1]));
        png.extend(chunk(b"IEND", &[]));

        let err = load_image(&png, "png").err().unwrap().to_string();
        assert_eq!("Image is too large, 60000x60000", err);

        // One pixel over the longest side, and a real image this time.
        let width = MAX_DIMENSION + 1;
        let mut png = Vec::new();
        image::codecs::png::PngEncoder::new(&mut png)
            .write_image(
                &vec![0u8; width as usize],
                width,
                1,
                image::ExtendedColorType::L8,
            )
            .unwrap();
        let err = load_image(&png, "png").err().unwrap().to_string();
        assert_eq!(format!("Image is too large, {width}x1"), err);
    }

    /// The crc of a png chunk.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for byte in data {
            crc ^= *byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// avif is the encoder that keeps rav1e - and therefore paste
    /// (RUSTSEC-2024-0436) - in the tree, so make sure it is actually used.
    #[test]
    fn test_avif_encodes() {
        let info: ImageInfo = sample().into();
        let out = optimize_avif(&info, 60, 10).unwrap();
        assert!(!out.is_empty());
        assert_eq!(
            Some(image::ImageFormat::Avif),
            image::guess_format(&out).ok()
        );
    }
}
