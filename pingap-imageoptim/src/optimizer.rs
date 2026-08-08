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
use image::{ImageFormat, RgbaImage, load};
use lodepng::Bitmap;
use rgb::{ComponentBytes, RGBA8};
use snafu::{ResultExt, Snafu};
use std::{ffi::OsStr, io::Cursor};

#[derive(Debug, Snafu)]
pub enum ImageError {
    #[snafu(display("Image format is not supported"))]
    NotSupported,
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

pub(crate) fn load_image(data: &[u8], ext: &str) -> Result<ImageInfo> {
    let format = image::guess_format(data).or_else(|_| {
        ImageFormat::from_extension(OsStr::new(ext))
            .ok_or(ImageError::NotSupported)
    })?;
    let di = load(Cursor::new(&data), format).context(ImageSnafu {
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
