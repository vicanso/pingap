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

use image::codecs::avif;
use image::codecs::webp;
use image::ImageEncoder;
use image::{load, ImageFormat, RgbaImage};
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
        let mut buffer = Vec::with_capacity(width * height);

        for ele in img.chunks(4) {
            buffer.push(RGBA8 {
                r: ele[0],
                g: ele[1],
                b: ele[2],
                a: ele[3],
            })
        }

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
    let mut comp = comp.start_compress(Vec::new()).context(IoSnafu {})?;
    comp.write_scanlines(info.buffer.as_bytes())
        .context(IoSnafu {})?;
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
