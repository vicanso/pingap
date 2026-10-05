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

use crate::optimizer::{
    ImageError, load_image, optimize_avif, optimize_jpeg, optimize_png,
    optimize_webp,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use ctor::ctor;
use pingap_config::PluginConf;
use pingap_core::HTTP_HEADER_TRANSFER_CHUNKED;
use pingap_core::{
    Ctx, Plugin, PluginStep, RequestPluginResult, ResponsePluginResult,
};
use pingap_core::{ModifyResponseBody, ResponseBodyPluginResult};
use pingap_plugin::{
    Error, get_hash_key, get_int_conf, get_plugin_factory, get_str_conf,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::borrow::Cow;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::sync::Arc;
use tracing::{debug, warn};

mod optimizer;

const PLUGIN_ID: &str = "_image_optimize_";

/// The largest original that is converted, in bytes. A larger one is
/// passed on as it is.
const MAX_IMAGE_SIZE: usize = 20 * 1024 * 1024;

/// The formats an image can be converted to.
const OUTPUT_FORMATS: &[&str] = &["avif", "webp", "jpeg", "png"];

type Result<T, E = Error> = std::result::Result<T, E>;

struct ImageOptimizer {
    /// The format of the original, `png` or `jpeg`.
    image_type: String,
    png_quality: u8,
    jpeg_quality: u8,
    avif_quality: u8,
    avif_speed: u8,
    webp_quality: u8,
    /// The format to convert to, one of `OUTPUT_FORMATS`.
    format_type: String,
    buffer: BytesMut,
    /// The original turned out too large to convert: what was held back
    /// has been released, and the rest goes through as it comes.
    passthrough: bool,
}

/// Runs `f`, a long computation, without holding up the other connections
/// of this worker thread.
///
/// Decoding and encoding an image takes from tens of milliseconds to
/// seconds, and the body filter it happens in is not async. On the
/// work-stealing runtime `block_in_place` moves the worker's other tasks to
/// another thread first. A runtime without work stealing has no such
/// thread to move them to, and there `f` simply runs.
fn run_blocking<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        },
        _ => f(),
    }
}

impl ImageOptimizer {
    fn optimize(&self, data: &[u8]) -> Result<Vec<u8>, ImageError> {
        let info = load_image(data, &self.image_type)?;
        match self.format_type.as_str() {
            "jpeg" => optimize_jpeg(&info, self.jpeg_quality),
            "avif" => optimize_avif(&info, self.avif_quality, self.avif_speed),
            "webp" => optimize_webp(&info, self.webp_quality),
            _ => optimize_png(&info, self.png_quality),
        }
    }
}

impl ModifyResponseBody for ImageOptimizer {
    fn handle(
        &mut self,
        _session: &Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if self.passthrough {
            return Ok(());
        }
        if let Some(data) = body {
            // Without a `Content-Length` the size is only known once it
            // has been exceeded. The body used to be collected whatever
            // its size.
            if self.buffer.len() + data.len() > MAX_IMAGE_SIZE {
                self.passthrough = true;
                self.buffer.extend_from_slice(data);
                *data = self.buffer.split().freeze();
                return Ok(());
            }
            self.buffer.extend_from_slice(data);
            data.clear();
        }
        if !end_of_stream {
            return Ok(());
        }
        let original = self.buffer.split().freeze();
        let optimized = run_blocking(|| self.optimize(&original));
        *body = Some(match optimized {
            Ok(data) => Bytes::from(data),
            // The original is what there is to send. A failure used to
            // leave the body empty: a 200 with no image in it.
            Err(e) => {
                warn!(
                    error = %e,
                    image_type = self.image_type,
                    format_type = self.format_type,
                    "optimize image fail, the original is sent"
                );
                original
            },
        });
        Ok(())
    }
    fn name(&self) -> &str {
        "image_optimization"
    }
}

pub struct ImageOptim {
    /// A unique identifier for this plugin instance.
    /// Used for internal tracking and debugging purposes.
    hash_value: String,
    support_types: HashSet<String>,
    /// The formats to convert to, in order of preference.
    output_types: Vec<String>,
    /// The media type of each of `output_types`, in the same order.
    output_mimes: Vec<String>,
    png_quality: u8,
    jpeg_quality: u8,
    avif_quality: u8,
    avif_speed: u8,
}

impl TryFrom<&PluginConf> for ImageOptim {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        debug!(params = value.to_string(), "new image optimizer plugin");
        let hash_value = get_hash_key(value);

        let output_types: Vec<String> = get_str_conf(value, "output_types")
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        // A format that is not known can not be produced. It used to be
        // taken as it was: the response was announced as `image/<format>`
        // and its body encoded as png.
        if let Some(format) = output_types
            .iter()
            .find(|format| !OUTPUT_FORMATS.contains(&format.as_str()))
        {
            return Err(Error::Invalid {
                category: "image_optim".to_string(),
                message: format!(
                    "output type {format} is not supported, expected one of {}",
                    OUTPUT_FORMATS.join(", ")
                ),
            });
        }
        let output_mimes = output_types
            .iter()
            .map(|format| format!("image/{}", format))
            .collect();

        let mut png_quality = get_int_conf(value, "png_quality") as u8;
        if png_quality == 0 || png_quality > 100 {
            png_quality = 90;
        }
        let mut jpeg_quality = get_int_conf(value, "jpeg_quality") as u8;
        if jpeg_quality == 0 || jpeg_quality > 100 {
            jpeg_quality = 80;
        }
        let mut avif_quality = get_int_conf(value, "avif_quality") as u8;
        if avif_quality == 0 || avif_quality > 100 {
            avif_quality = 75;
        }
        let mut avif_speed = get_int_conf(value, "avif_speed") as u8;
        if avif_speed == 0 || avif_speed > 10 {
            avif_speed = 3;
        }
        Ok(Self {
            hash_value,
            support_types: HashSet::from([
                "jpeg".to_string(),
                "png".to_string(),
            ]),
            output_types,
            output_mimes,
            png_quality,
            jpeg_quality,
            avif_quality,
            avif_speed,
        })
    }
}

impl ImageOptim {
    pub fn new(params: &PluginConf) -> Result<Self> {
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for ImageOptim {
    /// Returns a unique identifier for this plugin instance
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }

        if let Some(accept) = session.get_header(http::header::ACCEPT)
            && let Ok(accept_str) = accept.to_str()
        {
            let mut accept_images: Vec<_> = self
                .output_mimes
                .iter()
                .filter(|mime| accept_str.contains(*mime))
                .cloned()
                .collect();

            if !accept_images.is_empty() {
                accept_images.sort();
                ctx.extend_cache_keys(accept_images);
            }
        }
        Ok(RequestPluginResult::Continue)
    }
    fn handle_upstream_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        // A partial or an empty response is not an image to convert.
        if upstream_response.status != http::StatusCode::OK {
            return Ok(ResponsePluginResult::Unchanged);
        }
        let content_type = if let Some(value) =
            upstream_response.headers.get(http::header::CONTENT_TYPE)
        {
            value.to_str().unwrap_or_default()
        } else {
            return Ok(ResponsePluginResult::Unchanged);
        };

        // The media type without its parameters.
        let media_type = content_type.split(';').next().unwrap_or_default();
        let Some(image_type) = media_type.trim().strip_prefix("image/") else {
            return Ok(ResponsePluginResult::Unchanged);
        };

        if !self.support_types.contains(image_type) {
            return Ok(ResponsePluginResult::Unchanged);
        }

        let Some(accept) = session.get_header(http::header::ACCEPT) else {
            return Ok(ResponsePluginResult::Unchanged);
        };
        let Ok(accept_str) = accept.to_str() else {
            return Ok(ResponsePluginResult::Unchanged);
        };

        // The size the upstream announces. It used to be the size of the
        // buffer allocated right here, whatever it said. Too large an
        // image is left alone, headers included.
        let content_length = upstream_response
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        if content_length.is_some_and(|size| size > MAX_IMAGE_SIZE) {
            return Ok(ResponsePluginResult::Unchanged);
        }

        let image_type = image_type.to_string();
        // The first of the configured formats the client accepts, else the
        // format the image already has. This is the format's name; the
        // media type, with `image/` in front, used to be kept in its place,
        // so no conversion ever matched it and everything came out as png,
        // announced as avif or webp.
        let format_type = self
            .output_types
            .iter()
            .zip(self.output_mimes.iter())
            .find(|(_, mime)| accept_str.contains(mime.as_str()))
            .map(|(format, _)| format.clone())
            .unwrap_or_else(|| image_type.clone());
        // Remove content-length since we're modifying the body
        upstream_response.remove_header(&http::header::CONTENT_LENGTH);
        // Switch to chunked transfer encoding
        let _ = upstream_response.insert_header(
            http::header::TRANSFER_ENCODING,
            HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
        );
        let _ = upstream_response.insert_header(
            http::header::CONTENT_TYPE,
            format!("image/{format_type}"),
        );
        let capacity = content_length.unwrap_or(8192);

        ctx.add_modify_body_handler(
            PLUGIN_ID,
            Box::new(ImageOptimizer {
                image_type,
                png_quality: self.png_quality,
                jpeg_quality: self.jpeg_quality,
                avif_quality: self.avif_quality,
                avif_speed: self.avif_speed,
                // only support lossless
                webp_quality: 100,
                format_type,
                buffer: BytesMut::with_capacity(capacity),
                passthrough: false,
            }),
        );
        Ok(ResponsePluginResult::Modified)
    }
    fn handle_upstream_response_body(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        if let Some(modifier) = ctx.get_modify_body_handler(PLUGIN_ID) {
            modifier.handle(session, body, end_of_stream)?;
            let result = if end_of_stream {
                ResponseBodyPluginResult::FullyReplaced
            } else {
                ResponseBodyPluginResult::PartialReplaced
            };
            Ok(result)
        } else {
            Ok(ResponseBodyPluginResult::Unchanged)
        }
    }
}

#[ctor(unsafe)]
fn init() {
    get_plugin_factory().register("image_optim", |params| {
        Ok(Arc::new(ImageOptim::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, Plugin};
    use pingora::modules::http::HttpModules;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_new_image_optimize() {
        let optim = ImageOptim::try_from(
            &toml::from_str::<PluginConf>(
                r###"
avif_quality = 75
avif_speed = 3
category = "image_optim"
jpeg_quality = 80
output_types = "avif,webp"
png_quality = 90
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            HashSet::from(["jpeg".to_string(), "png".to_string(),]),
            optim.support_types
        );
        assert_eq!(
            vec!["image/avif".to_string(), "image/webp".to_string()],
            optim.output_mimes
        );
        assert_eq!(90, optim.png_quality);
        assert_eq!(80, optim.jpeg_quality);
        assert_eq!(75, optim.avif_quality);
        assert_eq!(3, optim.avif_speed);
    }

    #[tokio::test]
    async fn test_image_optimize_handle_request() {
        let optim = ImageOptim::try_from(
            &toml::from_str::<PluginConf>(
                r###"
avif_quality = 75
avif_speed = 3
category = "image_optim"
jpeg_quality = 80
output_types = "avif,webp"
png_quality = 90
"###,
            )
            .unwrap(),
        )
        .unwrap();
        // not accept value
        {
            let headers = [""].join("\r\n");
            let input_header = format!(
                "GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n"
            );
            let mock_io = Builder::new().read(input_header.as_bytes()).build();
            let mut session = Session::new_h1_with_modules(
                Box::new(mock_io),
                &HttpModules::new(),
            );
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();

            let result = optim
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();

            assert_eq!(true, RequestPluginResult::Continue == result);
            assert_eq!(true, ctx.cache.is_none());
        }

        // accept avif
        {
            let headers = ["Accept: image/avif"].join("\r\n");
            let input_header = format!(
                "GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n"
            );
            let mock_io = Builder::new().read(input_header.as_bytes()).build();
            let mut session = Session::new_h1_with_modules(
                Box::new(mock_io),
                &HttpModules::new(),
            );
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();

            let result = optim
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();

            assert_eq!(true, RequestPluginResult::Continue == result);
            assert_eq!(
                vec!["image/avif".to_string()],
                ctx.cache.unwrap().keys.unwrap()
            );
        }

        // accept avif, webp
        {
            let headers = ["Accept: image/webp, image/avif"].join("\r\n");
            let input_header = format!(
                "GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n"
            );
            let mock_io = Builder::new().read(input_header.as_bytes()).build();
            let mut session = Session::new_h1_with_modules(
                Box::new(mock_io),
                &HttpModules::new(),
            );
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();

            let result = optim
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();

            assert_eq!(true, RequestPluginResult::Continue == result);
            assert_eq!(
                vec!["image/avif".to_string(), "image/webp".to_string()],
                ctx.cache.unwrap().keys.unwrap()
            );
        }
    }

    #[tokio::test]
    async fn test_image_optimize_handle_upstream_response() {
        let optim = ImageOptim::try_from(
            &toml::from_str::<PluginConf>(
                r###"
avif_quality = 75
avif_speed = 3
category = "image_optim"
jpeg_quality = 80
output_types = "avif,webp"
png_quality = 90
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Accept: image/webp, image/avif"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1_with_modules(
            Box::new(mock_io),
            &HttpModules::new(),
        );
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        let mut upstream_response = ResponseHeader::build(200, None).unwrap();

        // no content type
        let result = optim
            .handle_upstream_response(
                &mut session,
                &mut ctx,
                &mut upstream_response,
            )
            .unwrap();
        assert_eq!(true, ResponsePluginResult::Unchanged == result);

        // content type is not image
        upstream_response
            .append_header("content-type", "application/json")
            .unwrap();
        let result = optim
            .handle_upstream_response(
                &mut session,
                &mut ctx,
                &mut upstream_response,
            )
            .unwrap();
        assert_eq!(true, ResponsePluginResult::Unchanged == result);

        // response image png
        upstream_response
            .insert_header("content-type", "image/png")
            .unwrap();
        let result = optim
            .handle_upstream_response(
                &mut session,
                &mut ctx,
                &mut upstream_response,
            )
            .unwrap();
        assert_eq!(
            "chunked",
            upstream_response.headers.get("transfer-encoding").unwrap()
        );
        assert_eq!(true, ResponsePluginResult::Modified == result);
        assert_eq!(true, ctx.get_modify_body_handler(PLUGIN_ID).is_some());
        // The first configured format the client accepts, as a media type.
        assert_eq!(
            "image/avif",
            upstream_response.headers.get("content-type").unwrap()
        );
    }

    fn new_optim(output_types: &str) -> ImageOptim {
        ImageOptim::try_from(
            &toml::from_str::<PluginConf>(&format!(
                "category = \"image_optim\"\noutput_types = \"{output_types}\""
            ))
            .unwrap(),
        )
        .unwrap()
    }

    async fn new_session(accept: &str) -> Session {
        let input_header =
            format!("GET /a.png HTTP/1.1\r\nAccept: {accept}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1_with_modules(
            Box::new(mock_io),
            &HttpModules::new(),
        );
        session.read_request().await.unwrap();
        session
    }

    fn sample_png() -> Vec<u8> {
        use image::ImageEncoder;
        let img = image::RgbaImage::from_fn(8, 6, |x, y| {
            image::Rgba([(x * 30) as u8, (y * 40) as u8, 0, 255])
        });
        let mut png = Vec::new();
        image::codecs::png::PngEncoder::new(&mut png)
            .write_image(img.as_raw(), 8, 6, image::ExtendedColorType::Rgba8)
            .unwrap();
        png
    }

    #[test]
    fn test_unknown_output_type_is_rejected() {
        let err = ImageOptim::try_from(
            &toml::from_str::<PluginConf>(
                "category = \"image_optim\"\noutput_types = \"avif,bmp\"",
            )
            .unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert_eq!(
            "Plugin image_optim invalid, message: output type bmp is not supported, expected one of avif, webp, jpeg, png",
            err
        );
    }

    /// Which responses are converted, and what the header says afterwards.
    #[tokio::test]
    async fn test_image_optimize_response_header() {
        let optim = new_optim("avif,webp");
        let run =
            async |accept: &str, status: u16, headers: &[(&str, &str)]| {
                let mut session = new_session(accept).await;
                let mut ctx = Ctx::default();
                let mut resp = ResponseHeader::build(status, None).unwrap();
                for (name, value) in headers {
                    resp.insert_header(name.to_string(), *value).unwrap();
                }
                let result = optim
                    .handle_upstream_response(&mut session, &mut ctx, &mut resp)
                    .unwrap();
                let header = |name: &str| {
                    resp.headers
                        .get(name)
                        .map(|value| value.to_str().unwrap().to_string())
                };
                (
                    result == ResponsePluginResult::Modified,
                    header("content-type"),
                    header("content-length"),
                )
            };
        let text = |value: &str| Some(value.to_string());
        let png = [("content-type", "image/png"), ("content-length", "100")];

        assert_eq!(
            (true, text("image/webp"), None),
            run("image/webp", 200, &png).await
        );
        // Regression: no configured format accepted, so the image keeps its
        // own. The header used to say `png`, which is not a media type.
        assert_eq!(
            (true, text("image/png"), None),
            run("image/*", 200, &png).await
        );
        // Parameters after the media type do not hide it.
        assert_eq!(
            (true, text("image/avif"), None),
            run(
                "image/avif",
                200,
                &[("content-type", "image/jpeg; charset=binary")]
            )
            .await
        );

        // Left alone, header and all: too large to convert,
        let too_large = (MAX_IMAGE_SIZE + 1).to_string();
        assert_eq!(
            (false, text("image/png"), Some(too_large.clone())),
            run(
                "image/webp",
                200,
                &[
                    ("content-type", "image/png"),
                    ("content-length", &too_large)
                ]
            )
            .await
        );
        // part of an image,
        assert_eq!(
            (false, text("image/png"), text("100")),
            run("image/webp", 206, &png).await
        );
        // not a format that is converted.
        assert_eq!(
            (false, text("image/gif"), None),
            run("image/webp", 200, &[("content-type", "image/gif")]).await
        );
    }

    /// The body that goes out for each target format, and when the
    /// conversion can not be done.
    #[tokio::test]
    async fn test_image_optimize_body() {
        let session = new_session("image/webp").await;
        let new_optimizer = |format_type: &str| ImageOptimizer {
            image_type: "png".to_string(),
            png_quality: 90,
            jpeg_quality: 80,
            avif_quality: 75,
            avif_speed: 10,
            webp_quality: 100,
            format_type: format_type.to_string(),
            buffer: BytesMut::new(),
            passthrough: false,
        };
        let png = sample_png();

        // Regression: every target used to come out as png, whatever the
        // header announced.
        for (format_type, expected) in [
            ("webp", image::ImageFormat::WebP),
            ("avif", image::ImageFormat::Avif),
            ("jpeg", image::ImageFormat::Jpeg),
            ("png", image::ImageFormat::Png),
        ] {
            let mut optimizer = new_optimizer(format_type);
            // in two chunks: nothing goes out before the last one
            let (head, tail) = png.split_at(png.len() / 2);
            let mut body = Some(Bytes::copy_from_slice(head));
            optimizer.handle(&session, &mut body, false).unwrap();
            assert_eq!(Some(Bytes::new()), body, "{format_type}");
            let mut body = Some(Bytes::copy_from_slice(tail));
            optimizer.handle(&session, &mut body, true).unwrap();
            assert_eq!(
                Some(expected),
                image::guess_format(&body.unwrap()).ok(),
                "{format_type}"
            );
        }

        // Regression: not an image after all. The body used to be empty.
        let mut optimizer = new_optimizer("webp");
        let mut body = Some(Bytes::from_static(b"not an image"));
        optimizer.handle(&session, &mut body, true).unwrap();
        assert_eq!(Some(Bytes::from_static(b"not an image")), body);

        // Regression: no `Content-Length`, and more than is converted. It
        // goes out as it came, and is not collected any further.
        let mut optimizer = new_optimizer("webp");
        let chunk = Bytes::from(vec![1u8; MAX_IMAGE_SIZE / 2 + 1]);
        let mut body = Some(chunk.clone());
        optimizer.handle(&session, &mut body, false).unwrap();
        assert_eq!(Some(Bytes::new()), body);
        let mut body = Some(chunk.clone());
        optimizer.handle(&session, &mut body, false).unwrap();
        assert_eq!(Some(2 * chunk.len()), body.map(|data| data.len()));
        assert_eq!(0, optimizer.buffer.len());
        let mut body = Some(Bytes::from_static(b"tail"));
        optimizer.handle(&session, &mut body, true).unwrap();
        assert_eq!(Some(Bytes::from_static(b"tail")), body);
    }

    /// On the work-stealing runtime the conversion goes through
    /// `block_in_place`, which is only allowed there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_image_optimize_on_multi_thread_runtime() {
        let png = sample_png();
        let output = tokio::spawn(async move {
            let session = new_session("image/webp").await;
            let mut optimizer = ImageOptimizer {
                image_type: "png".to_string(),
                png_quality: 90,
                jpeg_quality: 80,
                avif_quality: 75,
                avif_speed: 10,
                webp_quality: 100,
                format_type: "webp".to_string(),
                buffer: BytesMut::new(),
                passthrough: false,
            };
            let mut body = Some(Bytes::from(png));
            optimizer.handle(&session, &mut body, true).unwrap();
            body.unwrap()
        })
        .await
        .unwrap();
        assert_eq!(
            Some(image::ImageFormat::WebP),
            image::guess_format(&output).ok()
        );
    }
}
