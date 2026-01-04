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
    load_image, optimize_avif, optimize_jpeg, optimize_png, optimize_webp,
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
use tracing::debug;

mod optimizer;

const PLUGIN_ID: &str = "_image_optimize_";

type Result<T, E = Error> = std::result::Result<T, E>;

struct ImageOptimizer {
    image_type: String,
    png_quality: u8,
    jpeg_quality: u8,
    avif_quality: u8,
    avif_speed: u8,
    webp_quality: u8,
    format_type: String,
    buffer: BytesMut,
}

impl ModifyResponseBody for ImageOptimizer {
    fn handle(
        &mut self,
        _session: &Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if let Some(data) = body {
            self.buffer.extend(&data[..]);
            data.clear();
        }
        if !end_of_stream {
            return Ok(());
        }
        if let Ok(info) = load_image(&self.buffer, &self.image_type) {
            let result = match self.format_type.as_str() {
                "jpeg" => optimize_jpeg(&info, self.jpeg_quality),
                "avif" => {
                    optimize_avif(&info, self.avif_quality, self.avif_speed)
                },
                "webp" => optimize_webp(&info, self.webp_quality),
                _ => optimize_png(&info, self.png_quality),
            };
            if let Ok(data) = result {
                *body = Some(Bytes::from(data));
            }
        }
        Ok(())
    }
    fn name(&self) -> String {
        "image_optimization".to_string()
    }
}

pub struct ImageOptim {
    /// A unique identifier for this plugin instance.
    /// Used for internal tracking and debugging purposes.
    hash_value: String,
    support_types: HashSet<String>,
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

        if let Some(accept) = session.get_header(http::header::ACCEPT) {
            if let Ok(accept_str) = accept.to_str() {
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
        }
        Ok(RequestPluginResult::Continue)
    }
    fn handle_upstream_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        let content_type = if let Some(value) =
            upstream_response.headers.get(http::header::CONTENT_TYPE)
        {
            value.to_str().unwrap_or_default()
        } else {
            return Ok(ResponsePluginResult::Unchanged);
        };

        let Some(image_type) = content_type.strip_prefix("image/") else {
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

        let image_type = image_type.to_string();
        let mut format_type = image_type.clone();
        for item in self.output_mimes.iter() {
            if accept_str.contains(item.as_str()) {
                format_type = item.clone();
                break;
            }
        }
        let mut capacity = 8192;
        // if the image is not changed, it will be optimized again, so we need to remove the content-length
        // Remove content-length since we're modifying the body
        if let Some(value) =
            upstream_response.remove_header(&http::header::CONTENT_LENGTH)
        {
            if let Ok(size) =
                value.to_str().unwrap_or_default().parse::<usize>()
            {
                capacity = size;
            }
        }
        // Switch to chunked transfer encoding
        let _ = upstream_response.insert_header(
            http::header::TRANSFER_ENCODING,
            HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
        );
        let _ = upstream_response
            .insert_header(http::header::CONTENT_TYPE, &format_type);

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

#[ctor]
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
    }
}
