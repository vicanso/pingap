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
use bytes::Bytes;
use ctor::ctor;
use pingap_config::PluginConf;
use pingap_core::HttpResponse;
use pingap_core::ModifyResponseBody;
use pingap_core::HTTP_HEADER_TRANSFER_CHUNKED;
use pingap_core::{Ctx, Plugin, PluginStep};
use pingap_plugin::{
    get_hash_key, get_int_conf, get_plugin_factory, get_str_conf, Error,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::sync::Arc;
use tracing::debug;

mod optimizer;

type Result<T, E = Error> = std::result::Result<T, E>;

struct ImageOptimizer {
    image_type: String,
    png_quality: u8,
    jpeg_quality: u8,
    avif_quality: u8,
    avif_speed: u8,
    webp_quality: u8,
    format_type: String,
}

impl ModifyResponseBody for ImageOptimizer {
    fn handle(&self, data: Bytes) -> pingora::Result<Bytes> {
        if let Ok(info) = load_image(&data, &self.image_type) {
            let result = match self.format_type.as_str() {
                "jpeg" => optimize_jpeg(&info, self.jpeg_quality),
                "avif" => {
                    optimize_avif(&info, self.avif_quality, self.avif_speed)
                },
                "webp" => optimize_webp(&info, self.webp_quality),
                _ => optimize_png(&info, self.png_quality),
            };
            if let Ok(data) = result {
                return Ok(Bytes::from(data));
            }
        }
        Ok(data)
    }
    fn name(&self) -> String {
        "image_optimization".to_string()
    }
}

pub struct ImageOptim {
    /// A unique identifier for this plugin instance.
    /// Used for internal tracking and debugging purposes.
    hash_value: String,
    support_types: Vec<String>,
    plugin_step: PluginStep,
    output_types: Vec<String>,
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
        let mut output_types = vec![];
        for item in get_str_conf(value, "output_types").split(",") {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            output_types.push(item.to_string());
        }
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
            support_types: vec!["jpeg".to_string(), "png".to_string()],
            output_types,
            plugin_step: PluginStep::UpstreamResponse,
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
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<(bool, Option<HttpResponse>)> {
        if step != PluginStep::Request {
            return Ok((false, None));
        }
        // set cache key with accept image type
        let mut accept_images = Vec::with_capacity(2);
        if let Some(accept) = session.get_header(http::header::ACCEPT) {
            if let Ok(accept) = accept.to_str() {
                for item in self.output_types.iter() {
                    let key = format!("image/{item}");
                    if accept.contains(key.as_str()) {
                        accept_images.push(key);
                    }
                }
                accept_images.sort();
            }
        }
        if !accept_images.is_empty() {
            ctx.extend_cache_keys(accept_images);
        }
        Ok((false, None))
    }
    fn handle_upstream_response(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<bool> {
        // Skip if not at the correct plugin step
        if self.plugin_step != step {
            return Ok(false);
        }
        let Some(content_type) =
            upstream_response.headers.get(http::header::CONTENT_TYPE)
        else {
            return Ok(false);
        };
        let Ok(content_type) = content_type.to_str() else {
            return Ok(false);
        };
        let Some((content_type, image_type)) = content_type.split_once("/")
        else {
            return Ok(false);
        };
        if content_type != "image" {
            return Ok(false);
        }
        let image_type = image_type.to_string();
        if !self.support_types.contains(&image_type) {
            return Ok(false);
        }

        let mut format_type = image_type.clone();
        if let Some(accept) = session.get_header(http::header::ACCEPT) {
            if let Ok(accept) = accept.to_str() {
                for item in self.output_types.iter() {
                    if accept.contains(format!("image/{item}").as_str()) {
                        format_type = item.to_string();
                        break;
                    }
                }
            }
        }
        if format_type.is_empty() {
            return Ok(false);
        }
        // Remove content-length since we're modifying the body
        upstream_response.remove_header(&http::header::CONTENT_LENGTH);
        // Switch to chunked transfer encoding
        let _ = upstream_response.insert_header(
            http::header::TRANSFER_ENCODING,
            HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
        );
        let _ = upstream_response.insert_header(
            http::header::CONTENT_TYPE,
            format!("image/{format_type}").as_str(),
        );

        ctx.modify_upstream_response_body = Some(Box::new(ImageOptimizer {
            image_type,
            png_quality: self.png_quality,
            jpeg_quality: self.jpeg_quality,
            avif_quality: self.avif_quality,
            avif_speed: self.avif_speed,
            // only support lossless
            webp_quality: 100,
            format_type,
        }));
        Ok(true)
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("image_optim", |params| {
        Ok(Arc::new(ImageOptim::new(params)?))
    });
}
