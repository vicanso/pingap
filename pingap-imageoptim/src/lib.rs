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
use pingap_core::ModifyResponseBody;
use pingap_core::HTTP_HEADER_TRANSFER_CHUNKED;
use pingap_core::{
    Ctx, Plugin, PluginStep, RequestPluginResult, ResponsePluginResult,
};
use pingap_plugin::{
    get_hash_key, get_int_conf, get_plugin_factory, get_str_conf, Error,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::borrow::Cow;
use std::collections::HashSet;
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
    support_types: HashSet<String>,
    plugin_step: PluginStep,
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

        // let mut output_types = vec![];
        // for item in get_str_conf(value, "output_types").split(",") {
        //     let item = item.trim();
        //     if item.is_empty() {
        //         continue;
        //     }
        //     output_types.push(item.to_string());
        // }
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
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        // Skip if not at the correct plugin step
        if self.plugin_step != step {
            return Ok(ResponsePluginResult::Unchanged);
        }

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
        // if the image is not changed, it will be optimized again, so we need to remove the content-length
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

        let feature = ctx.features.get_or_insert_default();
        feature.modify_upstream_response_body =
            Some(Box::new(ImageOptimizer {
                image_type,
                png_quality: self.png_quality,
                jpeg_quality: self.jpeg_quality,
                avif_quality: self.avif_quality,
                avif_speed: self.avif_speed,
                // only support lossless
                webp_quality: 100,
                format_type,
            }));
        Ok(ResponsePluginResult::Modified)
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("image_optim", |params| {
        Ok(Arc::new(ImageOptim::new(params)?))
    });
}
