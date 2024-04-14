// Copyright 2024 Tree xie.
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

use super::ProxyPlugin;
use super::{Error, Result};
use crate::state::State;
use async_trait::async_trait;
use http::HeaderValue;
use once_cell::sync::Lazy;
use pingora::proxy::Session;

static ZSTD_ENCODING: Lazy<HeaderValue> = Lazy::new(|| "zstd".try_into().unwrap());
static BR_ENCODING: Lazy<HeaderValue> = Lazy::new(|| "br".try_into().unwrap());
static GZIP_ENCODING: Lazy<HeaderValue> = Lazy::new(|| "gzip".try_into().unwrap());

pub struct Compression {
    gzip_level: u32,
    br_level: u32,
    zstd_level: u32,
    support_compression: bool,
}

impl Compression {
    pub fn new(value: &str) -> Result<Compression> {
        let mut levels: [u32; 3] = [0, 0, 0];
        let mut support_compression = false;
        for (index, item) in value.split(' ').enumerate() {
            if index >= levels.len() {
                break;
            }
            let level = item
                .parse::<u32>()
                .map_err(|e| Error::ParseInt { source: e })?;
            if level > 0 {
                support_compression = true;
                levels[index] = level;
            }
        }
        Ok(Compression {
            gzip_level: levels[0],
            br_level: levels[1],
            zstd_level: levels[2],
            support_compression,
        })
    }
}

#[async_trait]
impl ProxyPlugin for Compression {
    #[inline]
    async fn handle(&self, session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
        if !self.support_compression {
            return Ok(false);
        }
        let header = session.req_header_mut();
        if let Some(accept_encoding) = header.headers.get(http::header::ACCEPT_ENCODING) {
            let accept_encoding = accept_encoding.to_str().unwrap_or_default();
            if accept_encoding.is_empty() {
                return Ok(false);
            }
            let level = if self.zstd_level > 0 && accept_encoding.contains("zstd") {
                let _ = header.insert_header(http::header::ACCEPT_ENCODING, ZSTD_ENCODING.clone());
                self.zstd_level
            } else if self.br_level > 0 && accept_encoding.contains("br") {
                let _ = header.insert_header(http::header::ACCEPT_ENCODING, BR_ENCODING.clone());
                self.br_level
            } else if self.gzip_level > 0 && accept_encoding.contains("gzip") {
                let _ = header.insert_header(http::header::ACCEPT_ENCODING, GZIP_ENCODING.clone());
                self.gzip_level
            } else {
                0
            };
            if level > 0 {
                session.downstream_compression.adjust_decompression(true);
                session.downstream_compression.adjust_level(level);
            }
        }
        Ok(false)
    }
}
