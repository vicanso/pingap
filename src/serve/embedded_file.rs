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

use crate::http_extra::HttpResponse;
use bytes::Bytes;
use hex::encode;
use http::{header, HeaderValue, StatusCode};
use rust_embed::EmbeddedFile;

pub struct EmbeddedStaticFile(pub Option<EmbeddedFile>, pub u32);

impl From<EmbeddedStaticFile> for HttpResponse {
    fn from(value: EmbeddedStaticFile) -> Self {
        if value.0.is_none() {
            return HttpResponse::not_found();
        }
        // value 0 is some
        let file = value.0.unwrap();
        // hash为基于内容生成
        let str = &encode(file.metadata.sha256_hash())[0..8];
        let mime_type = file.metadata.mimetype();
        // 长度+hash的一部分
        let entity_tag = format!(r#""{:x}-{str}""#, file.data.len());
        // 因为html对于网页是入口，避免缓存后更新不及时
        // 因此设置为0
        // 其它js,css会添加版本号，因此无影响
        let max_age = if mime_type.contains("text/html") {
            0
        } else {
            value.1
        };

        let mut headers = vec![];
        if let Ok(value) = HeaderValue::from_str(mime_type) {
            headers.push((header::CONTENT_TYPE, value));
        }
        if let Ok(value) = HeaderValue::from_str(&entity_tag) {
            headers.push((header::ETAG, value));
        }

        HttpResponse {
            status: StatusCode::OK,
            body: Bytes::copy_from_slice(&file.data),
            max_age: Some(max_age),
            headers: Some(headers),
            ..Default::default()
        }
    }
}
