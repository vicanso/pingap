use bytes::Bytes;
use hex::encode;
use http::{header, HeaderValue, StatusCode};
use rust_embed::EmbeddedFile;

use crate::cache::HttpResponse;

pub struct StaticFile(pub Option<EmbeddedFile>);

impl From<StaticFile> for HttpResponse {
    fn from(value: StaticFile) -> Self {
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
            24 * 3600
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
