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

use super::{
    HttpHeader, HTTP_HEADER_CONTENT_JSON, HTTP_HEADER_NO_CACHE, HTTP_HEADER_NO_STORE,
    HTTP_HEADER_TRANSFER_CHUNKED,
};
use crate::util;
use bytes::Bytes;
use http::header;
use http::StatusCode;
use log::error;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use serde::Serialize;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;

pub fn get_hour_duration() -> u32 {
    if let Ok(value) = SystemTime::now().duration_since(UNIX_EPOCH) {
        (value.as_millis() % (3600 * 1000)) as u32
    } else {
        0
    }
}

fn get_cache_control(max_age: Option<u32>, cache_private: Option<bool>) -> HttpHeader {
    if let Some(max_age) = max_age {
        let category = if cache_private.unwrap_or_default() {
            "private"
        } else {
            "public"
        };
        if let Ok(value) = header::HeaderValue::from_str(&format!("{category}, max-age={max_age}"))
        {
            return (header::CACHE_CONTROL, value);
        }
    }
    HTTP_HEADER_NO_CACHE.clone()
}

#[derive(Default, Clone, Debug)]
pub struct HttpResponse {
    // http response status
    pub status: StatusCode,
    // http response body
    pub body: Bytes,
    // max age of http response
    pub max_age: Option<u32>,
    // created time of http response
    pub created_at: Option<u32>,
    // private for cache control
    pub cache_private: Option<bool>,
    // headers for http response
    pub headers: Option<Vec<HttpHeader>>,
}

impl HttpResponse {
    /// Returns the no content `204` response.
    pub fn no_content() -> Self {
        HttpResponse {
            status: StatusCode::NO_CONTENT,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            ..Default::default()
        }
    }
    /// Return the bad request `400` response.
    pub fn bad_request(body: Bytes) -> Self {
        HttpResponse {
            status: StatusCode::BAD_REQUEST,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            body,
            ..Default::default()
        }
    }
    /// Returns the not found `404` response.
    pub fn not_found(body: Bytes) -> Self {
        HttpResponse {
            status: StatusCode::NOT_FOUND,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            body,
            ..Default::default()
        }
    }
    /// Returns the unknown error `500` response.
    pub fn unknown_error(body: Bytes) -> Self {
        HttpResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            body,
            ..Default::default()
        }
    }

    /// Gets the response from serde json, and sets the status of response.
    pub fn try_from_json_status<T>(value: &T, status: StatusCode) -> pingora::Result<Self>
    where
        T: ?Sized + Serialize,
    {
        let mut resp = HttpResponse::try_from_json(value)?;
        resp.status = status;
        Ok(resp)
    }
    /// Gets the response from serde json, the status sets to `200`.
    pub fn try_from_json<T>(value: &T) -> pingora::Result<Self>
    where
        T: ?Sized + Serialize,
    {
        let buf = serde_json::to_vec(value).map_err(|e| {
            error!("To json fail: {e}");
            util::new_internal_error(400, e.to_string())
        })?;
        Ok(HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from(buf),
            headers: Some(vec![HTTP_HEADER_CONTENT_JSON.clone()]),
            ..Default::default()
        })
    }
    /// Gets the response header for http response.
    pub fn get_response_header(&self) -> pingora::Result<ResponseHeader> {
        let fix_size = 3;
        let size = self
            .headers
            .as_ref()
            .map_or_else(|| fix_size, |headers| headers.len() + fix_size);
        let mut resp = ResponseHeader::build(self.status, Some(size))?;
        resp.insert_header(header::CONTENT_LENGTH, self.body.len().to_string())?;

        // set cache control
        let cache_control = get_cache_control(self.max_age, self.cache_private);
        resp.insert_header(cache_control.0, cache_control.1)?;

        if let Some(created_at) = self.created_at {
            let secs = util::get_super_ts() - created_at;
            if let Ok(value) = header::HeaderValue::from_str(&secs.to_string()) {
                resp.insert_header(header::AGE, value)?;
            }
        }

        if let Some(headers) = &self.headers {
            for (name, value) in headers {
                resp.insert_header(name.to_owned(), value)?;
            }
        }
        Ok(resp)
    }
    /// Sends http response to client, return how many bytes were sent.
    pub async fn send(self, session: &mut Session) -> pingora::Result<usize> {
        let header = self.get_response_header()?;
        let size = self.body.len();
        session.write_response_header(Box::new(header)).await?;
        session.write_response_body(self.body).await?;
        Ok(size)
    }
}

pub struct HttpChunkResponse<'r, R> {
    pub reader: Pin<&'r mut R>,
    pub chunk_size: usize,
    // max age of http response
    pub max_age: Option<u32>,
    // private for cache control
    pub cache_private: Option<bool>,
    // headers for http response
    pub headers: Option<Vec<HttpHeader>>,
}

// https://github.com/rust-lang/rust/blob/master/library/std/src/sys_common/io.rs#L1
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

impl<'r, R> HttpChunkResponse<'r, R>
where
    R: tokio::io::AsyncRead + std::marker::Unpin,
{
    /// Creates a new http chunk response.
    pub fn new(r: &'r mut R) -> Self {
        Self {
            reader: Pin::new(r),
            chunk_size: DEFAULT_BUF_SIZE,
            max_age: None,
            headers: None,
            cache_private: None,
        }
    }
    /// Gets the response header for http chunk response.
    pub fn get_response_header(&self) -> pingora::Result<ResponseHeader> {
        let mut resp = ResponseHeader::build(StatusCode::OK, Some(4))?;
        if let Some(headers) = &self.headers {
            for (name, value) in headers {
                resp.insert_header(name.to_owned(), value)?;
            }
        }

        let chunked = HTTP_HEADER_TRANSFER_CHUNKED.clone();
        resp.insert_header(chunked.0, chunked.1)?;

        let cache_control = get_cache_control(self.max_age, self.cache_private);
        resp.insert_header(cache_control.0, cache_control.1)?;
        Ok(resp)
    }
    /// Sends the chunk data to client until the end of reader, return how many bytes were sent.
    pub async fn send(&mut self, session: &mut Session) -> pingora::Result<usize> {
        let header = self.get_response_header()?;
        session.write_response_header(Box::new(header)).await?;

        let mut sent = 0;
        let mut buffer = vec![0; self.chunk_size.max(512)];
        loop {
            let size = self.reader.read(&mut buffer).await.map_err(|e| {
                error!("Read data fail: {e}");
                util::new_internal_error(400, e.to_string())
            })?;
            if size == 0 {
                break;
            }
            session
                .write_response_body(Bytes::copy_from_slice(&buffer[..size]))
                .await?;
            sent += size
        }
        session.finish_body().await?;

        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::{get_cache_control, HttpChunkResponse, HttpResponse};
    use crate::http_extra::convert_headers;
    use crate::util::{get_super_ts, resolve_path};
    use bytes::Bytes;
    use http::StatusCode;
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use tokio::fs;

    #[test]
    fn test_get_cache_control() {
        assert_eq!(
            r###"("cache-control", "private, max-age=3600")"###,
            format!("{:?}", get_cache_control(Some(3600), Some(true)))
        );
        assert_eq!(
            r###"("cache-control", "public, max-age=3600")"###,
            format!("{:?}", get_cache_control(Some(3600), None))
        );
    }

    #[test]
    fn test_http_response() {
        assert_eq!(
            r###"HttpResponse { status: 204, body: b"", max_age: None, created_at: None, cache_private: None, headers: Some([("cache-control", "private, no-store")]) }"###,
            format!("{:?}", HttpResponse::no_content())
        );
        assert_eq!(
            r###"HttpResponse { status: 404, body: b"Not Found", max_age: None, created_at: None, cache_private: None, headers: Some([("cache-control", "private, no-store")]) }"###,
            format!("{:?}", HttpResponse::not_found("Not Found".into()))
        );
        assert_eq!(
            r###"HttpResponse { status: 500, body: b"Unknown Error", max_age: None, created_at: None, cache_private: None, headers: Some([("cache-control", "private, no-store")]) }"###,
            format!("{:?}", HttpResponse::unknown_error("Unknown Error".into()))
        );

        #[derive(Serialize)]
        struct Data {
            message: String,
        }
        let resp = HttpResponse::try_from_json_status(
            &Data {
                message: "Hello World!".to_string(),
            },
            StatusCode::BAD_REQUEST,
        )
        .unwrap();
        assert_eq!(
            r###"HttpResponse { status: 400, body: b"{\"message\":\"Hello World!\"}", max_age: None, created_at: None, cache_private: None, headers: Some([("content-type", "application/json; charset=utf-8")]) }"###,
            format!("{resp:?}")
        );
        let resp = HttpResponse::try_from_json(&Data {
            message: "Hello World!".to_string(),
        })
        .unwrap();
        assert_eq!(
            r###"HttpResponse { status: 200, body: b"{\"message\":\"Hello World!\"}", max_age: None, created_at: None, cache_private: None, headers: Some([("content-type", "application/json; charset=utf-8")]) }"###,
            format!("{resp:?}")
        );

        let resp = HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from("Hello world!"),
            max_age: Some(3600),
            created_at: Some(get_super_ts() - 10),
            cache_private: Some(true),
            headers: Some(
                convert_headers(&[
                    "Contont-Type: application/json".to_string(),
                    "Content-Encoding: gzip".to_string(),
                ])
                .unwrap(),
            ),
        };

        let mut header = resp.get_response_header().unwrap();
        assert_eq!(true, !header.headers.get("Age").unwrap().is_empty());
        header.remove_header("Age").unwrap();

        assert_eq!(
            r###"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"content-length": "12", "cache-control": "private, max-age=3600", "content-encoding": "gzip", "contont-type": "application/json"} }, header_name_map: Some({"content-length": CaseHeaderName(b"Content-Length"), "cache-control": CaseHeaderName(b"Cache-Control"), "content-encoding": CaseHeaderName(b"Content-Encoding"), "contont-type": CaseHeaderName(b"contont-type")}) }"###,
            format!("{header:?}")
        );
    }
    #[tokio::test]
    async fn test_http_chunk_response() {
        let file = resolve_path("./error.html");
        let mut f = fs::OpenOptions::new().read(true).open(file).await.unwrap();
        let mut resp = HttpChunkResponse::new(&mut f);
        resp.max_age = Some(3600);
        resp.cache_private = Some(false);
        resp.headers = Some(convert_headers(&["Contont-Type: text/html".to_string()]).unwrap());
        let header = resp.get_response_header().unwrap();
        assert_eq!(
            r###"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"contont-type": "text/html", "transfer-encoding": "chunked", "cache-control": "public, max-age=3600"} }, header_name_map: Some({"contont-type": CaseHeaderName(b"contont-type"), "transfer-encoding": CaseHeaderName(b"Transfer-Encoding"), "cache-control": CaseHeaderName(b"Cache-Control")}) }"###,
            format!("{header:?}")
        );
    }
}
