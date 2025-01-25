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

#[cfg(feature = "full")]
use super::HTTP_HEADER_CONTENT_TEXT;
use super::{
    HttpHeader, HTTP_HEADER_CONTENT_HTML, HTTP_HEADER_CONTENT_JSON,
    HTTP_HEADER_NO_CACHE, HTTP_HEADER_NO_STORE, HTTP_HEADER_TRANSFER_CHUNKED,
};
use crate::util;
use bytes::Bytes;
use http::header;
use http::StatusCode;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use serde::Serialize;
use std::pin::Pin;
use tokio::io::AsyncReadExt;
use tracing::error;

/// Helper function to generate cache control headers
/// Returns a cache control header based on max age and privacy settings.
/// - If max_age is 0: returns "private, no-cache"
/// - If max_age is set: returns "private/public, max-age=X"
/// - Otherwise: returns "private, no-cache"
fn new_cache_control_header(
    max_age: Option<u32>,
    cache_private: Option<bool>,
) -> HttpHeader {
    if let Some(max_age) = max_age {
        if max_age == 0 {
            return HTTP_HEADER_NO_CACHE.clone();
        }
        let category = if cache_private.unwrap_or_default() {
            "private"
        } else {
            "public"
        };
        if let Ok(value) = header::HeaderValue::from_str(&format!(
            "{category}, max-age={max_age}"
        )) {
            return (header::CACHE_CONTROL, value);
        }
    }
    HTTP_HEADER_NO_CACHE.clone()
}

/// Main HTTP response struct for handling complete responses
#[derive(Default, Clone, Debug)]
pub struct HttpResponse {
    /// HTTP status code (200 OK, 404 Not Found, etc)
    pub status: StatusCode,
    /// Response body as bytes
    pub body: Bytes,
    /// Cache control max-age value in seconds
    pub max_age: Option<u32>,
    /// Timestamp when response was created
    pub created_at: Option<u32>,
    /// Whether cache should be private (true) or public (false)
    pub cache_private: Option<bool>,
    /// Additional HTTP headers
    pub headers: Option<Vec<HttpHeader>>,
}

impl HttpResponse {
    /// Creates a new HTTP response with 204 No Content status and no-store cache control
    pub fn no_content() -> Self {
        Self {
            status: StatusCode::NO_CONTENT,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            ..Default::default()
        }
    }
    /// Creates a new HTTP response with 400 Bad Request status and the given body
    pub fn bad_request(body: Bytes) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            body,
            ..Default::default()
        }
    }
    /// Creates a new HTTP response with 404 Not Found status and the given body
    pub fn not_found(body: Bytes) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            body,
            ..Default::default()
        }
    }
    /// Creates a new HTTP response with 500 Internal Server Error status and the given body
    pub fn unknown_error(body: Bytes) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            body,
            ..Default::default()
        }
    }
    /// Creates a new HTTP response with 200 OK status, HTML content type, and the given body
    pub fn html(body: Bytes) -> Self {
        Self {
            status: StatusCode::OK,
            headers: Some(vec![
                HTTP_HEADER_CONTENT_HTML.clone(),
                HTTP_HEADER_NO_CACHE.clone(),
            ]),
            body,
            ..Default::default()
        }
    }
    /// Creates a new HTTP response with 302 Temporary Redirect status to the given location
    pub fn redirect(location: &str) -> pingora::Result<Self> {
        let value = http::HeaderValue::from_str(location).map_err(|e| {
            error!(error = e.to_string(), "to header value fail");
            util::new_internal_error(500, e.to_string())
        })?;
        Ok(Self {
            status: StatusCode::TEMPORARY_REDIRECT,
            headers: Some(vec![
                (http::header::LOCATION.clone(), value),
                HTTP_HEADER_NO_CACHE.clone(),
            ]),
            ..Default::default()
        })
    }

    #[cfg(feature = "full")]
    /// Creates a new HTTP response with 200 OK status, text/plain content type, and the given body
    pub fn text(body: Bytes) -> Self {
        Self {
            status: StatusCode::OK,
            headers: Some(vec![
                HTTP_HEADER_CONTENT_TEXT.clone(),
                HTTP_HEADER_NO_CACHE.clone(),
            ]),
            body,
            ..Default::default()
        }
    }
    /// Creates a new HTTP response from a serializable value with the specified status code
    pub fn try_from_json_status<T>(
        value: &T,
        status: StatusCode,
    ) -> pingora::Result<Self>
    where
        T: ?Sized + Serialize,
    {
        let mut resp = Self::try_from_json(value)?;
        resp.status = status;
        Ok(resp)
    }

    /// Creates a new HTTP response from a serializable value with 200 OK status
    pub fn try_from_json<T>(value: &T) -> pingora::Result<Self>
    where
        T: ?Sized + Serialize,
    {
        let buf = serde_json::to_vec(value).map_err(|e| {
            error!(error = e.to_string(), "to json fail");
            util::new_internal_error(400, e.to_string())
        })?;
        Ok(Self {
            status: StatusCode::OK,
            body: buf.into(),
            headers: Some(vec![HTTP_HEADER_CONTENT_JSON.clone()]),
            ..Default::default()
        })
    }
    /// Builds and returns the HTTP response headers based on the response configuration
    pub fn new_response_header(&self) -> pingora::Result<ResponseHeader> {
        let fix_size = 3;
        let size = self
            .headers
            .as_ref()
            .map_or_else(|| fix_size, |headers| headers.len() + fix_size);
        let mut resp = ResponseHeader::build(self.status, Some(size))?;
        resp.insert_header(
            header::CONTENT_LENGTH,
            self.body.len().to_string(),
        )?;

        // set cache control
        let cache_control =
            new_cache_control_header(self.max_age, self.cache_private);
        resp.insert_header(cache_control.0, cache_control.1)?;

        if let Some(created_at) = self.created_at {
            let secs = util::get_super_ts() - created_at;
            if let Ok(value) = header::HeaderValue::from_str(&secs.to_string())
            {
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
    /// Sends the HTTP response to the client and returns the number of bytes sent
    pub async fn send(self, session: &mut Session) -> pingora::Result<usize> {
        let header = self.new_response_header()?;
        let size = self.body.len();
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session.write_response_body(Some(self.body), true).await?;
        session.finish_body().await?;
        Ok(size)
    }
}

/// Chunked response handler for streaming large responses
pub struct HttpChunkResponse<'r, R> {
    /// Pinned reader for streaming data
    pub reader: Pin<&'r mut R>,
    /// Size of each chunk in bytes
    pub chunk_size: usize,
    /// Cache control settings
    pub max_age: Option<u32>,
    pub cache_private: Option<bool>,
    pub headers: Option<Vec<HttpHeader>>,
}

// Default chunk size of 8KB for streaming responses
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

impl<'r, R> HttpChunkResponse<'r, R>
where
    R: tokio::io::AsyncRead + std::marker::Unpin,
{
    /// Creates a new chunked HTTP response with the given reader
    pub fn new(r: &'r mut R) -> Self {
        Self {
            reader: Pin::new(r),
            chunk_size: DEFAULT_BUF_SIZE,
            max_age: None,
            headers: None,
            cache_private: None,
        }
    }
    /// Builds and returns the HTTP response headers for chunked transfer
    pub fn get_response_header(&self) -> pingora::Result<ResponseHeader> {
        let mut resp = ResponseHeader::build(StatusCode::OK, Some(4))?;
        if let Some(headers) = &self.headers {
            for (name, value) in headers {
                resp.insert_header(name.to_owned(), value)?;
            }
        }

        let chunked = HTTP_HEADER_TRANSFER_CHUNKED.clone();
        resp.insert_header(chunked.0, chunked.1)?;

        let cache_control =
            new_cache_control_header(self.max_age, self.cache_private);
        resp.insert_header(cache_control.0, cache_control.1)?;
        Ok(resp)
    }
    /// Sends the chunked response data to the client and returns total bytes sent
    pub async fn send(
        &mut self,
        session: &mut Session,
    ) -> pingora::Result<usize> {
        let header = self.get_response_header()?;
        session
            .write_response_header(Box::new(header), false)
            .await?;

        let mut sent = 0;
        let chunk_size = self.chunk_size.max(512);
        let mut buffer = vec![0; chunk_size];
        loop {
            let size = self.reader.read(&mut buffer).await.map_err(|e| {
                error!(error = e.to_string(), "read data fail");
                util::new_internal_error(400, e.to_string())
            })?;
            let end = size < chunk_size;
            session
                .write_response_body(
                    Some(Bytes::copy_from_slice(&buffer[..size])),
                    end,
                )
                .await?;
            sent += size;
            if end {
                break;
            }
        }
        session.finish_body().await?;

        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::{new_cache_control_header, HttpChunkResponse, HttpResponse};
    use crate::http_extra::convert_headers;
    use crate::util::{get_super_ts, resolve_path};
    use bytes::Bytes;
    use http::StatusCode;
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use tokio::fs;

    #[test]
    fn test_new_cache_control_header() {
        assert_eq!(
            r###"("cache-control", "private, max-age=3600")"###,
            format!("{:?}", new_cache_control_header(Some(3600), Some(true)))
        );
        assert_eq!(
            r###"("cache-control", "public, max-age=3600")"###,
            format!("{:?}", new_cache_control_header(Some(3600), None))
        );
        assert_eq!(
            r###"("cache-control", "private, no-cache")"###,
            format!("{:?}", new_cache_control_header(None, None))
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
            format!(
                "{:?}",
                HttpResponse::unknown_error("Unknown Error".into())
            )
        );

        assert_eq!(
            r###"HttpResponse { status: 400, body: b"Bad Request", max_age: None, created_at: None, cache_private: None, headers: Some([("cache-control", "private, no-store")]) }"###,
            format!("{:?}", HttpResponse::bad_request("Bad Request".into()))
        );

        assert_eq!(
            r###"HttpResponse { status: 200, body: b"<p>Pingap</p>", max_age: None, created_at: None, cache_private: None, headers: Some([("content-type", "text/html; charset=utf-8"), ("cache-control", "private, no-cache")]) }"###,
            format!("{:?}", HttpResponse::html("<p>Pingap</p>".into()))
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

        let mut header = resp.new_response_header().unwrap();
        assert_eq!(true, !header.headers.get("Age").unwrap().is_empty());
        header.remove_header("Age").unwrap();

        assert_eq!(
            r###"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"content-length": "12", "cache-control": "private, max-age=3600", "content-encoding": "gzip", "contont-type": "application/json"} }, header_name_map: Some({"content-length": CaseHeaderName(b"Content-Length"), "cache-control": CaseHeaderName(b"Cache-Control"), "content-encoding": CaseHeaderName(b"Content-Encoding"), "contont-type": CaseHeaderName(b"contont-type")}), reason_phrase: None }"###,
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
        resp.headers = Some(
            convert_headers(&["Contont-Type: text/html".to_string()]).unwrap(),
        );
        let header = resp.get_response_header().unwrap();
        assert_eq!(
            r###"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"contont-type": "text/html", "transfer-encoding": "chunked", "cache-control": "public, max-age=3600"} }, header_name_map: Some({"contont-type": CaseHeaderName(b"contont-type"), "transfer-encoding": CaseHeaderName(b"Transfer-Encoding"), "cache-control": CaseHeaderName(b"Cache-Control")}), reason_phrase: None }"###,
            format!("{header:?}")
        );
    }
}
