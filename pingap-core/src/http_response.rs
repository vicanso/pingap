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

use super::{
    get_super_ts, new_internal_error, HttpHeader, HTTP_HEADER_CONTENT_HTML,
    HTTP_HEADER_CONTENT_JSON, HTTP_HEADER_CONTENT_TEXT, HTTP_HEADER_NO_CACHE,
    HTTP_HEADER_NO_STORE, HTTP_HEADER_TRANSFER_CHUNKED, LOG_TARGET,
};
use bytes::{Bytes, BytesMut};
use http::header;
use http::StatusCode;
use http::{HeaderName, HeaderValue};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use serde::Serialize;
use std::pin::Pin;
use tokio::io::AsyncReadExt;
use tracing::error;

/// A helper function to generate a `Cache-Control` header.
///
/// It determines the appropriate `Cache-Control` value based on the provided
/// `max_age` and `cache_private` settings. This is a performance-sensitive
/// function, so it's optimized to avoid allocations where possible.
///
/// # Arguments
/// * `max_age`: An `Option<u32>` specifying the max-age in seconds. If `Some(0)` or `None`,
///   a "no-cache" header is returned.
/// * `cache_private`: An `Option<bool>` indicating if the cache is private. Defaults to public.
///
/// # Returns
/// An `HttpHeader` tuple `(HeaderName, HeaderValue)` for the `Cache-Control` header.
fn new_cache_control_header(
    max_age: Option<u32>,
    cache_private: Option<bool>,
) -> HttpHeader {
    // Determine the max_age value. If it's 0 or not provided, return the static no-cache header immediately.
    let max_age = match max_age {
        Some(0) | None => return HTTP_HEADER_NO_CACHE.clone(),
        Some(age) => age,
    };

    // Determine the cache visibility ("private" or "public").
    let category: &[u8] = if cache_private.unwrap_or_default() {
        b"private"
    } else {
        b"public"
    };

    // Use a pre-allocated buffer (`BytesMut`) and the `itoa` crate to efficiently build the
    // header value without creating an intermediate `String` via `format!`.
    // The capacity is estimated to prevent reallocations.
    let mut buf = BytesMut::with_capacity(category.len() + 9 + 10); // e.g., "public, max-age=" + up to 10 digits for a u32
    buf.extend_from_slice(category);
    buf.extend_from_slice(b", max-age=");
    buf.extend_from_slice(itoa::Buffer::new().format(max_age).as_bytes());

    // Try to create a `HeaderValue` from the constructed bytes.
    if let Ok(value) = HeaderValue::from_bytes(&buf) {
        return (header::CACHE_CONTROL, value);
    }
    // If creation fails for any reason, fall back to the safe "no-cache" header.
    HTTP_HEADER_NO_CACHE.clone()
}

/// A builder for creating `HttpResponse` instances fluently using the builder pattern.
///
/// This allows for chaining method calls to configure a response, improving readability.
#[derive(Default, Debug)]
pub struct HttpResponseBuilder {
    /// The `HttpResponse` instance being built.
    response: HttpResponse,
}

impl HttpResponseBuilder {
    /// Creates a new builder with a given status code.
    pub fn new(status: StatusCode) -> Self {
        Self {
            response: HttpResponse {
                status,
                ..Default::default()
            },
        }
    }

    /// Sets the response body.
    ///
    /// This method is generic over `impl Into<Bytes>`, allowing various types like
    /// `Vec<u8>`, `String`, or `&'static str` to be passed as the body.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.response.body = body.into();
        self
    }

    /// Adds a single HTTP header to the response.
    ///
    /// If the headers vector doesn't exist yet, it will be created.
    pub fn header(mut self, header: HttpHeader) -> Self {
        self.response
            .headers
            .get_or_insert_with(Vec::new)
            .push(header);
        self
    }

    /// Appends multiple HTTP headers to the response.
    pub fn headers(mut self, headers: Vec<HttpHeader>) -> Self {
        self.response
            .headers
            .get_or_insert_with(Vec::new)
            .extend(headers);
        self
    }

    /// Sets the `Cache-Control` max-age and privacy directive.
    pub fn max_age(mut self, seconds: u32, is_private: bool) -> Self {
        self.response.max_age = Some(seconds);
        self.response.cache_private = Some(is_private);
        self
    }

    /// A convenience method to add a "no-store" `Cache-Control` header.
    pub fn no_store(self) -> Self {
        self.header(HTTP_HEADER_NO_STORE.clone())
    }

    /// Consumes the builder and returns the final `HttpResponse` instance.
    pub fn finish(self) -> HttpResponse {
        self.response
    }
}

/// Represents a complete HTTP response, including status, headers, and a body.
/// This struct is used for responses where the entire body is known upfront.
#[derive(Default, Clone, Debug)]
pub struct HttpResponse {
    /// The HTTP status code (e.g., 200 OK, 404 Not Found).
    pub status: StatusCode,
    /// The response body, stored as a `Bytes` object for efficiency.
    pub body: Bytes,
    /// The `max-age` directive for the `Cache-Control` header, in seconds.
    pub max_age: Option<u32>,
    /// The UNIX timestamp when the response content was created, used for the `Age` header.
    pub created_at: Option<u32>,
    /// A flag to indicate if the `Cache-Control` should be "private" (true) or "public" (false).
    pub cache_private: Option<bool>,
    /// A list of additional HTTP headers to include in the response.
    pub headers: Option<Vec<HttpHeader>>,
}

impl HttpResponse {
    /// Returns a new `HttpResponseBuilder` to start building a response.
    pub fn builder(status: StatusCode) -> HttpResponseBuilder {
        HttpResponseBuilder::new(status)
    }

    /// A convenience constructor for a 204 No Content response.
    pub fn no_content() -> Self {
        Self::builder(StatusCode::NO_CONTENT).no_store().finish()
    }

    /// A convenience constructor for a 400 Bad Request response.
    pub fn bad_request(body: impl Into<Bytes>) -> Self {
        Self::builder(StatusCode::BAD_REQUEST)
            .body(body)
            .header(HTTP_HEADER_CONTENT_TEXT.clone())
            .no_store()
            .finish()
    }

    /// A convenience constructor for a 404 Not Found response.
    pub fn not_found(body: impl Into<Bytes>) -> Self {
        Self::builder(StatusCode::NOT_FOUND)
            .body(body)
            .header(HTTP_HEADER_CONTENT_TEXT.clone())
            .no_store()
            .finish()
    }

    /// A convenience constructor for a 500 Internal Server Error response.
    pub fn unknown_error(body: impl Into<Bytes>) -> Self {
        Self::builder(StatusCode::INTERNAL_SERVER_ERROR)
            .body(body)
            .header(HTTP_HEADER_CONTENT_TEXT.clone())
            .no_store()
            .finish()
    }

    /// A convenience constructor for a 200 OK HTML response.
    pub fn html(body: impl Into<Bytes>) -> Self {
        Self::builder(StatusCode::OK)
            .body(body)
            .header(HTTP_HEADER_CONTENT_HTML.clone())
            .header(HTTP_HEADER_NO_CACHE.clone())
            .finish()
    }

    /// A convenience constructor for a 302 Temporary Redirect response.
    pub fn redirect(location: &str) -> pingora::Result<Self> {
        // Attempt to parse the location string into a valid HeaderValue.
        let value = HeaderValue::from_str(location).map_err(|e| {
            error!(error = e.to_string(), "to header value fail");
            new_internal_error(500, e)
        })?;
        // Build the redirect response.
        Ok(Self::builder(StatusCode::TEMPORARY_REDIRECT)
            .header((header::LOCATION, value))
            .header(HTTP_HEADER_NO_CACHE.clone())
            .finish())
    }

    /// A convenience constructor for a 200 OK plain text response.
    pub fn text(body: impl Into<Bytes>) -> Self {
        Self::builder(StatusCode::OK)
            .body(body)
            .header(HTTP_HEADER_CONTENT_TEXT.clone())
            .header(HTTP_HEADER_NO_CACHE.clone())
            .finish()
    }

    /// Creates a 200 OK JSON response by serializing the given value.
    pub fn try_from_json<T>(value: &T) -> pingora::Result<Self>
    where
        T: ?Sized + Serialize,
    {
        // Serialize the value to a JSON byte vector.
        let buf = serde_json::to_vec(value).map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "to json fail");
            new_internal_error(400, e)
        })?;
        // Build the JSON response.
        Ok(Self::builder(StatusCode::OK)
            .body(buf)
            .header(HTTP_HEADER_CONTENT_JSON.clone())
            .finish())
    }

    /// Creates a JSON response with a specified status code by serializing the given value.
    pub fn try_from_json_status<T>(
        value: &T,
        status: StatusCode,
    ) -> pingora::Result<Self>
    where
        T: ?Sized + Serialize,
    {
        // First, create a standard 200 OK JSON response.
        let mut resp = Self::try_from_json(value)?;
        // Then, simply overwrite the status code.
        resp.status = status;
        Ok(resp)
    }

    /// Builds a `pingora::http::ResponseHeader` from the `HttpResponse`'s properties.
    pub fn new_response_header(&self) -> pingora::Result<ResponseHeader> {
        // Build the response header with the status code.
        let mut resp = ResponseHeader::build(self.status, None)?;

        // A local helper closure to simplify adding headers and handling potential errors.
        let mut add_header =
            |name: &HeaderName, value: &HeaderValue| -> pingora::Result<()> {
                resp.insert_header(name, value)?;
                Ok(())
            };

        // Add the Content-Length header based on the body size.
        add_header(
            &header::CONTENT_LENGTH,
            &HeaderValue::from(self.body.len()),
        )?;

        // Generate and add the Cache-Control header.
        let (name, value) =
            new_cache_control_header(self.max_age, self.cache_private);
        add_header(&name, &value)?;

        // If a creation timestamp is provided, calculate and add the Age header.
        if let Some(created_at) = self.created_at {
            let secs = get_super_ts().saturating_sub(created_at);
            add_header(&header::AGE, &HeaderValue::from(secs))?;
        }

        // Add all custom headers from the `headers` field.
        if let Some(headers) = &self.headers {
            for (name, value) in headers {
                add_header(name, value)?;
            }
        }
        Ok(resp)
    }

    /// Sends the entire HTTP response (header and body) to the client via the session.
    pub async fn send(self, session: &mut Session) -> pingora::Result<usize> {
        // First, build the response header.
        let header = self.new_response_header()?;
        let size = self.body.len();
        // Write the header to the session.
        session
            .write_response_header(Box::new(header), false)
            .await?;
        // Write the body to the session. `end_stream` is true because this is the final body part.
        session.write_response_body(Some(self.body), true).await?;
        // Finalize the response stream.
        session.finish_body().await?;
        Ok(size)
    }
}

/// Represents a chunked HTTP response for streaming large bodies of data.
///
/// This is used when the response body is too large to fit in memory or is generated on-the-fly.
pub struct HttpChunkResponse<'r, R> {
    /// A pinned, mutable reference to an async reader that provides the body data.
    pub reader: Pin<&'r mut R>,
    /// The suggested size for each data chunk. Defaults to `DEFAULT_BUF_SIZE`.
    pub chunk_size: usize,
    /// Cache control `max-age` setting for the response.
    pub max_age: Option<u32>,
    /// Cache control privacy setting for the response.
    pub cache_private: Option<bool>,
    /// Additional headers to include in the response.
    pub headers: Option<Vec<HttpHeader>>,
}

/// The default buffer size (8KB) for chunked responses.
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

impl<'r, R> HttpChunkResponse<'r, R>
where
    // The reader must implement `AsyncRead` and be `Unpin`.
    R: tokio::io::AsyncRead + std::marker::Unpin,
{
    /// Creates a new `HttpChunkResponse` with a given reader and default settings.
    pub fn new(r: &'r mut R) -> Self {
        Self {
            reader: Pin::new(r),
            chunk_size: DEFAULT_BUF_SIZE,
            max_age: None,
            headers: None,
            cache_private: None,
        }
    }

    /// Builds the `ResponseHeader` for the chunked response.
    ///
    /// This will include a `Transfer-Encoding: chunked` header.
    pub fn get_response_header(&self) -> pingora::Result<ResponseHeader> {
        // Start building a 200 OK response header.
        let mut resp = ResponseHeader::build(StatusCode::OK, Some(4))?;
        // Add any custom headers.
        if let Some(headers) = &self.headers {
            for (name, value) in headers {
                resp.insert_header(name.to_owned(), value)?;
            }
        }

        // Add the mandatory `Transfer-Encoding: chunked` header.
        let chunked = HTTP_HEADER_TRANSFER_CHUNKED.clone();
        resp.insert_header(chunked.0, chunked.1)?;

        // Add the `Cache-Control` header.
        let cache_control =
            new_cache_control_header(self.max_age, self.cache_private);
        resp.insert_header(cache_control.0, cache_control.1)?;
        Ok(resp)
    }

    /// Streams the data from the reader to the client as a chunked response.
    ///
    /// Reads data from the `reader` in chunks and sends each chunk to the client until
    /// the reader is exhausted.
    pub async fn send(
        mut self,
        session: &mut Session,
    ) -> pingora::Result<usize> {
        // First, build and send the response headers. `end_stream` is false because a body will follow.
        let header = self.get_response_header()?;
        session
            .write_response_header(Box::new(header), false)
            .await?;

        let mut sent = 0;
        // Ensure the chunk size is not too small.
        let chunk_size = self.chunk_size.max(512);
        // Create a reusable buffer for reading data into.
        let mut buffer = vec![0; chunk_size];
        loop {
            // Read a chunk of data from the source reader.
            let size = self.reader.read(&mut buffer).await.map_err(|e| {
                error!(error = e.to_string(), "read data fail");
                new_internal_error(400, e)
            })?;
            // Determine if this is the final chunk.
            let end = size < chunk_size;
            // Write the chunk to the response body.
            session
                .write_response_body(
                    // `copy_from_slice` is necessary because `write_response_body` takes an `Option<Bytes>`.
                    Some(Bytes::copy_from_slice(&buffer[..size])),
                    end,
                )
                .await?;
            sent += size;
            // If it was the last chunk, exit the loop.
            if end {
                break;
            }
        }
        // Finalize the response stream.
        session.finish_body().await?;

        Ok(sent)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert_headers;
    use bytes::Bytes;
    use http::StatusCode;
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use std::io::Write;
    use tempfile::NamedTempFile;
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
            format!("{:?}", new_cache_control_header(Some(0), Some(false)))
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
            format!("{:?}", HttpResponse::not_found("Not Found"))
        );
        assert_eq!(
            r###"HttpResponse { status: 500, body: b"Unknown Error", max_age: None, created_at: None, cache_private: None, headers: Some([("cache-control", "private, no-store")]) }"###,
            format!("{:?}", HttpResponse::unknown_error("Unknown Error"))
        );

        assert_eq!(
            r###"HttpResponse { status: 400, body: b"Bad Request", max_age: None, created_at: None, cache_private: None, headers: Some([("cache-control", "private, no-store")]) }"###,
            format!("{:?}", HttpResponse::bad_request("Bad Request"))
        );

        assert_eq!(
            r###"HttpResponse { status: 200, body: b"<p>Pingap</p>", max_age: None, created_at: None, cache_private: None, headers: Some([("content-type", "text/html; charset=utf-8"), ("cache-control", "private, no-cache")]) }"###,
            format!("{:?}", HttpResponse::html("<p>Pingap</p>"))
        );

        assert_eq!(
            r###"HttpResponse { status: 307, body: b"", max_age: None, created_at: None, cache_private: None, headers: Some([("location", "http://example.com/"), ("cache-control", "private, no-cache")]) }"###,
            format!(
                "{:?}",
                HttpResponse::redirect("http://example.com/").unwrap()
            )
        );

        assert_eq!(
            r###"HttpResponse { status: 200, body: b"Hello World!", max_age: None, created_at: None, cache_private: None, headers: Some([("content-type", "text/plain; charset=utf-8"), ("cache-control", "private, no-cache")]) }"###,
            format!("{:?}", HttpResponse::text("Hello World!"))
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
            created_at: Some(0),
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
        let file = include_bytes!("../../error.html");
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(file).unwrap();
        let mut f = fs::OpenOptions::new().read(true).open(f).await.unwrap();
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

    #[test]
    fn test_new_cache_control_header_logic() {
        // Test max_age > 0 case
        let (name, value) = new_cache_control_header(Some(3600), Some(true));
        assert_eq!(name, header::CACHE_CONTROL);
        assert_eq!(value.to_str().unwrap(), "private, max-age=3600");

        let (name, value) = new_cache_control_header(Some(3600), Some(false));
        assert_eq!(name, header::CACHE_CONTROL);
        assert_eq!(value.to_str().unwrap(), "public, max-age=3600");

        // Test None is equivalent to public
        let (name, value) = new_cache_control_header(Some(3600), None);
        assert_eq!(name, header::CACHE_CONTROL);
        assert_eq!(value.to_str().unwrap(), "public, max-age=3600");

        // Test max_age = 0, should return no-cache
        let (name, value) = new_cache_control_header(Some(0), Some(true));
        assert_eq!(name, header::CACHE_CONTROL);
        assert_eq!(value, HTTP_HEADER_NO_CACHE.clone().1);

        // Test max_age = None, should return no-cache
        let (name, value) = new_cache_control_header(None, Some(false));
        assert_eq!(name, header::CACHE_CONTROL);
        assert_eq!(value, HTTP_HEADER_NO_CACHE.clone().1);
    }

    #[test]
    fn test_http_response_builder_pattern() {
        // Create a custom Header
        let etag_header = (header::ETAG, HeaderValue::from_static("\"12345\""));
        let server_header =
            (header::SERVER, HeaderValue::from_static("MyTestServer"));

        let response = HttpResponse::builder(StatusCode::OK)
            .body("Test Body")
            .header(etag_header.clone())
            .headers(vec![server_header.clone()])
            .max_age(60, true) // 60 seconds, private
            .finish();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from("Test Body"));
        assert_eq!(response.max_age, Some(60));
        assert_eq!(response.cache_private, Some(true));

        // Verify headers are correctly added
        let headers = response.headers.unwrap();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&etag_header));
        assert!(headers.contains(&server_header));

        // Test no_store in the chain call
        let no_store_response = HttpResponse::builder(StatusCode::ACCEPTED)
            .no_store()
            .finish();

        assert_eq!(no_store_response.status, StatusCode::ACCEPTED);
        assert!(no_store_response
            .headers
            .unwrap()
            .contains(&HTTP_HEADER_NO_STORE.clone()));
    }

    #[test]
    fn test_http_response_error_cases() {
        // Test redirect error cases (invalid location)
        // String containing \0 characters is invalid HeaderValue
        let invalid_location = "http://example.com/\0";
        let result = HttpResponse::redirect(invalid_location);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_response_header_generation() {
        let resp = HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from("Hello world!"),
            max_age: Some(3600),
            created_at: Some(get_super_ts().saturating_sub(10)), // 模拟10秒前创建
            cache_private: Some(true),
            headers: Some(vec![(
                header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            )]),
        };

        let header = resp.new_response_header().unwrap();
        let headers_map: std::collections::HashMap<_, _> =
            header.headers.iter().collect();

        // 验证基本 headers
        assert_eq!(header.status, StatusCode::OK);
        assert_eq!(
            headers_map
                .get(&header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            "12"
        );
        assert_eq!(
            headers_map
                .get(&header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            "private, max-age=3600"
        );
        assert_eq!(
            headers_map
                .get(&header::CONTENT_ENCODING)
                .unwrap()
                .to_str()
                .unwrap(),
            "gzip"
        );
    }
}
