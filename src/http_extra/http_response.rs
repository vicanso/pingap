use super::HTTP_HEADER_TRANSFER_CHUNKED;
use super::{HttpHeader, HTTP_HEADER_CONTENT_JSON, HTTP_HEADER_NO_STORE};
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
    HTTP_HEADER_NO_STORE.clone()
}

#[derive(Default, Clone)]
pub struct HttpResponse {
    // http response status
    pub status: StatusCode,
    // http response body
    pub body: Bytes,
    // max age of http response
    pub max_age: Option<u32>,
    // created time of http response
    pub created_at: Option<u64>,
    // private for cache control
    pub cache_private: Option<bool>,
    // headers for http response
    pub headers: Option<Vec<HttpHeader>>,
}

impl HttpResponse {
    pub fn no_content() -> Self {
        HttpResponse {
            status: StatusCode::NO_CONTENT,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            ..Default::default()
        }
    }
    pub fn not_found() -> Self {
        HttpResponse {
            status: StatusCode::NOT_FOUND,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            body: Bytes::from("Not Found"),
            ..Default::default()
        }
    }
    pub fn unknown_error() -> Self {
        HttpResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
            body: Bytes::from("Unknown error"),
            ..Default::default()
        }
    }
    pub fn try_from_json_status<T>(value: &T, status: StatusCode) -> pingora::Result<Self>
    where
        T: ?Sized + Serialize,
    {
        let mut resp = HttpResponse::try_from_json(value)?;
        resp.status = status;
        Ok(resp)
    }
    pub fn try_from_json<T>(value: &T) -> pingora::Result<Self>
    where
        T: ?Sized + Serialize,
    {
        let buf = serde_json::to_vec(value).map_err(|e| {
            error!("To json fail: {e}");
            pingora::Error::new_str("To json fail")
        })?;
        Ok(HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from(buf),
            headers: Some(vec![HTTP_HEADER_CONTENT_JSON.clone()]),
            ..Default::default()
        })
    }
    /// Gets the response header from http response
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
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                - created_at;
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
    /// Sends http response to client
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

impl<'r, R> HttpChunkResponse<'r, R>
where
    R: tokio::io::AsyncRead + std::marker::Unpin,
{
    pub fn new(r: &'r mut R) -> Self {
        Self {
            reader: Pin::new(r),
            chunk_size: 5 * 1024,
            max_age: None,
            headers: None,
            cache_private: None,
        }
    }
    pub async fn send(&mut self, session: &mut Session) -> pingora::Result<usize> {
        let mut sent = 0;
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

        session.write_response_header(Box::new(resp)).await?;

        let mut buffer = vec![0; self.chunk_size.max(512)];
        loop {
            let size = self.reader.read(&mut buffer).await.map_err(|e| {
                error!("Read data fail: {e}");
                pingora::Error::new_str("Read data fail")
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
    use super::HttpResponse;
    use crate::http_extra::convert_headers;
    use bytes::Bytes;
    use http::StatusCode;
    use pretty_assertions::assert_eq;
    use std::time::{SystemTime, UNIX_EPOCH};
    #[test]
    fn test_http_response() {
        let resp = HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from("Hello world!"),
            max_age: Some(3600),
            created_at: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - 10,
            ),
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
}
