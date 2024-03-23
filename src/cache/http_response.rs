use super::{HttpHeader, HTTP_HEADER_NO_STORE};
use bytes::Bytes;
use http::header;
use http::StatusCode;
use pingora::{http::ResponseHeader, proxy::Session};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub body: Bytes,
    pub max_age: Option<u32>,
    pub created_at: Option<u64>,
    pub private: Option<bool>,
    pub headers: Option<Vec<HttpHeader>>,
}

impl HttpResponse {
    pub async fn send(&self, session: &mut Session) -> pingora::Result<usize> {
        let fix_size = 3;
        let size = self
            .headers
            .as_ref()
            .map_or_else(|| fix_size, |headers| headers.len() + fix_size);
        let mut resp = ResponseHeader::build(self.status, Some(size))?;
        resp.insert_header(http::header::CONTENT_LENGTH, self.body.len().to_string())?;

        // set cache control
        if let Some(max_age) = self.max_age {
            let category = if self.private.unwrap_or_default() {
                "private"
            } else {
                "public"
            };
            if let Ok(value) =
                header::HeaderValue::from_str(&format!("{category}, max-age={max_age}"))
            {
                resp.insert_header(header::CACHE_CONTROL, value)?;
            }
        } else {
            let h = HTTP_HEADER_NO_STORE.clone();
            resp.insert_header(h.0, h.1)?;
        }

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

        let buf = self.body.clone();
        let size = buf.len();
        session.write_response_header(Box::new(resp)).await?;
        session.write_response_body(buf).await?;
        Ok(size)
    }
}
