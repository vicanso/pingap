use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use pingora::{http::ResponseHeader, proxy::Session};

#[derive(Default)]
pub struct ResponseData {
    pub status: StatusCode,
    pub body: Bytes,
    pub max_age: Option<u32>,
    pub created_at: Option<u64>,
    pub headers: Option<Vec<(HeaderName, HeaderValue)>>,
}

impl ResponseData {
    pub async fn send(&self, session: &mut Session) -> pingora::Result<usize> {
        let mut resp = ResponseHeader::build(self.status, Some(4))?;
        resp.insert_header(http::header::CONTENT_LENGTH, self.body.len().to_string())?;
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
