use crate::http_extra::{convert_headers, HttpResponse};
use crate::state::State;
use bytes::Bytes;
use http::StatusCode;
use pingora::proxy::Session;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use substring::Substring;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Json parse error {source}"))]
    Json { source: serde_json::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub static MOCK_PROTOCOL: &str = "mock://";

#[derive(Default, Deserialize, Serialize, Clone)]
pub struct MockInfo {
    status: Option<u16>,
    headers: Option<Vec<String>>,
    data: String,
}

pub struct MockResponse {
    pub resp: HttpResponse,
}

impl MockResponse {
    /// Creates a new mock response upstream, which will return a mock data.
    pub fn new(path: &str) -> Result<Self> {
        let new_data = path.substring(MOCK_PROTOCOL.len(), path.len());
        let info: MockInfo = serde_json::from_str(new_data).context(JsonSnafu)?;

        let mut resp = HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from(info.data.clone()),
            ..Default::default()
        };
        if let Some(status) = info.status {
            resp.status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
        }
        if let Some(value) = &info.headers {
            if let Ok(headers) = convert_headers(value) {
                resp.headers = Some(headers);
            }
        }

        Ok(MockResponse { resp })
    }
    /// Sends the mock data to client.
    pub async fn handle(&self, session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
        let _ = self.resp.clone().send(session).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::MockResponse;
    use bytes::Bytes;
    use http::StatusCode;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_mock_response() {
        let resp = MockResponse::new(
            r###"mock://{"status":500,"headers":["Content-Type: application/json"],"data":"{\"message\":\"Mock Service Unavailable\"}"}"###,
        ).unwrap().resp;
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, resp.status);
        assert_eq!(
            r###"Some([("content-type", "application/json")])"###,
            format!("{:?}", resp.headers)
        );
        assert_eq!(
            Bytes::from_static(b"{\"message\":\"Mock Service Unavailable\"}"),
            resp.body
        );
    }
}
