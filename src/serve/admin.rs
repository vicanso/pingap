use super::Serve;
use crate::cache;
use crate::cache::HttpResponse;
use crate::config;
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use log::error;
use once_cell::sync::Lazy;
use pingora::proxy::Session;

pub struct AdminServe {}

pub static ADMIN_SERVE: Lazy<&AdminServe> = Lazy::new(|| &AdminServe {});

impl AdminServe {
    async fn get_config(&self) -> pingora::Result<HttpResponse> {
        let conf = config::load_config(&config::get_config_path(), true).map_err(|e| {
            error!("failed to load config: {e}");
            pingora::Error::new_str("Load config fail")
        })?;
        let buf = serde_json::to_vec(&conf).map_err(|e| {
            error!("failed to format config: {e}");
            pingora::Error::new_str("Format config fail")
        })?;
        Ok(HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from(buf),
            headers: Some(vec![cache::HTTP_HEADER_CONTENT_JSON.clone()]),
            ..Default::default()
        })
    }
}

#[async_trait]
impl Serve for AdminServe {
    async fn handle(&self, session: &mut Session, ctx: &mut State) -> pingora::Result<bool> {
        let resp = self.get_config().await?;
        ctx.response_body_size = resp.send(session).await?;
        Ok(true)
    }
}
