use crate::state::State;
use async_trait::async_trait;
use pingora::proxy::Session;

mod admin;
mod static_file;

#[async_trait]
pub trait Serve {
    async fn handle(&self, _session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
        Ok(true)
    }
}

pub use admin::ADMIN_SERVE;
