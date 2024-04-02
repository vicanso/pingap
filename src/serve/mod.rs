use crate::state::State;
use async_trait::async_trait;
use pingora::proxy::Session;

mod admin;
mod directory;
mod embedded_file;
mod mock;

#[async_trait]
pub trait Serve {
    async fn handle(&self, _session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
        Ok(true)
    }
}

pub use admin::ADMIN_SERVE;
pub use directory::{Directory, FILE_PROTOCOL};
pub use mock::{MockResponse, MOCK_PROTOCOL};
