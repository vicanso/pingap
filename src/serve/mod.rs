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
