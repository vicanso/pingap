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

use crate::{Error, Observer};
use async_trait::async_trait;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone)]
pub struct History {
    pub data: String,
    pub created_at: u64,
}

#[async_trait]
pub trait Storage: Send + Sync {
    /// fetch from storage
    async fn fetch(&self, key: &str) -> Result<String>;

    /// save to storage
    async fn save(&self, key: &str, value: &str) -> Result<()>;

    /// delete from storage
    async fn delete(&self, key: &str) -> Result<()>;
    fn support_observer(&self) -> bool {
        false
    }
    fn support_history(&self) -> bool {
        false
    }
    async fn fetch_history(&self, _key: &str) -> Result<Option<Vec<History>>> {
        Ok(None)
    }
    /// Sets up a watch on the config path to observe changes
    /// Note: May miss changes if processing takes too long between updates
    /// Should be used with periodic full fetches to ensure consistency
    async fn observe(&self) -> Result<Observer> {
        Ok(Observer {
            etcd_watch_stream: None,
        })
    }
}
