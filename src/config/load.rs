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

use super::{
    ConfigStorage, EtcdStorage, FileStorage, PingapConf, Result, ETCD_PROTOCOL,
};

/// Save the confog to path.
///
/// Validate the config before save.
pub async fn save_config(
    path: &str,
    conf: &PingapConf,
    category: &str,
) -> Result<()> {
    if path.starts_with(ETCD_PROTOCOL) {
        EtcdStorage::new(path)?.save_config(conf, category).await
    } else {
        FileStorage::new(path)?.save_config(conf, category).await
    }
}

/// Load the config from path.
pub async fn load_config(path: &str, admin: bool) -> Result<PingapConf> {
    if path.starts_with(ETCD_PROTOCOL) {
        EtcdStorage::new(path)?.load_config(admin).await
    } else {
        FileStorage::new(path)?.load_config(admin).await
    }
}
