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

use crate::util;

use super::http_cache::{CacheObject, HttpCacheStorage};
use super::{Error, Result};
use async_trait::async_trait;
use std::path::Path;
use tokio::fs;

pub struct FileCache {
    directory: String,
}

pub fn new_file_cache(dir: &str) -> Result<FileCache> {
    let dir = util::resolve_path(dir);
    let path = Path::new(&dir);
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| Error::Io { source: e })?;
    }

    Ok(FileCache { directory: dir })
}

#[async_trait]
impl HttpCacheStorage for FileCache {
    async fn get(&self, key: &str) -> Option<CacheObject> {
        let file = Path::new(&self.directory).join(key);
        let Ok(buf) = fs::read(file).await else {
            return None;
        };
        if buf.len() < 8 {
            None
        } else {
            Some(CacheObject::from(buf))
        }
    }
    async fn put(
        &self,
        key: String,
        data: CacheObject,
        _weight: u16,
    ) -> Result<()> {
        let buf: Vec<u8> = data.into();
        let file = Path::new(&self.directory).join(key);
        fs::write(file, buf)
            .await
            .map_err(|e| Error::Io { source: e })?;
        Ok(())
    }
    async fn remove(&self, key: &str) -> Result<Option<CacheObject>> {
        let file = Path::new(&self.directory).join(key);
        fs::remove_file(file)
            .await
            .map_err(|e| Error::Io { source: e })?;
        Ok(None)
    }
}
