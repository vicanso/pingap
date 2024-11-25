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

use super::http_cache::{CacheObject, HttpCacheStats, HttpCacheStorage};
use super::{Error, Result};
#[cfg(feature = "full")]
use crate::state::{CACHE_READING_TIME, CACHE_WRITING_TIME};
use crate::util;
use async_trait::async_trait;
use bytes::Bytes;
#[cfg(feature = "full")]
use prometheus::Histogram;
use scopeguard::defer;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;
use tinyufo::TinyUfo;
use tokio::fs;
use tracing::{error, info};
use walkdir::WalkDir;

pub struct FileCache {
    directory: String,
    reading: AtomicU32,
    reading_max: u32,
    #[cfg(feature = "full")]
    read_time: Box<Histogram>,
    writing: AtomicU32,
    writing_max: u32,
    #[cfg(feature = "full")]
    write_time: Box<Histogram>,
    cache: TinyUfo<String, CacheObject>,
}

/// Create a file cache and use tinyufo for hotspot data caching
pub fn new_file_cache(dir: &str) -> Result<FileCache> {
    let dir = util::resolve_path(dir);
    let path = Path::new(&dir);
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| Error::Io { source: e })?;
    }
    info!(dir, "new file cache");

    Ok(FileCache {
        directory: dir,
        reading: AtomicU32::new(0),
        // TODO get max value from query string
        reading_max: 10 * 1000,
        #[cfg(feature = "full")]
        read_time: CACHE_READING_TIME.clone(),
        writing: AtomicU32::new(0),
        // TODO get max value from query string
        writing_max: 1000,
        #[cfg(feature = "full")]
        write_time: CACHE_WRITING_TIME.clone(),
        cache: TinyUfo::new(100, 100),
    })
}

#[async_trait]
impl HttpCacheStorage for FileCache {
    /// Get cache object from tinyufo,
    /// if not exists, then get from the file.
    async fn get(&self, key: &str) -> Result<Option<CacheObject>> {
        if let Some(obj) = self.cache.get(&key.to_string()) {
            return Ok(Some(obj));
        }
        #[cfg(feature = "full")]
        let start = SystemTime::now();
        let file = Path::new(&self.directory).join(key);
        // add reading count
        let count = self.reading.fetch_add(1, Ordering::Relaxed);
        defer!(self.reading.fetch_sub(1, Ordering::Relaxed););
        if self.reading_max > 0 && count >= self.reading_max {
            return Err(Error::OverQuota {
                max: self.reading_max,
                message: "too many reading".to_string(),
            });
        }
        let result = fs::read(file).await;
        #[cfg(feature = "full")]
        self.read_time.observe(util::elapsed_second(start));
        let buf = match result {
            Ok(buf) => Ok(buf),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(vec![])
                } else {
                    Err(Error::Io { source: e })
                }
            },
        }?;
        if buf.len() < 8 {
            Ok(None)
        } else {
            Ok(Some(CacheObject::from(Bytes::from(buf))))
        }
    }
    /// Put cache object to tinyufo and file.
    async fn put(
        &self,
        key: String,
        data: CacheObject,
        weight: u16,
    ) -> Result<()> {
        self.cache.put(key.clone(), data.clone(), weight);
        #[cfg(feature = "full")]
        let start = SystemTime::now();
        let buf: Bytes = data.into();
        let file = Path::new(&self.directory).join(key);
        // add writing count
        let count = self.writing.fetch_add(1, Ordering::Relaxed);
        defer!(self.writing.fetch_sub(1, Ordering::Relaxed););
        if self.writing_max > 0 && count >= self.writing_max {
            return Err(Error::OverQuota {
                max: self.writing_max,
                message: "too many writing".to_string(),
            });
        }
        let result = fs::write(file, buf).await;
        #[cfg(feature = "full")]
        self.write_time.observe(util::elapsed_second(start));
        result.map_err(|e| Error::Io { source: e })
    }
    /// Remove cache object from file, tinyufo doesn't support remove now.
    async fn remove(&self, key: &str) -> Result<Option<CacheObject>> {
        // TODO remove from tinyufo
        let file = Path::new(&self.directory).join(key);
        fs::remove_file(file)
            .await
            .map_err(|e| Error::Io { source: e })?;
        Ok(None)
    }
    /// Get the stats of file cache
    #[inline]
    fn stats(&self) -> Option<HttpCacheStats> {
        Some(HttpCacheStats {
            reading: self.reading.load(Ordering::Relaxed),
            writing: self.writing.load(Ordering::Relaxed),
        })
    }
    async fn clear(&self, access_before: SystemTime) -> Result<(i32, i32)> {
        let mut success = 0;
        let mut fail = 0;
        for entry in WalkDir::new(&self.directory)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().is_dir() {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let Ok(accessed) = metadata.accessed() else {
                continue;
            };
            if accessed > access_before {
                continue;
            }
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {
                    success += 1;
                },
                Err(e) => {
                    fail += 1;
                    error!(
                        err = e.to_string(),
                        entry = entry.path().to_string_lossy().to_string(),
                        "remove cache file fail"
                    );
                },
            };
        }
        Ok((success, fail))
    }
}

#[cfg(test)]
mod tests {
    use super::new_file_cache;
    use crate::cache::http_cache::{CacheObject, HttpCacheStorage};
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_cache() {
        let dir = TempDir::new().unwrap();
        let dir = dir.into_path().to_string_lossy().to_string();
        let cache = new_file_cache(&dir).unwrap();
        let key = "key".to_string();
        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: Bytes::from_static(b"Hello World!"),
        };
        let result = cache.get(&key).await.unwrap();
        assert_eq!(true, result.is_none());
        cache.put(key.clone(), obj.clone(), 1).await.unwrap();
        let result = cache.get(&key).await.unwrap().unwrap();
        assert_eq!(obj, result);

        // empty tinyufo, get from file
        let cache = new_file_cache(&dir).unwrap();
        let result = cache.get(&key).await.unwrap().unwrap();
        assert_eq!(obj, result);

        cache.remove(&key).await.unwrap();
        let result = cache.get(&key).await.unwrap();
        assert_eq!(true, result.is_none());

        cache.put(key.clone(), obj.clone(), 1).await.unwrap();
        cache
            .clear(
                SystemTime::now()
                    .checked_add(Duration::from_secs(365 * 24 * 3600))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    #[test]
    fn test_stats() {
        let dir = TempDir::new().unwrap();
        let dir = dir.into_path().to_string_lossy().to_string();
        let cache = new_file_cache(&dir).unwrap();
        assert_eq!(0, cache.stats().unwrap().reading);
        assert_eq!(0, cache.stats().unwrap().writing);
    }
}
