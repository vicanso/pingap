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
use super::{Error, Result, PAGE_SIZE};
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
use tracing::{debug, error, info};
use walkdir::WalkDir;

pub struct FileCache {
    pub directory: String,
    reading: AtomicU32,
    reading_max: u32,
    #[cfg(feature = "full")]
    read_time: Box<Histogram>,
    writing: AtomicU32,
    writing_max: u32,
    #[cfg(feature = "full")]
    write_time: Box<Histogram>,
    cache: Option<TinyUfo<String, CacheObject>>,
}

struct FileCacheParams {
    directory: String,
    reading_max: u32,
    writing_max: u32,
    cache_max: usize,
}

fn parse_params(dir: &str) -> FileCacheParams {
    let mut reading_max = 10 * 1000;
    let mut writing_max = 1000;
    let mut cache_max = 100;
    let dir = if let Some((dir, query)) = dir.split_once('?') {
        let m = util::convert_query_map(query);
        if let Some(max) = m.get("reading_max") {
            reading_max = max.parse::<u32>().unwrap_or(reading_max);
        }
        if let Some(max) = m.get("writing_max") {
            writing_max = max.parse::<u32>().unwrap_or(writing_max);
        }
        if let Some(value) = m.get("cache_max") {
            cache_max = value.parse::<usize>().unwrap_or(cache_max);
        }
        util::resolve_path(dir)
    } else {
        util::resolve_path(dir)
    };
    FileCacheParams {
        directory: dir,
        reading_max,
        writing_max,
        cache_max,
    }
}

/// Create a file cache and use tinyufo for hotspot data caching
pub fn new_file_cache(dir: &str) -> Result<FileCache> {
    let params = parse_params(dir);

    let path = Path::new(&params.directory);
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| Error::Io { source: e })?;
    }
    info!(
        dir = params.directory,
        reading_max = params.reading_max,
        writing_max = params.writing_max,
        cache_max = params.cache_max,
        "new file cache"
    );
    let mut cache = None;
    if params.cache_max > 0 {
        cache =
            Some(TinyUfo::new(params.cache_max, params.cache_max * PAGE_SIZE));
    }

    Ok(FileCache {
        directory: params.directory,
        reading: AtomicU32::new(0),
        reading_max: params.reading_max,
        #[cfg(feature = "full")]
        read_time: CACHE_READING_TIME.clone(),
        writing: AtomicU32::new(0),
        writing_max: params.writing_max,
        #[cfg(feature = "full")]
        write_time: CACHE_WRITING_TIME.clone(),
        cache,
    })
}

#[async_trait]
impl HttpCacheStorage for FileCache {
    /// Get cache object from tinyufo,
    /// if not exists, then get from the file.
    async fn get(
        &self,
        key: &str,
        namespace: &str,
    ) -> Result<Option<CacheObject>> {
        debug!(key, namespace, "get cache from file");
        if let Some(Some(obj)) =
            self.cache.as_ref().map(|c| c.get(&key.to_string()))
        {
            return Ok(Some(obj));
        }
        #[cfg(feature = "full")]
        let start = SystemTime::now();
        let file = if namespace.is_empty() {
            Path::new(&self.directory).join(key)
        } else {
            Path::new(&self.directory).join(format!("{namespace}/{key}"))
        };
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
        key: &str,
        namespace: &str,
        data: CacheObject,
        weight: u16,
    ) -> Result<()> {
        debug!(key, namespace, "put cache to file");
        if let Some(c) = &self.cache {
            c.put(key.to_string(), data.clone(), weight);
        }
        #[cfg(feature = "full")]
        let start = SystemTime::now();
        let buf: Bytes = data.into();
        let file = if namespace.is_empty() {
            Path::new(&self.directory).join(key)
        } else {
            Path::new(&self.directory).join(format!("{namespace}/{key}"))
        };
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
    async fn remove(
        &self,
        key: &str,
        namespace: &str,
    ) -> Result<Option<CacheObject>> {
        debug!(key, namespace, "remove cache from file");
        if let Some(c) = &self.cache {
            c.remove(&key.to_string());
        }
        let file = if namespace.is_empty() {
            Path::new(&self.directory).join(key)
        } else {
            Path::new(&self.directory).join(format!("{namespace}/{key}"))
        };
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
            match fs::remove_file(entry.path()).await {
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
    use super::{new_file_cache, parse_params};
    use crate::cache::http_cache::{CacheObject, HttpCacheStorage};
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    #[test]
    fn test_parse_params() {
        let params = parse_params(
            "~/pingap?reading_max=1000&writing_max=500&cache_max=100",
        );
        assert_eq!(1000, params.reading_max);
        assert_eq!(500, params.writing_max);
        assert_eq!(100, params.cache_max);
    }

    #[tokio::test]
    async fn test_file_cache() {
        let dir = TempDir::new().unwrap();
        let dir = dir.into_path().to_string_lossy().to_string();
        let cache = new_file_cache(&dir).unwrap();
        let key = "key";
        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: Bytes::from_static(b"Hello World!"),
        };
        let result = cache.get(key, "").await.unwrap();
        assert_eq!(true, result.is_none());
        cache.put(key, "", obj.clone(), 1).await.unwrap();
        let result = cache.get(key, "").await.unwrap().unwrap();
        assert_eq!(obj, result);

        // empty tinyufo, get from file
        let cache = new_file_cache(&dir).unwrap();
        let result = cache.get(key, "").await.unwrap().unwrap();
        assert_eq!(obj, result);

        cache.remove(key, "").await.unwrap();
        let result = cache.get(key, "").await.unwrap();
        assert_eq!(true, result.is_none());

        cache.put(key, "", obj.clone(), 1).await.unwrap();
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
