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

use super::{file, Error, Result, PAGE_SIZE};
use crate::config::get_current_config;
use crate::service::Error as ServiceError;
use crate::service::SimpleServiceTaskFuture;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use pingora::cache::key::CacheHashKey;
use pingora::cache::key::CompactCacheKey;
use pingora::cache::storage::{HandleHit, HandleMiss};
use pingora::cache::trace::SpanHandle;
use pingora::cache::{
    CacheKey, CacheMeta, HitHandler, MissHandler, PurgeType, Storage,
};
use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::info;

type BinaryMeta = (Vec<u8>, Vec<u8>);

/// Represents a cached object containing metadata and body content
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CacheObject {
    /// Tuple containing two metadata byte vectors (meta0, meta1)
    pub meta: BinaryMeta,
    /// The actual cached content
    pub body: Bytes,
}

const META_SIZE_LENGTH: usize = 8;

/// Creates a CacheObject from bytes with the following format:
/// - First 4 bytes: meta0 size (u32)
/// - Next 4 bytes: meta1 size (u32)
/// - Next meta0_size bytes: meta0 data
/// - Next meta1_size bytes: meta1 data
/// - Remaining bytes: body data
impl From<Bytes> for CacheObject {
    fn from(value: Bytes) -> Self {
        let size_byte = META_SIZE_LENGTH;
        // 8 bytes
        if value.len() < size_byte {
            return Self::default();
        }
        let mut data = value;

        let meta0_size = data.get_u32() as usize;
        let meta1_size = data.get_u32() as usize;

        let meta0 = data.split_to(meta0_size).to_vec();
        let meta1 = data.split_to(meta1_size).to_vec();

        Self {
            meta: (meta0, meta1),
            body: data,
        }
    }
}
/// Converts a CacheObject into bytes with the following format:
/// - First 4 bytes: meta0 size (u32)
/// - Next 4 bytes: meta1 size (u32)
/// - Next meta0_size bytes: meta0 data
/// - Next meta1_size bytes: meta1 data
/// - Remaining bytes: body data
impl From<CacheObject> for Bytes {
    fn from(value: CacheObject) -> Self {
        let meta_size =
            value.meta.0.len() + value.meta.1.len() + META_SIZE_LENGTH;
        let mut buf = BytesMut::with_capacity(value.body.len() + meta_size);
        let meta0_size = value.meta.0.len() as u32;
        let meta1_size = value.meta.1.len() as u32;
        buf.put_u32(meta0_size);
        buf.put_u32(meta1_size);
        buf.extend(value.meta.0);
        buf.extend(value.meta.1);
        buf.extend(value.body.iter());

        buf.into()
    }
}

#[derive(Debug)]
pub struct HttpCacheStats {
    pub reading: u32,
    pub writing: u32,
}

/// Storage interface for HTTP caching operations
///
/// This trait defines the core operations needed to implement a storage backend
/// for HTTP caching. Implementations must be both `Send` and `Sync` to support
/// concurrent access.
#[async_trait]
pub trait HttpCacheStorage: Sync + Send {
    /// Retrieves a cached object from storage
    /// Returns None if not found or Some(CacheObject) if present
    async fn get(
        &self,
        key: &str,
        namespace: &str,
    ) -> Result<Option<CacheObject>>;

    /// Stores a cache object with the given key, namespace and weight
    /// Weight determines the storage cost/priority of the cached item
    async fn put(
        &self,
        key: &str,
        namespace: &str,
        data: CacheObject,
        weight: u16,
    ) -> Result<()>;

    /// Removes a cached object from storage.
    ///
    /// # Arguments
    /// * `key` - The unique identifier for the cached object
    /// * `namespace` - The namespace to scope the cache key
    ///
    /// # Returns
    /// * `Result<Option<CacheObject>>` - The removed object if it existed
    async fn remove(
        &self,
        _key: &str,
        _namespace: &str,
    ) -> Result<Option<CacheObject>> {
        Ok(None)
    }

    /// Clears cached objects accessed before the specified time.
    ///
    /// # Arguments
    /// * `access_before` - Remove items last accessed before this timestamp
    ///
    /// # Returns
    /// * `Result<(i32, i32)>` - Count of (successful, failed) removals
    async fn clear(
        &self,
        _access_before: std::time::SystemTime,
    ) -> Result<(i32, i32)> {
        Ok((-1, -1))
    }

    /// Returns current storage statistics.
    ///
    /// # Returns
    /// * `Option<HttpCacheStats>` - Current read/write statistics if available
    fn stats(&self) -> Option<HttpCacheStats> {
        None
    }
}

async fn do_file_storage_clear(
    count: u32,
    dir: String,
) -> Result<bool, ServiceError> {
    // Add 1 every loop
    let offset = 60;
    if count % offset != 0 {
        return Ok(false);
    }
    let Ok(storage) = file::new_file_cache(&dir) else {
        return Ok(false);
    };

    let Some(access_before) =
        SystemTime::now().checked_sub(Duration::from_secs(24 * 3600))
    else {
        return Ok(false);
    };

    let Ok((success, fail)) = storage.clear(access_before).await else {
        return Ok(true);
    };
    if success < 0 {
        return Ok(true);
    }
    info!(dir, success, fail, "cache storage clear");
    Ok(true)
}

pub fn new_file_storage_clear_service(
) -> Option<(String, SimpleServiceTaskFuture)> {
    let dir = get_current_config().basic.cache_directory.as_ref()?.clone();
    let task: SimpleServiceTaskFuture = Box::new(move |count: u32| {
        Box::pin({
            let value = dir.clone();
            async move {
                let value = value.clone();
                do_file_storage_clear(count, value).await
            }
        })
    });
    Some(("cacheStorageClear".to_string(), task))
}

pub struct HttpCache {
    pub directory: Option<String>,
    pub(crate) cached: Arc<dyn HttpCacheStorage>,
}

impl HttpCache {
    #[inline]
    pub fn stats(&self) -> Option<HttpCacheStats> {
        self.cached.stats()
    }
}

/// Handles cache hits by managing access to cached content
pub struct CompleteHit {
    /// The cached content
    body: Bytes,
    /// Whether the content has been read
    done: bool,
    /// Start position for range requests
    range_start: usize,
    /// End position for range requests
    range_end: usize,
}

impl CompleteHit {
    fn get(&mut self) -> Option<Bytes> {
        if self.done {
            None
        } else {
            self.done = true;
            Some(self.body.slice(self.range_start..self.range_end))
        }
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        if start >= self.body.len() {
            return Err(Error::Invalid {
                message: format!(
                    "seek start out of range {start} >= {}",
                    self.body.len()
                ),
            });
        }
        self.range_start = start;
        if let Some(end) = end {
            // end over the actual last byte is allowed, we just need to return the actual bytes
            self.range_end = std::cmp::min(self.body.len(), end);
        }
        // seek resets read so that one handler can be used for multiple ranges
        self.done = false;
        Ok(())
    }
}

#[async_trait]
impl HandleHit for CompleteHit {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        Ok(self.get())
    }
    async fn finish(
        self: Box<Self>, // because self is always used as a trait object
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<()> {
        Ok(())
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(
        &mut self,
        start: usize,
        end: Option<usize>,
    ) -> pingora::Result<()> {
        self.seek(start, end)?;
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

/// Handles cache misses by collecting and storing new content
pub struct ObjectMissHandler {
    /// Metadata to store with the cached content
    meta: BinaryMeta,
    /// Buffer for collecting the body content
    body: BytesMut,
    /// Cache key for storing the final object
    key: String,
    /// Namespace for storing the final object
    namespace: String,
    /// Reference to the storage backend
    cache: Arc<dyn HttpCacheStorage>,
}

#[async_trait]
impl HandleMiss for ObjectMissHandler {
    async fn write_body(
        &mut self,
        data: bytes::Bytes,
        _eof: bool,
    ) -> pingora::Result<()> {
        self.body.extend(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<usize> {
        let size = self.body.len(); // FIXME: this just body size, also track meta size
        let _ = self
            .cache
            .put(
                &self.key,
                &self.namespace,
                CacheObject {
                    meta: self.meta,
                    body: self.body.into(),
                },
                get_weight(size),
            )
            .await?;

        Ok(size)
    }
}

// Maximum size for a single cached object (40MB)
static MAX_ONE_CACHE_SIZE: usize = 10 * 1024 * PAGE_SIZE;

/// Calculates the storage weight based on content size
/// Returns a weight between 1 and u16::MAX
fn get_weight(size: usize) -> u16 {
    if size <= PAGE_SIZE {
        return 1;
    }
    if size >= MAX_ONE_CACHE_SIZE {
        return u16::MAX;
    }
    (size / PAGE_SIZE) as u16
}

#[async_trait]
impl Storage for HttpCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let namespace = key.namespace();
        let hash = key.combined();
        if let Some(obj) = self.cached.get(&hash, namespace).await? {
            let meta = CacheMeta::deserialize(&obj.meta.0, &obj.meta.1)?;
            let size = obj.body.len();
            let hit_handler = CompleteHit {
                body: obj.body,
                done: false,
                range_start: 0,
                range_end: size,
            };
            Ok(Some((meta, Box::new(hit_handler))))
        } else {
            Ok(None)
        }
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<MissHandler> {
        // TODO: support multiple concurrent writes or panic if the is already a writer
        let capacity = 5 * 1024;
        let size = if let Some(content_length) =
            meta.headers().get(http::header::CONTENT_LENGTH)
        {
            content_length
                .to_str()
                .unwrap_or_default()
                .parse::<usize>()
                .unwrap_or(capacity)
        } else {
            capacity
        };
        let hash = key.combined();
        let meta = meta.serialize()?;
        let miss_handler = ObjectMissHandler {
            meta,
            key: hash,
            namespace: key.namespace().to_string(),
            cache: self.cached.clone(),
            body: BytesMut::with_capacity(size),
        };
        Ok(Box::new(miss_handler))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _type: PurgeType,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        // This usually purges the primary key because, without a lookup,
        // the variance key is usually empty
        let hash = key.combined();
        // TODO get namespace of cache key
        let cache_removed =
            if let Ok(result) = self.cached.remove(&hash, "").await {
                result.is_some()
            } else {
                false
            };
        Ok(cache_removed)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        let namespace = key.namespace();
        let hash = key.combined();
        if let Some(mut obj) = self.cached.get(&hash, namespace).await? {
            obj.meta = meta.serialize()?;
            let size = obj.body.len();
            let _ = self
                .cached
                .put(&hash, namespace, obj, get_weight(size))
                .await?;
            Ok(true)
        } else {
            Err(Error::Invalid {
                message: "no meta found".to_string(),
            }
            .into())
        }
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{CompleteHit, HttpCacheStorage, ObjectMissHandler};
    use crate::cache::tiny::new_tiny_ufo_cache;
    use bytes::{Bytes, BytesMut};
    use pingora::cache::storage::{HitHandler, MissHandler};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_complete_hit() {
        let body = Bytes::from_static(b"Hello World!");
        let size = body.len();
        let hit = CompleteHit {
            body,
            done: false,
            range_start: 0,
            range_end: size,
        };
        let mut handle: HitHandler = Box::new(hit);
        let body = handle.read_body().await.unwrap();
        assert_eq!(true, body.is_some());
        assert_eq!(b"Hello World!", body.unwrap().as_ref());

        handle.seek(1, Some(size - 1)).unwrap();
        let body = handle.read_body().await.unwrap();
        assert_eq!(true, body.is_some());
        assert_eq!(b"ello World", body.unwrap().as_ref());
    }

    #[tokio::test]
    async fn test_object_miss_handler() {
        let key = "key";

        let cache = Arc::new(new_tiny_ufo_cache(10, 10));
        let obj = ObjectMissHandler {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: BytesMut::new(),
            key: key.to_string(),
            namespace: "".to_string(),
            cache: cache.clone(),
        };
        let mut handle: MissHandler = Box::new(obj);

        handle
            .write_body(Bytes::from_static(b"Hello World!"), true)
            .await
            .unwrap();
        handle.finish().await.unwrap();

        let data = cache.get(key, "").await.unwrap().unwrap();
        assert_eq!("Hello World!", std::str::from_utf8(&data.body).unwrap());
    }
}
