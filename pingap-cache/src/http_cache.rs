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

use super::{get_cache_backend, is_cache_backend_init, LOG_CATEGORY};
use super::{Error, Result, PAGE_SIZE};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use pingap_core::Error as ServiceError;
use pingap_core::SimpleServiceTaskFuture;
use pingora::cache::key::{CacheHashKey, CompactCacheKey};
use pingora::cache::storage::MissFinishType;
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

// Maximum size for a single cached object (40MB)
static MAX_OBJECT_CACHE_SIZE: usize = 10 * 1024 * PAGE_SIZE;

impl CacheObject {
    pub fn get_weight(&self) -> u16 {
        let size = self.body.len() + self.meta.0.len() + self.meta.1.len();
        if size <= PAGE_SIZE {
            return 1;
        }
        if size >= MAX_OBJECT_CACHE_SIZE {
            return u16::MAX;
        }
        (size / PAGE_SIZE) as u16
    }
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
        // 8 bytes
        if value.len() < META_SIZE_LENGTH {
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
        namespace: &[u8],
    ) -> Result<Option<CacheObject>>;

    /// Stores a cache object with the given key and namespace
    async fn put(
        &self,
        key: &str,
        namespace: &[u8],
        data: CacheObject,
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
        _namespace: &[u8],
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

    /// Returns the inactive duration for the cache storage.
    ///
    /// # Returns
    /// * `Option<Duration>` - The inactive duration for the cache storage
    fn inactive(&self) -> Option<Duration> {
        None
    }
}

async fn do_file_storage_clear(
    count: u32,
    cache: Arc<dyn HttpCacheStorage>,
) -> Result<bool, ServiceError> {
    // Add 1 every loop
    let offset = 60;
    if count % offset != 0 {
        return Ok(false);
    }

    let Some(inactive_duration) = cache.inactive() else {
        return Ok(false);
    };

    let Some(access_before) = SystemTime::now().checked_sub(inactive_duration)
    else {
        return Ok(false);
    };

    let Ok((success, fail)) = cache.clear(access_before).await else {
        return Ok(true);
    };
    if success < 0 {
        return Ok(true);
    }
    info!(
        category = LOG_CATEGORY,
        success, fail, "file cache storage clear"
    );
    Ok(true)
}

pub fn new_storage_clear_service() -> Option<(String, SimpleServiceTaskFuture)>
{
    // if cache backend not initialized, do not create storage clear service
    if !is_cache_backend_init() {
        return None;
    }
    // because the cache backend is initialized once,
    // so we can use the default option
    let Ok(backend) = get_cache_backend(None) else {
        return None;
    };
    backend.cache.inactive()?;
    let task: SimpleServiceTaskFuture = Box::new(move |count: u32| {
        Box::pin({
            let value = backend.cache.clone();
            async move {
                let value = value.clone();
                do_file_storage_clear(count, value).await
            }
        })
    });
    Some(("cache_storage_clear".to_string(), task))
}

pub struct HttpCache {
    pub directory: Option<String>,
    pub cache: Arc<dyn HttpCacheStorage>,
}

impl HttpCache {
    #[inline]
    pub fn stats(&self) -> Option<HttpCacheStats> {
        self.cache.stats()
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

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
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
    /// Primary key for storing the final object
    primary_key: String,
    /// Namespace for storing the final object
    namespace: Vec<u8>,
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

    async fn finish(self: Box<Self>) -> pingora::Result<MissFinishType> {
        let size = self.body.len(); // FIXME: this just body size, also track meta size
        info!(
            category = LOG_CATEGORY,
            primary_key = self.primary_key,
            namespace = std::str::from_utf8(&self.namespace).ok(),
            size,
            "put data to cache"
        );
        let _ = self
            .cache
            .put(
                &self.key,
                &self.namespace,
                CacheObject {
                    meta: self.meta,
                    body: self.body.into(),
                },
            )
            .await?;

        Ok(MissFinishType::Created(size))
    }
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
        if let Some(obj) = self.cache.get(&hash, namespace).await? {
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
            primary_key: key.primary_key_str().unwrap_or_default().to_string(),
            namespace: key.namespace().to_vec(),
            cache: self.cache.clone(),
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
            if let Ok(result) = self.cache.remove(&hash, b"").await {
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
        if let Some(mut obj) = self.cache.get(&hash, namespace).await? {
            obj.meta = meta.serialize()?;
            let _ = self.cache.put(&hash, namespace, obj).await?;
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
    use super::*;
    use crate::tiny::new_tiny_ufo_cache;
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

        let cache = Arc::new(new_tiny_ufo_cache("", 10, 10));
        let obj = ObjectMissHandler {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: BytesMut::new(),
            key: key.to_string(),
            primary_key: "".to_string(),
            namespace: b"".to_vec(),
            cache: cache.clone(),
        };
        let mut handle: MissHandler = Box::new(obj);

        handle
            .write_body(Bytes::from_static(b"Hello World!"), true)
            .await
            .unwrap();
        handle.finish().await.unwrap();

        let data = cache.get(key, b"").await.unwrap().unwrap();
        assert_eq!("Hello World!", std::str::from_utf8(&data.body).unwrap());
    }

    #[test]
    fn test_cache_object_get_weight() {
        // data less than one page
        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: Bytes::from_static(b"Hello World!"),
        };
        assert_eq!(1, obj.get_weight());

        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: vec![0; PAGE_SIZE * 2].into(),
        };
        assert_eq!(2, obj.get_weight());

        // data larger than max size
        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: vec![0; MAX_OBJECT_CACHE_SIZE + 1].into(),
        };
        assert_eq!(u16::MAX, obj.get_weight());
    }
}
