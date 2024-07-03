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

use super::{Error, Result};
use async_trait::async_trait;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use dashmap::DashMap;
use parking_lot::RwLock;
use pingora::cache::key::CacheHashKey;
use pingora::cache::key::CompactCacheKey;
use pingora::cache::storage::{HandleHit, HandleMiss};
use pingora::cache::trace::SpanHandle;
use pingora::cache::{
    CacheKey, CacheMeta, HitHandler, MissHandler, PurgeType, Storage,
};
use std::any::Any;
use std::sync::Arc;
use tokio::sync::watch;

type BinaryMeta = (Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, Default)]
pub struct CacheObject {
    pub meta: BinaryMeta,
    pub body: Arc<Vec<u8>>,
}

impl From<Vec<u8>> for CacheObject {
    fn from(value: Vec<u8>) -> Self {
        let size_byte = 8;
        // 8 bytes
        if value.len() < size_byte {
            return Self::default();
        }
        let meta0_size =
            u32::from_be_bytes(value[0..4].try_into().unwrap()) as usize;
        let meta1_size =
            u32::from_be_bytes(value[4..8].try_into().unwrap()) as usize;
        let mut start = size_byte;
        let mut end = start + meta0_size;
        let meta0 = value[start..end].to_vec();

        start = end;
        end += meta1_size;
        let meta1 = value[start..end].to_vec();

        start = end;
        let body = value[start..value.len()].to_vec();
        Self {
            meta: (meta0, meta1),
            body: Arc::new(body),
        }
    }
}
impl From<CacheObject> for Vec<u8> {
    fn from(value: CacheObject) -> Self {
        let mut buf = BytesMut::with_capacity(value.body.len() + 1024);
        let meta0_size = value.meta.0.len() as u32;
        let meta1_size = value.meta.1.len() as u32;
        buf.put_u32(meta0_size);
        buf.put_u32(meta1_size);
        buf.extend(value.meta.0);
        buf.extend(value.meta.1);
        buf.extend(value.body.iter());

        buf.to_vec()
    }
}

pub(crate) struct TempObject {
    pub meta: BinaryMeta,
    // these are Arc because they need to continue to exist after this TempObject is removed
    pub body: Arc<RwLock<Vec<u8>>>,
    bytes_written: Arc<watch::Sender<PartialState>>, // this should match body.len()
}

impl TempObject {
    fn new(meta: BinaryMeta) -> Self {
        let (tx, _rx) = watch::channel(PartialState::Partial(0));
        TempObject {
            meta,
            body: Arc::new(RwLock::new(Vec::new())),
            bytes_written: Arc::new(tx),
        }
    }
    // this is not at all optimized
    fn make_cache_object(&self) -> CacheObject {
        let meta = self.meta.clone();
        let body = Arc::new(self.body.read().clone());
        CacheObject { meta, body }
    }
}

#[async_trait]
pub trait HttpCacheStorage: Sync + Send {
    async fn get(&self, key: &str) -> Option<CacheObject>;
    async fn put(
        &self,
        key: String,
        data: CacheObject,
        weight: u16,
    ) -> Result<()>;
    async fn remove(&self, _key: &str) -> Result<Option<CacheObject>> {
        Ok(None)
    }
}

pub struct HttpCache {
    pub(crate) cached: Arc<dyn HttpCacheStorage>,
    pub(crate) temp: Arc<DashMap<String, TempObject>>,
}

pub enum MemHitHandler {
    Complete(CompleteHit),
    Partial(PartialHit),
}

#[derive(Copy, Clone)]
enum PartialState {
    Partial(usize),
    Complete(usize),
}

pub struct CompleteHit {
    body: Arc<Vec<u8>>,
    done: bool,
    range_start: usize,
    range_end: usize,
}

impl CompleteHit {
    fn get(&mut self) -> Option<Bytes> {
        if self.done {
            None
        } else {
            self.done = true;
            Some(Bytes::copy_from_slice(
                &self.body.as_slice()[self.range_start..self.range_end],
            ))
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

pub struct PartialHit {
    body: Arc<RwLock<Vec<u8>>>,
    bytes_written: watch::Receiver<PartialState>,
    bytes_read: usize,
}

impl PartialHit {
    async fn read(&mut self) -> Option<Bytes> {
        loop {
            let bytes_written = *self.bytes_written.borrow_and_update();
            let bytes_end = match bytes_written {
                PartialState::Partial(s) => s,
                PartialState::Complete(c) => {
                    // no more data will arrive
                    if c == self.bytes_read {
                        return None;
                    }
                    c
                },
            };
            assert!(bytes_end >= self.bytes_read);

            // more data available to read
            if bytes_end > self.bytes_read {
                let new_bytes = Bytes::copy_from_slice(
                    &self.body.read()[self.bytes_read..bytes_end],
                );
                self.bytes_read = bytes_end;
                return Some(new_bytes);
            }

            // wait for more data
            if self.bytes_written.changed().await.is_err() {
                // err: sender dropped, body is finished
                // FIXME: sender could drop because of an error
                return None;
            }
        }
    }
}

#[async_trait]
impl HandleHit for MemHitHandler {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        match self {
            Self::Complete(c) => Ok(c.get()),
            Self::Partial(p) => Ok(p.read().await),
        }
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
        match self {
            Self::Complete(_) => true,
            Self::Partial(_) => false, // TODO: support seeking in partial reads
        }
    }

    fn seek(
        &mut self,
        start: usize,
        end: Option<usize>,
    ) -> pingora::Result<()> {
        match self {
            Self::Complete(c) => c.seek(start, end)?,
            Self::Partial(_) => Err(Error::Invalid {
                message: "seek not supported for partial cache".to_string(),
            })?,
        }
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

pub struct MemMissHandler {
    body: Arc<RwLock<Vec<u8>>>,
    bytes_written: Arc<watch::Sender<PartialState>>,
    // these are used only in finish() to data from temp to cache
    key: String,
    cache: Arc<dyn HttpCacheStorage>,
    temp: Arc<DashMap<String, TempObject>>,
}

#[async_trait]
impl HandleMiss for MemMissHandler {
    async fn write_body(
        &mut self,
        data: bytes::Bytes,
        eof: bool,
    ) -> pingora::Result<()> {
        let current_bytes = match *self.bytes_written.borrow() {
            PartialState::Partial(p) => p,
            PartialState::Complete(_) => panic!("already EOF"),
        };
        self.body.write().extend_from_slice(&data);
        let written = current_bytes + data.len();
        let new_state = if eof {
            PartialState::Complete(written)
        } else {
            PartialState::Partial(written)
        };
        self.bytes_written.send_replace(new_state);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<usize> {
        // safe, the temp object is inserted when the miss handler is created
        let cache_object =
            self.temp.get(&self.key).unwrap().make_cache_object();
        let size = cache_object.body.len(); // FIXME: this just body size, also track meta size
        let _ = self.cache.put(self.key.clone(), cache_object, 1).await?;
        Ok(size)
    }
}

impl Drop for MemMissHandler {
    fn drop(&mut self) {
        self.temp.remove(&self.key);
    }
}

#[async_trait]
impl Storage for HttpCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let hash = key.combined();
        // always prefer partial read otherwise fresh asset will not be visible on expired asset
        // until it is fully updated
        if let Some(temp_obj) = self.temp.get(&hash) {
            let meta =
                CacheMeta::deserialize(&temp_obj.meta.0, &temp_obj.meta.1)?;
            let partial = PartialHit {
                body: temp_obj.body.clone(),
                bytes_written: temp_obj.bytes_written.subscribe(),
                bytes_read: 0,
            };
            let hit_handler = MemHitHandler::Partial(partial);
            Ok(Some((meta, Box::new(hit_handler))))
        } else if let Some(obj) = self.cached.get(&hash).await {
            let meta = CacheMeta::deserialize(&obj.meta.0, &obj.meta.1)?;
            let hit_handler = CompleteHit {
                body: obj.body.clone(),
                done: false,
                range_start: 0,
                range_end: obj.body.len(),
            };
            let hit_handler = MemHitHandler::Complete(hit_handler);
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
        let hash = key.combined();
        let meta = meta.serialize()?;
        let temp_obj = TempObject::new(meta);
        let miss_handler = MemMissHandler {
            body: temp_obj.body.clone(),
            bytes_written: temp_obj.bytes_written.clone(),
            key: hash.clone(),
            cache: self.cached.clone(),
            temp: self.temp.clone(),
        };
        self.temp.insert(hash, temp_obj);
        Ok(Box::new(miss_handler))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _type: PurgeType,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        // This usually purges the primary key because, without a lookup, the variance key is usually
        // empty
        let hash = key.combined();
        let temp_removed = self.temp.remove(&hash).is_some();
        let cache_removed = if let Ok(result) = self.cached.remove(&hash).await
        {
            result.is_some()
        } else {
            false
        };
        Ok(temp_removed || cache_removed)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        let hash = key.combined();
        if let Some(mut obj) = self.cached.get(&hash).await {
            obj.meta = meta.serialize()?;
            let _ = self.cached.put(hash, obj, 1).await?;
            Ok(true)
        } else {
            Err(Error::Invalid {
                message: "no meta found".to_string(),
            }
            .into())
        }
    }

    fn support_streaming_partial_write(&self) -> bool {
        true
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}
