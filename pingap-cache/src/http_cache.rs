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

use super::LOG_TARGET;
use super::purge::CachePurgeEntry;
use super::{Error, PAGE_SIZE, Result};
use crate::get_file_backends;
use ahash::{AHashMap, AHashSet, RandomState};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::RwLock;
use pingap_core::BackgroundTask;
use pingap_core::Error as ServiceError;
use pingora::cache::key::CacheHashKey;
use pingora::cache::storage::MissFinishType;
use pingora::cache::storage::{HandleHit, HandleMiss};
use pingora::cache::trace::SpanHandle;
use pingora::cache::{
    CacheKey, CacheMeta, HitHandler, MissHandler, PurgeOutcome, PurgeTarget,
    PurgeType, Storage,
};
use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use tracing::{error, info};

/// The two halves of a serialized `CacheMeta`. `Bytes` so that parsing a
/// cache file and cloning an object out of the memory layer copy nothing.
pub type BinaryMeta = (Bytes, Bytes);

/// Body payload returned by [`HttpCacheStorage::lookup_hit`].
#[derive(Debug, Clone, PartialEq)]
pub enum HitBody {
    /// Body already buffered in memory (e.g. TinyUFO hot hit or small entry).
    Memory(Bytes),
    /// Body stored on disk at `path`, starting at `body_offset` for `body_len` bytes,
    /// read lazily in chunks on `HandleHit::read_body`.
    Disk {
        path: PathBuf,
        body_offset: u64,
        body_len: usize,
    },
}

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

/// Computes the TinyUFO page weight for a serialized cache payload
/// (`meta0.len() + meta1.len() + body.len()`).
#[inline]
pub(crate) fn payload_weight(payload_len: usize) -> u16 {
    if payload_len <= PAGE_SIZE {
        return 1;
    }
    if payload_len >= MAX_OBJECT_CACHE_SIZE {
        return u16::MAX;
    }
    payload_len.div_ceil(PAGE_SIZE) as u16
}

impl CacheObject {
    /// The weight of the object in the memory cache: its size in 4 KB
    /// pages, rounded up. Rounded down, 8191 bytes weighed one page, and
    /// a cache of small objects held up to twice its budget.
    pub fn get_weight(&self) -> u16 {
        payload_weight(self.body.len() + self.meta.0.len() + self.meta.1.len())
    }
}

pub(crate) const META_SIZE_LENGTH: usize = 8;
pub(crate) const STREAMING_SPILL_THRESHOLD: usize = 64 * 1024;

/// Creates a CacheObject from bytes with the following format:
/// - First 4 bytes: meta0 size (u32)
/// - Next 4 bytes: meta1 size (u32)
/// - Next meta0_size bytes: meta0 data
/// - Next meta1_size bytes: meta1 data
/// - Remaining bytes: body data
///
/// Fallible on purpose: the bytes come from a cache file, and a cache file can
/// be shorter than its header claims (a crash or a full disk mid write). The
/// declared sizes MUST be checked against what is actually there -
/// `Bytes::split_to` panics on out of range, and with `panic = "abort"` in the
/// release profile that panic would take the whole process down on every hit
/// of the poisoned key, restart after restart, until someone deletes the file.
impl TryFrom<Bytes> for CacheObject {
    type Error = Error;
    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        // 8 bytes
        if value.len() < META_SIZE_LENGTH {
            return Err(Error::Invalid {
                message: format!(
                    "cache object is truncated, {} bytes is shorter than the header",
                    value.len()
                ),
            });
        }
        let mut data = value;

        let meta0_size = data.get_u32() as usize;
        let meta1_size = data.get_u32() as usize;
        let meta_size = meta0_size.saturating_add(meta1_size);
        if meta_size > data.len() {
            return Err(Error::Invalid {
                message: format!(
                    "cache object is truncated, meta claims {meta_size} bytes but only {} are present",
                    data.len()
                ),
            });
        }

        let meta0 = data.split_to(meta0_size);
        let meta1 = data.split_to(meta1_size);

        Ok(Self {
            meta: (meta0, meta1),
            body: data,
        })
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
        buf.put_u32(value.meta.0.len() as u32);
        buf.put_u32(value.meta.1.len() as u32);
        // `put_slice`, not `extend`: `Extend` goes through the byte
        // iterator and copies one byte at a time.
        buf.put_slice(&value.meta.0);
        buf.put_slice(&value.meta.1);
        buf.put_slice(&value.body);

        buf.into()
    }
}

#[derive(Debug)]
pub struct HttpCacheStats {
    pub reading: u32,
    pub writing: u32,
}

#[derive(Debug, Clone)]
pub struct HttpCacheClearStats {
    pub success: i32,
    pub fail: i32,
    pub description: String,
}

/// Receives streamed cache miss body chunks directly into storage without
/// buffering the entire payload in memory.
#[async_trait]
pub trait StreamingMissWriter: Send + Sync {
    async fn write_chunk(&mut self, data: Bytes) -> Result<()>;
    async fn finish(self: Box<Self>) -> Result<()>;
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

    /// Retrieves serialized metadata and a body handle (in-memory or lazy disk slice)
    /// for a cache hit. Defaults to [`Self::get`] wrapped in [`HitBody::Memory`].
    async fn lookup_hit(
        &self,
        key: &str,
        namespace: &[u8],
    ) -> Result<Option<(BinaryMeta, HitBody)>> {
        Ok(self
            .get(key, namespace)
            .await?
            .map(|obj| (obj.meta, HitBody::Memory(obj.body))))
    }

    /// Stores a cache object with the given key and namespace
    async fn put(
        &self,
        key: &str,
        namespace: &[u8],
        data: CacheObject,
    ) -> Result<()>;

    /// Updates only the metadata of an existing cached object when supported by
    /// the storage backend, returning `Ok(false)` when no object exists.
    async fn update_meta(
        &self,
        key: &str,
        namespace: &[u8],
        meta: BinaryMeta,
    ) -> Result<bool> {
        let Some(mut obj) = self.get(key, namespace).await? else {
            return Ok(false);
        };
        obj.meta = meta;
        self.put(key, namespace, obj).await?;
        Ok(true)
    }

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
    /// * `Result<HttpCacheClearStats>` - Clear stats
    async fn clear(
        &self,
        _access_before: std::time::SystemTime,
    ) -> Result<HttpCacheClearStats> {
        Ok(HttpCacheClearStats {
            success: -1,
            fail: -1,
            description: "".to_string(),
        })
    }

    /// Removes every cached object in `namespace`.
    ///
    /// Storage keys are hashes, so this is only possible where the namespace
    /// survives as structure - the file backend keeps it as a directory. The
    /// default says "unsupported" (`Ok(None)`) rather than pretending: the
    /// memory backend has no way to enumerate its entries, and a purge that
    /// silently does nothing would leave stale content being served with no
    /// indication why.
    async fn purge_namespace(
        &self,
        _namespace: &str,
    ) -> Result<Option<HttpCacheClearStats>> {
        Ok(None)
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

    /// Called on a storage that another one has taken the place of, to
    /// let go of what it holds in memory.
    fn retire(&self) {}

    /// Maximum body size (bytes) eligible for the hot in-memory layer, or
    /// `None` when streaming miss writes are not used.
    fn max_hot_body_bytes(&self) -> Option<usize> {
        None
    }

    /// Starts a streaming miss write for objects that bypass the hot layer.
    /// Returns `Ok(None)` when the backend prefers buffered `put`.
    async fn begin_streaming_put(
        &self,
        _key: &str,
        _namespace: &[u8],
        _meta: BinaryMeta,
        _content_length: Option<u64>,
    ) -> Result<Option<Box<dyn StreamingMissWriter>>> {
        Ok(None)
    }

    /// Finds cached `(key, namespace)` entries matching any tag in `tags`,
    /// scoped to `namespace` when `Some`. Used by cold disk storage so
    /// pre-restart entries on disk can be purged by `Cache-Tag`.
    async fn find_keys_by_tags(
        &self,
        _namespace: Option<&str>,
        _tags: &[String],
    ) -> Result<Vec<(String, String)>> {
        Ok(Vec::new())
    }
}

/// Sweeps every file backend's inactive files, once every 60 ticks. A
/// backend whose sweep fails is logged and the others still get theirs.
async fn do_file_storage_clear(count: u32) -> bool {
    if !count.is_multiple_of(60) {
        return false;
    }
    for backend in get_file_backends() {
        let cache = &backend.cache;
        let Some(inactive) = cache.inactive() else {
            continue;
        };
        let Some(access_before) = SystemTime::now().checked_sub(inactive)
        else {
            continue;
        };
        match cache.clear(access_before).await {
            Ok(stats) => info!(
                target: LOG_TARGET,
                success = stats.success,
                fail = stats.fail,
                description = stats.description,
            ),
            Err(e) => error!(
                target: LOG_TARGET,
                error = %e,
                directory = backend.directory.as_deref(),
                "clear cache file fail"
            ),
        }
    }
    true
}

struct StorageClearTask {}

#[async_trait]
impl BackgroundTask for StorageClearTask {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        Ok(do_file_storage_clear(count).await)
    }
}

pub fn new_storage_clear_service() -> Option<Box<dyn BackgroundTask>> {
    Some(Box::new(StorageClearTask {}))
}

const META_INDEX_SHARDS: usize = 16;
const META_INDEX_SHARD_CAP: usize = 8192;

/// Splits `raw` on commas and ASCII whitespace, trimming and appending unique
/// non-empty tag tokens to `tags`.
pub fn push_cache_tag_tokens(raw: &str, tags: &mut Vec<String>) {
    for token in raw
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
    {
        if !tags.iter().any(|existing| existing == token) {
            tags.push(token.to_string());
        }
    }
}

/// Parses deduplicated `Cache-Tag` / `X-Cache-Tag` tokens from header values.
pub fn parse_cache_tag_headers<'a, I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a http::HeaderValue>,
{
    let mut tags = Vec::new();
    for value in values {
        if let Ok(raw) = value.to_str() {
            push_cache_tag_tokens(raw, &mut tags);
        }
    }
    tags
}

fn parse_cache_tags(meta: &CacheMeta) -> Vec<String> {
    parse_cache_tag_headers(meta.headers().get_all("cache-tag"))
}

fn is_method_token(seg: &str) -> bool {
    !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_uppercase())
}

fn is_host_prefix_without_nested_method(tail: &str) -> bool {
    let before_slash = tail.split('/').next().unwrap_or(tail);
    let mut in_brackets = false;
    for byte in before_slash.bytes() {
        match byte {
            b'[' => in_brackets = true,
            b']' => in_brackets = false,
            b':' if !in_brackets => return false,
            _ => {},
        }
    }
    true
}

fn matches_prefix(
    entry_namespace: &str,
    entry_primary: &str,
    target_namespace: &str,
    host_and_prefix: &str,
) -> bool {
    if entry_namespace != target_namespace || host_and_prefix.is_empty() {
        return false;
    }
    let rest = entry_primary
        .strip_prefix(target_namespace)
        .unwrap_or(entry_primary);
    let mut cursor = rest;
    while let Some((seg, tail)) = cursor.split_once(':') {
        if is_method_token(seg) && is_host_prefix_without_nested_method(tail) {
            return tail.starts_with(host_and_prefix);
        }
        cursor = tail;
    }
    false
}

#[derive(Clone, Debug)]
struct MetaIndexEntry {
    namespace: String,
    primary: String,
    combined_key: String,
    tags: Vec<String>,
    seq: u64,
}

#[derive(Default)]
struct MetaIndexShardInner {
    entries: AHashMap<String, Vec<MetaIndexEntry>>,
    total: usize,
    next_seq: u64,
}

impl MetaIndexShardInner {
    fn evict_oldest_half(&mut self, max_per_shard: usize) {
        let evict_count = (max_per_shard / 2).max(1);
        if self.total < evict_count {
            return;
        }
        let mut seqs: Vec<u64> = self
            .entries
            .values()
            .flat_map(|list| list.iter().map(|entry| entry.seq))
            .collect();
        if seqs.len() < evict_count {
            return;
        }
        let (_, pivot, _) = seqs.select_nth_unstable(evict_count - 1);
        let cutoff = *pivot;
        let mut kept = 0usize;
        self.entries.retain(|_, list| {
            list.retain(|entry| entry.seq > cutoff);
            kept += list.len();
            !list.is_empty()
        });
        self.total = kept;
    }

    fn upsert(
        &mut self,
        namespace: &str,
        primary: &str,
        combined_key: &str,
        tags: Vec<String>,
        max_per_shard: usize,
    ) {
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;
        if let Some(list) = self.entries.get_mut(combined_key)
            && let Some(existing) =
                list.iter_mut().find(|entry| entry.namespace == namespace)
        {
            if !primary.is_empty() {
                existing.primary = primary.to_string();
            }
            existing.tags = tags;
            existing.seq = seq;
            return;
        }
        if self.total >= max_per_shard {
            self.evict_oldest_half(max_per_shard);
        }
        self.entries
            .entry(combined_key.to_string())
            .or_default()
            .push(MetaIndexEntry {
                namespace: namespace.to_string(),
                primary: primary.to_string(),
                combined_key: combined_key.to_string(),
                tags,
                seq,
            });
        self.total += 1;
    }

    fn remove(&mut self, namespace: &str, combined_key: &str) {
        let Some(list) = self.entries.get_mut(combined_key) else {
            return;
        };
        let before = list.len();
        list.retain(|entry| entry.namespace != namespace);
        let removed = before.saturating_sub(list.len());
        self.total = self.total.saturating_sub(removed);
        if list.is_empty() {
            self.entries.remove(combined_key);
        }
    }

    fn remove_namespace(&mut self, namespace: &str) {
        let mut removed = 0usize;
        self.entries.retain(|_, list| {
            let before = list.len();
            list.retain(|entry| entry.namespace != namespace);
            removed += before.saturating_sub(list.len());
            !list.is_empty()
        });
        self.total = self.total.saturating_sub(removed);
    }
}

#[repr(align(128))]
#[derive(Default)]
struct MetaIndexShard {
    inner: RwLock<MetaIndexShardInner>,
}

/// Bounded 16-shard metadata index mapping cache keys to their primary strings
/// and `Cache-Tag` tokens for prefix and tag purges.
pub(crate) struct CacheMetaIndex {
    shards: [MetaIndexShard; META_INDEX_SHARDS],
    hasher: RandomState,
    max_per_shard: usize,
}

impl Default for CacheMetaIndex {
    fn default() -> Self {
        Self::with_shard_cap(META_INDEX_SHARD_CAP)
    }
}

impl CacheMetaIndex {
    pub(crate) fn with_shard_cap(max_per_shard: usize) -> Self {
        Self {
            shards: std::array::from_fn(|_| MetaIndexShard::default()),
            hasher: RandomState::new(),
            max_per_shard: max_per_shard.max(1),
        }
    }

    #[inline]
    fn shard(&self, combined_key: &str) -> &MetaIndexShard {
        let idx =
            (self.hasher.hash_one(combined_key) as usize) % META_INDEX_SHARDS;
        &self.shards[idx]
    }

    pub(crate) fn contains(&self, namespace: &str, combined_key: &str) -> bool {
        let guard = self.shard(combined_key).inner.read();
        guard.entries.get(combined_key).is_some_and(|list| {
            list.iter().any(|entry| entry.namespace == namespace)
        })
    }

    pub(crate) fn upsert(
        &self,
        namespace: &str,
        primary: &str,
        combined_key: &str,
        tags: Vec<String>,
    ) {
        let mut guard = self.shard(combined_key).inner.write();
        guard.upsert(
            namespace,
            primary,
            combined_key,
            tags,
            self.max_per_shard,
        );
    }

    pub(crate) fn remove(&self, namespace: &str, combined_key: &str) {
        let mut guard = self.shard(combined_key).inner.write();
        guard.remove(namespace, combined_key);
    }

    pub(crate) fn remove_namespace(&self, namespace: &str) {
        for shard in &self.shards {
            shard.inner.write().remove_namespace(namespace);
        }
    }

    pub(crate) fn find_by_prefix(
        &self,
        namespace: &str,
        host_and_prefix: &str,
    ) -> Vec<CachePurgeEntry> {
        let mut matches = Vec::new();
        for shard in &self.shards {
            let guard = shard.inner.read();
            for list in guard.entries.values() {
                for entry in list {
                    if matches_prefix(
                        &entry.namespace,
                        &entry.primary,
                        namespace,
                        host_and_prefix,
                    ) {
                        matches.push(CachePurgeEntry {
                            key: entry.combined_key.clone(),
                            namespace: entry.namespace.clone(),
                        });
                    }
                }
            }
        }
        matches
    }

    pub(crate) fn find_by_tags(
        &self,
        namespace: Option<&str>,
        tags: &[String],
    ) -> Vec<CachePurgeEntry> {
        let mut matches = Vec::new();
        for shard in &self.shards {
            let guard = shard.inner.read();
            for list in guard.entries.values() {
                for entry in list {
                    if namespace.is_some_and(|ns| entry.namespace != ns) {
                        continue;
                    }
                    if entry
                        .tags
                        .iter()
                        .any(|t| tags.iter().any(|wanted| wanted == t))
                    {
                        matches.push(CachePurgeEntry {
                            key: entry.combined_key.clone(),
                            namespace: entry.namespace.clone(),
                        });
                    }
                }
            }
        }
        matches
    }
}

pub struct HttpCache {
    pub directory: Option<String>,
    pub cache: Arc<dyn HttpCacheStorage>,
    pub max_size: u64,
    pub(crate) meta_index: Arc<CacheMetaIndex>,
}

impl HttpCache {
    pub fn new(
        directory: Option<String>,
        cache: Arc<dyn HttpCacheStorage>,
        max_size: u64,
    ) -> Self {
        Self {
            directory,
            cache,
            max_size,
            meta_index: Arc::new(CacheMetaIndex::default()),
        }
    }

    #[inline]
    pub fn stats(&self) -> Option<HttpCacheStats> {
        self.cache.stats()
    }
    pub fn max_size(&self) -> u64 {
        self.max_size
    }

    /// Removes `key` in `namespace` from both the storage backend and the
    /// metadata index.
    pub async fn remove(
        &self,
        key: &str,
        namespace: &str,
    ) -> Result<Option<CacheObject>> {
        let removed = self.cache.remove(key, namespace.as_bytes()).await?;
        self.meta_index.remove(namespace, key);
        Ok(removed)
    }

    /// Purges all entries in `namespace` from storage and clears matching
    /// entries from the metadata index.
    pub async fn purge_namespace(
        &self,
        namespace: &str,
    ) -> Result<Option<HttpCacheClearStats>> {
        let stats = self.cache.purge_namespace(namespace).await?;
        if stats.is_some() {
            self.meta_index.remove_namespace(namespace);
        }
        Ok(stats)
    }

    async fn purge_candidates(
        &self,
        candidates: Vec<CachePurgeEntry>,
    ) -> Result<Vec<CachePurgeEntry>> {
        let mut seen = AHashSet::with_capacity(candidates.len());
        let mut purged = Vec::new();
        let is_file_backend = self.directory.is_some();
        for entry in candidates {
            if !seen.insert((entry.namespace.clone(), entry.key.clone())) {
                continue;
            }
            let removed = self
                .cache
                .remove(&entry.key, entry.namespace.as_bytes())
                .await?;
            self.meta_index.remove(&entry.namespace, &entry.key);
            if removed.is_some() || is_file_backend {
                purged.push(entry);
            }
        }
        Ok(purged)
    }

    /// Purges cached entries in `namespace` whose primary key matches
    /// `<METHOD>:<host><prefix>`.
    pub async fn purge_by_prefix(
        &self,
        namespace: &str,
        host_and_prefix: &str,
    ) -> Result<Vec<CachePurgeEntry>> {
        let candidates =
            self.meta_index.find_by_prefix(namespace, host_and_prefix);
        self.purge_candidates(candidates).await
    }

    /// Purges cached entries matching any tag in `tags` (scoped to `namespace`
    /// when `Some`), searching both the in-memory index and cold disk storage.
    pub async fn purge_by_tags(
        &self,
        namespace: Option<&str>,
        tags: &[String],
    ) -> Result<Vec<CachePurgeEntry>> {
        if tags.is_empty() {
            return Ok(Vec::new());
        }
        let mut candidates = self.meta_index.find_by_tags(namespace, tags);
        let disk_matches =
            self.cache.find_keys_by_tags(namespace, tags).await?;
        for (key, ns) in disk_matches {
            candidates.push(CachePurgeEntry { key, namespace: ns });
        }
        self.purge_candidates(candidates).await
    }
}

/// The most of a cached body that is handed out at once.
///
/// The body is in memory whole, and used to be handed out whole. Whatever
/// holds a response back by what has gone out - the pace of a
/// `bandwidth_limit` - then had one piece to hold back: nothing for as
/// long as all of it takes at the rate, and all of it at once after that.
/// A piece of this size is what a read from an upstream brings.
pub(crate) const HIT_CHUNK_SIZE: usize = 64 * 1024;

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

/// Handles cache hits backed by an on-disk file, reading only the requested
/// byte range lazily in [`HIT_CHUNK_SIZE`] pieces.
pub struct DiskHit {
    path: PathBuf,
    body_offset: u64,
    body_len: usize,
    file: Option<std::fs::File>,
    needs_seek: bool,
    done: bool,
    range_start: usize,
    range_end: usize,
}

/// Whether `hit` - the handler of a response found in a storage of this
/// crate - has handed out the last piece of the body it was asked for.
/// `false` for the handler of any other storage.
///
/// For the proxy, on the one path where pingora does not say where a body
/// from the cache ends: see `Server::response_body_filter`.
pub fn is_hit_read_to_the_end(hit: &(dyn Any + Send + Sync)) -> bool {
    hit.downcast_ref::<CompleteHit>()
        .is_some_and(|hit| hit.done)
        || hit.downcast_ref::<DiskHit>().is_some_and(|hit| hit.done)
}

impl CompleteHit {
    /// The next piece of what is asked for, `None` once all of it has
    /// been handed out. A body of nothing is one empty piece.
    fn get(&mut self) -> Option<Bytes> {
        if self.done {
            return None;
        }
        let end = self
            .range_end
            .min(self.range_start.saturating_add(HIT_CHUNK_SIZE));
        let piece = self.body.slice(self.range_start..end);
        self.range_start = end;
        self.done = end >= self.range_end;
        Some(piece)
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

impl DiskHit {
    /// Creates a lazy disk-backed hit handler over `[0, body_len)` starting at
    /// `body_offset` in `path`.
    pub fn new(path: PathBuf, body_offset: u64, body_len: usize) -> Self {
        Self {
            path,
            body_offset,
            body_len,
            file: None,
            needs_seek: true,
            done: false,
            range_start: 0,
            range_end: body_len,
        }
    }

    fn seek_range(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        if start >= self.body_len {
            return Err(Error::Invalid {
                message: format!(
                    "seek start out of range {start} >= {}",
                    self.body_len
                ),
            });
        }
        self.range_start = start;
        self.range_end =
            end.map_or(self.range_end, |e| std::cmp::min(self.body_len, e));
        self.needs_seek = true;
        // seek resets read so that one handler can be used for multiple ranges
        self.done = false;
        Ok(())
    }
}

#[async_trait]
impl HandleHit for DiskHit {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        if self.done || self.range_start >= self.range_end {
            self.done = true;
            return Ok(None);
        }
        let len = (self.range_end - self.range_start).min(HIT_CHUNK_SIZE);
        let target_offset =
            self.body_offset.saturating_add(self.range_start as u64);
        let path = self.path.clone();
        let file = self.file.take();
        let needs_seek = self.needs_seek;

        let (file, buf) = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = match file {
                Some(mut f) => {
                    if needs_seek {
                        f.seek(SeekFrom::Start(target_offset))?;
                    }
                    f
                },
                None => {
                    let mut f = std::fs::File::open(&path)?;
                    f.seek(SeekFrom::Start(target_offset))?;
                    f
                },
            };
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf)?;
            Ok::<_, std::io::Error>((f, buf))
        })
        .await
        .map_err(|e| Error::Invalid {
            message: format!("disk cache read task failed: {e}"),
        })?
        .map_err(|source| Error::Io { source })?;

        self.file = Some(file);
        self.needs_seek = false;
        self.range_start += len;
        self.done = self.range_start >= self.range_end;
        Ok(Some(Bytes::from(buf)))
    }

    async fn finish(
        self: Box<Self>,
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
        self.seek_range(start, end)?;
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

fn parse_content_length(meta: &CacheMeta) -> Option<u64> {
    meta.headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok())
}

#[inline]
fn should_spill_payload(
    hot_limit: Option<usize>,
    meta_len: usize,
    body_len: u64,
) -> bool {
    let Some(hot_limit) = hot_limit else {
        return false;
    };
    let total_payload = (meta_len as u64).saturating_add(body_len);
    total_payload > hot_limit as u64
        && total_payload >= STREAMING_SPILL_THRESHOLD as u64
}

/// Handles cache misses by collecting and storing new content
pub struct ObjectMissHandler {
    /// Metadata to store with the cached content
    meta: BinaryMeta,
    /// Buffer for collecting the body content while below spill threshold
    body: BytesMut,
    /// Total body bytes written across buffered and streamed chunks
    body_bytes: usize,
    /// Known Content-Length from response headers, if present
    content_length: Option<u64>,
    /// Whether `begin_streaming_put` has already been attempted on write
    streaming_checked: bool,
    /// Active streaming writer once spilled out of `BytesMut`
    writer: Option<Box<dyn StreamingMissWriter>>,
    /// Cache key for storing the final object
    key: String,
    /// Primary key for storing the final object
    primary_key: String,
    /// Namespace for storing the final object
    namespace: Vec<u8>,
    /// Parsed `Cache-Tag` tokens for indexing once stored
    tags: Vec<String>,
    /// Shared metadata index on the parent `HttpCache`
    meta_index: Option<Arc<CacheMetaIndex>>,
    /// Reference to the storage backend
    cache: Arc<dyn HttpCacheStorage>,
}

impl ObjectMissHandler {
    fn should_spill_on_write(&self, incoming_len: usize) -> bool {
        let meta_len = self.meta.0.len().saturating_add(self.meta.1.len());
        let accumulated = (self.body.len().saturating_add(incoming_len)) as u64;
        let known_or_accumulated = self
            .content_length
            .map_or(accumulated, |cl| cl.max(accumulated));
        should_spill_payload(
            self.cache.max_hot_body_bytes(),
            meta_len,
            known_or_accumulated,
        )
    }

    async fn try_spill_to_writer(
        &mut self,
        data: Bytes,
    ) -> Result<Option<Bytes>> {
        let total_len = (self.body.len().saturating_add(data.len())) as u64;
        let content_length = self.content_length.filter(|&cl| cl >= total_len);
        let Some(mut writer) = self
            .cache
            .begin_streaming_put(
                &self.key,
                &self.namespace,
                self.meta.clone(),
                content_length,
            )
            .await?
        else {
            return Ok(Some(data));
        };
        if !self.body.is_empty() {
            let buffered = self.body.split().freeze();
            writer.write_chunk(buffered).await?;
        }
        writer.write_chunk(data).await?;
        self.writer = Some(writer);
        Ok(None)
    }
}

#[async_trait]
impl HandleMiss for ObjectMissHandler {
    async fn write_body(
        &mut self,
        data: bytes::Bytes,
        _eof: bool,
    ) -> pingora::Result<()> {
        self.body_bytes = self.body_bytes.saturating_add(data.len());
        if let Some(writer) = self.writer.as_mut() {
            writer.write_chunk(data).await?;
            return Ok(());
        }
        let data = if !self.streaming_checked
            && self.should_spill_on_write(data.len())
        {
            self.streaming_checked = true;
            match self.try_spill_to_writer(data).await? {
                Some(remaining) => remaining,
                None => return Ok(()),
            }
        } else {
            data
        };
        self.body.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> pingora::Result<MissFinishType> {
        // The same bytes `CacheObject::get_weight` counts. pingora's
        // eviction admits an entry by this size (`eviction = true` on
        // the memory cache). The body alone under-counted every entry
        // by its headers.
        let size = self.body_bytes + self.meta.0.len() + self.meta.1.len();
        info!(
            target: LOG_TARGET,
            key = self.key,
            primary_key = self.primary_key,
            namespace = std::str::from_utf8(&self.namespace).ok(),
            size,
            "put data to cache"
        );
        if let Some(writer) = self.writer.take() {
            writer.finish().await?;
        } else {
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
        }
        if let Some(index) = &self.meta_index {
            let ns = std::str::from_utf8(&self.namespace).unwrap_or_default();
            index.upsert(
                ns,
                &self.primary_key,
                &self.key,
                std::mem::take(&mut self.tags),
            );
        }

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
        let namespace_str = key.user_tag();
        let namespace = namespace_str.as_bytes();
        let hash = key.combined();
        if let Some((binary_meta, body)) =
            self.cache.lookup_hit(&hash, namespace).await?
        {
            let meta = CacheMeta::deserialize(&binary_meta.0, &binary_meta.1)?;
            if !self.meta_index.contains(namespace_str, &hash) {
                let primary = key.primary_key_str().unwrap_or_default();
                self.meta_index.upsert(
                    namespace_str,
                    primary,
                    &hash,
                    parse_cache_tags(&meta),
                );
            }
            let hit_handler: HitHandler = match body {
                HitBody::Memory(body) => {
                    let size = body.len();
                    Box::new(CompleteHit {
                        body,
                        done: false,
                        range_start: 0,
                        range_end: size,
                    })
                },
                HitBody::Disk {
                    path,
                    body_offset,
                    body_len,
                } => Box::new(DiskHit::new(path, body_offset, body_len)),
            };
            Ok(Some((meta, hit_handler)))
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
        let content_length = parse_content_length(meta);
        let hash = key.combined();
        let (meta0, meta1) = meta.serialize()?;
        let meta_len = meta0.len().saturating_add(meta1.len());
        let binary_meta: BinaryMeta = (meta0.into(), meta1.into());
        let namespace = key.user_tag().as_bytes().to_vec();

        let (writer, streaming_checked) = if let Some(cl) = content_length
            && should_spill_payload(
                self.cache.max_hot_body_bytes(),
                meta_len,
                cl,
            ) {
            let writer = self
                .cache
                .begin_streaming_put(
                    &hash,
                    &namespace,
                    binary_meta.clone(),
                    Some(cl),
                )
                .await?;
            (writer, true)
        } else {
            (None, false)
        };

        // Size the body buffer from Content-Length when there is one, capped
        // at the largest object worth caching: the header is the origin's
        // word, not a reason to reserve gigabytes up front. Skip preallocation
        // when streaming directly to disk.
        let capacity = if writer.is_some() {
            0
        } else {
            content_length
                .and_then(|cl| usize::try_from(cl).ok())
                .unwrap_or(5 * 1024)
                .min(MAX_OBJECT_CACHE_SIZE)
        };
        let miss_handler = ObjectMissHandler {
            meta: binary_meta,
            key: hash,
            primary_key: key.primary_key_str().unwrap_or_default().to_string(),
            namespace,
            tags: parse_cache_tags(meta),
            meta_index: Some(self.meta_index.clone()),
            cache: self.cache.clone(),
            body: BytesMut::with_capacity(capacity),
            body_bytes: 0,
            content_length,
            streaming_checked,
            writer,
        };
        Ok(Box::new(miss_handler))
    }

    async fn purge(
        &'static self,
        target: PurgeTarget<'_>,
        _type: PurgeType,
        _trace: &SpanHandle,
    ) -> pingora::Result<PurgeOutcome> {
        // This usually purges the primary key because, without a lookup,
        // the variance key is usually empty.
        let key = target.key();
        let hash = key.combined();
        let namespace = key.user_tag();
        // The namespace rides in user_tag, which a CompactCacheKey keeps, so
        // the purge reaches the same partition the entry was written to.
        let cache_removed =
            match self.cache.remove(&hash, namespace.as_bytes()).await {
                Ok(result) => result.is_some(),
                Err(_) => false,
            };
        self.meta_index.remove(namespace, &hash);
        // These storages have no per-entry identity beyond the key itself,
        // so an active purge has no CacheEntryId to report.
        Ok(if cache_removed {
            PurgeOutcome::Purged(None)
        } else {
            PurgeOutcome::NotFound
        })
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        let namespace_str = key.user_tag();
        let namespace = namespace_str.as_bytes();
        let hash = key.combined();
        let (meta0, meta1) = meta.serialize()?;
        if self
            .cache
            .update_meta(&hash, namespace, (meta0.into(), meta1.into()))
            .await?
        {
            self.meta_index.upsert(
                namespace_str,
                key.primary_key_str().unwrap_or_default(),
                &hash,
                parse_cache_tags(meta),
            );
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
    use crate::tiny::{CacheMode, TinyUfoCache};
    use bytes::{Bytes, BytesMut};
    use pingora::cache::storage::{HitHandler, MissHandler};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    #[test]
    fn test_cache_object_round_trip() {
        let obj = CacheObject {
            meta: (Bytes::from_static(b"meta0"), Bytes::from_static(b"meta1")),
            body: Bytes::from_static(b"cache body"),
        };
        let buf: Bytes = obj.clone().into();
        assert_eq!(obj, CacheObject::try_from(buf).unwrap());
    }

    #[test]
    fn test_cache_object_rejects_truncated_bytes() {
        // What a crash or a full disk mid write leaves behind: every prefix of
        // a valid encoding. None of them may panic - with `panic = "abort"`
        // that would abort the process on every hit of the poisoned key.
        let full: Bytes = CacheObject {
            meta: (Bytes::from_static(b"meta0"), Bytes::from_static(b"meta1")),
            body: Bytes::from_static(b"cache body"),
        }
        .into();
        for len in 0..full.len() {
            let truncated = full.slice(0..len);
            let result = CacheObject::try_from(truncated);
            // Anything shorter than header + both metas must be rejected;
            // only the body may legitimately be shorter (its length is not
            // recorded, so a torn body is indistinguishable from a short one).
            if len < META_SIZE_LENGTH + b"meta0meta1".len() {
                assert_eq!(true, result.is_err(), "len {len} must be rejected");
            }
        }

        // Sizes that overflow when added must not wrap around the check.
        let mut evil = BytesMut::new();
        evil.put_u32(u32::MAX);
        evil.put_u32(u32::MAX);
        evil.extend_from_slice(b"tiny");
        assert_eq!(true, CacheObject::try_from(Bytes::from(evil)).is_err());
    }

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
        assert_eq!(true, handle.read_body().await.unwrap().is_none());
    }

    /// A start at or past the body is refused. An empty body has no
    /// position 0 to seek to. Leaving the end unset keeps the range that
    /// was already there.
    #[tokio::test]
    async fn test_seek_start_past_the_body_is_an_error() {
        let mut hit = CompleteHit {
            body: Bytes::from_static(b"Hello"),
            done: true,
            range_start: 0,
            range_end: 5,
        };
        match hit.seek(5, Some(6)) {
            Err(Error::Invalid { message }) => {
                assert_eq!("seek start out of range 5 >= 5", message);
            },
            Ok(()) => panic!("a start at the end of the body was accepted"),
            Err(err) => panic!("expected invalid, got {err}"),
        }
        // The refused seek leaves the handler where it was.
        assert_eq!(true, hit.done);
        assert_eq!(0, hit.range_start);

        match hit.seek(1, None) {
            Ok(()) => {},
            Err(err) => panic!("seek inside the body failed: {err}"),
        }
        assert_eq!(false, hit.done);
        assert_eq!(1, hit.range_start);
        assert_eq!(5, hit.range_end);
        assert_eq!(Some(Bytes::from_static(b"ello")), hit.get());

        let mut empty = CompleteHit {
            body: Bytes::new(),
            done: false,
            range_start: 0,
            range_end: 0,
        };
        assert_eq!(true, empty.seek(0, None).is_err());
    }

    /// Regression: a body was handed out in one piece however large it
    /// was, and a response that is held to a rate went out as nothing
    /// for a long while and then all at once.
    #[tokio::test]
    async fn test_complete_hit_is_read_in_pieces() {
        let content: Vec<u8> =
            (0..150_000u32).map(|n| (n % 251) as u8).collect();
        let body = Bytes::from(content.clone());
        let mut handle: HitHandler = Box::new(CompleteHit {
            body: body.clone(),
            done: false,
            range_start: 0,
            range_end: body.len(),
        });
        let read = async |handle: &mut HitHandler| {
            let mut pieces = vec![];
            while let Some(piece) = handle.read_body().await.unwrap() {
                pieces.push(piece);
            }
            pieces
        };
        let pieces = read(&mut handle).await;
        assert_eq!(
            vec![HIT_CHUNK_SIZE, HIT_CHUNK_SIZE, 150_000 - 2 * HIT_CHUNK_SIZE],
            pieces.iter().map(|piece| piece.len()).collect::<Vec<_>>()
        );
        assert_eq!(content, pieces.concat());

        // A range of it, the same way, and no more than the range.
        handle.seek(1000, Some(140_000)).unwrap();
        let pieces = read(&mut handle).await;
        assert_eq!(3, pieces.len());
        assert_eq!(content[1000..140_000].to_vec(), pieces.concat());

        // Nothing at all is one piece of nothing, as it was.
        let mut empty: HitHandler = Box::new(CompleteHit {
            body: Bytes::new(),
            done: false,
            range_start: 0,
            range_end: 0,
        });
        assert_eq!(
            Some(0),
            empty.read_body().await.unwrap().map(|piece| piece.len())
        );
        assert_eq!(true, empty.read_body().await.unwrap().is_none());
    }

    /// The storage says when the piece it has handed out was the last:
    /// with it, and not after it. The proxy passes that on as the end of
    /// the body where pingora does not.
    #[tokio::test]
    async fn test_hit_says_when_it_is_read_to_the_end() {
        let body = Bytes::from(vec![7u8; 150_000]);
        let mut handle: HitHandler = Box::new(CompleteHit {
            body: body.clone(),
            done: false,
            range_start: 0,
            range_end: body.len(),
        });
        let mut ends = vec![];
        while handle.read_body().await.unwrap().is_some() {
            ends.push(is_hit_read_to_the_end(handle.as_any()));
        }
        assert_eq!(vec![false, false, true], ends);
        // Asked for another part, it is not at its end again.
        handle.seek(0, Some(10)).unwrap();
        assert_eq!(false, is_hit_read_to_the_end(handle.as_any()));
        assert_eq!(true, handle.read_body().await.unwrap().is_some());
        assert_eq!(true, is_hit_read_to_the_end(handle.as_any()));

        // A body of nothing ends with its one empty piece.
        let mut empty: HitHandler = Box::new(CompleteHit {
            body: Bytes::new(),
            done: false,
            range_start: 0,
            range_end: 0,
        });
        assert_eq!(false, is_hit_read_to_the_end(empty.as_any()));
        assert_eq!(true, empty.read_body().await.unwrap().is_some());
        assert_eq!(true, is_hit_read_to_the_end(empty.as_any()));

        // What is no handler of this storage is not known to have ended.
        let other: Box<dyn Any + Send + Sync> = Box::new(0u8);
        assert_eq!(false, is_hit_read_to_the_end(other.as_ref()));
    }

    #[tokio::test]
    async fn test_object_miss_handler() {
        let key = "key";

        let cache = Arc::new(TinyUfoCache::new(CacheMode::Normal, 10));
        let obj = ObjectMissHandler {
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
            body: BytesMut::new(),
            body_bytes: 0,
            content_length: None,
            streaming_checked: false,
            writer: None,
            key: key.to_string(),
            primary_key: "".to_string(),
            namespace: b"".to_vec(),
            tags: Vec::new(),
            meta_index: None,
            cache: cache.clone(),
        };
        let mut handle: MissHandler = Box::new(obj);

        handle
            .write_body(Bytes::from_static(b"Hello World!"), true)
            .await
            .unwrap();
        // "Hello World!" (12) plus the meta "Hello" and "World".
        match handle.finish().await {
            Ok(MissFinishType::Created(size)) => assert_eq!(22, size),
            Ok(_) => panic!("expected Created"),
            Err(err) => panic!("finish failed: {err}"),
        }

        let data = cache.get(key, b"").await.unwrap().unwrap();
        assert_eq!("Hello World!", std::str::from_utf8(&data.body).unwrap());
    }

    #[test]
    fn test_cache_object_get_weight() {
        // data less than one page
        let obj = CacheObject {
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
            body: Bytes::from_static(b"Hello World!"),
        };
        assert_eq!(1, obj.get_weight());

        // Regression: the size in pages was rounded down, so an object
        // weighed up to a page less than it takes.
        let sized = |size: usize| CacheObject {
            body: vec![0; size].into(),
            ..Default::default()
        };
        assert_eq!(1, sized(PAGE_SIZE).get_weight());
        assert_eq!(2, sized(PAGE_SIZE + 1).get_weight());
        assert_eq!(2, sized(PAGE_SIZE * 2 - 1).get_weight());
        assert_eq!(2, sized(PAGE_SIZE * 2).get_weight());
        assert_eq!(3, sized(PAGE_SIZE * 2 + 1).get_weight());

        // data larger than max size
        let obj = CacheObject {
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
            body: vec![0; MAX_OBJECT_CACHE_SIZE + 1].into(),
        };
        assert_eq!(u16::MAX, obj.get_weight());
    }

    #[tokio::test]
    async fn test_http_cache_update_meta() {
        let storage = Arc::new(TinyUfoCache::new(CacheMode::Normal, 100));
        let http_cache: &'static HttpCache =
            Box::leak(Box::new(HttpCache::new(None, storage, 4096 * 100)));
        let key = CacheKey::new("ns", "/update-meta");
        let span = pingora::cache::trace::Span::inactive().handle();

        let now = SystemTime::now();
        let mut h1 = pingora::http::ResponseHeader::build(200, None).unwrap();
        h1.insert_header("etag", "\"v1\"").unwrap();
        let m1 = CacheMeta::new(now + Duration::from_secs(10), now, 0, 0, h1);

        // Missing entry returns Err("no meta found").
        let err = http_cache
            .update_meta(&key, &m1, &span)
            .await
            .expect_err("missing key should error");
        assert!(err.to_string().contains("no meta found"), "{err}");

        // Seed via get_miss_handler.
        let mut miss =
            http_cache.get_miss_handler(&key, &m1, &span).await.unwrap();
        miss.write_body(Bytes::from_static(b"cached-payload"), true)
            .await
            .unwrap();
        miss.finish().await.unwrap();

        // Update meta via Storage::update_meta and verify lookup preserves body.
        let mut h2 = pingora::http::ResponseHeader::build(200, None).unwrap();
        h2.insert_header("etag", "\"v2\"").unwrap();
        let m2 = CacheMeta::new(now + Duration::from_secs(120), now, 0, 0, h2);
        assert_eq!(
            true,
            http_cache.update_meta(&key, &m2, &span).await.unwrap()
        );

        let (looked_meta, mut hit) =
            http_cache.lookup(&key, &span).await.unwrap().unwrap();
        assert_eq!(
            Some(b"\"v2\"".as_slice()),
            looked_meta.headers().get("etag").map(|v| v.as_bytes())
        );
        let body = hit.read_body().await.unwrap().unwrap();
        assert_eq!(b"cached-payload", body.as_ref());
        assert_eq!(true, hit.read_body().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_disk_hit_streaming_seek_and_eof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk-hit.bin");
        let prefix = b"HEADER_META_BYTES";
        let content: Vec<u8> =
            (0..150_000u32).map(|n| (n % 251) as u8).collect();
        let mut raw = Vec::with_capacity(prefix.len() + content.len());
        raw.extend_from_slice(prefix);
        raw.extend_from_slice(&content);
        std::fs::write(&path, &raw).unwrap();

        let mut handle: HitHandler =
            Box::new(DiskHit::new(path, prefix.len() as u64, content.len()));
        assert_eq!(true, handle.can_seek());
        assert_eq!(false, is_hit_read_to_the_end(handle.as_any()));

        let mut pieces = vec![];
        let mut ends = vec![];
        while let Some(piece) = handle.read_body().await.unwrap() {
            ends.push(is_hit_read_to_the_end(handle.as_any()));
            pieces.push(piece);
        }
        assert_eq!(
            vec![HIT_CHUNK_SIZE, HIT_CHUNK_SIZE, 150_000 - 2 * HIT_CHUNK_SIZE],
            pieces.iter().map(|piece| piece.len()).collect::<Vec<_>>()
        );
        assert_eq!(vec![false, false, true], ends);
        assert_eq!(content, pieces.concat());
        assert_eq!(true, handle.read_body().await.unwrap().is_none());

        // Range seek across multiple chunks resets `done` and reads only the slice.
        handle.seek(1000, Some(140_000)).unwrap();
        assert_eq!(false, is_hit_read_to_the_end(handle.as_any()));
        let mut range_pieces = vec![];
        let mut range_ends = vec![];
        while let Some(piece) = handle.read_body().await.unwrap() {
            range_ends.push(is_hit_read_to_the_end(handle.as_any()));
            range_pieces.push(piece);
        }
        assert_eq!(vec![false, false, true], range_ends);
        assert_eq!(content[1000..140_000].to_vec(), range_pieces.concat());

        // Consecutive seek beyond the previous `range_end` validates against `body_len`.
        handle.seek(149_990, Some(160_000)).unwrap();
        assert_eq!(false, is_hit_read_to_the_end(handle.as_any()));
        let tail = handle.read_body().await.unwrap().unwrap();
        assert_eq!(true, is_hit_read_to_the_end(handle.as_any()));
        assert_eq!(&content[149_990..], tail.as_ref());
        assert_eq!(true, handle.read_body().await.unwrap().is_none());

        // Leaving end unset keeps existing range_end, and out-of-range start fails.
        handle.seek(149_995, None).unwrap();
        let tail2 = handle.read_body().await.unwrap().unwrap();
        assert_eq!(&content[149_995..], tail2.as_ref());
        assert_eq!(true, handle.seek(150_000, None).is_err());
    }

    #[test]
    fn test_should_spill_payload() {
        assert_eq!(false, should_spill_payload(None, 200, 1_000_000));
        assert_eq!(false, should_spill_payload(Some(0), 200, 60_000));
        assert_eq!(true, should_spill_payload(Some(0), 200, 65_536));
        assert_eq!(
            false,
            should_spill_payload(Some(16 * 1024), 200, 32 * 1024)
        );
        assert_eq!(true, should_spill_payload(Some(16 * 1024), 200, 65_536));
        assert_eq!(
            false,
            should_spill_payload(Some(1024 * 1024), 200, 512 * 1024)
        );
        assert_eq!(
            true,
            should_spill_payload(Some(1024 * 1024), 200, 2 * 1024 * 1024)
        );
    }

    #[test]
    fn test_parse_cache_tag_headers() {
        let v1 = http::HeaderValue::from_static("news, blog  featured\tnews");
        let v2 = http::HeaderValue::from_static("  , blog, post-1 ");
        assert_eq!(
            vec![
                "news".to_string(),
                "blog".to_string(),
                "featured".to_string(),
                "post-1".to_string()
            ],
            parse_cache_tag_headers([&v1, &v2])
        );
    }

    #[test]
    fn test_cache_meta_index_prefix_and_bounded_eviction() {
        assert!(matches_prefix(
            "ns",
            "nsGET:a.com/blog/post",
            "ns",
            "a.com/blog/"
        ));
        assert!(matches_prefix(
            "ns",
            "nsgzip:HEAD:a.com/blog/post?x=1",
            "ns",
            "a.com/blog/"
        ));
        assert!(matches_prefix(
            "ns",
            "nsUS:GET:[::1]/blog/post",
            "ns",
            "[::1]/blog/"
        ));
        // Host isolation and query false-match guards.
        assert!(!matches_prefix(
            "ns",
            "nsGET:sub.a.com/blog/post",
            "ns",
            "a.com/blog/"
        ));
        assert!(!matches_prefix(
            "ns",
            "nsGET:a.com/other?next=GET:a.com/blog/post",
            "ns",
            "a.com/blog/"
        ));
        assert!(!matches_prefix(
            "ns2",
            "ns2GET:a.com/blog/post",
            "ns",
            "a.com/blog/"
        ));

        let index = CacheMetaIndex::with_shard_cap(4);
        // Pick keys that land on the same shard to verify half-eviction deterministically.
        let shard0_keys: Vec<String> = (0..1000)
            .map(|i| format!("k-{i:04}"))
            .filter(|k| {
                (index.hasher.hash_one(k.as_str()) as usize)
                    .is_multiple_of(META_INDEX_SHARDS)
            })
            .take(5)
            .collect();
        assert_eq!(5, shard0_keys.len());
        for (i, k) in shard0_keys.iter().enumerate() {
            index.upsert(
                "ns",
                &format!("nsGET:a.com/p/{i}"),
                k,
                vec![format!("tag-{i}")],
            );
        }
        // Oldest 2 (k[0], k[1]) were evicted when inserting k[4]; newer ones remain.
        assert!(!index.contains("ns", &shard0_keys[0]));
        assert!(!index.contains("ns", &shard0_keys[1]));
        assert!(index.contains("ns", &shard0_keys[2]));
        assert!(index.contains("ns", &shard0_keys[3]));
        assert!(index.contains("ns", &shard0_keys[4]));
    }

    #[tokio::test]
    async fn test_http_cache_purge_by_prefix_and_tags() {
        let storage = Arc::new(TinyUfoCache::new(CacheMode::Normal, 200));
        let http_cache: &'static HttpCache =
            Box::leak(Box::new(HttpCache::new(None, storage, 4096 * 200)));
        let span = pingora::cache::trace::Span::inactive().handle();
        let now = SystemTime::now();

        let seed = async |primary: &str, ns: &str, tag_header: Option<&str>| {
            let key = CacheKey::new(primary, ns);
            let mut resp =
                pingora::http::ResponseHeader::build(200, None).unwrap();
            if let Some(tag) = tag_header {
                resp.insert_header("cache-tag", tag).unwrap();
            }
            let meta =
                CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, resp);
            let mut miss = http_cache
                .get_miss_handler(&key, &meta, &span)
                .await
                .unwrap();
            miss.write_body(Bytes::from_static(b"payload"), true)
                .await
                .unwrap();
            miss.finish().await.unwrap();
            key
        };

        let k_blog_1 =
            seed("nsGET:a.com/blog/1", "ns", Some("news, home")).await;
        let k_blog_gz =
            seed("nsgzip:GET:a.com/blog/2", "ns", Some("news")).await;
        let k_other_host = seed("nsGET:b.com/blog/1", "ns", Some("news")).await;
        let k_other_path =
            seed("nsGET:a.com/static/app.js", "ns", Some("assets")).await;
        let k_other_ns =
            seed("otherGET:a.com/blog/1", "other", Some("news")).await;

        // Prefix purge isolates both namespace and host.
        let purged = http_cache
            .purge_by_prefix("ns", "a.com/blog/")
            .await
            .unwrap();
        assert_eq!(2, purged.len());
        assert!(http_cache.lookup(&k_blog_1, &span).await.unwrap().is_none());
        assert!(
            http_cache
                .lookup(&k_blog_gz, &span)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            http_cache
                .lookup(&k_other_host, &span)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            http_cache
                .lookup(&k_other_path, &span)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            http_cache
                .lookup(&k_other_ns, &span)
                .await
                .unwrap()
                .is_some()
        );

        // Update meta refreshes tags in the index.
        let mut updated_resp =
            pingora::http::ResponseHeader::build(200, None).unwrap();
        updated_resp
            .insert_header("cache-tag", "assets, refreshed")
            .unwrap();
        let updated_meta = CacheMeta::new(
            now + Duration::from_secs(60),
            now,
            0,
            0,
            updated_resp,
        );
        assert!(
            http_cache
                .update_meta(&k_other_path, &updated_meta, &span)
                .await
                .unwrap()
        );

        // Tag purge scoped to namespace "ns" skips "other".
        let tagged = http_cache
            .purge_by_tags(
                Some("ns"),
                &["news".to_string(), "refreshed".to_string()],
            )
            .await
            .unwrap();
        assert_eq!(2, tagged.len());
        assert!(
            http_cache
                .lookup(&k_other_host, &span)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            http_cache
                .lookup(&k_other_path, &span)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            http_cache
                .lookup(&k_other_ns, &span)
                .await
                .unwrap()
                .is_some()
        );

        // Unscoped tag purge clears remaining "other" entry.
        let remaining = http_cache
            .purge_by_tags(None, &["news".to_string()])
            .await
            .unwrap();
        assert_eq!(1, remaining.len());
        assert!(
            http_cache
                .lookup(&k_other_ns, &span)
                .await
                .unwrap()
                .is_none()
        );
    }
}
