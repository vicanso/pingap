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

use super::{
    Error, get_bool_conf, get_hash_key, get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use bstr::ByteSlice;
use bytes::Bytes;
use bytesize::ByteSize;
use fancy_regex::Regex;
use http::{Method, StatusCode};
use humantime::parse_duration;
use pingap_cache::{HttpCache, new_cache_backend};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ensure_verified_client_ip, get_cache_key,
};
use pingap_util::IpRules;
use pingora::cache::CacheOptionOverrides;
use pingora::cache::eviction::EvictionManager;
use pingora::cache::eviction::simple_lru::Manager;
use pingora::cache::key::CacheHashKey;
use pingora::cache::lock::{CacheKeyLock, CacheLock};
use pingora::cache::predictor::{CacheablePredictor, Predictor};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{debug, error};

type Result<T> = std::result::Result<T, Error>;

// Singleton instances using OnceCell for thread-safe lazy initialization
// Predictor: Determines if a response should be cached based on patterns/rules
static PREDICTOR: OnceLock<Predictor<32>> = OnceLock::new();
// EvictionManager: Handles removing entries when cache is full using LRU strategy
static EVICTION_MANAGER: OnceLock<Manager> = OnceLock::new();
// CacheLock: Prevents multiple requests from generating the same cache entry
// simultaneously. `session.cache.enable` wants a `&'static` lock, so one is
// leaked per distinct duration and reused from then on — bounded by the number
// of distinct `lock` values in the configuration, not by the number of plugin
// instances, so a hot reload does not leak.
static CACHE_LOCKS: LazyLock<
    Mutex<HashMap<Duration, &'static (dyn CacheKeyLock + Send + Sync)>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct Cache {
    // Determines when this plugin runs in the request/response lifecycle
    plugin_step: PluginStep,
    // Optional LRU-based memory management for cache entries
    // Static lifetime ensures the eviction manager lives for the program duration
    eviction: Option<&'static (dyn EvictionManager + Sync)>,
    // Optional predictor to determine if responses should be cached
    // Uses patterns and rules to make intelligent caching decisions
    predictor: Option<&'static (dyn CacheablePredictor + Sync)>,
    // Optional lock mechanism to prevent cache stampede
    // (multiple identical requests generating the same cache entry)
    lock: Option<&'static (dyn CacheKeyLock + Send + Sync)>,
    // How many times a request waiting on the cache lock re-checks the
    // cache before giving up; None keeps pingora's default of 2
    lock_retries: Option<usize>,
    // Backend storage implementation for the HTTP cache
    http_cache: &'static HttpCache,
    // Maximum size in bytes for individual cached files
    max_file_size: usize,
    // Optional maximum time a cache entry can live
    // Overrides Cache-Control headers if set
    max_ttl: Option<Duration>,
    // Optional namespace for cache isolation
    // Useful for multi-tenant systems or separating different types of cached content
    namespace: Option<String>,
    // Optional list of headers to include when generating cache keys
    // Allows for variant caching (e.g., different versions based on Accept-Encoding)
    headers: Option<Vec<String>>,
    // Optional allow list for the origin's `Vary` header: only these request
    // headers may create cache variants. None honours everything it names.
    vary_headers: Option<Arc<Vec<String>>>,
    // Whether to check the cache-control header, if not exist the response will not be cached.
    check_cache_control: bool,
    // IP-based access control for cache purge operations
    purge_ip_rules: IpRules,
    // Optional regex pattern to skip caching for certain requests
    skip: Option<Regex>,
    // Unique identifier for this cache configuration
    hash_value: String,
}

/// Helper function to initialize or retrieve the eviction manager singleton.
/// This manager handles the LRU (Least Recently Used) cache eviction strategy.
///
/// # Returns
/// Returns a static reference to the Manager instance that handles cache eviction.
///
/// # Implementation Details
/// - Uses the configured cache size from current config if available
/// - Falls back to MAX_MEMORY_SIZE (100MB) if not configured
/// - Ensures only one instance is created using OnceCell
///
/// In a dry run (`pingap_cache::dry_run`) nothing is created: the manager
/// is sized by whoever asks first, for good, and that must not be a
/// configuration that is only being checked.
fn get_eviction_manager(cache_max_size: u64) -> Option<&'static Manager> {
    if pingap_cache::is_dry_run() {
        return EVICTION_MANAGER.get();
    }
    Some(EVICTION_MANAGER.get_or_init(|| Manager::new(cache_max_size as usize)))
}

/// Returns the cache lock for `lock`, creating it on first use.
/// Cache locks prevent cache stampede by ensuring only one request generates a
/// cache entry.
///
/// # Arguments
/// * `lock` - The desired lock duration
///
/// # Returns
/// * `Some(&CacheLock)` - For any non-zero duration
/// * `None` - For a zero duration, which disables locking
fn get_cache_lock(
    lock: Duration,
) -> Option<&'static (dyn CacheKeyLock + Send + Sync)> {
    if lock.is_zero() {
        return None;
    }
    let mut locks = CACHE_LOCKS.lock().ok()?;
    if let Some(cache_lock) = locks.get(&lock) {
        return Some(*cache_lock);
    }
    // A lock is kept for the life of the process; one is not made for a
    // configuration that is only being checked.
    if pingap_cache::is_dry_run() {
        return None;
    }
    let cache_lock: &'static (dyn CacheKeyLock + Send + Sync) =
        Box::leak(CacheLock::new_boxed(lock));
    locks.insert(lock, cache_lock);
    Some(cache_lock)
}

/// Helper function to initialize or retrieve the predictor singleton.
/// The predictor determines whether responses should be cached based on configured rules.
///
/// # Returns
/// Returns a static reference to a CacheablePredictor implementation.
///
/// # Implementation Details
/// - Creates a new Predictor with capacity of 128 entries
/// - No additional predictor configuration (None parameter)
/// - Ensures only one instance is created using OnceCell
fn get_predictor() -> &'static (dyn CacheablePredictor + Sync) {
    PREDICTOR.get_or_init(|| Predictor::new(128, None))
}

/// The value of a header as one component of the cache key. The
/// components are joined with `:`, so one inside a value is written
/// `%3A` (and `%` as `%25`): `Origin: https://a.com` with nothing after it
/// and `Origin: https` followed by `//a.com:` were one key, and whoever
/// sent the second chose the response the first was given.
fn key_slot(value: &str) -> String {
    if !value.contains([':', '%']) {
        return value.to_string();
    }
    value.replace('%', "%25").replace(':', "%3A")
}

impl TryFrom<&PluginConf> for Cache {
    type Error = Error;

    /// Attempts to create a Cache instance from plugin configuration.
    ///
    /// # Arguments
    /// * `value` - Plugin configuration to convert
    ///
    /// # Returns
    /// * `Result<Self>` - Configured Cache instance or conversion error
    ///
    /// # Configuration Options
    /// - eviction: Enables LRU cache eviction
    /// - lock: Cache lock duration (1-3s)
    /// - max_ttl: Maximum cache entry lifetime
    /// - max_file_size: Maximum cached file size
    /// - namespace: Cache isolation namespace
    /// - headers: Headers to include in cache key
    /// - predictor: Enables cache prediction
    /// - purge_ip_list: IPs allowed to purge cache
    /// - skip: Regex pattern for requests to skip
    ///
    /// # Validation
    /// - Ensures plugin step is Request
    /// - Validates duration formats
    /// - Creates cache directories if needed
    /// - Compiles skip regex if provided
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let directory = get_str_conf(value, "directory");
        // By their value, not their presence: `eviction = false`, which is
        // what the admin form saves for "No", switched it on.
        let eviction = get_bool_conf(value, "eviction");
        let predictor = get_bool_conf(value, "predictor");
        let check_cache_control = get_bool_conf(value, "check_cache_control");

        let lock = get_str_conf(value, "lock");
        let lock = if !lock.is_empty() {
            parse_duration(&lock).map_err(|e| Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: e.to_string(),
            })?
        } else {
            Duration::from_secs(1)
        };

        let lock_retries = if value.get("lock_retries").is_some() {
            let retries =
                usize::try_from(crate::get_int_conf(value, "lock_retries"))
                    .map_err(|_| Error::Invalid {
                        category: PluginCategory::Cache.to_string(),
                        message:
                            "lock_retries should be a non-negative integer"
                                .to_string(),
                    })?;
            Some(retries)
        } else {
            None
        };

        let max_ttl = get_str_conf(value, "max_ttl");
        let max_ttl = if !max_ttl.is_empty() {
            Some(parse_duration(&max_ttl).map_err(|e| Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: e.to_string(),
            })?)
        } else {
            None
        };

        let max_file_size = get_str_conf(value, "max_file_size");
        let max_file_size = if !max_file_size.is_empty() {
            ByteSize::from_str(&max_file_size).map_err(|e| Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: e.to_string(),
            })?
        } else {
            ByteSize::mb(1)
        };
        let namespace = get_str_conf(value, "namespace");
        let namespace = if namespace.is_empty() {
            None
        } else {
            Some(namespace)
        };
        let headers = get_str_slice_conf(value, "headers");
        let headers = if headers.is_empty() {
            None
        } else {
            Some(headers)
        };
        let vary_headers = get_str_slice_conf(value, "vary_headers");
        let vary_headers = if vary_headers.is_empty() {
            None
        } else {
            Some(Arc::new(
                vary_headers
                    .iter()
                    .map(|name| name.trim().to_ascii_lowercase())
                    .collect(),
            ))
        };

        let purge_ip_rules =
            IpRules::try_new(&get_str_slice_conf(value, "purge_ip_list"))
                .map_err(|e| Error::Invalid {
                    category: PluginCategory::Cache.to_string(),
                    message: e.to_string(),
                })?;

        let skip_value = get_str_conf(value, "skip");
        let skip = if skip_value.is_empty() {
            None
        } else {
            Some(Regex::new(&skip_value).map_err(|e| Error::Regex {
                category: "cache".to_string(),
                source: Box::new(e),
            })?)
        };

        // The backend comes last, once everything else of the
        // configuration has been read and found good. Making it is what
        // reaches outside this plugin: a directory is created, and the
        // backend of a directory whose parameters changed is replaced.
        // Done first, a configuration refused for another of its settings
        // had already taken the backend away from the plugin it was to
        // replace, which then went on serving with a retired one.
        if let Some(err) = crate::wrong_types_error("cache") {
            return Err(err);
        }
        let cache = new_cache_backend(directory.as_str()).map_err(|e| {
            Error::Invalid {
                category: "cache".to_string(),
                message: e.to_string(),
            }
        })?;
        let eviction = if !eviction {
            None
        } else if cache.max_size > 0 {
            get_eviction_manager(cache.max_size).map(|eviction| {
                eviction as &'static (dyn EvictionManager + Sync)
            })
        } else {
            // Eviction needs a bounded backend to evict against. The file
            // backend does not report a size, so say so instead of leaving
            // the operator believing the cache is capped.
            error!(
                directory,
                "eviction is only supported by the memory cache backend, ignoring it"
            );
            None
        };
        if let Some(namespace) = &namespace
            && let Some(directory) = &cache.directory
            && !pingap_cache::is_dry_run()
        {
            let path = format!("{directory}/{namespace}");
            if let Err(e) = std::fs::create_dir_all(&path) {
                error!(
                    error = e.to_string(),
                    path, "create directory of cache fail"
                );
            }
        }

        let params = Self {
            hash_value,
            http_cache: cache,
            plugin_step: PluginStep::Request,
            eviction,
            predictor: predictor.then(get_predictor),
            lock: get_cache_lock(lock),
            lock_retries,
            max_ttl,
            max_file_size: max_file_size.as_u64() as usize,
            namespace,
            headers,
            vary_headers,
            purge_ip_rules,
            check_cache_control,
            skip,
        };
        Ok(params)
    }
}

impl Cache {
    /// Creates a new Cache instance from the provided plugin configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Self>` - New Cache instance or error if configuration is invalid
    ///
    /// # Logging
    /// Logs debug information about the cache plugin creation
    /// Per-request overrides for pingora's cache lock. Only the retry
    /// budget is configurable, and only when the plugin sets it; otherwise
    /// pingora keeps its defaults.
    fn cache_option_overrides(&self) -> Option<CacheOptionOverrides> {
        let retries = self.lock_retries?;
        let mut overrides = CacheOptionOverrides::default();
        overrides.max_lock_retries = Some(retries);
        Some(overrides)
    }

    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new http cache plugin"
        );
        Self::try_from(params)
    }
}

static METHOD_PURGE: LazyLock<Method> = LazyLock::new(|| {
    Method::from_bytes(b"PURGE").expect("Failed to create PURGE method")
});

#[async_trait]
impl Plugin for Cache {
    /// Returns the unique hash key for this cache configuration.
    /// Used to identify different cache configurations in the system.
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming HTTP requests for caching operations.
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - HTTP session containing request/response data
    /// * `ctx` - Ctx context for sharing data between plugins
    ///
    /// # Returns
    /// * `Ok(Some(HttpResponse))` - For immediate responses (e.g., PURGE operations)
    /// * `Ok(None)` - To continue normal request processing
    ///
    /// # Processing Steps
    /// 1. Validates plugin step and HTTP method
    /// 2. Checks skip patterns
    /// 3. Builds cache key from URI and headers
    /// 4. Handles PURGE requests with access control
    /// 5. Configures cache settings for the session
    /// 6. Enables caching with configured components
    /// 7. Sets up size limits and tracking
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // Only process if we're in the correct plugin step
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // Cache operations only support GET/HEAD for retrieval and PURGE for invalidation
        let req_header = session.req_header();
        let method = &req_header.method;
        if ![&Method::GET, &Method::HEAD, &*METHOD_PURGE].contains(&method) {
            return Ok(RequestPluginResult::Skipped);
        }

        // Check if request matches skip pattern (if configured)
        if let Some(skip) = &self.skip
            && let Some(value) = req_header.uri.path_and_query()
            && skip.is_match(value.as_str()).unwrap_or_default()
        {
            return Ok(RequestPluginResult::Skipped);
        }

        // Build cache key components including configured headers
        let mut keys = Vec::with_capacity(4);
        {
            let cache_info = ctx.cache.get_or_insert_default();
            cache_info.namespace = self.namespace.clone();
        }
        if let Some(headers) = &self.headers {
            // One slot per configured header, kept for a header the
            // request does not have: with the empty ones left out, `X-A: 1`
            // alone and `X-B: 1` alone gave the same key. A request with
            // none of them adds nothing, as before.
            keys.extend(headers.iter().map(|key| {
                key_slot(&session.get_header_bytes(key).to_str_lossy())
            }));
            if keys.iter().all(|value| value.is_empty()) {
                keys.clear();
            }
        }
        if !keys.is_empty() {
            ctx.extend_cache_keys(keys);
            if let Some(cache_info) = &ctx.cache {
                debug!("Cache keys: {:?}", cache_info.keys);
            }
        }

        // Handle PURGE requests with IP-based access control
        if method == *METHOD_PURGE {
            // Not the plain client ip: without trusted proxies that is
            // whatever `X-Forwarded-For` says.
            let ip = ensure_verified_client_ip(session, ctx);
            let found = match self.purge_ip_rules.is_match(ip) {
                Ok(matched) => matched,
                Err(e) => {
                    return Ok(RequestPluginResult::Respond(
                        HttpResponse::bad_request(e.to_string()),
                    ));
                },
            };
            if !found {
                return Ok(RequestPluginResult::Respond(HttpResponse {
                    status: StatusCode::FORBIDDEN,
                    body: Bytes::from_static(b"Forbidden, ip is not allowed"),
                    ..Default::default()
                }));
            }

            // `PURGE /*` empties the whole namespace. Anything else purges
            // exactly the requested uri.
            if session.req_header().uri.path() == "/*" {
                let Some(namespace) = &self.namespace else {
                    return Ok(RequestPluginResult::Respond(HttpResponse {
                        status: StatusCode::NOT_IMPLEMENTED,
                        body: Bytes::from_static(
                            b"namespace purge requires the namespace option",
                        ),
                        ..Default::default()
                    }));
                };
                let result =
                    self.http_cache.cache.purge_namespace(namespace).await?;
                let Some(stats) = result else {
                    return Ok(RequestPluginResult::Respond(HttpResponse {
                        status: StatusCode::NOT_IMPLEMENTED,
                        body: Bytes::from_static(
                            b"namespace purge is not supported by the memory cache backend",
                        ),
                        ..Default::default()
                    }));
                };
                return Ok(RequestPluginResult::Respond(HttpResponse::text(
                    format!("purged: {}, fail: {}", stats.success, stats.fail),
                )));
            }

            // Cached GET and HEAD responses are separate entries (the method
            // is part of the key); purge both so a HEAD variant cannot keep
            // answering for a url that was just purged.
            //
            // And one entry for each coding or image format another plugin
            // makes a part of the key. This request names the url and no
            // coding: with its own key alone it removed the entry no
            // browser asks for, and the compressed ones went on being
            // served.
            for keys in ctx.cache_key_alternatives() {
                if let Some(cache_info) = ctx.cache.as_mut() {
                    cache_info.keys = Some(keys);
                }
                for method in [Method::GET, Method::HEAD] {
                    let key = get_cache_key(
                        ctx,
                        method.as_ref(),
                        session.req_header(),
                    );
                    self.http_cache
                        .cache
                        .remove(&key.combined(), key.user_tag().as_bytes())
                        .await?;
                }
            }
            return Ok(
                RequestPluginResult::Respond(HttpResponse::no_content()),
            );
        }

        // Configure cache settings for this request
        if let Some(cache_info) = &mut ctx.cache {
            cache_info.max_ttl = self.max_ttl;
            cache_info.check_cache_control = self.check_cache_control;
            cache_info.vary_headers = self.vary_headers.clone();
        }

        // Enable caching for this session with configured components
        session.cache.enable(
            self.http_cache,
            self.eviction,
            self.predictor,
            self.lock,
            self.cache_option_overrides(),
        );

        // Set maximum cached file size if configured
        if self.max_file_size > 0 {
            session.cache.set_max_file_size_bytes(self.max_file_size);
        }

        // Track cache statistics if available
        if let Some(stats) = self.http_cache.stats()
            && let Some(cache_info) = ctx.cache.as_mut()
        {
            cache_info.reading_count = Some(stats.reading);
            cache_info.writing_count = Some(stats.writing);
        }

        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("cache", Cache);

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_cache_params() {
        let params = Cache::try_from(
            &toml::from_str::<PluginConf>(
                r###"
eviction = true
headers = ["Accept-Encoding"]
lock = "2s"
lock_retries = 5
max_file_size = "100kb"
predictor = true
max_ttl = "1m"
vary_headers = ["Accept-Encoding", " accept "]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            Some(vec!["accept-encoding".to_string(), "accept".to_string()]),
            params.vary_headers.as_deref().cloned()
        );
        assert_eq!(Some(5), params.lock_retries);
        assert_eq!(
            Some(5),
            params.cache_option_overrides().unwrap().max_lock_retries
        );
        assert_eq!(true, params.eviction.is_some());
        assert_eq!(
            r#"Some(["Accept-Encoding"])"#,
            format!("{:?}", params.headers)
        );
        assert_eq!(true, params.lock.is_some());
        assert_eq!(100 * 1000, params.max_file_size);
        assert_eq!(60, params.max_ttl.unwrap().as_secs());
        assert_eq!(true, params.predictor.is_some());

        // Unset leaves pingora's defaults alone; negatives are rejected.
        let params = Cache::try_from(
            &toml::from_str::<PluginConf>(r###"lock = "1s""###).unwrap(),
        )
        .unwrap();
        assert_eq!(None, params.lock_retries);
        assert_eq!(true, params.cache_option_overrides().is_none());
        let err = Cache::try_from(
            &toml::from_str::<PluginConf>("lock_retries = -1").unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert_eq!(true, err.contains("lock_retries"), "{err}");
    }

    /// Regression: `eviction` and `predictor` were on whenever the key was
    /// there, so `false` - what the admin form saves for "No" - enabled
    /// them.
    #[test]
    fn test_cache_flags_are_read_by_their_value() {
        let cache = |conf: &str| {
            Cache::try_from(&toml::from_str::<PluginConf>(conf).unwrap())
                .unwrap()
        };
        let off = cache("eviction = false\npredictor = false");
        assert_eq!(true, off.eviction.is_none());
        assert_eq!(true, off.predictor.is_none());
        let unset = cache("");
        assert_eq!(true, unset.eviction.is_none());
        assert_eq!(true, unset.predictor.is_none());
        let on = cache("eviction = true\npredictor = true");
        assert_eq!(true, on.eviction.is_some());
        assert_eq!(true, on.predictor.is_some());
    }

    /// Regression: the values of the configured headers went into the key
    /// without their place, the empty ones left out, so `X-A: 1` alone and
    /// `X-B: 1` alone shared an entry.
    #[tokio::test]
    async fn test_cache_key_keeps_a_slot_per_header() {
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>("headers = [\"X-A\", \"X-B\"]")
                .unwrap(),
        )
        .unwrap();
        let key_of = async |headers: &str| {
            let input = format!("GET /a HTTP/1.1\r\n{headers}\r\n");
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            cache
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();
            ctx.cache
                .and_then(|info| info.keys)
                .map(|keys| keys.join(":"))
        };
        assert_eq!(Some("1:".to_string()), key_of("X-A: 1\r\n").await);
        assert_eq!(Some(":1".to_string()), key_of("X-B: 1\r\n").await);
        assert_eq!(
            Some("1:2".to_string()),
            key_of("X-A: 1\r\nX-B: 2\r\n").await
        );
        // None of them: nothing is added, as before.
        assert_eq!(None, key_of("").await);
        // A `:` in a value cannot move the border between two of them.
        let split = key_of("X-A: https://a.com\r\n").await;
        let shifted = key_of("X-A: https\r\nX-B: //a.com:\r\n").await;
        assert_eq!(Some("https%3A//a.com:".to_string()), split);
        assert_eq!(Some("https://a.com%3A".to_string()), shifted);
        assert_eq!(Some("50%25:".to_string()), key_of("X-A: 50%\r\n").await);
    }

    /// The backend is made once the rest of the configuration is known to
    /// be good. Made first, a configuration that was then refused had
    /// created its directory already - and, on a reload, replaced the
    /// backend of the plugin that stayed in use.
    #[test]
    fn test_cache_backend_is_made_last() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("cache");
        let build = |extra: &str| {
            crate::build_plugin("cache", || {
                Cache::try_from(
                    &toml::from_str::<PluginConf>(&format!(
                        "directory = \"{}\"\n{extra}",
                        dir.display()
                    ))
                    .unwrap(),
                )
            })
        };
        for extra in [
            "max_ttl = \"oops\"",
            "skip = \"(\"",
            "purge_ip_list = [\"nope\"]",
            // of the wrong type, which is only reported after the build
            "eviction = \"yes\"",
            "check_cache_control = \"yes\"",
        ] {
            assert_eq!(true, build(extra).is_err(), "{extra}");
            assert_eq!(false, dir.exists(), "{extra}");
        }
        assert_eq!(true, build("").is_ok());
        assert_eq!(true, dir.exists());
    }

    /// Regression: only 1, 2 and 3 second locks used to be honoured, every
    /// other value silently disabled locking altogether.
    #[test]
    fn test_cache_lock_any_duration() {
        let lock_of = |lock: &str| {
            Cache::try_from(
                &toml::from_str::<PluginConf>(&format!(
                    r###"lock = "{lock}""###
                ))
                .unwrap(),
            )
            .unwrap()
            .lock
            .is_some()
        };

        for lock in ["1s", "2s", "3s", "5s", "30s", "500ms", "1m"] {
            assert_eq!(true, lock_of(lock), "lock({lock}) was disabled");
        }
        // Zero explicitly means "no lock".
        assert_eq!(false, lock_of("0s"));
    }
    #[tokio::test]
    async fn test_cache() {
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>(
                r###"
namespace = "pingap"
eviction = true
headers = ["Accept-Encoding"]
purge_ip_list = ["127.0.0.1"]
lock = "2s"
max_file_size = "100kb"
predictor = true
max_ttl = "1m"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        cache
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(
            "pingap",
            ctx.cache.as_ref().unwrap().namespace.as_ref().unwrap()
        );
        assert_eq!(
            "gzip",
            ctx.cache.as_ref().unwrap().keys.as_ref().unwrap().join(":")
        );
        assert_eq!(true, session.cache.enabled());
        assert_eq!(100 * 1000, cache.max_file_size);
    }

    async fn purge(cache: &Cache, path: &str) -> HttpResponse {
        let input_header = format!("PURGE {path} HTTP/1.1\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        // The mock io has no peer address; the proxy records it here when
        // the request comes in.
        ctx.conn.remote_addr = Some("127.0.0.1".to_string());
        let result = cache
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("purge must respond, got a pass-through");
        };
        resp
    }

    /// Regression: a purge removed the entry under its own key. With a
    /// plugin that makes the coding a part of the key that is the entry of
    /// a request that accepts none, and the compressed ones stayed.
    #[tokio::test]
    async fn test_purge_removes_every_key_variant() {
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>(
                r###"
namespace = "purge-variants"
purge_ip_list = ["127.0.0.1"]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let alternatives = Arc::new(vec![
            vec![],
            vec!["zstd".to_string()],
            vec!["gzip".to_string()],
        ]);
        // What the compression plugin leaves in the context of a request
        // that takes `coding`.
        let request = async |method: &str, coding: Option<&str>| {
            let input = format!("{method} /x HTTP/1.1\r\nHost: a.test\r\n\r\n");
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            ctx.conn.remote_addr = Some("127.0.0.1".to_string());
            ctx.push_cache_key_variant(
                coding
                    .map(|coding| coding.to_string())
                    .into_iter()
                    .collect(),
                alternatives.clone(),
            );
            (session, ctx)
        };
        let obj = pingap_cache::CacheObject {
            meta: (Bytes::from_static(b"m"), Bytes::from_static(b"h")),
            body: Bytes::from_static(b"body"),
        };
        let key_of = async |method: &str, coding: Option<&str>| {
            let (session, mut ctx) = request("GET", coding).await;
            ctx.cache.as_mut().unwrap().namespace =
                Some("purge-variants".to_string());
            get_cache_key(&ctx, method, session.req_header())
        };
        let stored = async |method: &str, coding: Option<&str>| {
            let key = key_of(method, coding).await;
            cache
                .http_cache
                .cache
                .get(&key.combined(), key.user_tag().as_bytes())
                .await
                .unwrap()
                .is_some()
        };
        let entries = [
            ("GET", None),
            ("GET", Some("gzip")),
            ("HEAD", Some("gzip")),
            ("GET", Some("zstd")),
        ];
        for (method, coding) in entries {
            let key = key_of(method, coding).await;
            cache
                .http_cache
                .cache
                .put(&key.combined(), key.user_tag().as_bytes(), obj.clone())
                .await
                .unwrap();
            assert_eq!(true, stored(method, coding).await);
        }

        // A purge that names no coding, as `curl -X PURGE` sends it.
        let (mut session, mut ctx) = request("PURGE", None).await;
        let result = cache
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("purge must respond");
        };
        assert_eq!(StatusCode::NO_CONTENT, resp.status);
        for (method, coding) in entries {
            assert_eq!(
                false,
                stored(method, coding).await,
                "{method} {coding:?} is still there"
            );
        }
    }

    #[tokio::test]
    async fn test_purge_namespace_memory_backend_unsupported() {
        // No directory -> memory backend, which cannot enumerate entries.
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>(
                r###"
namespace = "purge-mem"
purge_ip_list = ["127.0.0.1"]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let resp = purge(&cache, "/*").await;
        assert_eq!(StatusCode::NOT_IMPLEMENTED, resp.status);
    }

    #[tokio::test]
    async fn test_purge_namespace_file_backend() {
        // Keys of the shape pingora gives: a namespace purge only takes
        // files named like them for the cache's own.
        const PURGE_KEY: &str = "00000000000000000000000000000001";
        const OTHER_KEY: &str = "00000000000000000000000000000002";
        let dir = tempfile::TempDir::new().unwrap();
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>(&format!(
                r###"
directory = "{}"
namespace = "purge-ns"
purge_ip_list = ["127.0.0.1"]
"###,
                dir.path().to_string_lossy()
            ))
            .unwrap(),
        )
        .unwrap();

        // Seed one object in the plugin's namespace and one outside it.
        let obj = pingap_cache::CacheObject {
            meta: (Bytes::from_static(b"meta0"), Bytes::from_static(b"meta1")),
            body: Bytes::from_static(b"cached body"),
        };
        cache
            .http_cache
            .cache
            .put(PURGE_KEY, b"purge-ns", obj.clone())
            .await
            .unwrap();
        cache
            .http_cache
            .cache
            .put(OTHER_KEY, b"other-ns", obj)
            .await
            .unwrap();

        let resp = purge(&cache, "/*").await;
        assert_eq!(StatusCode::OK, resp.status);
        assert_eq!(
            "purged: 1, fail: 0",
            std::str::from_utf8(&resp.body).unwrap()
        );

        // The namespace is empty, the other one is untouched.
        let purged = cache
            .http_cache
            .cache
            .get(PURGE_KEY, b"purge-ns")
            .await
            .unwrap();
        assert_eq!(true, purged.is_none());
        let kept = cache
            .http_cache
            .cache
            .get(OTHER_KEY, b"other-ns")
            .await
            .unwrap();
        assert_eq!(true, kept.is_some());

        // An exact purge responds 204 whether or not the entry existed.
        let resp = purge(&cache, "/vicanso/pingap").await;
        assert_eq!(StatusCode::NO_CONTENT, resp.status);
    }

    /// Regression: without trusted proxies the address of a `PURGE` is the
    /// peer's. It used to be the client ip, which is then the first entry
    /// of `X-Forwarded-For`: sending the header was enough to purge.
    #[tokio::test]
    async fn test_purge_ignores_forged_forwarded_for() {
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>(
                r###"
namespace = "purge-forged"
purge_ip_list = ["127.0.0.1"]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let status = async |remote_addr: &str, headers: &str| {
            let input_header =
                format!("PURGE /vicanso/pingap HTTP/1.1\r\n{headers}\r\n");
            let mock_io = Builder::new().read(input_header.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            ctx.conn.remote_addr = Some(remote_addr.to_string());
            let result = cache
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();
            let RequestPluginResult::Respond(resp) = result else {
                panic!("purge must respond, got a pass-through");
            };
            resp.status
        };
        let forged = "X-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1\r\n";
        assert_eq!(StatusCode::FORBIDDEN, status("9.9.9.9", forged).await);
        assert_eq!(StatusCode::FORBIDDEN, status("9.9.9.9", "").await);
        // From the allowed address, with or without the headers.
        assert_eq!(StatusCode::NO_CONTENT, status("127.0.0.1", "").await);
        assert_eq!(
            StatusCode::NO_CONTENT,
            status("127.0.0.1", "X-Forwarded-For: 9.9.9.9\r\n").await
        );
    }

    #[tokio::test]
    async fn test_purge_forbidden_ip() {
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>(
                r###"
namespace = "purge-deny"
purge_ip_list = ["192.168.1.1"]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let resp = purge(&cache, "/*").await;
        assert_eq!(StatusCode::FORBIDDEN, resp.status);
    }
}
