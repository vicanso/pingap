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
    get_bool_conf, get_hash_key, get_plugin_factory, get_str_conf,
    get_str_slice_conf, Error,
};
use async_trait::async_trait;
use bstr::ByteSlice;
use bytes::Bytes;
use bytesize::ByteSize;
use ctor::ctor;
use fancy_regex::Regex;
use http::{Method, StatusCode};
use humantime::parse_duration;
use once_cell::sync::{Lazy, OnceCell};
use pingap_cache::{get_cache_backend, CacheBackendOption, HttpCache};
use pingap_config::{get_current_config, PluginCategory, PluginConf};
use pingap_core::{get_cache_key, Ctx, HttpResponse, Plugin, PluginStep};
use pingora::cache::eviction::simple_lru::Manager;
use pingora::cache::eviction::EvictionManager;
use pingora::cache::key::CacheHashKey;
use pingora::cache::lock::{CacheKeyLock, CacheLock};
use pingora::cache::predictor::{CacheablePredictor, Predictor};
use pingora::proxy::Session;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error};

type Result<T> = std::result::Result<T, Error>;

// Maximum memory size for cache (100MB) - default if not configured otherwise
const MAX_MEMORY_SIZE: usize = 100 * 1024 * 1024;

// Singleton instances using OnceCell for thread-safe lazy initialization
// Predictor: Determines if a response should be cached based on patterns/rules
static PREDICTOR: OnceCell<Predictor<32>> = OnceCell::new();
// EvictionManager: Handles removing entries when cache is full using LRU strategy
static EVICTION_MANAGER: OnceCell<Manager> = OnceCell::new();
// CacheLock: Prevents multiple requests from generating the same cache entry simultaneously
static CACHE_LOCK_ONE_SECOND: Lazy<
    Box<(dyn CacheKeyLock + std::marker::Send + Sync + 'static)>,
> = Lazy::new(|| {
    CacheLock::new_boxed(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_millis(300),
    )
});

static CACHE_LOCK_TWO_SECONDS: Lazy<
    Box<(dyn CacheKeyLock + std::marker::Send + Sync + 'static)>,
> = Lazy::new(|| {
    CacheLock::new_boxed(
        std::time::Duration::from_secs(2),
        std::time::Duration::from_millis(600),
    )
});

static CACHE_LOCK_THREE_SECONDS: Lazy<
    Box<(dyn CacheKeyLock + std::marker::Send + Sync + 'static)>,
> = Lazy::new(|| {
    CacheLock::new_boxed(
        std::time::Duration::from_secs(3),
        std::time::Duration::from_millis(900),
    )
});

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
    // Whether to check the cache-control header, if not exist the response will not be cached.
    check_cache_control: bool,
    // IP-based access control for cache purge operations
    purge_ip_rules: pingap_util::IpRules,
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
fn get_eviction_manager() -> &'static Manager {
    EVICTION_MANAGER.get_or_init(|| {
        // Use configured cache size or fall back to default MAX_MEMORY_SIZE
        let size = if let Some(cache_max_size) =
            get_current_config().basic.cache_max_size
        {
            cache_max_size.as_u64() as usize
        } else {
            MAX_MEMORY_SIZE
        };
        Manager::new(size)
    })
}

/// Helper function to get an appropriate cache lock based on the specified duration.
/// Cache locks prevent cache stampede by ensuring only one request generates a cache entry.
///
/// # Arguments
/// * `lock` - The desired lock duration
///
/// # Returns
/// * `Some(&CacheLock)` - If duration is 1, 2, or 3 seconds
/// * `None` - For any other duration
///
/// # Limitations
/// Only supports lock durations of exactly 1, 2, or 3 seconds
fn get_cache_lock(
    lock: Duration,
) -> Option<&'static (dyn CacheKeyLock + Send + Sync)> {
    match lock.as_secs() {
        1 => Some(CACHE_LOCK_ONE_SECOND.as_ref()),
        2 => Some(CACHE_LOCK_TWO_SECONDS.as_ref()),
        3 => Some(CACHE_LOCK_THREE_SECONDS.as_ref()),
        _ => None,
    }
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
        let basic_conf = &get_current_config().basic;
        let cache = get_cache_backend(Some(CacheBackendOption {
            cache_directory: basic_conf.cache_directory.clone(),
            cache_max_size: basic_conf.cache_max_size,
        }))
        .map_err(|e| Error::Invalid {
            category: "cache_backend".to_string(),
            message: e.to_string(),
        })?;
        let eviction = if value.contains_key("eviction") {
            let eviction = get_eviction_manager();
            Some(eviction as &'static (dyn EvictionManager + Sync))
        } else {
            None
        };

        let lock = get_str_conf(value, "lock");
        let lock = if !lock.is_empty() {
            parse_duration(&lock).map_err(|e| Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: e.to_string(),
            })?
        } else {
            Duration::from_secs(1)
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
        if !namespace.is_empty() && cache.directory.is_some() {
            let path = format!(
                "{}/{namespace}",
                cache.directory.clone().unwrap_or_default()
            );
            if let Err(e) = std::fs::create_dir_all(&path) {
                error!(
                    error = e.to_string(),
                    path, "create directory of cache fail"
                );
            }
        }
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

        let predictor = if value.contains_key("predictor") {
            Some(get_predictor())
        } else {
            None
        };

        let purge_ip_rules = pingap_util::IpRules::new(&get_str_slice_conf(
            value,
            "purge_ip_list",
        ));

        let skip_value = get_str_conf(value, "skip");
        let skip = if skip_value.is_empty() {
            None
        } else {
            Some(Regex::new(&skip_value).map_err(|e| Error::Regex {
                category: "cache".to_string(),
                source: Box::new(e),
            })?)
        };

        let params = Self {
            hash_value,
            http_cache: cache,
            plugin_step: PluginStep::Request,
            eviction,
            predictor,
            lock: get_cache_lock(lock),
            max_ttl,
            max_file_size: max_file_size.as_u64() as usize,
            namespace,
            headers,
            purge_ip_rules,
            check_cache_control: get_bool_conf(value, "check_cache_control"),
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
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new http cache plugin");
        Self::try_from(params)
    }
}

static METHOD_PURGE: Lazy<Method> =
    Lazy::new(|| Method::from_bytes(b"PURGE").unwrap());

#[async_trait]
impl Plugin for Cache {
    /// Returns the unique hash key for this cache configuration.
    /// Used to identify different cache configurations in the system.
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
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
    ) -> pingora::Result<(bool, Option<HttpResponse>)> {
        // Only process if we're in the correct plugin step
        if step != self.plugin_step {
            return Ok((false, None));
        }

        // Cache operations only support GET/HEAD for retrieval and PURGE for invalidation
        let req_header = session.req_header();
        let method = &req_header.method;
        if ![Method::GET, Method::HEAD, METHOD_PURGE.to_owned()]
            .contains(method)
        {
            return Ok((false, None));
        }

        // Check if request matches skip pattern (if configured)
        if let Some(skip) = &self.skip {
            if let Some(value) = req_header.uri.path_and_query() {
                if skip.is_match(value.as_str()).unwrap_or_default() {
                    return Ok((false, None));
                }
            }
        }

        // Build cache key components including configured headers
        let mut keys = Vec::with_capacity(4);
        ctx.cache_namespace = self.namespace.clone();
        if let Some(headers) = &self.headers {
            for key in headers.iter() {
                let buf = session.get_header_bytes(key).to_str_lossy();
                if !buf.is_empty() {
                    keys.push(buf.to_string());
                }
            }
        }
        if !keys.is_empty() {
            debug!("Cache keys: {keys:?}");
            ctx.cache_keys = Some(keys);
        }

        // Handle PURGE requests with IP-based access control
        if method == METHOD_PURGE.to_owned() {
            let found = match self
                .purge_ip_rules
                .is_match(&pingap_core::get_client_ip(session))
            {
                Ok(matched) => matched,
                Err(e) => {
                    return Ok((
                        true,
                        Some(HttpResponse::bad_request(e.to_string().into())),
                    ));
                },
            };
            if !found {
                return Ok((
                    true,
                    Some(HttpResponse {
                        status: StatusCode::FORBIDDEN,
                        body: Bytes::from_static(
                            b"Forbidden, ip is not allowed",
                        ),
                        ..Default::default()
                    }),
                ));
            }

            let key = get_cache_key(
                ctx,
                Method::GET.as_ref(),
                &session.req_header().uri,
            );
            self.http_cache
                .cache
                .remove(&key.combined(), key.namespace())
                .await?;
            return Ok((true, Some(HttpResponse::no_content())));
        }

        // Configure cache settings for this request
        ctx.cache_max_ttl = self.max_ttl;
        ctx.check_cache_control = self.check_cache_control;

        // Enable caching for this session with configured components
        session.cache.enable(
            self.http_cache,
            self.eviction,
            self.predictor,
            self.lock,
        );

        // Set maximum cached file size if configured
        if self.max_file_size > 0 {
            session.cache.set_max_file_size_bytes(self.max_file_size);
        }

        // Track cache statistics if available
        if let Some(stats) = self.http_cache.stats() {
            ctx.cache_reading = Some(stats.reading);
            ctx.cache_writing = Some(stats.writing);
        }

        Ok((true, None))
    }
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("cache", |params| Ok(Arc::new(Cache::new(params)?)));
}

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
max_file_size = "100kb"
predictor = true
max_ttl = "1m"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(true, params.eviction.is_some());
        assert_eq!(
            r#"Some(["Accept-Encoding"])"#,
            format!("{:?}", params.headers)
        );
        assert_eq!(true, params.lock.is_some());
        assert_eq!(100 * 1000, params.max_file_size);
        assert_eq!(60, params.max_ttl.unwrap().as_secs());
        assert_eq!(true, params.predictor.is_some());
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
        assert_eq!("pingap", ctx.cache_namespace.unwrap());
        assert_eq!("gzip", ctx.cache_keys.unwrap().join(":"));
        assert_eq!(true, session.cache.enabled());
        assert_eq!(100 * 1000, cache.max_file_size);

        // purge
        let headers = ["Accept-Encoding: gzip", "X-Forwarded-For: 127.0.0.1"]
            .join("\r\n");
        let input_header = format!(
            "PURGE /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        cache
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
    }
}
