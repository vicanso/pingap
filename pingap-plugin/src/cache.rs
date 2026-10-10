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
use http::header::{CACHE_CONTROL, PRAGMA};
use http::{HeaderName, Method, StatusCode};
use humantime::parse_duration;
use pingap_cache::{HttpCache, new_cache_backend};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    CacheQueryRule, Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ensure_verified_client_ip, get_cache_key, normalize_path,
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
    /// How long a response stays fresh when the origin names no lifetime,
    /// in place of one second.
    default_ttl: Option<Duration>,
    /// The same for single statuses.
    status_ttl: Option<Arc<Vec<(u16, Duration)>>>,
    /// A request with one of these headers is neither answered from the
    /// cache nor stored.
    bypass_headers: Vec<HeaderName>,
    /// The same for a request with one of these cookies.
    bypass_cookies: Vec<String>,
    /// Which parameters of the query are a part of the cache key.
    query_rule: Option<Arc<CacheQueryRule>>,
    /// Whether a client may ask for what is cached to be checked with
    /// the origin first.
    respect_client_no_cache: bool,
    // Unique identifier for this cache configuration
    hash_value: String,
}

/// Whether the request carries a cookie of one of `names`.
///
/// Read from the bytes of the header. Through `to_str`, a `Cookie` header
/// with one byte that is not ASCII in it - a name in UTF-8, which
/// browsers send as it is - had no cookies at all, and the page of
/// whoever is logged in came from the cache, or went into it.
fn has_cookie(header: &pingora::http::RequestHeader, names: &[String]) -> bool {
    if names.is_empty() {
        return false;
    }
    header
        .headers
        .get_all(http::header::COOKIE)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b';'))
        .any(|pair| {
            let name = pair
                .split(|byte| *byte == b'=')
                .next()
                .unwrap_or(pair)
                .trim_ascii();
            names.iter().any(|wanted| wanted.as_bytes() == name)
        })
}

/// Whether the client asks for a copy that is not older than the origin's:
/// `Cache-Control: no-cache` or `max-age=0`, what a reload sends, or the
/// `Pragma: no-cache` of HTTP/1.0.
fn wants_fresh(header: &pingora::http::RequestHeader) -> bool {
    let named = |name: &HeaderName, wanted: &[&str]| {
        header
            .headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|directive| {
                let directive = directive.trim();
                wanted
                    .iter()
                    .any(|wanted| directive.eq_ignore_ascii_case(wanted))
            })
    };
    named(&CACHE_CONTROL, &["no-cache", "max-age=0"])
        || named(&PRAGMA, &["no-cache"])
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

        let invalid = |message: String| Error::Invalid {
            category: PluginCategory::Cache.to_string(),
            message,
        };
        let default_ttl = get_str_conf(value, "default_ttl");
        let default_ttl = if default_ttl.is_empty() {
            None
        } else {
            Some(
                parse_duration(&default_ttl)
                    .map_err(|e| invalid(format!("default_ttl: {e}")))?,
            )
        };
        let mut status_ttl: Vec<(u16, Duration)> = vec![];
        for item in get_str_slice_conf(value, "status_ttl").iter() {
            let entry = item
                .split_once(':')
                .and_then(|(status, ttl)| {
                    let status = status.trim().parse::<u16>().ok()?;
                    let ttl = parse_duration(ttl.trim()).ok()?;
                    (100..=599).contains(&status).then_some((status, ttl))
                })
                .ok_or_else(|| {
                    invalid(format!(
                        "status_ttl: {item:?} should be status:duration, like 404:10s"
                    ))
                })?;
            // The answer to a revalidation, which renews what was stored
            // as a 200 for as long as a 200 is kept: a lifetime given to
            // it here was never read.
            if entry.0 == 304 {
                return Err(invalid(
                    "status_ttl: 304 renews a stored 200 and has no lifetime of its own, set the one of 200"
                        .to_string(),
                ));
            }
            if status_ttl.iter().any(|(status, _)| *status == entry.0) {
                return Err(invalid(format!(
                    "status_ttl: {} is there twice",
                    entry.0
                )));
            }
            status_ttl.push(entry);
        }
        let bypass_headers = get_str_slice_conf(value, "bypass_headers")
            .iter()
            .map(|name| {
                HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| {
                    invalid(format!(
                        "bypass_headers: {name:?} is not a header name"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let names = |key: &str| -> Result<Vec<String>> {
            get_str_slice_conf(value, key)
                .into_iter()
                .map(|name| {
                    let name = name.trim().to_string();
                    if name.is_empty() {
                        return Err(invalid(format!(
                            "{key}: an entry is empty"
                        )));
                    }
                    Ok(name)
                })
                .collect()
        };
        let bypass_cookies = names("bypass_cookies")?;
        let query_rule = match (names("ignore_query")?, names("query_allow")?) {
            (ignore, allow) if !ignore.is_empty() && !allow.is_empty() => {
                return Err(invalid(
                    "ignore_query and query_allow can not both be set"
                        .to_string(),
                ));
            },
            (ignore, _) if !ignore.is_empty() => {
                Some(Arc::new(CacheQueryRule::Ignore(ignore)))
            },
            (_, allow) if !allow.is_empty() => {
                Some(Arc::new(CacheQueryRule::Allow(allow)))
            },
            _ => None,
        };

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
            default_ttl,
            status_ttl: (!status_ttl.is_empty()).then(|| Arc::new(status_ttl)),
            bypass_headers,
            bypass_cookies,
            query_rule,
            respect_client_no_cache: get_bool_conf(
                value,
                "respect_client_no_cache",
            ),
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

/// Whether `skip` takes the request out of the cache: by its path and
/// query as they were sent, or as the path is read.
///
/// The location a request goes to is chosen by the path with its dot
/// segments, doubled slashes and percent-encoding resolved
/// (`normalize_path`), and that is the path most upstreams answer for.
/// `skip` saw the path as it was sent and nothing else: with
/// `skip = "^/api/"`, written to keep what `/api/` answers out of the
/// cache, `//api/me`, `/./api/me` and `/%61pi/me` were all kept there.
///
/// A match of either takes it out. Skipping is the side that keeps
/// nothing, and a pattern written for the path as it is sent goes on
/// matching what it matched.
fn is_skipped(skip: &Regex, uri: &http::Uri) -> bool {
    let Some(sent) = uri.path_and_query() else {
        return false;
    };
    if skip.is_match(sent.as_str()).unwrap_or_default() {
        return true;
    }
    // Nearly every path is read as it is sent.
    let Cow::Owned(path) = normalize_path(uri.path()) else {
        return false;
    };
    let read = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    skip.is_match(&read).unwrap_or_default()
}

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
        let is_purge = method == *METHOD_PURGE;
        if ![&Method::GET, &Method::HEAD, &*METHOD_PURGE].contains(&method) {
            return Ok(RequestPluginResult::Skipped);
        }

        // Check if request matches skip pattern (if configured)
        if let Some(skip) = &self.skip
            && is_skipped(skip, &req_header.uri)
        {
            return Ok(RequestPluginResult::Skipped);
        }

        // A request that carries one of these is somebody's own: a
        // session cookie, a preview header. It is not answered with what
        // is cached and what it gets is not kept. A purge is about the
        // url, whoever sends it.
        if !is_purge
            && (self
                .bypass_headers
                .iter()
                .any(|name| req_header.headers.contains_key(name))
                || has_cookie(req_header, &self.bypass_cookies))
        {
            return Ok(RequestPluginResult::Skipped);
        }

        // Build cache key components including configured headers
        let mut keys = Vec::with_capacity(4);
        {
            // The rule the key takes its query by, in place of the query
            // as it came; a purge names the url the same way. The proxy
            // settles the query when it makes the key, once every request
            // plugin has run, and asks the upstream with the same
            // (`CacheInfo::settle_key_query`, `ask_with_key_query`). The
            // request itself stays as the client sent it, for the access
            // log and the plugins after this one.
            let cache_info = ctx.cache.get_or_insert_default();
            cache_info.namespace = self.namespace.clone();
            cache_info.query_rule = self.query_rule.clone();
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
        if is_purge {
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
        let revalidate =
            self.respect_client_no_cache && wants_fresh(session.req_header());
        if let Some(cache_info) = &mut ctx.cache {
            cache_info.max_ttl = self.max_ttl;
            cache_info.check_cache_control = self.check_cache_control;
            cache_info.vary_headers = self.vary_headers.clone();
            cache_info.default_ttl = self.default_ttl;
            cache_info.status_ttl = self.status_ttl.clone();
            cache_info.revalidate = revalidate;
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

    #[test]
    fn test_key_query() {
        let ignore = CacheQueryRule::Ignore(vec![
            "utm_source".to_string(),
            "fbclid".to_string(),
        ]);
        // In the order of the names, whatever order they came in.
        assert_eq!("a=1&b=2", ignore.key_query("b=2&a=1"));
        assert_eq!("a=1&b=2", ignore.key_query("a=1&b=2"));
        // What is ignored is gone, wherever it stands.
        assert_eq!(
            "a=1&b=2",
            ignore.key_query("utm_source=x&b=2&fbclid=y&a=1")
        );
        assert_eq!("", ignore.key_query("utm_source=x"));
        assert_eq!("", ignore.key_query(""));
        // The same name twice keeps its order: it may mean something.
        assert_eq!("a=1&id=2&id=1", ignore.key_query("id=2&id=1&a=1"));
        // A name is the whole name, and a parameter may have no value.
        assert_eq!(
            "debug&utm_source2=x",
            ignore.key_query("utm_source2=x&&debug")
        );

        let allow =
            CacheQueryRule::Allow(vec!["page".to_string(), "size".to_string()]);
        assert_eq!("page=2&size=10", allow.key_query("size=10&x=1&page=2"));
        assert_eq!("", allow.key_query("x=1&y=2"));
    }

    #[test]
    fn test_cache_control_params() {
        let new = |conf: &str| {
            Cache::try_from(&toml::from_str::<PluginConf>(conf).unwrap())
        };
        let cache = new(
            "default_ttl = \"30s\"\nstatus_ttl = [\"404:10s\", \" 301 : 1h \", \"500:0s\"]\nbypass_headers = [\"X-Preview\"]\nbypass_cookies = [\"session\"]\nignore_query = [\"utm_source\"]\nrespect_client_no_cache = true",
        )
        .unwrap();
        assert_eq!(Some(Duration::from_secs(30)), cache.default_ttl);
        assert_eq!(
            Some(Arc::new(vec![
                (404, Duration::from_secs(10)),
                (301, Duration::from_secs(3600)),
                (500, Duration::ZERO),
            ])),
            cache.status_ttl
        );
        assert_eq!(vec!["x-preview"], cache.bypass_headers);
        assert_eq!(vec!["session"], cache.bypass_cookies);
        assert_eq!(
            Some(Arc::new(CacheQueryRule::Ignore(vec![
                "utm_source".to_string()
            ]))),
            cache.query_rule
        );
        assert_eq!(true, cache.respect_client_no_cache);
        // None of it unless it is asked for.
        let plain = new("").unwrap();
        assert_eq!(None, plain.default_ttl);
        assert_eq!(None, plain.status_ttl);
        assert_eq!(None, plain.query_rule);
        assert_eq!(false, plain.respect_client_no_cache);

        let error = |conf: &str| new(conf).err().unwrap().to_string();
        let prefix = "Plugin cache invalid, message: ";
        for (conf, message) in [
            (
                "status_ttl = [\"404\"]",
                r#"status_ttl: "404" should be status:duration, like 404:10s"#,
            ),
            (
                "status_ttl = [\"abc:10s\"]",
                r#"status_ttl: "abc:10s" should be status:duration, like 404:10s"#,
            ),
            (
                "status_ttl = [\"99:10s\"]",
                r#"status_ttl: "99:10s" should be status:duration, like 404:10s"#,
            ),
            (
                "status_ttl = [\"404:soon\"]",
                r#"status_ttl: "404:soon" should be status:duration, like 404:10s"#,
            ),
            (
                "status_ttl = [\"404:1s\", \"404:2s\"]",
                "status_ttl: 404 is there twice",
            ),
            (
                "status_ttl = [\"304:1m\"]",
                "status_ttl: 304 renews a stored 200 and has no lifetime of its own, set the one of 200",
            ),
            (
                "bypass_headers = [\"X Preview\"]",
                r#"bypass_headers: "X Preview" is not a header name"#,
            ),
            (
                "bypass_cookies = [\" \"]",
                "bypass_cookies: an entry is empty",
            ),
            (
                "ignore_query = [\"a\"]\nquery_allow = [\"b\"]",
                "ignore_query and query_allow can not both be set",
            ),
        ] {
            assert_eq!(format!("{prefix}{message}"), error(conf), "{conf}");
        }
        assert_eq!(
            true,
            error("default_ttl = \"soon\"")
                .starts_with(&format!("{prefix}default_ttl: "))
        );
    }

    /// Regression: the query of the key was taken when the cache plugin
    /// ran, and the upstream asked with it. A `key_auth` listed after the
    /// cache takes its credential out of the query (`hide_credentials`)
    /// - and the upstream got it all the same, and each holder of a key
    /// an entry of their own.
    #[tokio::test]
    async fn test_key_query_is_of_the_request_the_plugins_leave() {
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>("ignore_query = [\"utm_source\"]")
                .unwrap(),
        )
        .unwrap();
        let auth = crate::key_auth::KeyAuth::new(
            &toml::from_str::<PluginConf>(
                "query = \"apikey\"\nkeys = [\"S\"]\nhide_credentials = true",
            )
            .unwrap(),
        )
        .unwrap();
        let mock_io = Builder::new()
            .read(b"GET /x?apikey=S&utm_source=mail&a=1 HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        for plugin in [&cache as &dyn Plugin, &auth] {
            let result = plugin
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();
            assert_eq!(true, result == RequestPluginResult::Continue);
        }
        // What the proxy does from here: the key, then the upstream.
        let info = ctx.cache.as_mut().unwrap();
        info.settle_key_query(session.req_header());
        let mut upstream_request = session.req_header().clone();
        assert_eq!(true, info.ask_with_key_query(&mut upstream_request));
        assert_eq!("/x?a=1", upstream_request.uri.to_string());
        let key = pingap_core::get_cache_key(&ctx, "GET", session.req_header());
        assert_eq!(Some("GET:/x?a=1"), key.primary_key_str());
    }

    /// What the plugin tells the proxy about a request: whether the cache
    /// is asked at all, what the key is made of, and whether the client
    /// gets its copy checked.
    #[tokio::test]
    async fn test_cache_control_of_a_request() {
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>(
                "bypass_headers = [\"X-Preview\"]\nbypass_cookies = [\"session\"]\nignore_query = [\"utm_source\"]\nrespect_client_no_cache = true\ndefault_ttl = \"30s\"",
            )
            .unwrap(),
        )
        .unwrap();
        let handle = async |cache: &Cache, target: &str, headers: &str| {
            let input = format!("GET {target} HTTP/1.1\r\n{headers}\r\n");
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            let result = cache
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();
            // As the proxy does when it makes the key.
            if let Some(info) = ctx.cache.as_mut() {
                info.settle_key_query(session.req_header());
            }
            let key =
                pingap_core::get_cache_key(&ctx, "GET", session.req_header());
            // What the upstream is asked with, which the proxy makes of
            // the request once it goes there, and the request itself.
            let mut upstream_request = session.req_header().clone();
            if let Some(info) = &ctx.cache {
                assert_eq!(
                    true,
                    info.ask_with_key_query(&mut upstream_request)
                );
            }
            let sent = upstream_request.uri.to_string();
            let asked = session.req_header().uri.to_string();
            (
                result == RequestPluginResult::Continue
                    && session.cache.enabled(),
                key.primary_key_str().unwrap_or_default().to_string(),
                ctx.cache.unwrap_or_default(),
                (sent, asked),
            )
        };

        // The key has the parameters in order and none that is ignored,
        // and the upstream is asked with the same.
        let (cached, key, info, (sent, asked)) =
            handle(&cache, "/list?b=2&utm_source=mail&a=1", "").await;
        assert_eq!(true, cached);
        assert_eq!("GET:/list?a=1&b=2", key);
        assert_eq!("/list?a=1&b=2", sent);
        // The request is left as the client sent it: that is what the
        // access log and the plugins after this one see.
        assert_eq!("/list?b=2&utm_source=mail&a=1", asked);
        assert_eq!(Some(Duration::from_secs(30)), info.default_ttl);
        assert_eq!(false, info.revalidate);
        let (_, same, _, (sent, asked)) =
            handle(&cache, "/list?a=1&b=2", "").await;
        assert_eq!(key, same);
        // As it came: nothing to put in its place.
        assert_eq!(("/list?a=1&b=2", "/list?a=1&b=2"), (&*sent, &*asked));
        // Nothing left of the query is no query.
        let (_, bare, _, (sent, _)) =
            handle(&cache, "/list?utm_source=mail", "").await;
        assert_eq!("GET:/list", bare);
        assert_eq!("/list", sent);

        // Regression: the key was made of the parameters the rule names
        // and the upstream was asked with all of them. Spelled so that
        // the rule does not know it and the upstream does, a parameter
        // was out of the key and in the response: page 2, stored as the
        // page without a number.
        let allow = Cache::try_from(
            &toml::from_str::<PluginConf>("query_allow = [\"page\"]").unwrap(),
        )
        .unwrap();
        for target in [
            "/list?p%61ge=2",
            "/list?Page=2",
            "/list?x=1;page=2",
            "/list?x=1&p%61ge=2",
        ] {
            let (_, key, _, (sent, _)) = handle(&allow, target, "").await;
            assert_eq!(
                ("GET:/list", "/list"),
                (key.as_str(), sent.as_str()),
                "{target}"
            );
        }
        let (_, key, _, (sent, _)) =
            handle(&allow, "/list?x=1&page=2", "").await;
        assert_eq!(
            ("GET:/list?page=2", "/list?page=2"),
            (key.as_str(), sent.as_str())
        );
        // The same with a list of what is left out: what hides behind
        // the name of a parameter that is ignored goes with it.
        let (_, key, _, (sent, _)) =
            handle(&cache, "/list?utm_source=x;page=2&a=1", "").await;
        assert_eq!(
            ("GET:/list?a=1", "/list?a=1"),
            (key.as_str(), sent.as_str())
        );

        // Somebody's own request: the cache is not asked. Also with a
        // cookie next to it that is not ASCII, which browsers send as it
        // is and which used to hide every cookie of the header.
        for headers in [
            "X-Preview: 1\r\n",
            "Cookie: theme=dark; session=abc\r\n",
            "Cookie: session=abc\r\n",
            "Cookie: name=张三; session=abc\r\n",
            "Cookie: theme=dark\r\nCookie: session=abc\r\n",
        ] {
            let (cached, ..) = handle(&cache, "/list", headers).await;
            assert_eq!(false, cached, "{headers}");
        }
        // Another cookie is not, nor one that only starts or ends the
        // same.
        for headers in [
            "Cookie: theme=dark\r\n",
            "Cookie: session2=abc; my_session=abc\r\n",
            "Cookie: name=session\r\n",
        ] {
            let (cached, ..) = handle(&cache, "/list", headers).await;
            assert_eq!(true, cached, "{headers}");
        }

        // A reload asks for a checked copy, and gets one where the plugin
        // says clients may.
        for headers in [
            "Cache-Control: no-cache\r\n",
            "Cache-Control: max-age=0\r\n",
            "Cache-Control: no-store, No-Cache\r\n",
            "Pragma: no-cache\r\n",
        ] {
            let (cached, _, info, _) = handle(&cache, "/list", headers).await;
            assert_eq!(true, cached, "{headers}");
            assert_eq!(true, info.revalidate, "{headers}");
        }
        let (_, _, info, _) =
            handle(&cache, "/list", "Cache-Control: max-age=60\r\n").await;
        assert_eq!(false, info.revalidate);

        // Without the options the key is the query as it came, and a
        // client's `no-cache` is not gone by.
        let plain = Cache::try_from(&toml::from_str::<PluginConf>("").unwrap())
            .unwrap();
        let (cached, key, info, (sent, asked)) = handle(
            &plain,
            "/list?b=2&a=1",
            "Cache-Control: no-cache\r\nCookie: session=abc\r\n",
        )
        .await;
        assert_eq!(true, cached);
        assert_eq!("GET:/list?b=2&a=1", key);
        assert_eq!(("/list?b=2&a=1", "/list?b=2&a=1"), (&*sent, &*asked));
        assert_eq!(false, info.revalidate);
        assert_eq!(None, info.key_query);
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

    /// Regression: `skip` was matched against the path as it was sent,
    /// while the location - and the upstream - go by the path as it is
    /// read. Whatever `skip = "^/api/"` was to keep out of the cache got
    /// in with a second slash in front of it.
    #[tokio::test]
    async fn test_skip_goes_by_the_path_as_it_is_read_too() {
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>(
                "skip = \"^/api/|[?&]preview=\"\nmax_ttl = \"1m\"\n",
            )
            .unwrap(),
        )
        .unwrap();
        let skipped = async |path: &str| {
            let input_header = format!("GET {path} HTTP/1.1\r\n\r\n");
            let mock_io = Builder::new().read(input_header.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let result = cache
                .handle_request(
                    PluginStep::Request,
                    &mut session,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            assert_eq!(
                matches!(result, RequestPluginResult::Skipped),
                !session.cache.enabled(),
                "{path}"
            );
            !session.cache.enabled()
        };
        for path in [
            "/api/me",
            "//api/me",
            "/./api/me",
            "/x/../api/me",
            "/%61pi/me",
            "/api//me?a=1",
            // The query is a part of what is matched, as it is sent.
            "/page?preview=1",
            "//page?a=1&preview=1",
        ] {
            assert_eq!(true, skipped(path).await, "{path}");
        }
        for path in ["/page", "//page", "/apis/me", "/x/api/me", "/page?a=1"] {
            assert_eq!(false, skipped(path).await, "{path}");
        }

        // What a pattern matches of the path as it is sent, it still does.
        let pattern = Regex::new("^//internal/|%2e").unwrap();
        for (path, expected) in [
            ("//internal/x", true),
            ("/internal/x", false),
            ("/a/%2e%2e/b", true),
            ("/b", false),
        ] {
            let uri: http::Uri = path.parse().unwrap();
            assert_eq!(expected, is_skipped(&pattern, &uri), "{path}");
        }
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
