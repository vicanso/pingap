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

#[cfg(feature = "tracing")]
use super::tracing::{
    initialize_telemetry, inject_telemetry_headers, set_otel_request_attrs,
    set_otel_upstream_attrs, update_otel_cache_attrs,
};
use super::{set_append_proxy_headers, ServerConf, LOG_CATEGORY};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use once_cell::sync::Lazy;
use pingap_acme::handle_lets_encrypt;
use pingap_certificate::{GlobalCertificate, TlsSettingParams};
use pingap_config::get_config_storage;
use pingap_core::BackgroundTask;
use pingap_core::PluginProvider;
use pingap_core::{
    get_cache_key, CompressionStat, Ctx, PluginStep, RequestPluginResult,
    ResponseBodyPluginResult, ResponsePluginResult,
};
use pingap_core::{
    get_digest_detail, HttpResponse, HTTP_HEADER_NAME_X_REQUEST_ID,
};
use pingap_core::{new_internal_error, Plugin};
use pingap_location::{Location, LocationProvider};
use pingap_logger::Parser;
#[cfg(feature = "tracing")]
use pingap_otel::{trace::Span, KeyValue};
use pingap_performance::{accept_request, end_request};
#[cfg(feature = "tracing")]
use pingap_performance::{
    new_prometheus, new_prometheus_push_service, Prometheus,
};
use pingap_upstream::{Upstream, UpstreamProvider};
use pingora::apps::HttpServerOptions;
use pingora::cache::cache_control::DirectiveValue;
use pingora::cache::cache_control::{CacheControl, InterpretCacheControl};
use pingora::cache::filters::resp_cacheable;
use pingora::cache::key::CacheHashKey;
use pingora::cache::{
    CacheKey, CacheMetaDefaults, NoCacheReason, RespCacheable,
};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::listeners::TcpSocketOptions;
use pingora::modules::http::compression::{
    ResponseCompression, ResponseCompressionBuilder,
};
use pingora::modules::http::grpc_web::{GrpcWeb, GrpcWebBridge};
use pingora::modules::http::HttpModules;
use pingora::protocols::http::error_resp;
use pingora::protocols::Digest;
use pingora::proxy::{http_proxy_service, FailToProxy, HttpProxy};
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::configuration;
use pingora::services::listening::Service;
use pingora::upstreams::peer::{HttpPeer, Peer};
use scopeguard::defer;
use snafu::Snafu;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Common error, category: {category}, {message}"))]
    Common { category: String, message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

/// Represents a mapping of server names to their location configurations.
/// This allows efficient lookup of location settings for each virtual host/server.
type ServerLocations = AHashMap<String, Arc<Vec<String>>>;

/// Global static map storing server location configurations.
/// Uses ArcSwap for thread-safe atomic updates without locking.
static SERVER_LOCATIONS_MAP: Lazy<ArcSwap<ServerLocations>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

/// Initializes server locations with their associated configurations.
/// - Orders locations by weight to determine processing priority
/// - Updates only modified server configurations
/// - Returns list of updated server names
pub fn try_init_server_locations(
    servers: &HashMap<String, pingap_config::ServerConf>,
    locations: &HashMap<String, pingap_config::LocationConf>,
) -> Result<Vec<String>> {
    // get the location weight
    let mut location_weights = HashMap::new();
    for (name, item) in locations.iter() {
        location_weights.insert(name.to_string(), item.get_weight());
    }
    let mut server_locations = AHashMap::new();
    let mut updated_servers = vec![];
    for (name, server) in servers.iter() {
        if let Some(items) = &server.locations {
            let mut items = items.clone();
            // sort the location by weight
            items.sort_by_key(|item| {
                let weight = location_weights
                    .get(item.as_str())
                    .map(|value| value.to_owned())
                    .unwrap_or_default();
                std::cmp::Reverse(weight)
            });
            let mut not_modified = false;
            if let Some(current_locations) = get_server_locations(name) {
                if current_locations.join(",") == items.join(",") {
                    not_modified = true;
                }
            }
            if !not_modified {
                updated_servers.push(name.to_string());
            }

            server_locations.insert(name.to_string(), Arc::new(items));
        }
    }
    SERVER_LOCATIONS_MAP.store(Arc::new(server_locations));
    Ok(updated_servers)
}

#[inline]
fn get_server_locations(name: &str) -> Option<Arc<Vec<String>>> {
    SERVER_LOCATIONS_MAP.load().get(name).cloned()
}

#[inline]
pub fn get_start_time(started_at: &Instant) -> i32 {
    // the offset of start time
    let value = started_at.elapsed().as_millis() as i32;
    if value == 0 {
        return -1;
    }
    -value
}

#[inline]
pub fn get_latency(started_at: &Instant, value: &Option<i32>) -> Option<i32> {
    let Some(value) = value else {
        return None;
    };
    if *value >= 0 {
        return None;
    }
    let latency = started_at.elapsed().as_millis() as i32 + *value;

    Some(latency)
}

/// Core HTTP proxy server implementation that handles request processing, caching, and monitoring.
/// Manages server configuration, connection lifecycle, and integration with various modules.
pub struct Server {
    /// Server name identifier used for logging and metrics
    name: String,

    /// Whether this instance serves admin endpoints and functionality
    admin: bool,

    /// Comma-separated list of listening addresses (e.g. "127.0.0.1:8080,127.0.0.1:8081")
    addr: String,

    /// Counter tracking total number of accepted connections since server start
    accepted: AtomicU64,

    /// Counter tracking number of currently active request processing operations
    processing: AtomicI32,

    /// Optional parser for customizing access log format and output
    log_parser: Option<Parser>,

    /// HTML/JSON template used for rendering error responses
    error_template: String,

    /// Number of worker threads for request processing. None uses default.
    threads: Option<usize>,

    /// OpenSSL cipher list string for TLS connections
    tls_cipher_list: Option<String>,

    /// TLS 1.3 cipher suites configuration
    tls_ciphersuites: Option<String>,

    /// Minimum TLS protocol version to accept (e.g. "TLSv1.2")
    tls_min_version: Option<String>,

    /// Maximum TLS protocol version to accept
    tls_max_version: Option<String>,

    /// Whether HTTP/2 protocol is enabled
    enabled_h2: bool,

    /// Whether Let's Encrypt certificate automation is enabled
    lets_encrypt_enabled: bool,

    /// Whether to use global certificate store for TLS
    global_certificates: bool,

    /// TCP socket configuration options (keepalive, TCP fastopen etc)
    tcp_socket_options: Option<TcpSocketOptions>,

    /// Prometheus metrics registry when metrics collection is enabled
    #[cfg(feature = "tracing")]
    prometheus: Option<Arc<Prometheus>>,

    /// Whether to push metrics to remote Prometheus pushgateway
    prometheus_push_mode: bool,

    /// Prometheus metrics endpoint path or push gateway URL
    #[cfg(feature = "tracing")]
    prometheus_metrics: String,

    /// Whether OpenTelemetry tracing is enabled
    #[cfg(feature = "tracing")]
    enabled_otel: bool,

    /// List of enabled modules (e.g. "grpc-web")
    modules: Option<Vec<String>>,

    /// Whether to enable server-timing header
    enable_server_timing: bool,

    // downstream read timeout
    downstream_read_timeout: Option<Duration>,
    // downstream write timeout
    downstream_write_timeout: Option<Duration>,

    // plugin loader
    plugin_provider: Arc<dyn PluginProvider>,

    // locations
    location_provider: Arc<dyn LocationProvider>,

    // upstreams
    upstream_provider: Arc<dyn UpstreamProvider>,
}

pub struct ServerServices {
    pub lb: Service<HttpProxy<Server>>,
}

const META_DEFAULTS: CacheMetaDefaults =
    CacheMetaDefaults::new(|_| Some(Duration::from_secs(1)), 1, 1);

static HTTP_500_RESPONSE: Lazy<ResponseHeader> =
    Lazy::new(|| error_resp::gen_error_response(500));

impl Server {
    /// Creates a new HTTP proxy server instance with the given configuration.
    /// Initializes all server components including:
    /// - TCP socket options
    /// - TLS settings
    /// - Prometheus metrics (if enabled)
    /// - Threading configuration
    pub fn new(
        conf: &ServerConf,
        location_provider: Arc<dyn LocationProvider>,
        upstream_provider: Arc<dyn UpstreamProvider>,
        plugin_provider: Arc<dyn PluginProvider>,
    ) -> Result<Self> {
        debug!(
            category = LOG_CATEGORY,
            config = conf.to_string(),
            "new server"
        );
        let mut p = None;
        let access_log = conf.access_log.clone().unwrap_or_default();
        if !access_log.is_empty() {
            p = Some(Parser::from(access_log.as_str()));
        }
        let tcp_socket_options = if conf.tcp_fastopen.is_some()
            || conf.tcp_keepalive.is_some()
            || conf.reuse_port.is_some()
        {
            let mut opts = TcpSocketOptions::default();
            opts.tcp_fastopen = conf.tcp_fastopen;
            opts.tcp_keepalive.clone_from(&conf.tcp_keepalive);
            opts.so_reuseport = conf.reuse_port;
            Some(opts)
        } else {
            None
        };
        let prometheus_metrics =
            conf.prometheus_metrics.clone().unwrap_or_default();
        #[cfg(feature = "tracing")]
        let prometheus = if prometheus_metrics.is_empty() {
            None
        } else {
            let p = new_prometheus(&conf.name).map_err(|e| Error::Common {
                category: "prometheus".to_string(),
                message: e.to_string(),
            })?;
            Some(Arc::new(p))
        };
        let s = Server {
            name: conf.name.clone(),
            admin: conf.admin,
            accepted: AtomicU64::new(0),
            processing: AtomicI32::new(0),
            addr: conf.addr.clone(),
            log_parser: p,
            error_template: conf.error_template.clone(),
            tls_cipher_list: conf.tls_cipher_list.clone(),
            tls_ciphersuites: conf.tls_ciphersuites.clone(),
            tls_min_version: conf.tls_min_version.clone(),
            tls_max_version: conf.tls_max_version.clone(),
            threads: conf.threads,
            lets_encrypt_enabled: false,
            global_certificates: conf.global_certificates,
            enabled_h2: conf.enabled_h2,
            tcp_socket_options,
            prometheus_push_mode: prometheus_metrics.contains("://"),
            #[cfg(feature = "tracing")]
            enabled_otel: conf.otlp_exporter.is_some(),
            #[cfg(feature = "tracing")]
            prometheus_metrics,
            #[cfg(feature = "tracing")]
            prometheus,
            enable_server_timing: conf.enable_server_timing,
            modules: conf.modules.clone(),
            downstream_read_timeout: conf.downstream_read_timeout,
            downstream_write_timeout: conf.downstream_write_timeout,
            location_provider,
            upstream_provider,
            plugin_provider,
        };
        Ok(s)
    }
    /// Enable lets encrypt proxy plugin for handling ACME challenges at
    /// `/.well-known/acme-challenge` path
    pub fn enable_lets_encrypt(&mut self) {
        self.lets_encrypt_enabled = true;
    }
    /// Get the prometheus push service configuration if enabled.
    /// Returns a tuple of (metrics endpoint, service future) if push mode is configured.
    pub fn get_prometheus_push_service(
        &self,
    ) -> Option<Box<dyn BackgroundTask>> {
        if !self.prometheus_push_mode {
            return None;
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "tracing")] {
                let Some(prometheus) = &self.prometheus else {
                    return None;
                };
                match new_prometheus_push_service(
                    &self.name,
                    &self.prometheus_metrics,
                    prometheus.clone(),
                ) {
                    Ok(service) => Some(service),
                    Err(e) => {
                        error!(
                            category = LOG_CATEGORY,
                            error = %e,
                            name = self.name,
                            "new prometheus push service fail"
                        );
                        None
                    },
                }
            } else {
               None
            }
        }
    }

    /// Starts the server and sets up TCP/TLS listening endpoints.
    /// - Configures listeners for each address
    /// - Sets up TLS if enabled
    /// - Initializes HTTP/2 support
    /// - Configures thread pool
    pub fn run(
        self,
        conf: &Arc<configuration::ServerConf>,
    ) -> Result<ServerServices> {
        let addr = self.addr.clone();
        let tcp_socket_options = self.tcp_socket_options.clone();

        let name = self.name.clone();
        let mut dynamic_cert = None;
        // tls
        if self.global_certificates {
            dynamic_cert = Some(GlobalCertificate::default());
        }

        let is_tls = dynamic_cert.is_some();

        let enabled_h2 = self.enabled_h2;
        let threads = if let Some(threads) = self.threads {
            // use cpus when set threads:0
            let value = if threads == 0 {
                num_cpus::get()
            } else {
                threads
            };
            Some(value)
        } else {
            None
        };

        info!(
            category = LOG_CATEGORY,
            name,
            addr,
            threads,
            is_tls,
            h2 = enabled_h2,
            tcp_socket_options = format!("{:?}", tcp_socket_options),
            "server is listening"
        );
        let cipher_list = self.tls_cipher_list.clone();
        let cipher_suites = self.tls_ciphersuites.clone();
        let tls_min_version = self.tls_min_version.clone();
        let tls_max_version = self.tls_max_version.clone();
        let mut lb = http_proxy_service(conf, self);
        // use h2c if not tls and enable http2
        if !is_tls && enabled_h2 {
            if let Some(http_logic) = lb.app_logic_mut() {
                let mut http_server_options = HttpServerOptions::default();
                http_server_options.h2c = true;
                http_logic.server_options = Some(http_server_options);
            }
        }
        lb.threads = threads;
        // support listen multi address
        for addr in addr.split(',') {
            // tls
            if let Some(dynamic_cert) = &dynamic_cert {
                let tls_settings = dynamic_cert
                    .new_tls_settings(&TlsSettingParams {
                        server_name: name.clone(),
                        enabled_h2,
                        cipher_list: cipher_list.clone(),
                        cipher_suites: cipher_suites.clone(),
                        tls_min_version: tls_min_version.clone(),
                        tls_max_version: tls_max_version.clone(),
                    })
                    .map_err(|e| Error::Common {
                        category: "tls".to_string(),
                        message: e.to_string(),
                    })?;
                lb.add_tls_with_settings(
                    addr,
                    tcp_socket_options.clone(),
                    tls_settings,
                );
            } else if let Some(opt) = &tcp_socket_options {
                lb.add_tcp_with_settings(addr, opt.clone());
            } else {
                lb.add_tcp(addr);
            }
        }
        Ok(ServerServices { lb })
    }
    /// Handles requests to the admin interface.
    /// Processes admin-specific plugins and returns response if handled.
    async fn serve_admin(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<bool> {
        if let Some(plugin) = self.plugin_provider.get("pingap:admin") {
            let result = plugin
                .handle_request(PluginStep::Request, session, ctx)
                .await?;
            if let RequestPluginResult::Respond(resp) = result {
                ctx.state.status = Some(resp.status);
                resp.send(session).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    #[inline]
    fn initialize_context(&self, session: &mut Session, ctx: &mut Ctx) {
        session.set_read_timeout(self.downstream_read_timeout);
        session.set_write_timeout(self.downstream_write_timeout);

        if let Some(stream) = session.stream() {
            ctx.conn.id = stream.id() as usize;
        }
        // get digest of timing and tls
        if let Some(digest) = session.digest() {
            let digest_detail = get_digest_detail(digest);
            ctx.timing.connection_duration = digest_detail.connection_time;
            ctx.conn.reused = digest_detail.connection_reused;

            if !ctx.conn.reused
                && digest_detail.tls_established
                    >= digest_detail.tcp_established
            {
                let latency = digest_detail.tls_established
                    - digest_detail.tcp_established;
                ctx.timing.tls_handshake = Some(latency as i32);
            }
            ctx.conn.tls_cipher = digest_detail.tls_cipher;
            ctx.conn.tls_version = digest_detail.tls_version;
        };
        accept_request();

        ctx.state.processing_count =
            self.processing.fetch_add(1, Ordering::Relaxed) + 1;
        ctx.state.accepted_count =
            self.accepted.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some((remote_addr, remote_port)) =
            pingap_core::get_remote_addr(session)
        {
            ctx.conn.remote_addr = Some(remote_addr);
            ctx.conn.remote_port = Some(remote_port);
        }
        if let Some(addr) =
            session.server_addr().and_then(|addr| addr.as_inet())
        {
            ctx.conn.server_addr = Some(addr.ip().to_string());
            ctx.conn.server_port = Some(addr.port());
        }
    }

    #[inline]
    async fn find_and_apply_location(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        let header = session.req_header();
        let host = pingap_core::get_host(header).unwrap_or_default();
        let path = header.uri.path();

        // locations not found
        let Some(locations) = get_server_locations(&self.name) else {
            return Ok(());
        };

        // use find_map to optimize logic, performance and readability
        let matched_info = locations.iter().find_map(|name| {
            let location = self.location_provider.get(name)?;
            let (matched, captures) = location.match_host_path(host, path);
            if matched {
                Some((location, captures))
            } else {
                None
            }
        });

        let Some((location, captures)) = matched_info else {
            return Ok(());
        };

        // only execute all subsequent operations after successtracingy matching location
        ctx.upstream.location = location.name.clone();
        if let Some(captures) = captures {
            ctx.extend_variables(captures);
        }

        debug!(
            category = LOG_CATEGORY,
            "variables: {:?}",
            ctx.features.as_ref().map(|item| &item.variables)
        );

        // set prometheus stats
        #[cfg(feature = "tracing")]
        if let Some(prom) = &self.prometheus {
            prom.before(&ctx.upstream.location);
        }

        // validate content length
        location
            .validate_content_length(header)
            .map_err(|e| new_internal_error(413, e))?;

        // limit processing
        let (accepted, processing) = location
            .add_processing()
            .map_err(|e| new_internal_error(429, e))?;
        ctx.state.location_accepted_count = accepted;
        ctx.state.location_processing_count = processing;

        // initialize gRPC Web
        if location.support_grpc_web() {
            let grpc_web = session
                .downstream_modules_ctx
                .get_mut::<GrpcWebBridge>()
                .ok_or_else(|| {
                    new_internal_error(
                        500,
                        "grpc web bridge module should be added",
                    )
                })?;
            grpc_web.init();
        }

        // initialize plugins and execute
        ctx.plugins = self.get_context_plugins(location.clone(), session);
        let _ = self
            .handle_request_plugin(PluginStep::EarlyRequest, session, ctx)
            .await?;

        Ok(())
    }

    #[inline]
    async fn handle_admin_request(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> Option<pingora::Result<bool>> {
        if self.admin {
            match self.serve_admin(session, ctx).await {
                Ok(true) => return Some(Ok(true)), // handled
                Ok(false) => {}, // not admin request, continue
                Err(e) => return Some(Err(e)), // error
            }
        }
        None // not admin service, continue
    }
    #[inline]
    async fn handle_acme_challenge(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> Option<pingora::Result<bool>> {
        if self.lets_encrypt_enabled {
            let storage = match get_config_storage() {
                Some(s) => s,
                None => {
                    return Some(Err(new_internal_error(
                        500,
                        "get config storage fail".to_string(),
                    )));
                },
            };

            return match handle_lets_encrypt(storage, session, ctx).await {
                Ok(true) => Some(Ok(true)),   // 已处理 ACME 请求
                Ok(false) => Some(Ok(false)), // 明确表示未处理，进入标准流程（虽然通常ACME处理后会是true）
                Err(e) => Some(Err(e)),
            };
        }
        None // 未启用 Let's Encrypt，继续
    }
    #[inline]
    #[cfg(feature = "tracing")]
    async fn handle_metrics_request(
        &self,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> Option<pingora::Result<bool>> {
        let header = session.req_header();
        let should_handle = !self.prometheus_push_mode
            && self.prometheus.is_some()
            && header.uri.path() == self.prometheus_metrics;

        if should_handle {
            let prom = self.prometheus.as_ref().unwrap(); // is_some() 检查已通过
            let result = async {
                let body =
                    prom.metrics().map_err(|e| new_internal_error(500, e))?;
                HttpResponse::text(body).send(session).await?;
                Ok(true)
            }
            .await;
            return Some(result);
        }
        None
    }
    #[inline]
    async fn handle_standard_request(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<bool> {
        let Some(location) = self.location_provider.get(&ctx.upstream.location)
        else {
            let header = session.req_header();
            let host = pingap_core::get_host(header).unwrap_or_default();
            let body = Bytes::from(format!(
                "Location not found, host:{host} path:{}",
                header.uri.path()
            ));
            HttpResponse::unknown_error(body).send(session).await?;
            return Ok(true);
        };

        debug!(
            category = LOG_CATEGORY,
            server = self.name,
            location = location.name,
            "location is matched"
        );

        let variables =
            ctx.features.as_ref().and_then(|f| f.variables.as_ref());
        location.rewrite(session.req_header_mut(), variables);

        if self
            .handle_request_plugin(PluginStep::Request, session, ctx)
            .await?
        {
            return Ok(true);
        }

        Ok(false)
    }
}

const MODULE_GRPC_WEB: &str = "grpc-web";

impl Server {
    #[inline]
    fn get_context_plugins(
        &self,
        location: Arc<Location>,
        session: &Session,
    ) -> Option<Vec<(String, Arc<dyn Plugin>)>> {
        if session.is_upgrade_req() {
            return None;
        }
        let plugins = location.plugins.as_ref()?;

        let location_plugins: Vec<_> = plugins
            .iter()
            .filter_map(|name| {
                self.plugin_provider
                    .get(name)
                    .map(|plugin| (name.clone(), plugin))
            })
            .collect();

        // use then_some to handle empty collection
        (!location_plugins.is_empty()).then_some(location_plugins)
    }

    /// Executes request plugins in the configured chain
    /// Returns true if a plugin handled the request completely
    #[inline]
    pub async fn handle_request_plugin(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<bool> {
        let plugins = match ctx.plugins.take() {
            Some(p) => p,
            None => return Ok(false), // No plugins, exit early.
        };
        if plugins.is_empty() {
            return Ok(false);
        }

        let result = async {
            let mut request_done = false;
            for (name, plugin) in plugins.iter() {
                let now = Instant::now();
                let result = plugin.handle_request(step, session, ctx).await?;
                let elapsed = now.elapsed().as_millis() as u32;

                // extract repeated logging and timing logic
                let mut record_time = |msg: &str| {
                    debug!(
                        category = LOG_CATEGORY,
                        name,
                        elapsed,
                        step = step.to_string(),
                        "{msg}"
                    );
                    ctx.add_plugin_processing_time(name, elapsed);
                };

                match result {
                    RequestPluginResult::Skipped => {
                        continue;
                    },
                    RequestPluginResult::Respond(resp) => {
                        record_time("request plugin create new response");
                        // ignore status >= 900
                        if resp.status.as_u16() < 900 {
                            ctx.state.status = Some(resp.status);
                            resp.send(session).await?;
                        }
                        request_done = true;
                        break;
                    },
                    RequestPluginResult::Continue => {
                        record_time("request plugin run and continue request");
                    },
                }
            }
            Ok(request_done)
        }
        .await;
        ctx.plugins = Some(plugins);
        result
    }

    /// Run response plugins
    #[inline]
    pub async fn handle_response_plugin(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<()> {
        let plugins = match ctx.plugins.take() {
            Some(p) => p,
            None => return Ok(()), // No plugins, exit early.
        };
        if plugins.is_empty() {
            return Ok(());
        }

        let result = async {
            for (name, plugin) in plugins.iter() {
                let now = Instant::now();
                if let ResponsePluginResult::Modified = plugin
                    .handle_response(session, ctx, upstream_response)
                    .await?
                {
                    let elapsed = now.elapsed().as_millis() as u32;
                    debug!(
                        category = LOG_CATEGORY,
                        name, elapsed, "response plugin modify headers"
                    );
                    ctx.add_plugin_processing_time(name, elapsed);
                };
            }
            Ok(())
        }
        .await;
        ctx.plugins = Some(plugins);
        result
    }

    #[inline]
    pub fn handle_upstream_response_plugin(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<()> {
        let plugins = match ctx.plugins.take() {
            Some(p) => p,
            None => return Ok(()), // No plugins, exit early.
        };
        if plugins.is_empty() {
            return Ok(());
        }

        let result = {
            for (name, plugin) in plugins.iter() {
                let now = Instant::now();
                if let ResponsePluginResult::Modified = plugin
                    .handle_upstream_response(session, ctx, upstream_response)?
                {
                    let elapsed = now.elapsed().as_millis() as u32;
                    debug!(
                        category = LOG_CATEGORY,
                        name,
                        elapsed,
                        "upstream response plugin modify headers"
                    );
                    ctx.add_plugin_processing_time(name, elapsed);
                };
            }
            Ok(())
        };
        ctx.plugins = Some(plugins);
        result
    }

    #[inline]
    pub fn handle_upstream_response_body_plugin(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        let plugins = match ctx.plugins.take() {
            Some(p) => p,
            None => return Ok(()), // No plugins, exit early.
        };
        if plugins.is_empty() {
            return Ok(());
        }

        let result = {
            for (name, plugin) in plugins.iter() {
                let now = Instant::now();
                match plugin.handle_upstream_response_body(
                    session,
                    ctx,
                    body,
                    end_of_stream,
                )? {
                    ResponseBodyPluginResult::PartialReplaced
                    | ResponseBodyPluginResult::FullyReplaced => {
                        let elapsed = now.elapsed().as_millis() as u32;
                        ctx.add_plugin_processing_time(name, elapsed);
                        debug!(
                            category = LOG_CATEGORY,
                            name, elapsed, "response body plugin modify body"
                        );
                    },
                    _ => {},
                }
            }
            Ok(())
        };
        ctx.plugins = Some(plugins);
        result
    }

    #[inline]
    pub fn handle_response_body_plugin(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        let plugins = match ctx.plugins.take() {
            Some(p) => p,
            None => return Ok(()), // No plugins, exit early.
        };
        if plugins.is_empty() {
            return Ok(());
        }
        let result = {
            for (name, plugin) in plugins.iter() {
                let now = Instant::now();
                match plugin.handle_response_body(
                    session,
                    ctx,
                    body,
                    end_of_stream,
                )? {
                    ResponseBodyPluginResult::PartialReplaced
                    | ResponseBodyPluginResult::FullyReplaced => {
                        let elapsed = now.elapsed().as_millis() as u32;
                        ctx.add_plugin_processing_time(name, elapsed);
                        debug!(
                            category = LOG_CATEGORY,
                            name, elapsed, "response body plugin modify body"
                        );
                    },
                    _ => {},
                }
            }
            Ok(())
        };
        ctx.plugins = Some(plugins);
        result
    }

    fn process_cache_control(
        &self,
        c: &mut CacheControl,
        max_ttl: Option<Duration>,
    ) -> Result<(), NoCacheReason> {
        // no-cache, no-store, private
        if c.no_cache() || c.no_store() || c.private() {
            return Err(NoCacheReason::OriginNotCache);
        }

        // max-age=0
        if c.max_age().ok().flatten().unwrap_or_default() == 0 {
            return Err(NoCacheReason::OriginNotCache);
        }

        // set cache max ttl
        if let Some(d) = max_ttl {
            if c.fresh_duration().unwrap_or_default() > d {
                // 更新 s-maxage 的值
                let s_maxage_value =
                    itoa::Buffer::new().format(d.as_secs()).as_bytes().to_vec();
                c.directives.insert(
                    "s-maxage".to_string(),
                    Some(DirectiveValue(s_maxage_value)),
                );
            }
        }

        Ok(())
    }

    #[inline]
    fn handle_cache_headers(
        &self,
        session: &Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) {
        let cache_status = session.cache.phase().as_str();
        let _ = upstream_response.insert_header("x-cache-status", cache_status);

        // process lookup duration
        let lookup_duration_str = self.process_cache_timing(
            session.cache.lookup_duration(),
            "x-cache-lookup",
            upstream_response,
            &mut ctx.timing.cache_lookup,
        );

        // process lock duration
        let lock_duration_str = self.process_cache_timing(
            session.cache.lock_duration(),
            "x-cache-lock",
            upstream_response,
            &mut ctx.timing.cache_lock,
        );

        #[cfg(not(feature = "tracing"))]
        {
            let _ = lookup_duration_str;
            let _ = lock_duration_str;
        }

        // (optional) process OpenTelemetry
        #[cfg(feature = "tracing")]
        update_otel_cache_attrs(
            ctx,
            cache_status,
            lookup_duration_str,
            lock_duration_str,
        );
    }

    #[inline]
    fn process_cache_timing(
        &self,
        duration_opt: Option<Duration>,
        header_name: &'static str,
        resp: &mut ResponseHeader,
        ctx_field: &mut Option<i32>,
    ) -> String {
        if let Some(d) = duration_opt {
            let ms = d.as_millis() as i32;

            // use itoa to avoid format! heap memory allocation
            let mut buffer = itoa::Buffer::new();
            let mut value_bytes = Vec::with_capacity(6);
            value_bytes.extend_from_slice(buffer.format(ms).as_bytes());
            value_bytes.extend_from_slice(b"ms");

            let _ = resp.insert_header(header_name, value_bytes);
            *ctx_field = Some(ms);

            #[cfg(feature = "tracing")]
            return humantime::Duration::from(d).to_string();
        }
        String::new()
    }
}

#[inline]
fn get_upstream_with_variables(
    upstream: &str,
    ctx: &Ctx,
    upstreams: &dyn UpstreamProvider,
) -> Option<Arc<Upstream>> {
    let key = upstream
        .strip_prefix('$')
        .and_then(|var_name| ctx.get_variable(var_name))
        .unwrap_or(upstream);
    upstreams.get(key)
}

#[async_trait]
impl ProxyHttp for Server {
    type CTX = Ctx;
    fn new_ctx(&self) -> Self::CTX {
        debug!(category = LOG_CATEGORY, "new ctx");
        Ctx::new()
    }
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        debug!(category = LOG_CATEGORY, "--> init downstream modules");
        defer!(debug!(category = LOG_CATEGORY, "<-- init downstream modules"););
        // Add disabled downstream compression module by default
        modules.add_module(ResponseCompressionBuilder::enable(0));

        self.modules.iter().flatten().for_each(|item| {
            if item == MODULE_GRPC_WEB {
                modules.add_module(Box::new(GrpcWeb));
            }
        });
    }
    /// Handles early request processing before main request handling.
    /// Key responsibilities:
    /// - Sets up connection tracking and metrics
    /// - Records timing information
    /// - Initializes OpenTelemetry tracing
    /// - Matches request to location configuration
    /// - Validates request parameters
    /// - Initializes compression and gRPC modules if needed
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> early request filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- early request filter"););

        self.initialize_context(session, ctx);
        #[cfg(feature = "tracing")]
        if self.enabled_otel {
            initialize_telemetry(&self.name, session, ctx);
        }
        self.find_and_apply_location(session, ctx).await?;

        Ok(())
    }
    /// Main request processing filter.
    /// Handles:
    /// - Admin interface requests
    /// - Let's Encrypt certificate challenges
    /// - Location-specific processing
    /// - URL rewriting
    /// - Plugin execution
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> request filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- request filter"););
        // try to handle special requests in order
        // admin route
        if let Some(result) = self.handle_admin_request(session, ctx).await {
            return result;
        }
        // acme http challengt
        if let Some(result) = self.handle_acme_challenge(session, ctx).await {
            return result;
        }
        // prometheus metrics pull request
        #[cfg(feature = "tracing")]
        if let Some(result) = self.handle_metrics_request(session, ctx).await {
            return result;
        }

        self.handle_standard_request(session, ctx).await
    }

    /// Filters requests before sending to upstream.
    /// Allows modifying request before proxying.
    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> proxy upstream filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- proxy upstream filter"););
        let done = self
            .handle_request_plugin(PluginStep::ProxyUpstream, session, ctx)
            .await?;

        if done {
            return Ok(false);
        }
        Ok(true)
    }

    /// Selects and configures the upstream peer to proxy to.
    /// Handles upstream connection pooling and health checking.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<Box<HttpPeer>> {
        debug!(category = LOG_CATEGORY, "--> upstream peer");
        defer!(debug!(category = LOG_CATEGORY, "<-- upstream peer"););
        // let mut location_name = "unknown".to_string();
        let peer = self
            .location_provider
            .get(&ctx.upstream.location)
            .and_then(|location| {
                let upstream = get_upstream_with_variables(
                    &location.upstream,
                    ctx,
                    self.upstream_provider.as_ref(),
                )?;
                Some((location, upstream))
            })
            .and_then(|(location, up)| {
                ctx.upstream.connected_count = up.connected();
                #[cfg(not(feature = "tracing"))]
                let _location = &location;
                #[cfg(feature = "tracing")]
                if let Some(features) = &ctx.features {
                    if let Some(tracer) = &features.otel_tracer {
                        let name = format!("upstream.{}", &location.upstream);
                        let mut span = tracer.new_upstream_span(&name);
                        span.set_attribute(KeyValue::new(
                            "upstream.connected",
                            ctx.upstream.connected_count.unwrap_or_default()
                                as i64,
                        ));
                        let features = ctx.features.get_or_insert_default();
                        features.upstream_span = Some(span);
                    }
                }
                let peer = up
                    .new_http_peer(session, &ctx.conn.client_ip)
                    .inspect(|peer| {
                        ctx.upstream.address = peer.address().to_string();
                    });
                ctx.upstream.name = up.name.clone();
                peer
            })
            .ok_or_else(|| {
                new_internal_error(
                    503,
                    format!(
                        "No available upstream for {}",
                        &ctx.upstream.location
                    ),
                )
            })?;

        // start connect to upstream
        ctx.timing.upstream_connect =
            Some(get_start_time(&ctx.timing.created_at));

        Ok(Box::new(peer))
    }
    /// Called when connection is established to upstream.
    /// Records timing metrics and TLS details.
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        _peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> connected to upstream");
        defer!(debug!(category = LOG_CATEGORY, "<-- connected to upstream"););
        ctx.timing.upstream_connect =
            get_latency(&ctx.timing.created_at, &ctx.timing.upstream_connect);
        if let Some(digest) = digest {
            ctx.update_upstream_timing_from_digest(digest, reused);
        }
        ctx.upstream.reused = reused;

        // upstream start processing
        ctx.timing.upstream_processing =
            Some(get_start_time(&ctx.timing.created_at));

        Ok(())
    }
    /// Filters upstream request before sending.
    /// Adds proxy headers and performs any request modifications.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> upstream request filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- upstream request filter"););
        if let Some(location) =
            self.location_provider.get(&ctx.upstream.location)
        {
            set_append_proxy_headers(session, ctx, upstream_response, location);
        }
        Ok(())
    }
    /// Filters request body chunks before sending upstream.
    /// Tracks payload size and enforces size limits.
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> request body filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- request body filter"););
        if let Some(buf) = body {
            ctx.state.payload_size += buf.len();
            if let Some(location) =
                self.location_provider.get(&ctx.upstream.location)
            {
                location
                    .client_body_size_limit(ctx.state.payload_size)
                    .map_err(|e| new_internal_error(413, e))?;
            }
        }
        Ok(())
    }
    /// Generates cache keys for request caching.
    /// Combines:
    /// - Cache namespace
    /// - Request method
    /// - URL path and query
    /// - Optional custom prefix
    fn cache_key_callback(
        &self,
        session: &Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<CacheKey> {
        debug!(category = LOG_CATEGORY, "--> cache key callback");
        defer!(debug!(category = LOG_CATEGORY, "<-- cache key callback"););
        let key = get_cache_key(
            ctx,
            session.req_header().method.as_ref(),
            &session.req_header().uri,
        );
        debug!(
            category = LOG_CATEGORY,
            namespace = key.namespace_str(),
            primary = key.primary_key_str(),
            user_tag = key.user_tag(),
            "cache key callback"
        );
        Ok(key)
    }

    /// Determines if and how responses should be cached.
    /// Checks:
    /// - Cache-Control headers
    /// - TTL settings
    /// - Cache privacy settings
    /// - Custom cache control directives
    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<RespCacheable> {
        debug!(category = LOG_CATEGORY, "--> response cache filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- response cache filter"););

        let (check_cache_control, max_ttl) = ctx.cache.as_ref().map_or(
            (false, None), // 如果 ctx.cache 为 None 时的默认值
            |c| (c.check_cache_control, c.max_ttl),
        );

        let mut cc = CacheControl::from_resp_headers(resp);

        if let Some(c) = &mut cc {
            // 将所有复杂的验证和修改逻辑委托给辅助函数
            if let Err(reason) = self.process_cache_control(c, max_ttl) {
                return Ok(RespCacheable::Uncacheable(reason));
            }
        } else if check_cache_control {
            // 如果需要 Cache-Control 头但它不存在或解析失败
            return Ok(RespCacheable::Uncacheable(
                NoCacheReason::OriginNotCache,
            ));
        }

        Ok(resp_cacheable(
            cc.as_ref(),
            resp.clone(),
            false,
            &META_DEFAULTS,
        ))
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> response filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- response filter"););
        if session.cache.enabled() {
            self.handle_cache_headers(session, upstream_response, ctx);
        }

        // call response plugin
        self.handle_response_plugin(session, ctx, upstream_response)
            .await?;

        // add server-timing response header
        if self.enable_server_timing {
            let _ = upstream_response
                .insert_header("server-timing", ctx.generate_server_timing());
        }
        Ok(())
    }

    fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        debug!(category = LOG_CATEGORY, "--> upstream response filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- upstream response filter"););
        self.handle_upstream_response_plugin(session, ctx, upstream_response)?;
        #[cfg(feature = "tracing")]
        inject_telemetry_headers(ctx, upstream_response);
        ctx.upstream.status = Some(upstream_response.status);

        if ctx.state.status.is_none() {
            ctx.state.status = Some(upstream_response.status);
            // start to get upstream response data
            ctx.timing.upstream_response =
                Some(get_start_time(&ctx.timing.created_at));
        }

        if let Some(id) = &ctx.state.request_id {
            let _ = upstream_response
                .insert_header(&HTTP_HEADER_NAME_X_REQUEST_ID, id);
        }

        ctx.timing.upstream_processing = get_latency(
            &ctx.timing.created_at,
            &ctx.timing.upstream_processing,
        );
        Ok(())
    }

    /// Filters upstream response body chunks.
    /// Records timing metrics and finalizes spans.
    fn upstream_response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        debug!(category = LOG_CATEGORY, "--> upstream response body filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- upstream response body filter"););

        self.handle_upstream_response_body_plugin(
            session,
            ctx,
            body,
            end_of_stream,
        )?;

        if end_of_stream {
            ctx.timing.upstream_response = get_latency(
                &ctx.timing.created_at,
                &ctx.timing.upstream_response,
            );

            #[cfg(feature = "tracing")]
            set_otel_upstream_attrs(ctx);
            // self.finalize_upstream_session(ctx);
        }
        Ok(())
    }

    /// Final filter for response body before sending to client.
    /// Handles response body modifications and compression.
    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> response body filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- response body filter"););
        self.handle_response_body_plugin(session, ctx, body, end_of_stream)?;
        Ok(None)
    }

    /// Handles proxy failures and generates appropriate error responses.
    /// Error handling for:
    /// - Upstream connection failures (502)
    /// - Client timeouts (408)
    /// - Client disconnections (499)
    /// - Internal server errors (500)
    /// Generates error pages using configured template
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> fail to proxy");
        defer!(debug!(category = LOG_CATEGORY, "<-- fail to proxy"););
        let server_session = session.as_mut();

        let code = match e.etype() {
            pingora::HTTPStatus(code) => *code,
            _ => match e.esource() {
                pingora::ErrorSource::Upstream => 502,
                pingora::ErrorSource::Downstream => match e.etype() {
                    pingora::ErrorType::ConnectTimedout => 408,
                    // client close the connection
                    pingora::ErrorType::ConnectionClosed => 499,
                    _ => 500,
                },
                pingora::ErrorSource::Internal
                | pingora::ErrorSource::Unset => 500,
            },
        };
        let mut resp = match code {
            502 => error_resp::HTTP_502_RESPONSE.clone(),
            400 => error_resp::HTTP_400_RESPONSE.clone(),
            500 => HTTP_500_RESPONSE.clone(),
            _ => error_resp::gen_error_response(code),
        };

        let error_type = e.etype().as_str();
        let content = self
            .error_template
            .replace("{{version}}", pingap_util::get_pkg_version())
            .replace("{{content}}", &e.to_string())
            .replace("{{error_type}}", error_type);
        let buf = Bytes::from(content);
        ctx.state.status = Some(
            StatusCode::from_u16(code)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        );
        let content_type = if buf.starts_with(b"{") {
            "application/json; charset=utf-8"
        } else {
            "text/html; charset=utf-8"
        };
        let _ = resp.insert_header(http::header::CONTENT_TYPE, content_type);
        let _ = resp.insert_header("X-Pingap-EType", error_type);
        let _ = resp
            .insert_header(http::header::CONTENT_LENGTH, buf.len().to_string());

        let user_agent = server_session
            .get_header(http::header::USER_AGENT)
            .map(|v| v.clone().to_str().unwrap_or_default().to_string());

        error!(
            category = LOG_CATEGORY,
            error = %e,
            remote_addr = ctx.conn.remote_addr,
            client_ip = ctx.conn.client_ip,
            user_agent,
            error_type,
            path = server_session.req_header().uri.path(),
            "fail to proxy"
        );

        // TODO: we shouldn't be closing downstream connections on internally generated errors
        // and possibly other upstream connect() errors (connection refused, timeout, etc)
        //
        // This change is only here because we DO NOT re-use downstream connections
        // today on these errors and we should signal to the client that pingora is dropping it
        // rather than a misleading the client with 'keep-alive'
        server_session.set_keepalive(None);

        server_session
            .write_response_header(Box::new(resp))
            .await
            .unwrap_or_else(|e| {
                error!(
                    category = LOG_CATEGORY,
                    error = %e,
                    "send error response to downstream fail"
                );
            });

        let _ = server_session.write_response_body(buf, true).await;
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
    /// Performs request logging and cleanup after request completion.
    /// Handles:
    /// - Request counting cleanup
    /// - Compression statistics
    /// - Prometheus metrics
    /// - OpenTelemetry span completion
    /// - Access logging
    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> logging");
        defer!(debug!(category = LOG_CATEGORY, "<-- logging"););
        end_request();
        self.processing.fetch_sub(1, Ordering::Relaxed);
        if let Some(location) =
            self.location_provider.get(&ctx.upstream.location)
        {
            location.sub_processing();
        }
        // get from cache does not connect to upstream
        if let Some(upstream) = get_upstream_with_variables(
            &ctx.upstream.name,
            ctx,
            self.upstream_provider.as_ref(),
        ) {
            ctx.upstream.processing_count = Some(upstream.completed());
        }
        if ctx.state.status.is_none() {
            if let Some(header) = session.response_written() {
                ctx.state.status = Some(header.status);
            }
        }
        #[cfg(feature = "tracing")]
        // enable open telemetry and proxy upstream fail
        if let Some(features) = ctx.features.as_mut() {
            if let Some(ref mut span) = features.upstream_span.as_mut() {
                span.end();
            }
        }

        if let Some(c) =
            session.downstream_modules_ctx.get::<ResponseCompression>()
        {
            if c.is_enabled() {
                if let Some((algorithm, in_bytes, out_bytes, took)) =
                    c.get_info()
                {
                    let features = ctx.features.get_or_insert_default();
                    features.compression_stat = Some(CompressionStat {
                        algorithm: algorithm.to_string(),
                        in_bytes,
                        out_bytes,
                        duration: took,
                    });
                }
            }
        }
        #[cfg(feature = "tracing")]
        if let Some(prom) = &self.prometheus {
            // because prom.before will not be called if location is empty
            if !ctx.upstream.location.is_empty() {
                prom.after(session, ctx);
            }
        }

        #[cfg(feature = "tracing")]
        set_otel_request_attrs(session, ctx);

        if let Some(p) = &self.log_parser {
            info!("{}", p.format(session, ctx));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_conf::parse_from_conf;
    use pingap_config::PingapConf;
    use pingap_core::{CacheInfo, Ctx, UpstreamInfo};
    use pingap_location::LocationStats;
    use pingora::http::ResponseHeader;
    use pingora::protocols::tls::SslDigest;
    use pingora::protocols::{Digest, TimingDigest};
    use pingora::proxy::{ProxyHttp, Session};
    use pingora::server::configuration;
    use pingora::services::Service;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    use tokio_test::io::Builder;

    #[test]
    fn test_get_digest_detail() {
        let digest = Digest {
            timing_digest: vec![Some(TimingDigest {
                established_ts: SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(10))
                    .unwrap(),
            })],
            ssl_digest: Some(Arc::new(SslDigest {
                cipher: "123",
                version: "1.3",
                organization: None,
                serial_number: None,
                cert_digest: vec![],
            })),
            ..Default::default()
        };
        let result = get_digest_detail(&digest);
        assert_eq!(10000, result.tcp_established);
        assert_eq!("1.3", result.tls_version.unwrap_or_default());
    }

    /// Creates a new test server instance with default configuration
    fn new_server() -> Server {
        let toml_data = r###"
[upstreams.charts]
# upstream address list
addrs = ["127.0.0.1:5000"]


[upstreams.diving]
addrs = ["127.0.0.1:5001"]


[locations.lo]
# upstream of location (default none)
upstream = "charts"

# location match path (default none)
path = "/"

# location match host, multiple domain names are separated by commas (default none)
host = ""

# set headers to request (default none)
includes = ["proxySetHeader"]

# add headers to request (default none)
proxy_add_headers = ["name:value"]


# the weigh of location (default none)
weight = 1024


# plugin list for location
plugins = ["pingap:requestId", "stats"]

[servers.test]
# server linsten address, multiple addresses are separated by commas (default none)
addr = "0.0.0.0:6188"

# access log format (default none)
access_log = "tiny"

# the locations for server
locations = ["lo"]

# the threads count for server (default 1)
threads = 1

[plugins.stats]
value = "/stats"
category = "stats"

[storages.authToken]
category = "secret"
secret = "123123"
value = "PLpKJqvfkjTcYTDpauJf+2JnEayP+bm+0Oe60Jk="

[storages.proxySetHeader]
category = "config"
value = 'proxy_set_headers = ["name:value"]'
        "###;
        let pingap_conf = PingapConf::new(toml_data.as_ref(), false).unwrap();
        try_init_server_locations(&pingap_conf.servers, &pingap_conf.locations)
            .unwrap();

        let location = Arc::new(
            Location::new("lo", pingap_conf.locations.get("lo").unwrap())
                .unwrap(),
        );
        let upstream = Arc::new(
            Upstream::new(
                "charts",
                pingap_conf.upstreams.get("charts").unwrap(),
                None,
            )
            .unwrap(),
        );

        struct TmpPluginLoader {}
        impl PluginProvider for TmpPluginLoader {
            fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
                None
            }
        }
        struct TmpLocationLoader {
            location: Arc<Location>,
        }
        impl LocationProvider for TmpLocationLoader {
            fn get(&self, _name: &str) -> Option<Arc<Location>> {
                Some(self.location.clone())
            }
            fn stats(&self) -> HashMap<String, LocationStats> {
                HashMap::new()
            }
        }
        struct TmpUpstreamLoader {
            upstream: Arc<Upstream>,
        }
        impl UpstreamProvider for TmpUpstreamLoader {
            fn get(&self, _name: &str) -> Option<Arc<Upstream>> {
                Some(self.upstream.clone())
            }
            fn list(&self) -> Vec<(String, Arc<Upstream>)> {
                vec![("charts".to_string(), self.upstream.clone())]
            }
        }
        let confs = parse_from_conf(pingap_conf);
        Server::new(
            &confs[0],
            Arc::new(TmpLocationLoader { location }),
            Arc::new(TmpUpstreamLoader { upstream }),
            Arc::new(TmpPluginLoader {}),
        )
        .unwrap()
    }

    #[test]
    fn test_new_server() {
        let server = new_server();
        let services = server
            .run(&Arc::new(configuration::ServerConf::default()))
            .unwrap();

        assert_eq!("Pingora HTTP Proxy Service", services.lb.name());
    }

    #[tokio::test]
    async fn test_early_request_filter() {
        let server = new_server();

        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut ctx = Ctx::default();
        server
            .early_request_filter(&mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!("lo", ctx.upstream.location);
    }

    #[tokio::test]
    async fn test_request_filter() {
        let server = new_server();

        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut ctx = Ctx {
            upstream: UpstreamInfo {
                location: "lo".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let done = server.request_filter(&mut session, &mut ctx).await.unwrap();
        assert_eq!(false, done);
    }

    #[tokio::test]
    async fn test_cache_key_callback() {
        let server = new_server();

        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let key = server
            .cache_key_callback(
                &session,
                &mut Ctx {
                    cache: Some(CacheInfo {
                        namespace: Some("pingap".to_string()),
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            key.primary_key_str(),
            Some("ss:GET:/vicanso/pingap?size=1")
        );
        assert_eq!(key.namespace_str(), Some("pingap"));
        assert_eq!(
            r#"CacheKey { namespace: [112, 105, 110, 103, 97, 112], primary: [115, 115, 58, 71, 69, 84, 58, 47, 118, 105, 99, 97, 110, 115, 111, 47, 112, 105, 110, 103, 97, 112, 63, 115, 105, 122, 101, 61, 49], primary_bin_override: None, variance: None, user_tag: "", extensions: Extensions }"#,
            format!("{key:?}")
        );
    }

    #[tokio::test]
    async fn test_response_cache_filter() {
        let server = new_server();

        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();
        upstream_response
            .append_header("Content-Type", "application/json")
            .unwrap();
        let result = server
            .response_cache_filter(
                &session,
                &upstream_response,
                &mut Ctx {
                    cache: Some(CacheInfo {
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(true, result.is_cacheable());

        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();
        upstream_response
            .append_header("Cache-Control", "no-cache")
            .unwrap();
        let result = server
            .response_cache_filter(
                &session,
                &upstream_response,
                &mut Ctx {
                    cache: Some(CacheInfo {
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(false, result.is_cacheable());

        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();
        upstream_response
            .append_header("Cache-Control", "no-store")
            .unwrap();
        let result = server
            .response_cache_filter(
                &session,
                &upstream_response,
                &mut Ctx {
                    cache: Some(CacheInfo {
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(false, result.is_cacheable());

        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();
        upstream_response
            .append_header("Cache-Control", "private, max-age=100")
            .unwrap();
        let result = server
            .response_cache_filter(
                &session,
                &upstream_response,
                &mut Ctx {
                    cache: Some(CacheInfo {
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(false, result.is_cacheable());
    }
}
