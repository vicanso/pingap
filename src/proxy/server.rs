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

use super::dynamic_certificate::{GlobalCertificate, TlsSettingParams};
use super::logger::Parser;
use super::upstream::get_upstream;
use super::{ServerConf, LOG_CATEGORY};
use crate::acme::handle_lets_encrypt;
use crate::config;
use crate::config::get_config_storage;
use crate::config::PluginStep;
use crate::http_extra::{HttpResponse, HTTP_HEADER_NAME_X_REQUEST_ID};
#[cfg(feature = "full")]
use crate::otel;
use crate::plugin::{get_plugin, ADMIN_SERVER_PLUGIN};
use crate::proxy::location::get_location;
use crate::service::SimpleServiceTaskFuture;
#[cfg(feature = "full")]
use crate::state::OtelTracer;
use crate::state::{accept_request, end_request};
use crate::state::{get_cache_key, CompressionStat, State};
#[cfg(feature = "full")]
use crate::state::{new_prometheus, new_prometheus_push_service, Prometheus};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::StatusCode;
use once_cell::sync::Lazy;
#[cfg(feature = "full")]
use opentelemetry::{
    global,
    trace::{Span, SpanKind, Tracer},
    KeyValue,
};
#[cfg(feature = "full")]
use opentelemetry_http::HeaderExtractor;
use pingora::apps::HttpServerOptions;
use pingora::cache::cache_control::CacheControl;
use pingora::cache::cache_control::DirectiveValue;
use pingora::cache::cache_control::InterpretCacheControl;
use pingora::cache::filters::resp_cacheable;
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
use pingora::protocols::TimingDigest;
use pingora::proxy::{http_proxy_service, HttpProxy};
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::configuration;
use pingora::services::listening::Service;
use pingora::upstreams::peer::{HttpPeer, Peer};
use scopeguard::defer;
use snafu::Snafu;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
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
    servers: &HashMap<String, config::ServerConf>,
    locations: &HashMap<String, config::LocationConf>,
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
    #[cfg(feature = "full")]
    prometheus: Option<Arc<Prometheus>>,

    /// Whether to push metrics to remote Prometheus pushgateway
    prometheus_push_mode: bool,

    /// Prometheus metrics endpoint path or push gateway URL
    #[cfg(feature = "full")]
    prometheus_metrics: String,

    /// Whether OpenTelemetry tracing is enabled
    #[cfg(feature = "full")]
    enabled_otel: bool,

    /// List of enabled modules (e.g. "grpc-web")
    modules: Option<Vec<String>>,
}

pub struct ServerServices {
    pub lb: Service<HttpProxy<Server>>,
}

const META_DEFAULTS: CacheMetaDefaults =
    CacheMetaDefaults::new(|_| Some(1), 1, 1);

static HTTP_500_RESPONSE: Lazy<ResponseHeader> =
    Lazy::new(|| error_resp::gen_error_response(500));

impl Server {
    /// Creates a new HTTP proxy server instance with the given configuration.
    /// Initializes all server components including:
    /// - TCP socket options
    /// - TLS settings
    /// - Prometheus metrics (if enabled)
    /// - Threading configuration
    pub fn new(conf: &ServerConf) -> Result<Self> {
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
        let tcp_socket_options =
            if conf.tcp_fastopen.is_some() || conf.tcp_keepalive.is_some() {
                let mut opts = TcpSocketOptions::default();
                opts.tcp_fastopen = conf.tcp_fastopen;
                opts.tcp_keepalive.clone_from(&conf.tcp_keepalive);
                Some(opts)
            } else {
                None
            };
        let prometheus_metrics =
            conf.prometheus_metrics.clone().unwrap_or_default();
        #[cfg(feature = "full")]
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
            #[cfg(feature = "full")]
            enabled_otel: conf.otlp_exporter.is_some(),
            #[cfg(feature = "full")]
            prometheus_metrics,
            #[cfg(feature = "full")]
            prometheus,
            modules: conf.modules.clone(),
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
    ) -> Option<(String, SimpleServiceTaskFuture)> {
        if !self.prometheus_push_mode {
            return None;
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "full")] {
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
            "server is listening"
        );
        let cipher_list = self.tls_cipher_list.clone();
        let ciphersuites = self.tls_ciphersuites.clone();
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
                        ciphersuites: ciphersuites.clone(),
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
        ctx: &mut State,
    ) -> pingora::Result<bool> {
        if let Some(plugin) = get_plugin(ADMIN_SERVER_PLUGIN.as_str()) {
            let result = plugin
                .handle_request(PluginStep::Request, session, ctx)
                .await?;
            if let Some(resp) = result {
                ctx.status = Some(resp.status);
                resp.send(session).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Helper struct to store connection timing and TLS details
#[derive(Debug, Default)]
struct DigestDetail {
    /// Whether the connection was reused from pool
    connection_reused: bool,
    /// Total connection time in milliseconds
    connection_time: u64,
    /// Timestamp when TCP connection was established
    tcp_established: u64,
    /// Timestamp when TLS handshake completed
    tls_established: u64,
    /// TLS protocol version if using HTTPS
    tls_version: Option<String>,
    /// TLS cipher suite in use if using HTTPS
    tls_cipher: Option<String>,
}

/// Extracts timing and TLS information from connection digest.
/// Used for metrics and logging connection details.
#[inline]
fn get_digest_detail(digest: &Digest) -> DigestDetail {
    let get_established = |value: Option<&Option<TimingDigest>>| -> u64 {
        value
            .map(|item| {
                if let Some(item) = item {
                    item.established_ts
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64
                } else {
                    0
                }
            })
            .unwrap_or_default()
    };

    let tcp_established = get_established(digest.timing_digest.first());
    let mut connection_time = 0;
    if tcp_established > 0 {
        connection_time = pingap_util::now_ms() - tcp_established;
    }
    let connection_reused = connection_time > 100;

    let Some(ssl_digest) = &digest.ssl_digest else {
        return DigestDetail {
            connection_reused,
            tcp_established,
            connection_time,
            ..Default::default()
        };
    };

    DigestDetail {
        connection_reused,
        tcp_established,
        connection_time,
        tls_established: get_established(digest.timing_digest.last()),
        tls_version: Some(ssl_digest.version.to_string()),
        tls_cipher: Some(ssl_digest.cipher.to_string()),
    }
}

static MODULE_GRPC_WEB: &str = "grpc-web";

#[async_trait]
impl ProxyHttp for Server {
    type CTX = State;
    fn new_ctx(&self) -> Self::CTX {
        debug!(category = LOG_CATEGORY, "new ctx");
        State::new()
    }
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        debug!(category = LOG_CATEGORY, "--> init downstream modules");
        defer!(debug!(category = LOG_CATEGORY, "<-- init downstream modules"););
        // Add disabled downstream compression module by default
        modules.add_module(ResponseCompressionBuilder::enable(0));
        let Some(value) = &self.modules else {
            return;
        };
        for item in value.iter() {
            if item == MODULE_GRPC_WEB {
                modules.add_module(Box::new(GrpcWeb));
            }
        }
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

        if let Some(stream) = session.stream() {
            ctx.connection_id = stream.id() as usize;
        }
        // get digest of timing and tls
        if let Some(digest) = session.digest() {
            let digest_detail = get_digest_detail(digest);
            ctx.connection_time = digest_detail.connection_time;
            ctx.connection_reused = digest_detail.connection_reused;

            if !ctx.connection_reused
                && digest_detail.tls_established
                    >= digest_detail.tcp_established
            {
                ctx.tls_handshake_time = Some(
                    digest_detail.tls_established
                        - digest_detail.tcp_established,
                );
            }
            ctx.tls_cipher = digest_detail.tls_cipher;
            ctx.tls_version = digest_detail.tls_version;
        };
        accept_request();

        ctx.processing = self.processing.fetch_add(1, Ordering::Relaxed) + 1;
        ctx.accepted = self.accepted.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some((remote_addr, remote_port)) =
            pingap_util::get_remote_addr(session)
        {
            ctx.remote_addr = Some(remote_addr);
            ctx.remote_port = Some(remote_port);
        }
        if let Some(addr) =
            session.server_addr().and_then(|addr| addr.as_inet())
        {
            ctx.server_addr = Some(addr.ip().to_string());
            ctx.server_port = Some(addr.port());
        }

        let header = session.req_header_mut();
        let host = pingap_util::get_host(header).unwrap_or_default();
        let path = header.uri.path();

        #[cfg(feature = "full")]
        if self.enabled_otel {
            // enable open telemetry
            if let Some(tracer) = otel::new_tracer(&self.name) {
                let cx = global::get_text_map_propagator(|propagator| {
                    propagator.extract(&HeaderExtractor(&header.headers))
                });
                let span_names = [header.method.to_string(), path.to_string()];
                let span = tracer
                    .span_builder(span_names.join(" "))
                    .with_kind(SpanKind::Server)
                    .start_with_context(&tracer, &cx);
                ctx.otel_tracer = Some(OtelTracer {
                    tracer,
                    http_request_span: span,
                });
            }
        }

        // locations not found
        let Some(locations) = get_server_locations(&self.name) else {
            return Ok(());
        };

        for name in locations.iter() {
            let Some(location) = get_location(name) else {
                continue;
            };
            let (matched, variables) = location.match_host_path(host, path);
            if matched {
                ctx.location = Some(location);
                if let Some(variables) = variables {
                    for (key, value) in variables.iter() {
                        ctx.add_variable(key, value);
                    }
                };
                break;
            }
        }
        // set prometheus stats
        #[cfg(feature = "full")]
        if let Some(prom) = &self.prometheus {
            let location_name =
                ctx.location.as_ref().map_or("", |item| &item.name);
            prom.before(location_name);
        }

        if let Some(location) = &ctx.location {
            location.validate_content_length(header).map_err(|e| {
                pingap_util::new_internal_error(413, e.to_string())
            })?;

            // add processing, if processing is max than limit,
            // it will return error with 429 status code
            match location.add_processing() {
                Ok((accepted, processing)) => {
                    ctx.location_accepted = accepted;
                    ctx.location_processing = processing;
                },
                Err(e) => {
                    return Err(pingap_util::new_internal_error(
                        429,
                        e.to_string(),
                    ));
                },
            };
            if location.support_grpc_web() {
                // Initialize grpc web module for this request
                let grpc_web = session
                    .downstream_modules_ctx
                    .get_mut::<GrpcWebBridge>()
                    .ok_or_else(|| {
                        pingap_util::new_internal_error(
                            500,
                            "grpc web bridge module should be added"
                                .to_string(),
                        )
                    })?;
                grpc_web.init();
            }

            let _ = location
                .clone()
                .handle_request_plugin(PluginStep::EarlyRequest, session, ctx)
                .await?;
        }
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
        if self.admin && self.serve_admin(session, ctx).await? {
            return Ok(true);
        }
        // only enable for http 80
        if self.lets_encrypt_enabled {
            let Some(storage) = get_config_storage() else {
                return Err(pingap_util::new_internal_error(
                    500,
                    "get config storage fail".to_string(),
                ));
            };
            let done = handle_lets_encrypt(storage, session, ctx).await?;
            if done {
                return Ok(true);
            }
        }

        let header = session.req_header_mut();

        // prometheus pull metric
        #[cfg(feature = "full")]
        if !self.prometheus_push_mode
            && self.prometheus.is_some()
            && header.uri.path() == self.prometheus_metrics
        {
            let body = self
                .prometheus
                .as_ref()
                .ok_or(pingap_util::new_internal_error(
                    500,
                    "get prometheus fail".to_string(),
                ))?
                .metrics()
                .map_err(|e| {
                    pingap_util::new_internal_error(500, e.to_string())
                })?;
            HttpResponse::text(body.into()).send(session).await?;
            return Ok(true);
        }

        let Some(location) = &ctx.location else {
            let host = pingap_util::get_host(header).unwrap_or_default();
            HttpResponse::unknown_error(Bytes::from(format!(
                "Location not found, host:{host} path:{}",
                header.uri.path(),
            )))
            .send(session)
            .await?;
            return Ok(true);
        };

        debug!(
            category = LOG_CATEGORY,
            name = location.name,
            "location is matched"
        );
        location.rewrite(header, ctx.variables.as_ref());

        let done = location
            .clone()
            .handle_request_plugin(PluginStep::Request, session, ctx)
            .await?;

        if done {
            return Ok(true);
        }

        Ok(false)
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
        if let Some(location) = &ctx.location {
            let done = location
                .clone()
                .handle_request_plugin(PluginStep::ProxyUpstream, session, ctx)
                .await?;
            if done {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Selects and configures the upstream peer to proxy to.
    /// Handles upstream connection pooling and health checking.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Box<HttpPeer>> {
        debug!(category = LOG_CATEGORY, "--> upstream peer");
        defer!(debug!(category = LOG_CATEGORY, "<-- upstream peer"););
        let mut location_name = "unknown".to_string();
        let peer = if let Some(location) = &ctx.location {
            location_name.clone_from(&location.name);
            if let Some(up) = get_upstream(&location.upstream) {
                ctx.upstream_connected = up.connected();
                #[cfg(feature = "full")]
                if let Some(tracer) = &ctx.otel_tracer {
                    let name = format!("upstream.{}", &location.upstream);
                    let mut span = tracer.new_upstream_span(&name);
                    span.set_attribute(KeyValue::new(
                        "upstream.connected",
                        ctx.upstream_connected.unwrap_or_default().to_string(),
                    ));
                    ctx.upstream_span = Some(span);
                }
                let peer = up.new_http_peer(session, ctx).map(|peer| {
                    ctx.upstream_address = peer.address().to_string();
                    peer
                });
                ctx.upstream = Some(up);
                peer
            } else {
                None
            }
        } else {
            None
        }
        .ok_or_else(|| {
            pingap_util::new_internal_error(
                503,
                format!("No available upstream for {location_name}"),
            )
        })?;

        ctx.upstream_connect_time =
            pingap_util::get_latency(&ctx.upstream_connect_time);

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
        if let Some(digest) = digest {
            let detail = get_digest_detail(digest);
            if !reused {
                let upstream_connect_time =
                    ctx.upstream_connect_time.unwrap_or_default();
                if upstream_connect_time > 0
                    && detail.tcp_established > upstream_connect_time
                {
                    ctx.upstream_tcp_connect_time =
                        Some(detail.tcp_established - upstream_connect_time);
                }
                if detail.tls_established > detail.tcp_established {
                    ctx.upstream_tls_handshake_time =
                        Some(detail.tls_established - detail.tcp_established);
                }
            }
            ctx.upstream_connection_time = Some(detail.connection_time);
        }

        ctx.upstream_reused = reused;
        ctx.upstream_connect_time =
            pingap_util::get_latency(&ctx.upstream_connect_time);
        ctx.upstream_processing_time =
            pingap_util::get_latency(&ctx.upstream_processing_time);

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
        if let Some(location) = &ctx.location {
            location.set_append_proxy_headers(session, ctx, upstream_response);
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
            ctx.payload_size += buf.len();
            if let Some(location) = &ctx.location {
                location.client_body_size_limit(ctx).map_err(|e| {
                    pingap_util::new_internal_error(413, e.to_string())
                })?;
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
            key = format!("{key:?}"),
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
        if ctx.check_cache_control
            && resp.headers.get("Cache-Control").is_none()
        {
            return Ok(RespCacheable::Uncacheable(
                NoCacheReason::OriginNotCache,
            ));
        }
        let mut cc = CacheControl::from_resp_headers(resp);
        if let Some(ref mut c) = &mut cc {
            if c.no_cache() || c.no_store() || c.private() {
                return Ok(RespCacheable::Uncacheable(
                    NoCacheReason::OriginNotCache,
                ));
            }
            //  max-age=0
            if let Ok(max_age) = c.max_age() {
                if max_age.unwrap_or_default() == 0 {
                    return Ok(RespCacheable::Uncacheable(
                        NoCacheReason::OriginNotCache,
                    ));
                }
            }
            // adjust cache ttl
            if let Some(d) = ctx.cache_max_ttl {
                if c.fresh_sec().unwrap_or_default() > d.as_secs() as u32 {
                    // update cache-control s-maxage value
                    c.directives.insert(
                        "s-maxage".to_string(),
                        Some(DirectiveValue(
                            itoa::Buffer::new()
                                .format(d.as_secs())
                                .as_bytes()
                                .to_vec(),
                        )),
                    );
                }
            }
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
            // ignore insert header error
            let _ = upstream_response.insert_header(
                "X-Cache-Status",
                session.cache.phase().as_str(),
            );
            if let Some(d) = session.cache.lookup_duration() {
                let ms = d.as_millis() as u64;
                let _ = upstream_response
                    .insert_header("X-Cache-Lookup", format!("{ms}ms"));
                ctx.cache_lookup_time = Some(ms);
            }
            if let Some(d) = session.cache.lock_duration() {
                let ms = d.as_millis() as u64;
                let _ = upstream_response
                    .insert_header("X-Cache-Lock", format!("{ms}ms"));
                ctx.cache_lock_time = Some(ms);
            }
        }

        if let Some(location) = &ctx.location {
            location
                .clone()
                .handle_response_plugin(
                    PluginStep::Response,
                    session,
                    ctx,
                    upstream_response,
                )
                .await?;
        }

        Ok(())
    }

    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) {
        debug!(category = LOG_CATEGORY, "--> upstream response filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- upstream response filter"););
        if ctx.status.is_none() {
            ctx.status = Some(upstream_response.status);
            ctx.upstream_response_time =
                pingap_util::get_latency(&ctx.upstream_response_time);
        }
        if let Some(id) = &ctx.request_id {
            let _ = upstream_response
                .insert_header(HTTP_HEADER_NAME_X_REQUEST_ID.clone(), id);
        }
        ctx.upstream_processing_time =
            pingap_util::get_latency(&ctx.upstream_processing_time);
    }

    /// Filters upstream response body chunks.
    /// Records timing metrics and finalizes spans.
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        debug!(category = LOG_CATEGORY, "--> upstream response body filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- upstream response body filter"););
        if end_of_stream {
            ctx.upstream_response_time =
                pingap_util::get_latency(&ctx.upstream_response_time);
            #[cfg(feature = "full")]
            if let Some(ref mut span) = ctx.upstream_span.as_mut() {
                span.set_attributes([
                    KeyValue::new(
                        "upstream.addr",
                        ctx.upstream_address.clone(),
                    ),
                    KeyValue::new(
                        "upstream.reused",
                        ctx.upstream_reused.to_string(),
                    ),
                    KeyValue::new(
                        "upstream.connect_time",
                        ctx.upstream_connect_time
                            .unwrap_or_default()
                            .to_string(),
                    ),
                    KeyValue::new(
                        "upstream.processing_time",
                        ctx.upstream_processing_time
                            .unwrap_or_default()
                            .to_string(),
                    ),
                    KeyValue::new(
                        "upstream.response_time",
                        ctx.upstream_response_time
                            .unwrap_or_default()
                            .to_string(),
                    ),
                ]);
                span.end();
                ctx.upstream_span = None;
            }
        }
        Ok(())
    }

    /// Final filter for response body before sending to client.
    /// Handles response body modifications and compression.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        debug!(category = LOG_CATEGORY, "--> response body filter");
        defer!(debug!(category = LOG_CATEGORY, "<-- response body filter"););
        // set modify response body
        if let Some(modify) = &ctx.modify_response_body {
            if let Some(ref mut buf) = ctx.response_body {
                if let Some(b) = body {
                    buf.extend(&b[..]);
                    b.clear();
                }
            } else {
                let mut buf = BytesMut::new();
                if let Some(b) = body {
                    buf.extend(&b[..]);
                    b.clear();
                }
                ctx.response_body = Some(buf);
            };

            if end_of_stream {
                if let Some(ref buf) = ctx.response_body {
                    *body = Some(modify.handle(Bytes::from(buf.to_owned())));
                }
            }
        }

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
    ) -> u16
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
        ctx.status = Some(
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

        error!(
            category = LOG_CATEGORY,
            error = %e,
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
        code
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
        if let Some(location) = &ctx.location {
            location.sub_processing();
        }
        // get from cache does not connect to upstream
        if let Some(up) = &ctx.upstream {
            ctx.upstream_processing = Some(up.completed());
        }
        if ctx.status.is_none() {
            if let Some(header) = session.response_written() {
                ctx.status = Some(header.status);
            }
        }
        #[cfg(feature = "full")]
        // enable open telemetry and proxy upstream fail
        if let Some(ref mut span) = ctx.upstream_span.as_mut() {
            span.end();
        }

        if let Some(c) =
            session.downstream_modules_ctx.get::<ResponseCompression>()
        {
            if c.is_enabled() {
                if let Some((_, in_bytes, out_bytes, took)) = c.get_info() {
                    ctx.compression_stat = Some(CompressionStat {
                        in_bytes,
                        out_bytes,
                        duration: took,
                    });
                }
            }
        }
        #[cfg(feature = "full")]
        if let Some(prom) = &self.prometheus {
            prom.after(session, ctx);
        }

        #[cfg(feature = "full")]
        // open telemetry
        if let Some(ref mut tracer) = ctx.otel_tracer.as_mut() {
            let ip = if let Some(ip) = &ctx.client_ip {
                ip.to_string()
            } else {
                let ip = pingap_util::get_client_ip(session);
                ctx.client_ip = Some(ip.clone());
                ip
            };
            let mut attrs = vec![
                KeyValue::new("http.client_ip", ip),
                KeyValue::new(
                    "http.status",
                    ctx.status.unwrap_or_default().to_string(),
                ),
            ];
            if let Some(lo) = &ctx.location {
                attrs.push(KeyValue::new("location", lo.name.clone()));
            }
            tracer.http_request_span.set_attributes(attrs);
            tracer.http_request_span.end()
        }

        if let Some(p) = &self.log_parser {
            info!("{}", p.format(session, ctx));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Server;
    use crate::config::{LocationConf, PingapConf};
    use crate::proxy::server::get_digest_detail;
    use crate::proxy::{
        try_init_locations, try_init_server_locations, try_init_upstreams,
        Location, ServerConf,
    };
    use crate::state::State;
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
        try_init_upstreams(&pingap_conf.upstreams).unwrap();
        try_init_locations(&pingap_conf.locations).unwrap();
        try_init_server_locations(&pingap_conf.servers, &pingap_conf.locations)
            .unwrap();
        let confs: Vec<ServerConf> = pingap_conf.into();
        Server::new(&confs[0]).unwrap()
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

        let mut ctx = State::default();
        server
            .early_request_filter(&mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!("lo", ctx.location.unwrap().name);
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

        let mut ctx = State {
            location: Some(Arc::new(
                Location::new("lo", &LocationConf::default()).unwrap(),
            )),
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

        let key = server.cache_key_callback(
            &session,
            &mut State {
                cache_namespace: Some("pingap".to_string()),
                cache_prefix: Some("ss:".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(
            r#"Ok(CacheKey { namespace: "pingap", primary: "ss:GET:/vicanso/pingap?size=1", primary_bin_override: None, variance: None, user_tag: "", extensions: Extensions })"#,
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
                &mut State {
                    cache_prefix: Some("ss:".to_string()),
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
                &mut State {
                    cache_prefix: Some("ss:".to_string()),
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
                &mut State {
                    cache_prefix: Some("ss:".to_string()),
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
                &mut State {
                    cache_prefix: Some("ss:".to_string()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(false, result.is_cacheable());
    }
}
