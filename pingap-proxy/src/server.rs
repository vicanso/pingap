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
    initialize_telemetry, inject_telemetry_headers, inject_trace_context,
    set_otel_request_attrs, set_otel_upstream_attrs,
};
use super::{ErrorTemplate, LOG_TARGET, ServerConf, set_append_proxy_headers};
use crate::ServerLocationsProvider;
use crate::ja4::{Ja4Collector, Ja4Store};
use crate::proxy_protocol::{PreTls, ProxyProtocolApp};
use ahash::AHashMap;
use async_trait::async_trait;
use bstr::ByteSlice;
use bytes::Bytes;
use bytes::BytesMut;
use http::StatusCode;
use pingap_acme::{handle_lets_encrypt, is_http_challenge_path};
use pingap_certificate::CertificateProvider;
use pingap_certificate::{GlobalCertificate, TlsSettingParams};
use pingap_config::ConfigManager;
use pingap_core::BackgroundTask;
#[cfg(feature = "tracing")]
use pingap_core::HttpResponse;
use pingap_core::LocationInstance;
use pingap_core::PluginProvider;
use pingap_core::new_internal_error;
use pingap_core::{
    CompressionStat, Ctx, PluginStep, RequestPluginResult,
    ResponseBodyPluginResult, ResponsePluginResult, get_cache_key,
};
use pingap_core::{HTTP_HEADER_NAME_X_REQUEST_ID, get_digest_detail};
use pingap_location::LocationProvider;
use pingap_logger::{
    AccessLogFilter, Parser, check_access_log_target,
    parse_access_log_directive,
};
#[cfg(feature = "tracing")]
use pingap_otel::{KeyValue, trace::Span};
#[cfg(feature = "tracing")]
use pingap_performance::{
    Prometheus, new_prometheus, new_prometheus_push_service,
};
use pingap_performance::{accept_request, end_request};
use pingap_upstream::{PeerAttempt, Upstream, UpstreamProvider};
use pingora::apps::HttpServerOptions;
use pingora::cache::cache_control::{CacheControl, InterpretCacheControl};
use pingora::cache::filters::resp_cacheable;
use pingora::cache::key::{CacheHashKey, HashBinary};
use pingora::cache::storage::HitHandler;
use pingora::cache::{
    CacheKey, CacheMeta, CacheMetaDefaults, ForcedFreshness, NoCacheReason,
    RespCacheable, VarianceBuilder,
};
#[cfg(feature = "tracing")]
use pingora::connectors::ConnectorOptions;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::listeners::TcpSocketOptions;
use pingora::modules::http::HttpModules;
use pingora::modules::http::compression::{
    ResponseCompression, ResponseCompressionBuilder,
};
use pingora::modules::http::grpc_web::{GrpcWeb, GrpcWebBridge};
use pingora::protocols::Digest;
use pingora::protocols::http::error_resp;
use pingora::protocols::http::v2::server::{H2Options, default_h2_options};
use pingora::proxy::{FailToProxy, ProxyServiceBuilder, http_proxy};
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::configuration;
use pingora::services::ServiceWithDependents;
use pingora::services::listening::Service;
use pingora::upstreams::peer::{HttpPeer, Peer};
use scopeguard::defer;
use snafu::Snafu;
use std::any::Any;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, warn};

/// Access-log lines dropped because the async logger channel was full.
static ACCESS_LOG_DROPPED: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Common error, category: {category}, {message}"))]
    Common { category: String, message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

/// Marks the start of a phase: the milliseconds since `started_at`, stored
/// as `-(elapsed + 1)` so that a start is always negative, even in the
/// request's first millisecond, and a finished latency never is.
#[inline]
pub fn get_start_time(started_at: &Instant) -> i32 {
    -(started_at.elapsed().as_millis() as i32) - 1
}

/// The latency of a phase from the marker `get_start_time` left; `None`
/// when there is no marker, including a latency that was already taken.
#[inline]
pub fn get_latency(started_at: &Instant, value: &Option<i32>) -> Option<i32> {
    let Some(value) = value else {
        return None;
    };
    if *value >= 0 {
        return None;
    }
    // elapsed - start, where start is `-value - 1`
    let latency = started_at.elapsed().as_millis() as i32 + *value + 1;

    Some(latency)
}

/// A 1xx other than 101: an interim response such as 103 Early Hints.
/// pingora runs the response hooks for it and then again for the final
/// response, which is the one the status, the timings and the plugins are
/// about.
#[inline]
fn is_interim_response(status: StatusCode) -> bool {
    status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS
}

/// Core HTTP proxy server implementation that handles request processing, caching, and monitoring.
/// Manages server configuration, connection lifecycle, and integration with various modules.
/// Carried from one HTTP/1 request to the next on the same downstream
/// connection; its presence is the whole message.
struct KeepaliveReuse;

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
    /// Which requests get a line in the access log; every one of them
    /// when there is none.
    log_filter: Option<AccessLogFilter>,

    /// HTML/JSON template used for rendering error responses, parsed once
    error_template: ErrorTemplate,

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

    /// The CA that clients' certificates are verified against, `None`
    /// when clients are not asked for one.
    tls_client_ca: Option<String>,

    /// Whether a client without a certificate is let in all the same.
    tls_client_auth_optional: bool,

    /// Whether HTTP/2 protocol is enabled
    enabled_h2: bool,
    /// Downstream HTTP/2 SETTINGS overrides, None = pingora's bounded defaults
    h2_max_concurrent_streams: Option<u32>,
    h2_max_header_list_size: Option<u32>,
    h2_initial_window_size: Option<u32>,
    h2_initial_connection_window_size: Option<u32>,
    /// Idle timeout for downstream HTTP/2 connections
    h2_idle_timeout: Option<Duration>,
    /// Serve HTTP/1.1 pipelined requests sequentially on a keep-alive connection
    h1_pipelining: bool,

    /// Whether Let's Encrypt certificate automation is enabled
    lets_encrypt_enabled: bool,

    /// Whether to use global certificate store for TLS
    global_certificates: bool,

    /// The JA4 fingerprints of this server's open TLS connections, filled
    /// before each handshake; `None` unless `ja4` is enabled.
    ja4: Option<Arc<Ja4Store>>,

    /// Whether the listeners read the PROXY protocol header of a
    /// trusted proxy for the address of the client.
    proxy_protocol: bool,

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

    // server locations
    server_locations_provider: Arc<dyn ServerLocationsProvider>,
    // plugin loader
    plugin_provider: Arc<dyn PluginProvider>,

    // locations
    location_provider: Arc<dyn LocationProvider>,

    // upstreams
    upstream_provider: Arc<dyn UpstreamProvider>,

    // certificates
    certificate_provider: Arc<dyn CertificateProvider>,

    // config manager
    config_manager: Arc<ConfigManager>,

    // logger
    access_logger: Option<Sender<BytesMut>>,
    /// The access log names no destination: its lines are events of the
    /// application log, handed to a task that writes them there.
    access_log_to_application: bool,
}

pub struct ServerServices {
    /// The listening service of the server, for
    /// `pingora::server::Server::add_boxed_service`. Boxed because it is
    /// one of two kinds: the HTTP application as pingora makes it, or,
    /// for a listener without TLS that reads the PROXY protocol, that
    /// application behind the reader of the header.
    pub lb: Box<dyn ServiceWithDependents>,
}

/// What the listeners of a server are made of.
struct ListenerParams {
    name: String,
    addr: String,
    threads: Option<usize>,
    tcp_socket_options: Option<TcpSocketOptions>,
    dynamic_cert: Option<GlobalCertificate>,
    tls: TlsSettingParams,
    ja4: Option<Arc<Ja4Store>>,
    proxy_protocol: bool,
}

impl ListenerParams {
    /// Gives `lb` its threads, what it does with a connection before
    /// the TLS handshake, and an endpoint for each address.
    fn add_to<A>(
        self,
        lb: &mut Service<A>,
        conf: &Arc<configuration::ServerConf>,
    ) -> Result<()> {
        let is_tls = self.dynamic_cert.is_some();
        lb.threads = self.threads;
        // pingora has one hook ahead of the handshake, in code its TLS
        // backends share, and it only ever runs on TLS listeners: the
        // PROXY protocol header of a listener without TLS is read by
        // `ProxyProtocolApp`, and config validation rejects `ja4` without
        // TLS.
        if self.ja4.is_some() && !is_tls {
            warn!(
                target: LOG_TARGET,
                name = self.name,
                "ja4 needs a TLS listener, not collecting it"
            );
        }
        if is_tls && (self.ja4.is_some() || self.proxy_protocol) {
            lb.endpoints().set_pre_tls_callback(Arc::new(PreTls {
                proxy_protocol: self.proxy_protocol,
                ja4: self.ja4.map(Ja4Collector::new),
            }));
        }
        // support listen multi address
        for addr in self
            .addr
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            // tls
            if let Some(dynamic_cert) = &self.dynamic_cert {
                let mut tls_settings = dynamic_cert
                    .new_tls_settings(&self.tls)
                    .map_err(|e| Error::Common {
                        category: "tls".to_string(),
                        message: e.to_string(),
                    })?;
                // Handshakes move to the dedicated pools when
                // `basic.downstream_tls_offload_*` asks for them. pingora
                // applies this per listener because every listener owns its
                // TlsSettings, and leaves it off while the pair is unset.
                tls_settings.set_offload_threadpool_from_server_conf(conf);
                lb.add_tls_with_settings(
                    addr,
                    self.tcp_socket_options.clone(),
                    tls_settings,
                );
            } else if let Some(opt) = &self.tcp_socket_options {
                lb.add_tcp_with_settings(addr, opt.clone());
            } else {
                lb.add_tcp(addr);
            }
        }
        Ok(())
    }
}

/// How long a response that names no lifetime of its own stays fresh: one
/// second, and only for the statuses RFC 9110 section 15.1 lists as
/// heuristically cacheable. Anything else - a 5xx, a 302, a 401 - is only
/// stored when the origin asks for it, so one client's error is not
/// replayed to the next.
fn default_fresh_duration(status: StatusCode) -> Option<Duration> {
    match status.as_u16() {
        200 | 203 | 204 | 206 | 300 | 301 | 308 | 404 | 405 | 410 | 414
        | 501 => Some(Duration::from_secs(1)),
        _ => None,
    }
}

const META_DEFAULTS: CacheMetaDefaults =
    CacheMetaDefaults::new(default_fresh_duration, 0, 1);

/// Whether an origin response's `Vary` names `*`, checked without building
/// the lowercased name list.
fn has_vary_star(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|name| name.trim() == "*")
}

/// The header names an origin response lists in `Vary`, trimmed and
/// lowercased.
fn vary_header_names(
    headers: &http::HeaderMap,
) -> impl Iterator<Item = String> + '_ {
    headers
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
}

/// Builds pingora's variance key for `req` from the response's `Vary`
/// header: one entry per named request header (an absent header counts as
/// empty), restricted to `allowed` when the cache plugin configured a list.
/// `None` when nothing varies, which keeps the single-slot behaviour.
fn cache_variance(
    headers: &http::HeaderMap,
    req: &RequestHeader,
    allowed: Option<&[String]>,
) -> Option<HashBinary> {
    let mut names: Vec<String> = vary_header_names(headers)
        .filter(|name| {
            allowed.is_none_or(|allowed| allowed.iter().any(|a| a == name))
        })
        .collect();
    names.sort();
    names.dedup();
    let mut builder = VarianceBuilder::new();
    for name in names.iter() {
        let value = req
            .headers
            .get(name.as_str())
            .map_or(&[][..], |value| value.as_bytes());
        builder.add_value(name, value);
    }
    builder.finalize()
}

/// Error response headers for the statuses pingap raises itself, built
/// once; any other status is generated on demand the way pingora does it.
static ERROR_RESPONSES: LazyLock<AHashMap<u16, ResponseHeader>> =
    LazyLock::new(|| {
        [400, 404, 408, 413, 429, 500, 502, 503, 504]
            .into_iter()
            .map(|code| (code, error_resp::gen_error_response(code)))
            .collect()
    });

/// The bare response header (status, server, date placeholder, cache
/// control) for an error status, cloned from a prebuilt one when there is
/// one.
pub fn error_response_header(code: u16) -> ResponseHeader {
    ERROR_RESPONSES
        .get(&code)
        .cloned()
        .unwrap_or_else(|| error_resp::gen_error_response(code))
}

/// The status to answer a proxy failure with, and whether the client is
/// gone, so that nothing can be sent to it.
///
/// pingora's own default writes nothing for a downstream read error, write
/// error or closed connection; a write that timed out is treated the same
/// here, since another write would only wait it out again. The `499` is
/// nginx's code for a client that went away, kept for the access log and
/// the metrics. A downstream read timeout is the client failing to send
/// its request or body in time, which is `408` (it used to fall through to
/// `500`).
fn classify_proxy_error(e: &pingora::Error) -> (u16, bool) {
    use pingora::ErrorType::*;
    match e.etype() {
        HTTPStatus(code) => (*code, false),
        // spellchecker:off
        _ => {
            match e.esource() {
                // An upstream that did not answer in time is a 504, one
                // that failed any other way a 502: they are different
                // things to be woken up for, and used to be one status.
                pingora::ErrorSource::Upstream => match e.etype() {
                    ConnectTimedout | ReadTimedout | WriteTimedout
                    | TLSHandshakeTimedout => (504, false),
                    _ => (502, false),
                },
                pingora::ErrorSource::Downstream => match e.etype() {
                    ConnectionClosed | ReadError | WriteError
                    | WriteTimedout => (499, true),
                    ReadTimedout | ConnectTimedout => (408, false),
                    // The request itself is malformed - e.g. `Connection`
                    // nominating Host, which the upstream request policy
                    // rejects. pingora's own default answers 400 here; 500
                    // would file a client mistake under server errors.
                    InvalidHTTPHeader => (400, false),
                    _ => (500, false),
                },
                pingora::ErrorSource::Internal
                | pingora::ErrorSource::Unset => (500, false),
            }
        },
        // spellchecker:on
    }
}

/// What the error page tells the client about a failure answered with
/// `code`.
///
/// A 4xx that pingap or a plugin raised carries a message written for the
/// client: which route did not match, which limit was exceeded. Every other
/// error describes the inside of the deployment - an upstream's address, a
/// file path, a pingora error chain - so the page only names the status,
/// and the error itself stays in the log line `fail_to_proxy` writes.
fn client_error_message(e: &pingora::Error, code: u16) -> &str {
    let is_status = |e: &pingora::Error| {
        matches!(e.etype(), pingora::ErrorType::HTTPStatus(_))
    };
    if (400..500).contains(&code) && is_status(e) {
        // The error as it was raised. One of a request that is being
        // proxied comes wrapped (`error_while_proxy`) in an error of the
        // same type whose context names the peer: that one is for the
        // log, and showed the address of the upstream on the page.
        let mut raised = e;
        while let Some(cause) = raised
            .cause
            .as_ref()
            .and_then(|cause| cause.downcast_ref::<pingora::BError>())
            && is_status(cause)
        {
            raised = cause;
        }
        if let Some(context) = &raised.context {
            return context.as_str();
        }
    }
    StatusCode::from_u16(code)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("Unknown Error")
}

#[derive(Clone)]
pub struct AppContext {
    pub logger: Option<Sender<BytesMut>>,
    pub config_manager: Arc<ConfigManager>,
    pub server_locations_provider: Arc<dyn ServerLocationsProvider>,
    pub location_provider: Arc<dyn LocationProvider>,
    pub upstream_provider: Arc<dyn UpstreamProvider>,
    pub plugin_provider: Arc<dyn PluginProvider>,
    pub certificate_provider: Arc<dyn CertificateProvider>,
}

impl Server {
    /// Creates a new HTTP proxy server instance with the given configuration.
    /// Initializes all server components including:
    /// - TCP socket options
    /// - TLS settings
    /// - Prometheus metrics (if enabled)
    /// - Threading configuration
    pub fn new(conf: &ServerConf, ctx: AppContext) -> Result<Self> {
        debug!(target: LOG_TARGET, config = conf.to_string(), "new server");
        let mut p = None;
        let (access_log, access_log_path) =
            parse_access_log_directive(conf.access_log.as_ref());
        if let Some(access_log) = access_log {
            p = Some(Parser::from(access_log.as_str()));
        }
        // The conditions are parameters of where the log goes to; one
        // that goes to the application log has no place to carry them.
        let log_filter = match &access_log_path {
            Some(target) => {
                let invalid = |message: String| Error::Common {
                    category: "access_log".to_string(),
                    message,
                };
                // The other parameters of the destination are read by
                // the task that writes the log, which a check of the
                // configuration does not start.
                check_access_log_target(target)
                    .map_err(|e| invalid(e.to_string()))?;
                AccessLogFilter::new(target)
                    .map_err(|e| invalid(e.to_string()))?
            },
            None => None,
        };
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
            log_filter,
            error_template: ErrorTemplate::new(&conf.error_template),
            tls_cipher_list: conf.tls_cipher_list.clone(),
            tls_ciphersuites: conf.tls_ciphersuites.clone(),
            tls_min_version: conf.tls_min_version.clone(),
            tls_max_version: conf.tls_max_version.clone(),
            tls_client_ca: conf.tls_client_ca.clone(),
            tls_client_auth_optional: conf.tls_client_auth_optional,
            threads: conf.threads,
            lets_encrypt_enabled: false,
            global_certificates: conf.global_certificates,
            ja4: conf.ja4.then(|| Arc::new(Ja4Store::default())),
            proxy_protocol: conf.proxy_protocol,
            enabled_h2: conf.enabled_h2,
            h2_max_concurrent_streams: conf.h2_max_concurrent_streams,
            h2_max_header_list_size: conf.h2_max_header_list_size,
            h2_initial_window_size: conf.h2_initial_window_size,
            h2_initial_connection_window_size: conf
                .h2_initial_connection_window_size,
            h2_idle_timeout: conf.h2_idle_timeout,
            h1_pipelining: conf.h1_pipelining,
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
            server_locations_provider: ctx.server_locations_provider,
            location_provider: ctx.location_provider,
            upstream_provider: ctx.upstream_provider,
            plugin_provider: ctx.plugin_provider,
            certificate_provider: ctx.certificate_provider,
            access_logger: ctx.logger,
            access_log_to_application: access_log_path.is_none(),
            config_manager: ctx.config_manager,
        };
        Ok(s)
    }
    /// Downstream HTTP/2 SETTINGS for this listener. `None` when nothing is
    /// configured, so pingora's bounded defaults apply untouched. Otherwise
    /// start from those same defaults - `H2Options::default()` is the bare h2
    /// builder, with no stream cap and a 16 MiB header list, which would undo
    /// the memory-exhaustion mitigation - and override only what is set.
    fn new_h2_options(&self) -> Option<H2Options> {
        if self.h2_max_concurrent_streams.is_none()
            && self.h2_max_header_list_size.is_none()
            && self.h2_initial_window_size.is_none()
            && self.h2_initial_connection_window_size.is_none()
        {
            return None;
        }
        let mut options = default_h2_options();
        if let Some(value) = self.h2_max_concurrent_streams {
            options.max_concurrent_streams(value);
        }
        if let Some(value) = self.h2_max_header_list_size {
            options.max_header_list_size(value);
        }
        if let Some(value) = self.h2_initial_window_size {
            options.initial_window_size(value);
        }
        if let Some(value) = self.h2_initial_connection_window_size {
            options.initial_connection_window_size(value);
        }
        Some(options)
    }
    /// Lets this server answer ACME http-01 challenges at
    /// `/.well-known/acme-challenge`: for a server on port 80, where a CA
    /// comes for them. Whether a request to that path is a challenge of
    /// this proxy is decided when it arrives, by the certificates of the
    /// configuration that is running then.
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
                            target: LOG_TARGET,
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
        conf: Arc<configuration::ServerConf>,
    ) -> Result<ServerServices> {
        self.build(conf, true)
    }
    /// Builds what [`Server::run`] builds and drops it, for a check of the
    /// configuration: the TLS settings of each listener are made, which is
    /// where a cipher list or a protocol version that the TLS library does
    /// not take is found. Nothing is bound: a listener opens its socket
    /// when its service is started, and this one never is.
    pub fn check(self, conf: Arc<configuration::ServerConf>) -> Result<()> {
        self.build(conf, false).map(|_| ())
    }
    fn build(
        self,
        conf: Arc<configuration::ServerConf>,
        announce: bool,
    ) -> Result<ServerServices> {
        let addr = self.addr.clone();
        let tcp_socket_options = self.tcp_socket_options.clone();

        let name = self.name.clone();
        let mut dynamic_cert = None;
        // tls
        if self.global_certificates {
            dynamic_cert =
                Some(GlobalCertificate::new(self.certificate_provider.clone()));
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

        if announce {
            info!(
                target: LOG_TARGET,
                name,
                addr,
                threads,
                is_tls,
                h2 = enabled_h2,
                tcp_socket_options = format!("{:?}", tcp_socket_options),
                "server is listening"
            );
        }
        let h2_options = self.new_h2_options();
        let mut http_server_options = HttpServerOptions::default();
        // use h2c if not tls and enable http2
        http_server_options.h2c = !is_tls && enabled_h2;
        http_server_options.h2_idle_timeout = self.h2_idle_timeout;
        let listeners = ListenerParams {
            name: name.clone(),
            addr,
            threads,
            tcp_socket_options,
            dynamic_cert,
            tls: TlsSettingParams {
                server_name: name,
                enabled_h2,
                cipher_list: self.tls_cipher_list.clone(),
                cipher_suites: self.tls_ciphersuites.clone(),
                tls_min_version: self.tls_min_version.clone(),
                tls_max_version: self.tls_max_version.clone(),
                client_ca: self.tls_client_ca.clone(),
                client_auth_optional: self.tls_client_auth_optional,
            },
            ja4: self.ja4.clone(),
            proxy_protocol: self.proxy_protocol,
        };
        const SERVICE_NAME: &str = "Pingora HTTP Proxy Service";
        // A listener without TLS that reads the PROXY protocol: pingora
        // has no place for that ahead of its HTTP application, so the
        // application is made here and put behind the reader of the
        // header. What its builder would add is not there this way, which
        // is the report of how long evicted upstream connections had been
        // idle (see below).
        if self.proxy_protocol && !is_tls {
            let mut http_logic = http_proxy(&conf, self);
            http_logic.server_options = Some(http_server_options);
            http_logic.h2_options = h2_options;
            let mut lb = Service::new(
                SERVICE_NAME.to_string(),
                ProxyProtocolApp::new(http_logic),
            );
            listeners.add_to(&mut lb, &conf)?;
            return Ok(ServerServices { lb: Box::new(lb) });
        }
        #[cfg(feature = "tracing")]
        let pool_observer = self.prometheus.clone();
        let builder = ProxyServiceBuilder::new(&conf, self).name(SERVICE_NAME);
        // With metrics enabled, pingora reports every keep-alive pool
        // eviction together with how long the evicted upstream connection
        // had been idle; feed that into this server's registry.
        #[cfg(feature = "tracing")]
        let builder = match pool_observer {
            Some(prometheus) => {
                let mut options = ConnectorOptions::from_server_conf(&conf);
                options.keepalive_pool_callback = Some(Arc::new(move |idle| {
                    prometheus.observe_upstream_pool_eviction(idle)
                }));
                builder.client_options(options)
            },
            None => builder,
        };
        let mut lb = builder.build();
        if let Some(http_logic) = lb.app_logic_mut() {
            http_logic.server_options = Some(http_server_options);
            // Applies to every h2 handshake this listener performs, TLS/ALPN
            // and h2c alike. None keeps pingora's bounded defaults.
            http_logic.h2_options = h2_options;
        }
        listeners.add_to(&mut lb, &conf)?;
        Ok(ServerServices { lb: Box::new(lb) })
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
            // HTTP/1: pingora already told us about keepalive reuse through
            // on_connection_reuse(), which runs before this. HTTP/2 streams
            // share one connection with no such signal, so only there is the
            // "older than 100 ms" guess still applied.
            if session.is_http2() {
                ctx.conn.reused = digest_detail.connection_reused;
            }

            // The handshake only costs the first request on a connection.
            // Prefer the TLS layer's own measurement; the wall-clock gap
            // between the layers' timestamps is the fallback.
            if !ctx.conn.reused
                && let Some(handshake) =
                    digest_detail.tls_handshake.or_else(|| {
                        (digest_detail.tls_established
                            >= digest_detail.tcp_established
                            && digest_detail.tls_established > 0)
                            .then(|| {
                                digest_detail.tls_established
                                    - digest_detail.tcp_established
                            })
                    })
            {
                ctx.timing.tls_handshake = Some(handshake as i32);
            }
            ctx.conn.tls_cipher = digest_detail.tls_cipher;
            ctx.conn.tls_version = digest_detail.tls_version;
            ctx.conn.tls_client_cert = digest_detail.tls_client_cert;
            // The fingerprint was filed under this connection's socket
            // digest before its handshake.
            if let Some(store) = &self.ja4
                && digest.ssl_digest.is_some()
                && let Some(socket_digest) = &digest.socket_digest
            {
                ctx.conn.ja4 = store.get(socket_digest);
            }
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
        // Matched in normalized form, so an encoded or roundabout spelling
        // of a path lands in the location of the path it stands for. The
        // request itself is not changed.
        let path = &pingap_core::normalize_path(header.uri.path());

        // locations not found
        let Some(route) = self.server_locations_provider.get(&self.name) else {
            return Ok(());
        };

        // Host-bucket index shrinks candidates; weight order is preserved so
        // the first full match equals a linear scan of `route.ordered`.
        let matched_info = route
            .host_index
            .candidate_indices(host)
            .into_iter()
            .find_map(|idx| {
                // The route holds the location of each name, so a candidate
                // costs no lookup and only the one that matches is cloned.
                // A route made from names alone holds none, and those are
                // looked up as they used to be.
                let looked_up;
                let location = match route.location(idx) {
                    Some(location) => location,
                    None => {
                        let name = route.ordered.get(idx)?;
                        looked_up = self.location_provider.get(name)?;
                        &looked_up
                    },
                };
                let (matched, captures) = location.match_host_path(host, path);
                if matched && location.match_conditions(header) {
                    Some((location.clone(), captures))
                } else {
                    None
                }
            });

        let Some((location, captures)) = matched_info else {
            return Ok(());
        };

        // The name is all the access log and the per-location metrics
        // need; they pair their own counters by it.
        ctx.upstream.location = location.name.clone();
        if let Some(captures) = captures {
            ctx.extend_variables(captures);
        }

        debug!(
            target: LOG_TARGET,
            "variables: {:?}",
            ctx.features.as_ref().map(|item| &item.variables)
        );

        // set prometheus stats
        #[cfg(feature = "tracing")]
        if let Some(prom) = &self.prometheus {
            prom.on_location_matched(&ctx.upstream.location);
        }

        // The plugins of the location, ahead of everything that may
        // refuse the request: the page of an error is asked of them
        // (`error_page`), and so are the headers the location sets on
        // every response. Set where they are first run, the `413` and the
        // `429` below went out with the page of the server and without
        // the CORS headers of the location.
        let plugins = location.plugins_for(self.plugin_provider.as_ref());
        if let Some(plugins) = &plugins {
            keep_response_plugins(ctx, plugins);
        }
        ctx.plugins = plugins;

        // Rejected before the location counts the request. `logging` calls
        // `on_response` for whatever `location_instance` holds, so the
        // instance is only recorded once `on_request` is about to run: a
        // 413 used to leave it in place without the matching increment,
        // and every such request pushed the location's processing count
        // one below the truth, loosening `max_processing` a little more.
        location
            .validate_content_length(header)
            .map_err(|e| new_internal_error(413, e))?;

        ctx.upstream.location_instance = Some(location.clone());
        ctx.upstream.max_retries = location.max_retries;
        ctx.upstream.max_retry_window = location.max_retry_window;

        // `on_request` counts the request before it can reject it with a
        // 429, and the instance is recorded already, so that rejection is
        // undone in `logging` like any completed request.
        let (accepted, processing) = location.on_request()?;
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

        // The first step of the plugins. A plugin answering here is
        // honoured by `request_filter`, which is where pingora first lets
        // the request stop; the flag is the response itself.
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
        if self.lets_encrypt_enabled
            && is_http_challenge_path(session.req_header().uri.path())
        {
            return match handle_lets_encrypt(
                self.config_manager.clone(),
                session,
                ctx,
            )
            .await
            {
                Ok(true) => Some(Ok(true)), // handle ACME request
                Ok(false) => None,          // not ACME request, continue
                Err(e) => Some(Err(e)),
            };
        }
        None // not enable ACME, continue
    }
    #[inline]
    #[cfg(feature = "tracing")]
    async fn handle_metrics_request(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> Option<pingora::Result<bool>> {
        let header = session.req_header();
        let should_handle = !self.prometheus_push_mode
            && self.prometheus.is_some()
            && header.uri.path() == self.prometheus_metrics;

        if should_handle {
            let prom = self.prometheus.as_ref()?;
            let result = async {
                // The path belongs to a location like any other, and what
                // guards that location guards the metrics: its request
                // plugins run first, and one that answers - a 401, a 403 -
                // has answered. The endpoint used to be served ahead of
                // them, to anyone who could reach the port, next to a
                // location that asked everyone else for a password.
                if ctx.upstream.location_instance.is_some()
                    && self
                        .handle_request_plugin(
                            PluginStep::Request,
                            session,
                            ctx,
                        )
                        .await?
                {
                    return Ok(true);
                }
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
        let Some(location) = &ctx.upstream.location_instance else {
            let header = session.req_header();
            let host = pingap_core::get_host(header).unwrap_or_default();
            let message = format!(
                "No matching location, host:{host} path:{}",
                header.uri.path()
            );
            // Nothing is configured for this host/path, which is the
            // client's problem (wrong Host, unknown route), not a server
            // fault: answer 404 rather than 500.
            return Err(pingap_core::new_internal_error(404, message));
        };

        debug!(
            target: LOG_TARGET,
            server = self.name,
            location = location.name(),
            "location is matched"
        );

        // Taken out so the rewrite can read and extend them without
        // borrowing `ctx`, then put back with any captures added.
        let mut variables = ctx
            .features
            .as_mut()
            .and_then(|features| features.variables.take());
        let original_uri = location
            .has_rewrite()
            .then(|| session.req_header().uri.clone());
        let rewritten =
            location.rewrite(session.req_header_mut(), &mut variables);
        if let Some(variables) = variables {
            ctx.extend_variables(variables);
        }
        let rewritten = rewritten?;
        if rewritten {
            ctx.features.get_or_insert_default().original_uri = original_uri;
        }

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

/// Sends the response that the plugin at `responder` answered a request
/// with.
///
/// It goes out from the request step and never reaches the response step,
/// so what the plugins of that step add was missing from it. For CORS that
/// is more than a missing header: a 401 or a 429 without it is withheld
/// from the page by the browser, which reports a failed request. The
/// plugins that ask for it (`handles_plugin_response`) get to set their
/// headers; the responder itself has said what it had to say.
async fn send_plugin_response(
    session: &mut Session,
    ctx: &mut Ctx,
    plugins: &[pingap_core::NamedPlugin],
    responder: usize,
    resp: pingap_core::HttpResponse,
) -> pingora::Result<()> {
    // Built only when a plugin wants it: most responses go out as they are.
    let mut header = None;
    for (index, (_, plugin)) in plugins.iter().enumerate() {
        if index == responder || !plugin.handles_plugin_response() {
            continue;
        }
        let header = match &mut header {
            Some(header) => header,
            None => header.insert(resp.new_response_header()?),
        };
        plugin.handle_response(session, ctx, header).await?;
    }
    match header {
        Some(header) => resp.send_with_header(session, header).await?,
        None => resp.send(session).await?,
    };
    Ok(())
}

/// Whether the response is one from the cache whose body pingora ends
/// without saying so to `response_body_filter`.
///
/// A response found in the cache is read to the client by
/// `proxy_cache_hit`, which passes the end of the body on like any other
/// (a last, empty chunk with `end_of_stream`). Not so the stored response
/// that is sent after the upstream was asked: one it confirmed with a
/// `304`, and a stale one answered for its `5xx`. Those are fed through
/// the path of an upstream response (pingora's `ServeFromCache`), chunk
/// after chunk with `end_of_stream` unset, and ended by a task of their
/// own (`HttpTask::Done`) that no body filter is called for. A plugin
/// that holds the body until its end and writes it then - `sub_filter`
/// has to see all of it - kept waiting, and the client got a `200` with
/// nothing in it: for every stored page, once each time it expired and
/// was confirmed. Where the end is not said the proxy asks the storage,
/// which knows when it has handed out the last piece.
///
/// (pingora 0.9: `proxy_cache.rs`, `ServeFromCache::next_http_task`, and
/// `h1_response_filter` / `h2_response_filter`, which pass `Done` on.)
fn cached_body_ends_unsaid(
    phase: pingora::cache::CachePhase,
    stale_for_status: bool,
) -> bool {
    use pingora::cache::CachePhase;
    match phase {
        CachePhase::Revalidated | CachePhase::RevalidatedNoCache(_) => true,
        CachePhase::Stale => stale_for_status,
        _ => false,
    }
}

/// Notes the plugins of the location for the responses that do not pass
/// the response step - one a plugin writes itself, an error page -, when
/// one of them sets headers on those too: see `decorate_plugin_response`.
fn keep_response_plugins(
    ctx: &mut Ctx,
    plugins: &Arc<[pingap_core::NamedPlugin]>,
) {
    if ctx.response_plugins.is_none()
        && plugins
            .iter()
            .any(|(_, plugin)| plugin.handles_plugin_response())
    {
        ctx.response_plugins = Some(plugins.clone());
    }
}

impl Server {
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
        keep_response_plugins(ctx, &plugins);

        let result = async {
            let mut request_done = false;
            for (index, (name, plugin)) in plugins.iter().enumerate() {
                let now = Instant::now();
                let result = plugin.handle_request(step, session, ctx).await?;
                let elapsed = now.elapsed().as_millis() as u32;

                // extract repeated logging and timing logic
                let mut record_time = |msg: &str| {
                    debug!(
                        target: LOG_TARGET,
                        name = &**name,
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
                            send_plugin_response(
                                session, ctx, &plugins, index, resp,
                            )
                            .await?;
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
                        target: LOG_TARGET,
                        name = &**name, elapsed, "response plugin modify headers"
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

        // The plugins are put back whatever one of them says: the error
        // page that follows an error is asked of them. Left with `?`,
        // they were gone with it.
        let mut result = Ok(());
        for (name, plugin) in plugins.iter() {
            let now = Instant::now();
            match plugin.handle_upstream_response(
                session,
                ctx,
                upstream_response,
            ) {
                Ok(ResponsePluginResult::Modified) => {
                    let elapsed = now.elapsed().as_millis() as u32;
                    debug!(
                        target: LOG_TARGET,
                        name = &**name,
                        elapsed,
                        "upstream response plugin modify headers"
                    );
                    ctx.add_plugin_processing_time(name, elapsed);
                },
                Ok(_) => {},
                Err(e) => {
                    result = Err(e);
                    break;
                },
            }
        }
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
        // Same reasoning as handle_response_body_plugin: after the 101 these
        // bytes are the upgraded protocol, not a body to rewrite.
        if session.was_upgraded() {
            return Ok(());
        }
        let plugins = match ctx.plugins.take() {
            Some(p) => p,
            None => return Ok(()), // No plugins, exit early.
        };
        if plugins.is_empty() {
            return Ok(());
        }

        // Put back also after an error, as in
        // `handle_upstream_response_plugin`.
        let mut result = Ok(());
        for (name, plugin) in plugins.iter() {
            let now = Instant::now();
            match plugin.handle_upstream_response_body(
                session,
                ctx,
                body,
                end_of_stream,
            ) {
                Ok(
                    ResponseBodyPluginResult::PartialReplaced
                    | ResponseBodyPluginResult::FullyReplaced,
                ) => {
                    let elapsed = now.elapsed().as_millis() as u32;
                    ctx.add_plugin_processing_time(name, elapsed);
                    debug!(
                        target: LOG_TARGET,
                        name = &**name, elapsed, "response body plugin modify body"
                    );
                },
                Ok(_) => {},
                Err(e) => {
                    result = Err(e);
                    break;
                },
            }
        }
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
        // Once the upstream answered 101 the connection carries the upgraded
        // protocol, not an HTTP body, so a body-rewriting plugin would corrupt
        // it (#114, sub_filter breaking websockets).
        //
        // The test is `was_upgraded`, which is only true after the backend's
        // 101, never `is_upgrade_req`: pingora treats any HTTP/1.1 request
        // carrying an `Upgrade` header as an upgrade request without checking
        // its value, so keying off the request would let a client turn plugins
        // off with one header.
        if session.was_upgraded() {
            return Ok(());
        }
        let plugins = match ctx.plugins.take() {
            Some(p) => p,
            None => return Ok(()), // No plugins, exit early.
        };
        if plugins.is_empty() {
            return Ok(());
        }
        // Put back also after an error, as in
        // `handle_upstream_response_plugin`.
        let mut result = Ok(());
        for (name, plugin) in plugins.iter() {
            let now = Instant::now();
            match plugin.handle_response_body(session, ctx, body, end_of_stream)
            {
                Ok(
                    ResponseBodyPluginResult::PartialReplaced
                    | ResponseBodyPluginResult::FullyReplaced,
                ) => {
                    let elapsed = now.elapsed().as_millis() as u32;
                    ctx.add_plugin_processing_time(name, elapsed);
                    debug!(
                        target: LOG_TARGET,
                        name = &**name, elapsed, "response body plugin modify body"
                    );
                },
                Ok(_) => {},
                Err(e) => {
                    result = Err(e);
                    break;
                },
            }
        }
        ctx.plugins = Some(plugins);
        result
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

/// Notes the backend of the attempt that has just failed, for the next
/// one to go to another.
fn remember_failed_backend(ctx: &mut Ctx) {
    let address = &ctx.upstream.address;
    if !address.is_empty()
        && !ctx
            .upstream
            .failed_addresses
            .iter()
            .any(|item| item == address)
    {
        ctx.upstream.failed_addresses.push(address.clone());
    }
}

/// Whether the target of the request is one of the forms a request has
/// (RFC 9112 §3.2): a path (`/a?b=1`), a url (`http://host/a`) or `*`.
///
/// pingora keeps a target of any other kind (`GET robots.txt HTTP/1.1`,
/// no slash in front) as it came for the request to the upstream, and
/// gives the uri of the request the path `/`. Everything here goes by
/// that uri: such a request matched the locations of `/`, ran their
/// plugins and was kept by a cache under the key of `/` - while the
/// upstream was asked for `robots.txt`. `secret/report` got past the
/// plugins of a location for `/secret` that way, and a `404` for `nf`
/// became the cached front page. It is no request, and is answered
/// with `400` before any of that.
fn has_routable_target(header: &RequestHeader) -> bool {
    use pingora::protocols::http::authority::{
        RawTargetAuthority, raw_target_authority,
    };
    let target = header.raw_path();
    if target.is_empty()
        || matches!(target.first(), Some(b'/' | b'?'))
        || target == b"*"
    {
        return true;
    }
    matches!(
        raw_target_authority(target),
        RawTargetAuthority::Absolute { .. }
    )
}

#[async_trait]
impl ProxyHttp for Server {
    type CTX = Ctx;
    fn new_ctx(&self) -> Self::CTX {
        debug!(target: LOG_TARGET, "new ctx");
        Ctx::new()
    }
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        debug!(target: LOG_TARGET, "--> init downstream modules");
        defer!(debug!(target: LOG_TARGET, "<-- init downstream modules"););
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
        debug!(target: LOG_TARGET, "--> early request filter");
        defer!(debug!(target: LOG_TARGET, "<-- early request filter"););

        self.initialize_context(session, ctx);
        // Before anything goes by the path: see `has_routable_target`.
        if !has_routable_target(session.req_header()) {
            return Err(new_internal_error(
                400,
                "the target of the request is not a path or a url",
            ));
        }
        pingap_core::merge_cookie_headers(session.req_header_mut());
        // Counted before any routing, so the totals cover requests that
        // match no location, the admin endpoints, ACME challenges and the
        // metrics endpoint itself.
        #[cfg(feature = "tracing")]
        if let Some(prom) = &self.prometheus {
            prom.on_request_start();
        }
        if self.h1_pipelining {
            // Opt this HTTP/1.1 connection into sequential pipelining
            // (RFC 9112 §9.3.2). pingora keeps the flag across keep-alive
            // reuses and ignores it on HTTP/2.
            session.as_downstream_mut().set_pipelining_enabled(true);
        }
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
        debug!(target: LOG_TARGET, "--> request filter");
        defer!(debug!(target: LOG_TARGET, "<-- request filter"););
        // pingora cannot stop after early_request_filter, so a plugin that
        // answered at the EarlyRequest step arrives here with its response
        // already on the wire. Nothing else writes one before this point,
        // and proxying on top of it would have pingora drop the second
        // header with a warning and append the upstream body to the
        // plugin's page.
        if session.response_written().is_some() {
            return Ok(true);
        }
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
        debug!(target: LOG_TARGET, "--> proxy upstream filter");
        defer!(debug!(target: LOG_TARGET, "<-- proxy upstream filter"););
        let done = self
            .handle_request_plugin(PluginStep::ProxyUpstream, session, ctx)
            .await?;

        if done {
            return Ok(false);
        }
        // The last of the filters: see `RequestState::proxying`.
        ctx.state.proxying = true;
        Ok(true)
    }

    /// Selects and configures the upstream peer to proxy to.
    /// Handles upstream connection pooling and health checking.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<Box<HttpPeer>> {
        debug!(target: LOG_TARGET, "--> upstream peer");
        defer!(debug!(target: LOG_TARGET, "<-- upstream peer"););

        let no_available_upstream = |ctx: &Ctx| {
            new_internal_error(
                503,
                format!("No available upstream for {}", ctx.upstream.location),
            )
        };
        let location = ctx.upstream.location_instance.clone();
        let upstream = location.as_ref().and_then(|location| {
            let name = if ctx.upstream.name.is_empty() {
                location.upstream()
            } else {
                // override upstream by other plugin
                &ctx.upstream.name
            };
            get_upstream_with_variables(
                name,
                ctx,
                self.upstream_provider.as_ref(),
            )
        });
        let Some(upstream) = upstream else {
            return Err(no_available_upstream(ctx));
        };
        ctx.upstream.connected_count = upstream.connected();
        ctx.upstream.name = upstream.name.clone();
        #[cfg(feature = "tracing")]
        if let Some(features) = &ctx.features
            && let Some(tracer) = &features.otel_tracer
        {
            let name = format!("upstream.{}", upstream.name);
            let mut span = tracer.new_upstream_span(&name);
            span.set_attribute(KeyValue::new(
                "upstream.connected",
                ctx.upstream.connected_count.unwrap_or_default() as i64,
            ));
            let features = ctx.features.get_or_insert_default();
            features.upstream_span = Some(span);
        }
        // Count processing only on the first attempt: pingora re-calls
        // upstream_peer on every retry, and completed() runs once. Told by
        // the upstream being recorded already, not by `retries`: that only
        // counts failed connects, and a retry after a reused connection
        // went stale came here looking like a first attempt.
        let first_attempt = ctx.upstream.upstream_instance.is_none();
        if !first_attempt {
            // The body kept for the retry is sent through
            // `request_body_filter` again; counted twice it could pass
            // `client_max_body_size` on its own.
            ctx.state.payload_size = 0;
            // And whoever follows the body starts over with it.
            if let Some(handlers) = ctx
                .features
                .as_mut()
                .and_then(|features| features.request_body_handlers.as_mut())
            {
                for handler in handlers.iter_mut() {
                    handler.restart();
                }
            }
        }
        // Async: a transparent upstream resolves the request's host here.
        // A retry goes to another backend than the ones that have just
        // failed this request, where there is one.
        let Some(mut peer) = upstream
            .new_http_peer_for(
                session,
                PeerAttempt {
                    client_ip: &mut ctx.conn.client_ip,
                    count_processing: first_attempt,
                    failed: &ctx.upstream.failed_addresses,
                    inflight: Some(&mut ctx.upstream.backend_inflight),
                    sticky_cookie: Some(&mut ctx.upstream.sticky_cookie),
                },
            )
            .await
        else {
            return Err(no_available_upstream(ctx));
        };
        // What this location waits for the upstream, where it says so.
        if let Some(location) = &location {
            location.apply_timeouts(&mut peer.options);
        }
        // Recorded only now that there is a peer: `new_http_peer` counts
        // the request once it has one, and `logging` takes that count back
        // for the instance it finds here. Recorded earlier, a request that
        // found no backend was uncounted without ever being counted.
        ctx.upstream.upstream_instance = Some(upstream);
        ctx.upstream.address = peer.address().to_string();

        // start connect to upstream
        ctx.timing.upstream_connect =
            Some(get_start_time(&ctx.timing.created_at));

        Ok(Box::new(peer))
    }
    /// Runs after `logging` when the downstream HTTP/1 connection stays open
    /// for another request. Whatever this returns reaches that request's
    /// `on_connection_reuse`, and returning `None` skips the hook entirely,
    /// so a marker goes back even though nothing needs carrying over: the
    /// next request has to learn that its connection is a reused one.
    fn persist_connection_context(
        &self,
        _session: &Session,
        _ctx: &Self::CTX,
    ) -> Option<Box<dyn Any + Send + Sync>> {
        Some(Box::new(KeepaliveReuse))
    }

    /// The exact HTTP/1 keepalive signal. It replaces the "connection older
    /// than 100 ms" guess for this protocol, which flagged the first request
    /// on a fresh connection whenever the handshake or the client took longer
    /// than that; `initialize_context` leaves the flag alone for HTTP/1.
    fn on_connection_reuse(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
        _prev_ctx: Box<dyn Any + Send + Sync>,
    ) {
        ctx.conn.reused = true;
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
        debug!(target: LOG_TARGET, "--> connected to upstream");
        defer!(debug!(target: LOG_TARGET, "<-- connected to upstream"););
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
    /// An error after the connection to the upstream was established.
    ///
    /// The retry decision is pingora's default one. What this adds is the
    /// report to the backend's statistics: `fail_to_connect` covers a
    /// backend that cannot be reached, and nothing covered one that accepts
    /// the connection and then never answers. To the circuit breaker such a
    /// request had no outcome at all, so the breaker neither tripped on a
    /// hanging backend nor got an answer to the probes it sent to one.
    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<pingora::Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<pingora::Error> {
        let mut e = e.more_context(format!("Peer: {peer}"));
        // The cookie of a `sticky` upstream was for the backend of this
        // attempt. A retry has its own, and a stale response of the
        // cache that is answered in place of the error is not to keep
        // the client on the backend that has just failed.
        ctx.upstream.sticky_cookie = None;
        // A pooled connection the backend had already closed. That says
        // nothing about its health, whether the request is retried (a GET)
        // or not (a POST), so it is read before the retry is decided.
        let stale_connection =
            client_reused && matches!(e.retry, pingora::RetryType::ReusedOnly);
        if !session.req_header().method.is_idempotent()
            || session.as_ref().retry_buffer_truncated()
        {
            e.set_retry(false);
        } else {
            e.retry.decide_reuse(client_reused);
        }
        // Not once a response header arrived either, `on_response` has
        // counted that request.
        if !stale_connection
            && e.esource() == &pingora::ErrorSource::Upstream
            && ctx.upstream.status.is_none()
            && let Some(upstream_instance) = &ctx.upstream.upstream_instance
        {
            upstream_instance.on_transport_failure(&ctx.upstream.address);
        }
        // The retry goes elsewhere, unless what failed was only the
        // connection: one that had been kept too long, or an HTTP/2 one
        // that the backend is retiring (`GOAWAY`, a stream it refuses)
        // or that has to be HTTP/1.1 after all. The backend is as good
        // as it was, and by a hash it is where the request belongs.
        let connection_only = stale_connection
            || matches!(
                e.etype(),
                pingora::ErrorType::H2Error
                    | pingora::ErrorType::H2Downgrade
                    | pingora::ErrorType::InvalidH2
            );
        if e.retry() && !connection_only {
            remember_failed_backend(ctx);
        }
        e
    }
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        // The peer is the one `upstream_peer` just returned, whose address
        // it recorded on the context; no need to format it again.
        if let Some(upstream_instance) = &ctx.upstream.upstream_instance {
            upstream_instance.on_transport_failure(&ctx.upstream.address);
        }
        // As in `error_while_proxy`: no cookie for a backend that could
        // not be reached.
        ctx.upstream.sticky_cookie = None;
        let Some(max_retries) = ctx.upstream.max_retries else {
            return e;
        };
        if ctx.upstream.retries >= max_retries {
            return e;
        }
        if let Some(max_retry_window) = ctx.upstream.max_retry_window
            && ctx.timing.created_at.elapsed() > max_retry_window
        {
            return e;
        }
        ctx.upstream.retries += 1;
        remember_failed_backend(ctx);
        e.set_retry(true);
        e
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
        debug!(target: LOG_TARGET, "--> upstream request filter");
        defer!(debug!(target: LOG_TARGET, "<-- upstream request filter"););
        // Ahead of the location's headers, which may say otherwise.
        #[cfg(feature = "tracing")]
        inject_trace_context(ctx, upstream_response);
        set_append_proxy_headers(session, ctx, upstream_response);
        // A cache that makes its key of a part of the query asks the
        // upstream with that part, so that what is stored under a key
        // can not depend on a parameter the key leaves out.
        if let Some(cache) = &ctx.cache
            && !cache.ask_with_key_query(upstream_response)
        {
            return Err(new_internal_error(
                400,
                "the query of the request can not be sent to the upstream",
            ));
        }
        Ok(())
    }
    /// Filters request body chunks before sending upstream.
    /// Tracks payload size and enforces size limits.
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        debug!(target: LOG_TARGET, "--> request body filter");
        defer!(debug!(target: LOG_TARGET, "<-- request body filter"););
        if let Some(buf) = body {
            ctx.state.payload_size += buf.len();
            // After a 101 this is no request body any more but the
            // client's half of the tunnel, which pingora still passes
            // through here. It is counted, as before, and not held to
            // `client_max_body_size`: a websocket was cut off once its
            // client had sent that many bytes in total.
            if session.was_upgraded() {
                return Ok(());
            }
            if let Some(location) = &ctx.upstream.location_instance {
                let size = location.client_body_size_limit();
                if size > 0 && ctx.state.payload_size > size {
                    return Err(new_internal_error(
                        413,
                        format!("Request Entity Too Large, max:{size}"),
                    ));
                }
            }
        }
        // The plugins that follow the body: a digest to check, a copy to
        // keep. Not what comes after a 101, which is no body.
        if session.was_upgraded() {
            return Ok(());
        }
        if let Some(handlers) = ctx
            .features
            .as_mut()
            .and_then(|features| features.request_body_handlers.as_mut())
        {
            // No chunk is the end as well, as pingora has it.
            let end_of_stream = end_of_stream || body.is_none();
            for handler in handlers.iter_mut() {
                handler.handle(body.as_ref(), end_of_stream)?;
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
        debug!(target: LOG_TARGET, "--> cache key callback");
        defer!(debug!(target: LOG_TARGET, "<-- cache key callback"););
        // Every request plugin has run by now: the query the key is made
        // of is the one of the request as they left it, and the upstream
        // is asked with the same.
        if let Some(cache) = ctx.cache.as_mut() {
            cache.settle_key_query(session.req_header());
        }
        let key = get_cache_key(
            ctx,
            session.req_header().method.as_ref(),
            session.req_header(),
        );
        debug!(
            target: LOG_TARGET,
            primary = key.primary_key_str(),
            // The namespace: it rides in user_tag now that CacheKey has no
            // namespace field of its own.
            user_tag = key.user_tag(),
            "cache key callback"
        );
        Ok(key)
    }

    /// Permit Pingora to serve an expired entry while its lock holder
    /// revalidates it in a background subrequest. The cache metadata still
    /// bounds this path to the origin's `stale-while-revalidate` window.
    fn should_serve_stale(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
        error: Option<&pingora::Error>,
    ) -> bool {
        match error {
            Some(error) => {
                let stale = error.esource() == &pingora::ErrorSource::Upstream;
                // The stale response goes out in place of what a backend
                // failed to give: the cookie of a `sticky` upstream is
                // not to keep the client on that backend. A connection
                // that failed has dropped it already; a `5xx` comes here
                // straight from the response header, past every filter.
                if stale {
                    ctx.upstream.sticky_cookie = None;
                    // That `5xx` is the one error pingora itself makes
                    // of a status, and its stale answer the one whose
                    // end goes unsaid: see `cached_body_ends_unsaid`.
                    ctx.state.stale_for_status = matches!(
                        error.etype(),
                        pingora::ErrorType::HTTPStatus(_)
                    );
                }
                stale
            },
            // Pingora 0.9 serializes the background subrequest as HTTP/1
            // text. An HTTP/2 request line cannot be parsed back, which
            // leaves its write lock dangling. Let the HTTP/2 lock holder
            // revalidate in foreground until Pingora fixes that path.
            // Tracked upstream: https://github.com/cloudflare/pingora/issues/1033
            None => {
                !(session.is_http2() && session.cache.is_cache_lock_writer())
            },
        }
    }

    /// Determines if and how responses should be cached.
    /// Checks:
    /// - Cache-Control headers
    /// - TTL settings
    /// - Cache privacy settings
    /// - Custom cache control directives
    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<RespCacheable> {
        debug!(target: LOG_TARGET, "--> response cache filter");
        defer!(debug!(target: LOG_TARGET, "<-- response cache filter"););

        // RFC 9111 §4.1: `Vary: *` never matches a later request, so the
        // response cannot be reused; pingora does not check this itself.
        if has_vary_star(&resp.headers) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "vary *",
            )));
        }
        // A cookie is set for the client that asked. Stored, the same
        // cookie - a session id, say - would go to everyone served from
        // the cache. To cache such a response, remove the header first
        // with a `response_headers` plugin in `upstream` mode.
        if resp.headers.contains_key(http::header::SET_COOKIE) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "set-cookie",
            )));
        }

        let (check_cache_control, max_ttl) = ctx.cache.as_ref().map_or(
            (false, None), // ctx.cache is None
            |c| (c.check_cache_control, c.max_ttl),
        );
        // The lifetimes the plugin gives a response that names none.
        let own_ttl = ctx.cache.as_ref().and_then(|c| {
            (c.default_ttl.is_some() || c.status_ttl.is_some())
                .then(|| (c.default_ttl, c.status_ttl.clone()))
        });

        let mut cc = CacheControl::from_resp_headers(resp);

        // RFC 9111 §3.5: the response to a request with credentials is the
        // requester's own unless the origin marks it as shareable (`public`,
        // `s-maxage` or `must-revalidate`). Checked here, on what the
        // origin sent: the `max_ttl` cap below adds an `s-maxage` of its
        // own, which must not count as that permission.
        //
        // By the request as it is now, which is as the upstream gets it:
        // a plugin that authenticates it and takes the header off
        // (`hide_credentials`) leaves a request the upstream can not tell
        // from anybody's, and its response is stored like any other. The
        // documentation of the `cache` plugin says so.
        if session
            .req_header()
            .headers
            .contains_key(http::header::AUTHORIZATION)
            && !cc
                .as_ref()
                .is_some_and(|c| c.allow_caching_authorized_req())
        {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "authorization",
            )));
        }

        if let Some(c) = &mut cc {
            // delegate all complex validation and modification logic to the helper function
            if let Err(reason) = crate::cache::process_cache_control(c, max_ttl)
            {
                return Ok(RespCacheable::Uncacheable(reason));
            }
        } else if check_cache_control {
            // if Cache-Control header is required but it doesn't exist or parsing fails
            return Ok(RespCacheable::Uncacheable(
                NoCacheReason::OriginNotCache,
            ));
        }

        // A response whose origin names no lifetime gets the plugin's:
        // `status_ttl` for its status, `default_ttl` for the statuses
        // that are kept by default. Only then: what the origin says
        // about its own response comes first, as it does for the one
        // second there is without these.
        if let Some((default_ttl, status_ttl)) = own_ttl
            && !crate::cache::names_a_lifetime(cc.as_ref(), resp)
        {
            return Ok(crate::cache::limit_freshness(
                crate::cache::cacheable_for(
                    cc.as_ref(),
                    resp,
                    crate::cache::own_lifetime(
                        resp.status,
                        default_ttl,
                        status_ttl.as_deref().map(Vec::as_slice),
                        default_fresh_duration,
                    ),
                    &META_DEFAULTS,
                ),
                max_ttl,
            ));
        }

        Ok(crate::cache::limit_freshness(
            resp_cacheable(cc.as_ref(), resp.clone(), false, &META_DEFAULTS),
            max_ttl,
        ))
    }

    /// A client that asked for a checked copy, where the `cache` plugin
    /// lets clients ask (`respect_client_no_cache`), has what is cached
    /// taken as expired: it is revalidated with the origin, and stays the
    /// stored copy when the origin answers `304`.
    async fn cache_hit_filter(
        &self,
        _session: &mut Session,
        _meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        _is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<ForcedFreshness>> {
        // Also for what has expired and would be served while it is
        // being refreshed (`stale-while-revalidate`): that is a copy
        // which was not checked either.
        let revalidate = ctx.cache.as_ref().is_some_and(|c| c.revalidate);
        Ok(revalidate.then_some(ForcedFreshness::ForceExpired))
    }

    /// Turns the origin's `Vary` header into pingora's variance key, so each
    /// combination of the named request headers gets its own cache slot.
    /// pingora calls this both when filling the cache and on every lookup.
    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        ctx: &mut Self::CTX,
        req: &RequestHeader,
    ) -> Option<HashBinary> {
        let allowed = ctx
            .cache
            .as_ref()
            .and_then(|cache| cache.vary_headers.as_deref())
            .map(Vec::as_slice);
        cache_variance(meta.headers(), req, allowed)
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
        debug!(target: LOG_TARGET, "--> response filter");
        defer!(debug!(target: LOG_TARGET, "<-- response filter"););
        if is_interim_response(upstream_response.status) {
            return Ok(());
        }
        if session.cache.enabled() {
            crate::cache::handle_cache_headers(session, upstream_response, ctx);
        }

        // The ids of this request. Set here, on what goes to the client,
        // and not in `upstream_response_filter`: what is set there is
        // stored with a cached response, and every hit then carried the
        // ids of the request that filled the cache.
        #[cfg(feature = "tracing")]
        inject_telemetry_headers(ctx, upstream_response);
        if let Some(id) = &ctx.state.request_id {
            let _ = upstream_response
                .insert_header(&HTTP_HEADER_NAME_X_REQUEST_ID, id);
        }

        // call response plugin
        self.handle_response_plugin(session, ctx, upstream_response)
            .await?;

        // The cookie of a `sticky` upstream, for a client that has none
        // for the backend it was given. Here and not on the upstream's
        // response as it comes in: that one is what a cache keeps, and
        // the cookie of one client is not for the next.
        if let Some(cookie) = ctx.upstream.sticky_cookie.take() {
            let secure = if ctx.conn.tls_version.is_some() {
                "; Secure"
            } else {
                ""
            };
            let _ = upstream_response.append_header(
                http::header::SET_COOKIE,
                format!("{cookie}; Path=/; HttpOnly; SameSite=Lax{secure}"),
            );
        }

        // add server-timing response header
        if self.enable_server_timing {
            let _ = upstream_response
                .insert_header("server-timing", ctx.generate_server_timing());
        }
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        debug!(target: LOG_TARGET, "--> upstream response filter");
        defer!(debug!(target: LOG_TARGET, "<-- upstream response filter"););
        if is_interim_response(upstream_response.status) {
            return Ok(());
        }
        // A plugin may stop the response here, for the proxy to answer
        // in its place (`error_page` with `intercept`). The upstream has
        // answered all the same: its status, its timing and the count of
        // the backend are recorded before that error is passed on. Left
        // with `?` they were not, and to the circuit breaker a backend
        // answering nothing but `503` had no result at all.
        let plugin_result = self.handle_upstream_response_plugin(
            session,
            ctx,
            upstream_response,
        );
        ctx.upstream.status = Some(upstream_response.status);

        if ctx.state.status.is_none() {
            ctx.state.status = Some(upstream_response.status);
            // start to get upstream response data
            ctx.timing.upstream_response =
                Some(get_start_time(&ctx.timing.created_at));
        }

        ctx.timing.upstream_processing = get_latency(
            &ctx.timing.created_at,
            &ctx.timing.upstream_processing,
        );

        if let Some(upstream_instance) = &ctx.upstream.upstream_instance {
            upstream_instance
                .on_response(&ctx.upstream.address, upstream_response.status);
        }

        // A response that is answered by the location's page is not one
        // the cache will keep, and the requests that wait for it at the
        // cache lock are told so, as for any response that is not
        // cacheable: each asks the upstream itself. Left to the error
        // path, the lock was handed on as after a failure, to one waiter
        // at a time, and the requests for a url that answers `404` went
        // to the upstream in single file.
        if let Err(e) = &plugin_result
            && pingap_core::is_upstream_status_error(e)
            && session.cache.enabled()
        {
            session.cache.disable(NoCacheReason::OriginNotCache);
        }

        plugin_result
    }

    /// Filters upstream response body chunks.
    /// Records timing metrics and finalizes spans.
    fn upstream_response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<std::time::Duration>> {
        debug!(target: LOG_TARGET, "--> upstream response body filter");
        defer!(debug!(target: LOG_TARGET, "<-- upstream response body filter"););

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
        Ok(None)
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
        debug!(target: LOG_TARGET, "--> response body filter");
        defer!(debug!(target: LOG_TARGET, "<-- response body filter"););
        // The plugins are told where the body ends also where pingora
        // does not say: a plugin that holds the body until then
        // (`sub_filter`) would not let go of it.
        let end_of_stream = end_of_stream
            || (cached_body_ends_unsaid(
                session.cache.phase(),
                ctx.state.stale_for_status,
            ) && !session
                .req_header()
                .headers
                .contains_key(http::header::RANGE)
                && pingap_cache::is_hit_read_to_the_end(
                    session.cache.hit_handler().as_any(),
                ));
        // Once: a plugin that writes what it has held at the end would
        // write it again, should the end be said here and by pingora.
        let end_of_stream = end_of_stream && !ctx.state.body_end_said;
        ctx.state.body_end_said |= end_of_stream;
        self.handle_response_body_plugin(session, ctx, body, end_of_stream)?;
        // What a `bandwidth_limit` plugin of the location allows this
        // response: pingora holds the chunk back for as long as is said
        // here. By what goes out, after the plugins that change the body.
        // Not what follows a 101: that is the other protocol's own
        // traffic, a websocket's frames, and no body to pace. Nor a
        // subrequest: that is the proxy itself, fetching a cached
        // response anew in the background while the client has its
        // answer from the cache (`stale-while-revalidate`). Paced, the
        // fetch took as long as a download and held the cache lock of the
        // entry all the while.
        if session.was_upgraded() || session.subrequest_ctx.is_some() {
            return Ok(None);
        }
        // The wait before a chunk is for what was sent before it: the
        // first goes out at once. And nothing waits before a byte of
        // the body is out, which is when the header is. pingora filters
        // all it has read from the upstream in one go and writes it
        // afterwards, and the header of a response with a length stays
        // in the write buffer until a part of the body follows it: a
        // wait for a chunk held the header back with it, and a client
        // limited to 100 kB a second saw no status for more than two
        // seconds. What goes out first is counted, and what follows
        // waits for it.
        let delay = match (&mut ctx.features, body.as_ref()) {
            (Some(features), Some(body)) => features
                .body_pace
                .as_mut()
                .and_then(|pace| pace.delay_before(body.len())),
            _ => None,
        };
        Ok(delay.filter(|_| session.body_bytes_sent() > 0))
    }

    /// Handles proxy failures and generates appropriate error responses.
    /// Error handling for:
    /// - Upstream failures (502)
    /// - Downstream read timeouts (408)
    /// - Malformed request headers (400)
    /// - A client that went away (499, nothing is written)
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
        debug!(target: LOG_TARGET, "--> fail to proxy");
        defer!(debug!(target: LOG_TARGET, "<-- fail to proxy"););
        let server_session = session.as_mut();

        let (code, client_gone) = classify_proxy_error(e);
        let error_type = e.etype().as_str();
        // Counted here, where the error says whose it is: by the end of
        // the request a failed upstream is one more `502`.
        #[cfg(feature = "tracing")]
        if let Some(prom) = &self.prometheus
            && e.esource() == &pingora::ErrorSource::Upstream
            && !matches!(e.etype(), pingora::ErrorType::HTTPStatus(_))
        {
            prom.on_upstream_error(&ctx.upstream.name);
        }
        // A final response header is already out (pingora counts a 101 as
        // final too): the status the client saw stays on record, and no
        // page goes after it, the rule of pingora's own
        // `write_error_response`. Writing anyway would have the header
        // dropped with a warning and the page appended to the body.
        let response_started =
            server_session.response_written().is_some_and(|resp| {
                !resp.status.is_informational() || resp.status == 101
            });
        if !response_started {
            ctx.state.status = Some(
                StatusCode::from_u16(code)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            );
        }

        let req_header = server_session.req_header();
        let user_agent = req_header
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok());
        let method = req_header.method.as_str();
        let host = pingap_core::get_host(req_header).unwrap_or_default();
        let path = req_header.uri.path();
        // The one line per failure; pingora's own is suppressed, see
        // `suppress_error_log`.
        if client_gone {
            // Nothing to fix on this side, and nobody left to answer.
            info!(
                target: LOG_TARGET,
                error = %e,
                remote_addr = ctx.conn.remote_addr,
                client_ip = ctx.conn.client_ip,
                user_agent,
                error_type,
                method,
                host,
                path,
                status = code,
                "client gone, no response sent"
            );
        } else if pingap_core::is_upstream_status_error(e) {
            // The upstream answered, and the location answers that status
            // with a page of its own (`error_page` with `intercept`).
            // Nothing failed on this side, and the request is in the
            // access log with its status like any other.
            debug!(
                target: LOG_TARGET,
                method,
                host,
                path,
                status = code,
                "upstream status answered with the page of the location"
            );
        } else if code < 500 {
            // The request's fault, or nothing's: no location for the host,
            // a body over the limit, a location at its `max_processing`.
            // An error in the log for each of these was a line per request
            // of whoever was scanning or being throttled, with nothing in
            // it to fix on this side.
            info!(
                target: LOG_TARGET,
                error = %e,
                remote_addr = ctx.conn.remote_addr,
                client_ip = ctx.conn.client_ip,
                user_agent,
                error_type,
                method,
                host,
                path,
                status = code,
                response_started,
                "request refused"
            );
        } else {
            error!(
                target: LOG_TARGET,
                error = %e,
                remote_addr = ctx.conn.remote_addr,
                client_ip = ctx.conn.client_ip,
                user_agent,
                error_type,
                method,
                host,
                path,
                status = code,
                response_started,
                "fail to proxy"
            );
        }
        if client_gone || response_started {
            return FailToProxy {
                error_code: code,
                can_reuse_downstream: false,
            };
        }

        let mut resp = error_response_header(code);
        let message = client_error_message(e, code);
        // The page of the location, where a plugin of it has one for
        // this status (`error_page`), and the page of the server
        // otherwise. Asked of every plugin of the location, also those
        // behind the one that refused the request: the list is there
        // from the moment the location is found.
        let own_page = StatusCode::from_u16(code).ok().and_then(|status| {
            ctx.plugins.as_ref()?.iter().find_map(|(_, plugin)| {
                plugin.error_page(session, status, message)
            })
        });
        let (content_type, buf) = own_page.unwrap_or_else(|| {
            let content = self.error_template.render(
                pingap_util::get_pkg_version(),
                message,
                error_type,
            );
            let content_type = if self.error_template.is_json() {
                "application/json; charset=utf-8"
            } else {
                "text/html; charset=utf-8"
            };
            (
                http::HeaderValue::from_static(content_type),
                Bytes::from(content),
            )
        });
        let _ = resp
            .insert_header(http::header::CONTENT_TYPE, content_type.clone());
        let _ = resp.insert_header("X-Pingap-EType", error_type);
        // The page of a request that had a location is a response of that
        // location: the plugins that set headers on what other plugins
        // answer set them here as well. A `502` without the CORS headers
        // is withheld from the page by the browser, which then reports a
        // failed request and not the status, and a security header is no
        // less wanted on an error. A plugin that fails at it is no reason
        // to leave the client without the page.
        if let Err(e) =
            pingap_core::decorate_plugin_response(session, ctx, &mut resp).await
        {
            error!(
                target: LOG_TARGET,
                error = %e,
                "set the headers of the location on the error page fail"
            );
        }
        // After the plugins: how long the page is and what it is are not
        // theirs to say. A rule that takes `Content-Length` off every
        // response would leave this one with no end but the connection's.
        let _ = resp
            .insert_header(http::header::CONTENT_LENGTH, buf.len().to_string());
        let _ = resp.insert_header(http::header::CONTENT_TYPE, content_type);
        let server_session = session.as_mut();

        // The connection is as good as it was when the request was refused
        // by one of the filters - no location for it, a plugin or a limit
        // saying no - and is all read: the answer is a complete response
        // like any other, and the next request can follow it. Every error
        // page used to close the connection, so a client that was refused
        // came back with a new connection for each request, a TLS
        // handshake included.
        //
        // Not past the filters. pingora closes the connection after a
        // request that failed on its way to an upstream whatever is
        // answered here, and the page has to say so: told `keep-alive`, a
        // client sends its next request into a connection that is gone.
        // Nor with some of the request body still to come: it is not read
        // for the sake of a request that failed.
        let can_reuse_downstream = !ctx.state.proxying
            && e.esource() != &pingora::ErrorSource::Downstream
            && server_session.is_body_done();
        if !can_reuse_downstream {
            server_session.set_keepalive(None);
        }

        let header_written = server_session
            .write_response_header(Box::new(resp))
            .await
            .map_err(|e| {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    "send error response to downstream fail"
                );
            })
            .is_ok();

        // The page is the body of a GET. A HEAD is told its length and
        // gets none of it: HTTP/1.1 drops what is written after the header
        // of such a response, HTTP/2 does not, and the client reset the
        // stream with a protocol error instead of reading the status.
        let is_head = server_session.req_header().method == http::Method::HEAD;
        let body = if is_head { Bytes::new() } else { buf };
        let written = server_session.write_response_body(body, true).await;
        FailToProxy {
            error_code: code,
            can_reuse_downstream: can_reuse_downstream
                && header_written
                && written.is_ok(),
        }
    }
    /// pingora logs every proxy failure itself through the `log` crate,
    /// which pingap bridges into its own output, so each one showed up
    /// twice: once from `fail_to_proxy` with the client, the request and
    /// the error type, and once more from pingora with only the request
    /// summary. The first line covers the second, so pingora's is dropped.
    fn suppress_error_log(
        &self,
        _session: &Session,
        _ctx: &Self::CTX,
        _error: &pingora::Error,
    ) -> bool {
        true
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
        debug!(target: LOG_TARGET, "--> logging");
        defer!(debug!(target: LOG_TARGET, "<-- logging"););
        end_request();
        self.processing.fetch_sub(1, Ordering::Relaxed);
        if let Some(location) = &ctx.upstream.location_instance {
            location.on_response();
        }
        // get from cache does not connect to upstream
        if let Some(upstream_instance) = &ctx.upstream.upstream_instance {
            ctx.upstream.processing_count = Some(upstream_instance.completed());
        }
        // The status the client was sent, when it was sent one. What was
        // noted on the way is the upstream's, and that is another status
        // whenever the response comes from the cache: an upstream that
        // answers a revalidation with 304 had the log and the metrics say
        // 304 for a client that got the stored 200.
        if let Some(header) = session.response_written()
            && !is_interim_response(header.status)
        {
            ctx.state.status = Some(header.status);
        }
        #[cfg(feature = "tracing")]
        // enable open telemetry and proxy upstream fail
        if let Some(features) = ctx.features.as_mut()
            && let Some(ref mut span) = features.upstream_span.as_mut()
        {
            span.end();
        }

        if let Some(c) =
            session.downstream_modules_ctx.get::<ResponseCompression>()
            && c.is_enabled()
            && let Some((algorithm, in_bytes, out_bytes, took)) = c.get_info()
        {
            let features = ctx.features.get_or_insert_default();
            features.compression_stat = Some(CompressionStat {
                algorithm: algorithm.to_string(),
                in_bytes,
                out_bytes,
                duration: took,
            });
        }
        // Every request, matched or not: `on_request_start` ran for all of
        // them in `early_request_filter`, and this is what pairs with it.
        #[cfg(feature = "tracing")]
        if let Some(prom) = &self.prometheus {
            prom.after(session, ctx);
        }

        #[cfg(feature = "tracing")]
        set_otel_request_attrs(session, ctx);

        if let Some(p) = &self.log_parser {
            // Before the line is made: a request that is not logged
            // costs no formatting.
            if let Some(filter) = &self.log_filter {
                // What the client asked for, not what a rewrite of the
                // location made of it.
                let uri = ctx
                    .features
                    .as_ref()
                    .and_then(|features| features.original_uri.as_ref())
                    .unwrap_or(&session.req_header().uri);
                let target = uri
                    .path_and_query()
                    .map_or(uri.path(), |value| value.as_str());
                let status =
                    ctx.state.status.map_or(0, |status| status.as_u16());
                if !filter.allows(
                    target,
                    status,
                    ctx.timing.created_at.elapsed(),
                ) {
                    return;
                }
            }
            let buf = p.format(session, ctx);
            if let Some(logger) = &self.access_logger {
                if let Err(e) = logger.try_send(buf) {
                    // A line for the application log is not dropped: with
                    // the task behind, or no longer taking lines (it stops
                    // at the shutdown signal), this request writes its own.
                    if self.access_log_to_application {
                        let msg = e.into_inner();
                        info!(target: LOG_TARGET, "{}", msg.as_bstr());
                        return;
                    }
                    // Channel full: drop the line rather than block the request
                    // path, but surface the loss so operators can size the buffer.
                    let dropped =
                        ACCESS_LOG_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                    #[cfg(feature = "tracing")]
                    if let Some(prom) = &self.prometheus {
                        prom.on_access_log_dropped();
                    }
                    // Rate-limit the warning: log every power-of-two drop so a
                    // saturated channel does not flood the error log.
                    if dropped.is_power_of_two() {
                        error!(
                            target: LOG_TARGET,
                            dropped,
                            "access log channel full, dropping lines"
                        );
                    }
                }
            } else {
                let msg = buf.as_bstr();
                info!(target: LOG_TARGET, "{msg}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_conf::parse_from_conf;
    use ahash::AHashMap;
    use pingap_certificate::{DynamicCertificates, TlsCertificate};
    use pingap_config::{PingapConfig, new_file_config_manager};
    use pingap_core::{CacheInfo, Ctx, Plugin, UpstreamInfo};
    use pingap_location::Location;
    use pingap_location::LocationStats;
    use pingora::http::ResponseHeader;
    use pingora::protocols::tls::SslDigest;
    use pingora::protocols::tls::SslDigestExtension;
    use pingora::protocols::{Digest, TimingDigest};
    use pingora::proxy::{ProxyHttp, Session};
    use pingora::server::configuration;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_test::io::Builder;

    #[test]
    fn test_get_digest_detail() {
        let digest = Digest {
            timing_digest: vec![Some(TimingDigest {
                established_ts: SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(10))
                    .unwrap(),
                ..Default::default()
            })],
            ssl_digest: Some(Arc::new(SslDigest {
                cipher: "123".into(),
                version: "1.3".into(),
                organization: None,
                serial_number: None,
                cert_digest: vec![],
                extension: SslDigestExtension::default(),
            })),
            ..Default::default()
        };
        let result = get_digest_detail(&digest);
        assert_eq!(10000, result.tcp_established);
        assert_eq!("1.3", result.tls_version.unwrap_or_default());
    }

    const TEST_TOML: &str = r###"
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

    /// Creates a test server from `toml_data` (normally `TEST_TOML`).
    /// Pass a plugin provider to exercise the plugin chain; the default one
    /// resolves nothing, which is enough for tests that ignore plugins.
    fn new_server_from(
        toml_data: &str,
        plugin_provider: Option<Arc<dyn PluginProvider>>,
    ) -> Server {
        let pingap_conf = PingapConfig::new(toml_data.as_ref(), false).unwrap();

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

        // Every name resolves, to a plugin that does nothing: a name that
        // does not resolve fails the request.
        struct NoopPlugin;
        impl Plugin for NoopPlugin {}
        struct TmpPluginLoader {}
        impl PluginProvider for TmpPluginLoader {
            fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
                Some(Arc::new(NoopPlugin))
            }
        }
        let plugin_provider =
            plugin_provider.unwrap_or_else(|| Arc::new(TmpPluginLoader {}));
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
        struct TmpServerLocationsLoader {
            route: Arc<crate::ServerLocationRoute>,
        }
        impl ServerLocationsProvider for TmpServerLocationsLoader {
            fn get(
                &self,
                _name: &str,
            ) -> Option<Arc<crate::ServerLocationRoute>> {
                Some(self.route.clone())
            }
        }

        struct TmpCertificateLoader {}
        impl CertificateProvider for TmpCertificateLoader {
            fn get(&self, _sni: &str) -> Option<Arc<TlsCertificate>> {
                None
            }
            fn list(&self) -> Arc<DynamicCertificates> {
                Arc::new(AHashMap::new())
            }
            fn store(&self, _data: DynamicCertificates) {}
        }

        let confs = parse_from_conf(pingap_conf);
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();

        Server::new(
            &confs[0],
            AppContext {
                logger: None,
                config_manager: Arc::new(
                    new_file_config_manager(&file.path().to_string_lossy())
                        .unwrap(),
                ),
                server_locations_provider: Arc::new({
                    let location_for_index = location.clone();
                    let route = crate::ServerLocationRoute::build(
                        vec!["lo".to_string()],
                        move |_| Some(location_for_index.clone()),
                    );
                    TmpServerLocationsLoader {
                        route: Arc::new(route),
                    }
                }),
                location_provider: Arc::new(TmpLocationLoader { location }),
                upstream_provider: Arc::new(TmpUpstreamLoader { upstream }),
                plugin_provider,
                certificate_provider: Arc::new(TmpCertificateLoader {}),
            },
        )
        .unwrap()
    }

    fn new_server_with(
        plugin_provider: Option<Arc<dyn PluginProvider>>,
    ) -> Server {
        new_server_from(TEST_TOML, plugin_provider)
    }

    fn new_server() -> Server {
        new_server_with(None)
    }

    /// The two halves of an in-memory connection carrying `request`, for
    /// the paths that write a response. The `tokio_test` mock used
    /// elsewhere panics on any write it was not told to expect, which is
    /// what the "nothing is written" tests rely on.
    async fn new_duplex_session(
        request: &str,
    ) -> (Session, tokio::io::DuplexStream) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(request.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(server));
        session.read_request().await.unwrap();
        (session, client)
    }

    /// Everything the server wrote; `session` has to be dropped first so
    /// the client sees the end of the stream.
    async fn read_response(mut client: tokio::io::DuplexStream) -> String {
        let mut buf = vec![];
        client.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn test_keepalive_reuse_signal() {
        let server = new_server();
        let input_header =
            "GET /vicanso/pingap HTTP/1.1\r\nHost: github.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::new();

        // A fresh request knows nothing about reuse until pingora says so.
        assert_eq!(false, ctx.conn.reused);
        // Always hand a marker back, or the next request's hook never runs.
        let carried = server
            .persist_connection_context(&session, &ctx)
            .expect("a marker must be carried to the next request");
        server.on_connection_reuse(&mut session, &mut ctx, carried);
        assert_eq!(true, ctx.conn.reused);
    }

    #[test]
    fn test_new_h2_options() {
        // Nothing configured: hand pingora `None` so its bounded defaults
        // apply exactly as shipped, rather than a copy we might drift from.
        let mut server = new_server();
        assert_eq!(true, server.new_h2_options().is_none());

        // Any single knob is enough to build an explicit options set.
        server.h2_max_concurrent_streams = Some(256);
        assert_eq!(true, server.new_h2_options().is_some());
        server.h2_max_concurrent_streams = None;
        server.h2_initial_connection_window_size = Some(4 * 1024 * 1024);
        assert_eq!(true, server.new_h2_options().is_some());

        // The idle timeout lives on HttpServerOptions, not on H2Options.
        server.h2_initial_connection_window_size = None;
        server.h2_idle_timeout = Some(Duration::from_secs(120));
        assert_eq!(true, server.new_h2_options().is_none());
    }

    #[test]
    fn test_new_server() {
        let server = new_server();
        let services = server
            .run(Arc::new(configuration::ServerConf::default()))
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
        assert_eq!("lo", ctx.upstream.location.as_ref());
    }

    /// Stands in for a plugin that gates a request, e.g. `basic_auth`. It only
    /// counts, so a test can tell "the chain ran" from "the chain was skipped"
    /// without the session having to write a response.
    #[derive(Default)]
    struct CountingPlugin {
        request_calls: Arc<AtomicUsize>,
        body_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Plugin for CountingPlugin {
        async fn handle_request(
            &self,
            _step: PluginStep,
            _session: &mut Session,
            _ctx: &mut Ctx,
        ) -> pingora::Result<RequestPluginResult> {
            self.request_calls.fetch_add(1, Ordering::SeqCst);
            Ok(RequestPluginResult::Continue)
        }

        fn handle_response_body(
            &self,
            _session: &mut Session,
            _ctx: &mut Ctx,
            _body: &mut Option<bytes::Bytes>,
            _end_of_stream: bool,
        ) -> pingora::Result<ResponseBodyPluginResult> {
            self.body_calls.fetch_add(1, Ordering::SeqCst);
            Ok(ResponseBodyPluginResult::Unchanged)
        }
    }

    struct CountingPluginProvider {
        plugin: Arc<dyn Plugin>,
    }
    impl PluginProvider for CountingPluginProvider {
        fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
            Some(self.plugin.clone())
        }
    }

    /// Server plus the counters of the single plugin every location resolves to.
    fn new_server_counting() -> (Server, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let plugin = CountingPlugin::default();
        let request_calls = plugin.request_calls.clone();
        let body_calls = plugin.body_calls.clone();
        let server = new_server_with(Some(Arc::new(CountingPluginProvider {
            plugin: Arc::new(plugin),
        })));
        (server, request_calls, body_calls)
    }

    /// Regression for the pre-auth bypass reported in #215.
    ///
    /// `get_context_plugins` used to return `None` when `session.is_upgrade_req()`,
    /// leaving `ctx.plugins` empty for the whole request and turning every plugin
    /// step into a no-op — authentication included. pingora treats any HTTP/1.1
    /// request carrying an `Upgrade` header as an upgrade request without looking
    /// at the value, so `Upgrade: x` on any path was enough to walk past
    /// `basic_auth`, `key_auth`, `jwt`, `ip_restriction` and the rest and still be
    /// proxied upstream.
    #[tokio::test]
    async fn test_upgrade_request_cannot_skip_plugins() {
        for headers in [
            // No upgrade at all, as the control.
            "",
            // What pingora accepts as an upgrade: an `Upgrade` header whose
            // value it never inspects.
            "Upgrade: x\r\n",
            // A well-formed websocket handshake.
            "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n",
        ] {
            let (server, request_calls, _) = new_server_counting();

            let input_header =
                format!("GET /vicanso/pingap HTTP/1.1\r\n{headers}\r\n");
            let mock_io = Builder::new().read(input_header.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();

            let mut ctx = Ctx::default();
            server
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();

            assert!(
                ctx.plugins.is_some(),
                "plugin chain was dropped for headers {headers:?}"
            );
            assert!(
                request_calls.load(Ordering::SeqCst) > 0,
                "request plugins never ran for headers {headers:?}"
            );

            // And they keep running at the Request step, not just EarlyRequest.
            let before = request_calls.load(Ordering::SeqCst);
            server
                .handle_request_plugin(
                    PluginStep::Request,
                    &mut session,
                    &mut ctx,
                )
                .await
                .unwrap();
            assert!(
                request_calls.load(Ordering::SeqCst) > before,
                "Request step was skipped for headers {headers:?}"
            );
        }
    }

    /// The websocket breakage that motivated the original skip (#114) is a
    /// response-body concern, so the guard belongs on the body hooks — and it
    /// has to key off the completed handshake, not the request header, or a
    /// client could switch the hooks off on demand.
    #[tokio::test]
    async fn test_response_body_plugins_wait_for_the_handshake() {
        let (server, _, body_calls) = new_server_counting();

        let input_header =
            "GET /vicanso/pingap HTTP/1.1\r\nUpgrade: websocket\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        // The client asked to upgrade, but no 101 came back, so this is still a
        // plain HTTP response and the body hooks must stay live. Only pingora
        // flips `was_upgraded`, and only on the 101, which is exactly why the
        // guard reads it instead of the request header.
        assert!(session.is_upgrade_req());
        assert!(!session.was_upgraded());

        let location = server.location_provider.get("lo").unwrap();
        let mut ctx = Ctx {
            plugins: location.plugins_for(server.plugin_provider.as_ref()),
            ..Default::default()
        };
        let mut body = Some(bytes::Bytes::from_static(b"hello"));
        server
            .handle_response_body_plugin(
                &mut session,
                &mut ctx,
                &mut body,
                true,
            )
            .unwrap();
        server
            .handle_upstream_response_body_plugin(
                &mut session,
                &mut ctx,
                &mut body,
                true,
            )
            .unwrap();
        assert_eq!(
            2,
            body_calls.load(Ordering::SeqCst),
            "body hooks must not bail out before the handshake completes"
        );
    }

    /// Regression: a plugin that is not loaded - a misspelled name, a config
    /// that failed to build - was left out, and the location served without
    /// it. When that plugin is the authentication, that is an open door.
    #[tokio::test]
    async fn test_missing_plugin_fails_the_request() {
        struct EmptyProvider;
        impl PluginProvider for EmptyProvider {
            fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
                None
            }
        }
        let server = new_server_with(Some(Arc::new(EmptyProvider)));
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let err = server
            .early_request_filter(&mut session, &mut Ctx::default())
            .await
            .unwrap_err();
        assert_eq!(&pingora::ErrorType::HTTPStatus(500), err.etype());
        assert_eq!(
            true,
            err.to_string()
                .contains("plugin pingap:requestId is not available"),
            "{err}"
        );
    }

    /// Regression: the location was picked by the path as sent, so an
    /// encoded or roundabout spelling of `/admin` missed the location for
    /// `/admin` - and its plugins - on its way to an upstream that reads it
    /// as `/admin`.
    #[tokio::test]
    async fn test_location_is_matched_by_the_normalized_path() {
        let toml = TEST_TOML.replace("path = \"/\"", "path = \"/admin\"");
        let server = new_server_from(&toml, None);
        let matched = async |path: &str| {
            let mock_io = Builder::new()
                .read(format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes())
                .build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            server
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();
            // The request is forwarded as it came.
            assert_eq!(path, session.req_header().uri.path());
            ctx.upstream.location.as_ref() == "lo"
        };
        for path in [
            "/admin",
            "/admin/users",
            "/%61dmin/users",
            "/%61%64%6d%69%6e",
            "//admin/users",
            "/./admin",
            "/public/../admin/users",
            "/public/%2e%2e/admin",
            "/public/..%2fadmin",
        ] {
            assert_eq!(true, matched(path).await, "{path}");
        }
        for path in [
            "/",
            "/public",
            "/public/admin",
            "/admin/../public",
            "/%2561dmin",
        ] {
            assert_eq!(false, matched(path).await, "{path}");
        }
    }

    #[tokio::test]
    async fn test_no_matching_location_is_404() {
        let server = new_server();
        let input_header =
            "GET /nowhere HTTP/1.1\r\nHost: nomatch.example\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        // No location matched during the early filter: the request must
        // fail as a routing miss, not as a server error.
        let mut ctx = Ctx::default();
        let err = server
            .request_filter(&mut session, &mut ctx)
            .await
            .expect_err("a request without a location cannot be served");
        assert_eq!(
            true,
            matches!(err.etype(), pingora::ErrorType::HTTPStatus(404)),
            "{err}"
        );
        assert_eq!(
            true,
            err.to_string()
                .contains("No matching location, host:nomatch.example"),
            "{err}"
        );
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

        let location = server.location_provider.get("lo").unwrap();
        let mut ctx = Ctx {
            upstream: UpstreamInfo {
                location: "lo".to_string().into(),
                location_instance: Some(location.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let done = server.request_filter(&mut session, &mut ctx).await.unwrap();
        assert_eq!(false, done);
    }

    /// What `request_filter` leaves in the context for the plugins that
    /// write a response themselves: the plugin list, when one of them asks
    /// to see the responses of the others (`decorate_plugin_response` works
    /// from it), and the uri the client used, when the location rewrote it.
    #[tokio::test]
    async fn test_request_filter_leaves_what_plugins_need() {
        struct Asks(bool);
        impl Plugin for Asks {
            fn handles_plugin_response(&self) -> bool {
                self.0
            }
        }
        struct Provider(bool);
        impl PluginProvider for Provider {
            fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
                Some(Arc::new(Asks(self.0)))
            }
        }
        let run = async |toml: &str, asks: bool, path: &str| {
            let server = new_server_from(toml, Some(Arc::new(Provider(asks))));
            let input = format!("GET {path} HTTP/1.1\r\n\r\n");
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            server
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();
            server.request_filter(&mut session, &mut ctx).await.unwrap();
            let original = ctx
                .features
                .as_ref()
                .and_then(|features| features.original_uri.as_ref())
                .map(|uri| uri.to_string());
            (
                ctx.response_plugins.is_some(),
                original,
                session.req_header().uri.to_string(),
            )
        };

        // No rewrite: nothing kept. The list is there when asked for.
        assert_eq!(
            (true, None, "/vicanso/pingap?a=1".to_string()),
            run(TEST_TOML, true, "/vicanso/pingap?a=1").await
        );
        assert_eq!(
            (false, None, "/vicanso/pingap?a=1".to_string()),
            run(TEST_TOML, false, "/vicanso/pingap?a=1").await
        );

        let rewriting = TEST_TOML.replace(
            "weight = 1024",
            "weight = 1024\nrewrite = \"^/vicanso/(.*)$ /$1\"",
        );
        assert_eq!(
            (
                false,
                Some("/vicanso/pingap?a=1".to_string()),
                "/pingap?a=1".to_string()
            ),
            run(&rewriting, false, "/vicanso/pingap?a=1").await
        );
        // A rule that does not apply to this request leaves it alone.
        assert_eq!(
            (false, None, "/other?a=1".to_string()),
            run(&rewriting, false, "/other?a=1").await
        );
    }

    /// Regression: the metrics endpoint was answered ahead of the plugins,
    /// so a location that asks for a password stood next to metrics that
    /// anyone could read. The request plugins of the location its path
    /// belongs to run first, and one that answers has answered.
    #[cfg(feature = "tracing")]
    #[tokio::test]
    async fn test_metrics_endpoint_is_behind_the_location_plugins() {
        struct Guard(bool);
        #[async_trait::async_trait]
        impl Plugin for Guard {
            async fn handle_request(
                &self,
                step: PluginStep,
                _session: &mut Session,
                _ctx: &mut Ctx,
            ) -> pingora::Result<RequestPluginResult> {
                if step == PluginStep::Request && self.0 {
                    return Ok(RequestPluginResult::Respond(
                        pingap_core::HttpResponse {
                            status: StatusCode::UNAUTHORIZED,
                            ..Default::default()
                        },
                    ));
                }
                Ok(RequestPluginResult::Skipped)
            }
        }
        struct Provider(bool);
        impl PluginProvider for Provider {
            fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
                Some(Arc::new(Guard(self.0)))
            }
        }
        let toml = TEST_TOML.replace(
            "threads = 1",
            "threads = 1\nprometheus_metrics = \"/metrics\"",
        );
        let get = async |refuses: bool| {
            let server =
                new_server_from(&toml, Some(Arc::new(Provider(refuses))));
            let (mut session, client) =
                new_duplex_session("GET /metrics HTTP/1.1\r\n\r\n").await;
            let mut ctx = Ctx::default();
            server
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();
            let done =
                server.request_filter(&mut session, &mut ctx).await.unwrap();
            assert_eq!(true, done);
            drop(session);
            read_response(client).await
        };

        let response = get(true).await;
        assert_eq!(true, response.starts_with("HTTP/1.1 401 "), "{response}");
        assert_eq!(false, response.contains("pingap_"), "{response}");

        let response = get(false).await;
        assert_eq!(true, response.starts_with("HTTP/1.1 200 "), "{response}");
        assert_eq!(true, response.contains("pingap_"), "{response}");
    }

    #[tokio::test]
    async fn test_cache_key_callback() {
        let server = new_server();

        let headers = ["Host: GitHub.com:8443"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let key = server
            .cache_key_callback(
                &session,
                &mut Ctx {
                    cache: Some(Box::new(CacheInfo {
                        namespace: Some("pingap".to_string()),
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            )
            .unwrap();
        // The namespace is folded into the primary (unframed) and repeated
        // in user_tag for the storage layer. The host is part of the key
        // over HTTP/1.1 too, in lower case and without its port.
        assert_eq!(
            key.primary_key_str(),
            Some("pingapss:GET:github.com/vicanso/pingap?size=1")
        );
        assert_eq!(key.user_tag(), "pingap");
        assert_eq!(key.variance(), None);
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
                    cache: Some(Box::new(CacheInfo {
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(0, result.unwrap_meta().stale_while_revalidate_sec());

        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();
        upstream_response
            .append_header(
                "Cache-Control",
                "max-age=60, stale-while-revalidate=120",
            )
            .unwrap();
        let result = server
            .response_cache_filter(
                &session,
                &upstream_response,
                &mut Ctx {
                    cache: Some(Box::new(CacheInfo {
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            )
            .unwrap();
        let meta = result.unwrap_meta();
        assert_eq!(120, meta.stale_while_revalidate_sec());
        let now = std::time::SystemTime::now();
        assert!(meta.serve_stale_while_revalidate(
            now.checked_add(Duration::from_secs(61)).unwrap()
        ));
        assert!(!meta.serve_stale_while_revalidate(
            now.checked_add(Duration::from_secs(181)).unwrap()
        ));

        // HTTP/1.1 sessions may serve stale during revalidation. The
        // HTTP/2 lock-writer exclusion is only exercised end-to-end: pingora
        // exposes no public h2 Session constructor for unit tests.
        let mut ctx = Ctx::default();
        assert!(server.should_serve_stale(&mut session, &mut ctx, None));
        let upstream_error =
            pingora::Error::new_up(pingora::ErrorType::ConnectError);
        assert!(server.should_serve_stale(
            &mut session,
            &mut ctx,
            Some(&upstream_error)
        ));
        let downstream_error =
            pingora::Error::new_down(pingora::ErrorType::ConnectionClosed);
        assert!(!server.should_serve_stale(
            &mut session,
            &mut ctx,
            Some(&downstream_error)
        ));

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
                    cache: Some(Box::new(CacheInfo {
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    })),
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
                    cache: Some(Box::new(CacheInfo {
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    })),
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
                    cache: Some(Box::new(CacheInfo {
                        keys: Some(vec!["ss".to_string()]),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(false, result.is_cacheable());
    }

    #[tokio::test]
    async fn test_response_cache_filter_vary_star() {
        let server = new_server();
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();
        upstream_response
            .append_header("Cache-Control", "max-age=60")
            .unwrap();
        upstream_response.append_header("Vary", "*").unwrap();
        let result = server
            .response_cache_filter(
                &session,
                &upstream_response,
                &mut Ctx {
                    cache: Some(Box::default()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(false, result.is_cacheable());
    }

    /// Whether `response_cache_filter` stores a response with these
    /// headers and status, for a request with these headers.
    async fn is_cacheable(
        request_headers: &[&str],
        status: u16,
        response_headers: &[(&'static str, &'static str)],
        max_ttl: Option<Duration>,
    ) -> bool {
        let server = new_server();
        let mut request = "GET /vicanso/pingap HTTP/1.1\r\n".to_string();
        for header in request_headers {
            request.push_str(header);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        let mock_io = Builder::new().read(request.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut upstream_response =
            ResponseHeader::build_no_case(status, None).unwrap();
        for (name, value) in response_headers {
            upstream_response.append_header(*name, *value).unwrap();
        }
        server
            .response_cache_filter(
                &session,
                &upstream_response,
                &mut Ctx {
                    cache: Some(Box::new(CacheInfo {
                        max_ttl,
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            )
            .unwrap()
            .is_cacheable()
    }

    /// A response that belongs to one client is not stored for the next:
    /// one that sets a cookie, and one to a request with credentials
    /// unless the origin marks it shareable.
    #[tokio::test]
    async fn test_response_cache_filter_keeps_private_responses_out() {
        let fresh = ("Cache-Control", "max-age=60");
        assert_eq!(true, is_cacheable(&[], 200, &[fresh], None).await);

        // Set-Cookie, whatever else the response says
        for headers in [
            vec![("Set-Cookie", "sid=1")],
            vec![fresh, ("Set-Cookie", "sid=1")],
            vec![
                ("Cache-Control", "public, max-age=60"),
                ("Set-Cookie", "a=1"),
            ],
        ] {
            assert_eq!(
                false,
                is_cacheable(&[], 200, &headers, None).await,
                "{headers:?}"
            );
        }

        // Authorization on the request
        let auth = ["Authorization: Bearer token"];
        assert_eq!(false, is_cacheable(&auth, 200, &[], None).await);
        assert_eq!(false, is_cacheable(&auth, 200, &[fresh], None).await);
        for shareable in [
            "public, max-age=60",
            "s-maxage=60",
            "max-age=60, must-revalidate",
        ] {
            assert_eq!(
                true,
                is_cacheable(&auth, 200, &[("Cache-Control", shareable)], None)
                    .await,
                "{shareable}"
            );
        }
        // The `max_ttl` cap writes an `s-maxage` of its own; that is not
        // the origin's permission.
        assert_eq!(
            false,
            is_cacheable(
                &auth,
                200,
                &[("Cache-Control", "max-age=3600")],
                Some(Duration::from_secs(60))
            )
            .await
        );
    }

    /// Without a lifetime from the origin, only the heuristically
    /// cacheable statuses get the one second default.
    #[tokio::test]
    async fn test_response_cache_filter_default_freshness_by_status() {
        for status in [200, 204, 301, 404, 410] {
            assert_eq!(
                true,
                is_cacheable(&[], status, &[], None).await,
                "{status}"
            );
        }
        for status in [302, 307, 401, 403, 500, 502, 503, 504] {
            assert_eq!(
                false,
                is_cacheable(&[], status, &[], None).await,
                "{status}"
            );
            // the origin can still ask for it
            assert_eq!(
                true,
                is_cacheable(
                    &[],
                    status,
                    &[("Cache-Control", "max-age=10")],
                    None
                )
                .await,
                "{status} with max-age"
            );
        }
    }

    /// The timings of a phase that starts in the request's first
    /// millisecond: it used to be marked `-1`, which read back as a
    /// latency of -1 and was then dropped.
    #[test]
    fn test_start_time_and_latency() {
        let now = Instant::now();
        let start = get_start_time(&now);
        assert_eq!(-1, start);
        assert_eq!(Some(0), get_latency(&now, &Some(start)));

        let earlier = now.checked_sub(Duration::from_millis(20)).unwrap();
        let start = get_start_time(&earlier);
        assert_eq!(true, start <= -21, "{start}");
        let latency = get_latency(&earlier, &Some(start)).unwrap();
        assert_eq!(true, (0..5).contains(&latency), "{latency}");
        // 20ms after a start at 0ms
        let latency = get_latency(&earlier, &Some(-1)).unwrap();
        assert_eq!(true, (20..25).contains(&latency), "{latency}");

        // nothing started, or already taken
        assert_eq!(None, get_latency(&now, &None));
        assert_eq!(None, get_latency(&now, &Some(3)));
    }

    /// 103 Early Hints goes through the response hooks before the final
    /// response does. The status, the timings and the plugins are about
    /// the final one.
    #[tokio::test]
    async fn test_interim_response_is_not_the_response() {
        let server = new_server_from(
            &TEST_TOML.replace(
                "threads = 1",
                "threads = 1\nenable_server_timing = true",
            ),
            None,
        );
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.state.request_id = Some("id".to_string());
        ctx.timing.upstream_processing =
            Some(get_start_time(&ctx.timing.created_at));

        let mut hints = ResponseHeader::build_no_case(103, None).unwrap();
        hints
            .append_header("Link", "</style.css>; rel=preload")
            .unwrap();
        server
            .upstream_response_filter(&mut session, &mut hints, &mut ctx)
            .await
            .unwrap();
        server
            .response_filter(&mut session, &mut hints, &mut ctx)
            .await
            .unwrap();
        assert_eq!(None, ctx.state.status);
        assert_eq!(None, ctx.upstream.status);
        // still running, and nothing of pingap's on the interim header
        assert_eq!(true, ctx.timing.upstream_processing.unwrap() < 0);
        assert_eq!(1, hints.headers.len());

        let mut resp = ResponseHeader::build_no_case(200, None).unwrap();
        server
            .upstream_response_filter(&mut session, &mut resp, &mut ctx)
            .await
            .unwrap();
        server
            .response_filter(&mut session, &mut resp, &mut ctx)
            .await
            .unwrap();
        assert_eq!(Some(StatusCode::OK), ctx.state.status);
        assert_eq!(Some(StatusCode::OK), ctx.upstream.status);
        assert_eq!(true, ctx.timing.upstream_processing.unwrap() >= 0);
        assert_eq!(true, resp.headers.contains_key("server-timing"));
        assert_eq!(true, resp.headers.contains_key("x-request-id"));

        // 101 is the final response of an upgrade
        let mut ctx = Ctx::default();
        let mut switching = ResponseHeader::build_no_case(101, None).unwrap();
        server
            .upstream_response_filter(&mut session, &mut switching, &mut ctx)
            .await
            .unwrap();
        assert_eq!(Some(StatusCode::SWITCHING_PROTOCOLS), ctx.state.status);
    }

    /// Regression: after a 101 the bytes a client sends are its half of the
    /// tunnel. They were counted as a request body, and a websocket was
    /// cut off once it had sent `client_max_body_size` in total.
    #[tokio::test]
    async fn test_upgraded_connection_is_not_a_request_body() {
        let toml = TEST_TOML.replace(
            "weight = 1024",
            "weight = 1024\nclient_max_body_size = \"1kb\"",
        );
        let server = new_server_from(&toml, None);
        let location = server.location_provider.get("lo").unwrap();
        let chunk = || Some(Bytes::from(vec![b'a'; 800]));

        // A request body is limited, as before.
        let (mut session, _client) = new_duplex_session(
            "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await;
        let mut ctx = Ctx::default();
        ctx.upstream.location_instance = Some(location.clone());
        server
            .request_body_filter(&mut session, &mut chunk(), false, &mut ctx)
            .await
            .unwrap();
        let err = server
            .request_body_filter(&mut session, &mut chunk(), false, &mut ctx)
            .await
            .unwrap_err();
        assert_eq!(
            true,
            matches!(err.etype(), pingora::ErrorType::HTTPStatus(413)),
            "{err}"
        );

        // What follows a 101 is not.
        let (mut session, _client) = new_duplex_session(
            "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .await;
        let mut switching = ResponseHeader::build(101, None).unwrap();
        switching.insert_header("Upgrade", "websocket").unwrap();
        switching.insert_header("Connection", "Upgrade").unwrap();
        session
            .write_response_header(Box::new(switching), false)
            .await
            .unwrap();
        assert_eq!(true, session.was_upgraded());
        let mut ctx = Ctx::default();
        ctx.upstream.location_instance = Some(location);
        for _ in 0..5 {
            server
                .request_body_filter(
                    &mut session,
                    &mut chunk(),
                    false,
                    &mut ctx,
                )
                .await
                .unwrap();
        }
        // Still counted, for the access log and the metrics.
        assert_eq!(5 * 800, ctx.state.payload_size);
    }

    /// The plugins of a location are there for every error of it, those
    /// that refuse a request before a plugin has run included: a `413`
    /// or a `429` of the location is answered with the page of the
    /// location (`error_page`) and the headers it sets on every
    /// response. They used to be set after these checks, so both went out
    /// as the page of the server, without the CORS headers.
    #[tokio::test]
    async fn test_location_limits_are_answered_with_its_plugins() {
        struct Pages;
        #[async_trait]
        impl Plugin for Pages {
            fn handles_plugin_response(&self) -> bool {
                true
            }
            async fn handle_response(
                &self,
                _session: &mut Session,
                _ctx: &mut Ctx,
                upstream_response: &mut ResponseHeader,
            ) -> pingora::Result<pingap_core::ResponsePluginResult>
            {
                upstream_response.insert_header("x-location", "lo")?;
                Ok(pingap_core::ResponsePluginResult::Modified)
            }
            fn error_page(
                &self,
                _session: &Session,
                status: StatusCode,
                _message: &str,
            ) -> Option<(http::HeaderValue, Bytes)> {
                Some((
                    http::HeaderValue::from_static("text/plain"),
                    Bytes::from(format!("own page {}", status.as_u16())),
                ))
            }
        }
        struct Provider;
        impl PluginProvider for Provider {
            fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
                Some(Arc::new(Pages))
            }
        }
        let toml = TEST_TOML.replace(
            "weight = 1024",
            "weight = 1024\nclient_max_body_size = \"1kb\"\nmax_processing = 1",
        );
        let server = new_server_from(&toml, Some(Arc::new(Provider)));
        let refused = async |request: &str| {
            let (mut session, client) = new_duplex_session(request).await;
            let mut ctx = Ctx::default();
            let error = server
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap_err();
            assert_eq!(true, ctx.plugins.is_some(), "{request}");
            assert_eq!(true, ctx.response_plugins.is_some(), "{request}");
            let result =
                server.fail_to_proxy(&mut session, &error, &mut ctx).await;
            server.logging(&mut session, None, &mut ctx).await;
            drop(session);
            (
                result.error_code,
                read_response(client).await.to_lowercase(),
            )
        };
        // Too large a body.
        let (code, response) = refused(
            "POST /vicanso/pingap HTTP/1.1\r\nContent-Length: 2048\r\n\r\n",
        )
        .await;
        assert_eq!(413, code);
        assert_eq!(true, response.contains("own page 413"), "{response}");
        assert_eq!(true, response.contains("x-location: lo"), "{response}");

        // One request in the location, which is all it takes: the next
        // is refused.
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\n\r\n")
            .build();
        let mut first = Session::new_h1(Box::new(mock_io));
        first.read_request().await.unwrap();
        let mut first_ctx = Ctx::default();
        server
            .early_request_filter(&mut first, &mut first_ctx)
            .await
            .unwrap();
        let (code, response) =
            refused("GET /vicanso/pingap HTTP/1.1\r\n\r\n").await;
        assert_eq!(429, code);
        assert_eq!(true, response.contains("own page 429"), "{response}");
        assert_eq!(true, response.contains("x-location: lo"), "{response}");
    }

    /// A plugin that stops a response of the upstream for the proxy to
    /// answer its status (`error_page` with `intercept`): what the
    /// upstream answered is on record all the same, the plugins are still
    /// there to be asked for the page, and the page is the location's.
    #[tokio::test]
    async fn test_upstream_status_answered_by_the_location() {
        use pingap_core::UpstreamInstance;

        #[derive(Default)]
        struct Recorder {
            responses: std::sync::Mutex<Vec<u16>>,
            failures: AtomicUsize,
        }
        impl UpstreamInstance for Recorder {
            fn on_transport_failure(&self, _address: &str) {
                self.failures.fetch_add(1, Ordering::Relaxed);
            }
            fn on_response(&self, _address: &str, status: StatusCode) {
                self.responses.lock().unwrap().push(status.as_u16());
            }
            fn completed(&self) -> i32 {
                0
            }
        }
        struct Intercepts;
        #[async_trait]
        impl Plugin for Intercepts {
            fn handle_upstream_response(
                &self,
                _session: &mut Session,
                _ctx: &mut Ctx,
                upstream_response: &mut ResponseHeader,
            ) -> pingora::Result<pingap_core::ResponsePluginResult>
            {
                if upstream_response.status.is_success() {
                    return Ok(pingap_core::ResponsePluginResult::Unchanged);
                }
                Err(pingap_core::new_upstream_status_error(
                    upstream_response.status,
                ))
            }
            fn error_page(
                &self,
                _session: &Session,
                status: StatusCode,
                message: &str,
            ) -> Option<(http::HeaderValue, Bytes)> {
                Some((
                    http::HeaderValue::from_static("text/plain"),
                    Bytes::from(format!(
                        "own page {} [{message}]",
                        status.as_u16()
                    )),
                ))
            }
        }
        let server = new_server();
        let peer = HttpPeer::new("127.0.0.1:5000", false, String::new());
        let answered = async |status: u16| {
            let (mut session, client) = new_duplex_session(
                "GET /vicanso/pingap HTTP/1.1\r\nHost: a\r\n\r\n",
            )
            .await;
            let recorder = Arc::new(Recorder::default());
            let mut ctx = Ctx::default();
            ctx.state.proxying = true;
            ctx.upstream.upstream_instance = Some(recorder.clone());
            ctx.upstream.address = "127.0.0.1:5000".to_string();
            let plugins: Vec<pingap_core::NamedPlugin> =
                vec![("pages".into(), Arc::new(Intercepts))];
            ctx.plugins = Some(Arc::from(plugins));
            let mut resp = ResponseHeader::build(status, None).unwrap();
            let result = server
                .upstream_response_filter(&mut session, &mut resp, &mut ctx)
                .await;
            // Whatever the plugin said of it, the upstream has answered.
            let status = StatusCode::from_u16(status).unwrap();
            assert_eq!(Some(status), ctx.upstream.status);
            assert_eq!(Some(status), ctx.state.status);
            assert_eq!(
                vec![status.as_u16()],
                *recorder.responses.lock().unwrap()
            );
            assert_eq!(true, ctx.plugins.is_some());
            let Err(error) = result else {
                return None;
            };
            // The way of every error of a request that is being proxied.
            let error = server.error_while_proxy(
                &peer,
                &mut session,
                error,
                &mut ctx,
                false,
            );
            assert_eq!(true, pingap_core::is_upstream_status_error(&error));
            // It is an answer: not tried again, no failure of the
            // backend, and no reason for a stale response of the cache.
            assert_eq!(false, error.retry());
            assert_eq!(0, recorder.failures.load(Ordering::Relaxed));
            assert_eq!(true, ctx.upstream.failed_addresses.is_empty());
            assert_eq!(
                false,
                server.should_serve_stale(&mut session, &mut ctx, Some(&error))
            );
            let result =
                server.fail_to_proxy(&mut session, &error, &mut ctx).await;
            drop(session);
            assert_eq!(false, result.can_reuse_downstream);
            Some((result.error_code, read_response(client).await))
        };
        assert_eq!(None, answered(200).await);
        let (code, response) = answered(503).await.unwrap();
        assert_eq!(503, code);
        assert_eq!(true, response.starts_with("HTTP/1.1 503"), "{response}");
        assert_eq!(
            true,
            response.ends_with("own page 503 [Service Unavailable]"),
            "{response}"
        );
        assert_eq!(
            true,
            response.to_lowercase().contains("connection: close"),
            "{response}"
        );
        // A `4xx` has the message that was written for the client, and
        // that is the reason of the status here: not what the error was
        // wrapped in on its way, which names the peer.
        let (code, response) = answered(404).await.unwrap();
        assert_eq!(404, code);
        assert_eq!(
            true,
            response.ends_with("own page 404 [Not Found]"),
            "{response}"
        );
        assert_eq!(false, response.contains("127.0.0.1:5000"), "{response}");
    }

    /// The message of a `4xx` is the one the error was raised with. An
    /// error of a request that is being proxied is wrapped in one that
    /// names the peer, and that context - the address of the upstream,
    /// its SNI - was what the page showed.
    #[tokio::test]
    async fn test_client_error_message_is_not_the_peer() {
        let server = new_server();
        let peer = HttpPeer::new("10.1.2.3:8443", true, "in.test".to_string());
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\nHost: a\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let raised = new_internal_error(400, "the query can not be sent");
        assert_eq!(
            "the query can not be sent",
            client_error_message(&raised, 400)
        );
        let wrapped = server.error_while_proxy(
            &peer,
            &mut session,
            raised,
            &mut Ctx::default(),
            false,
        );
        assert_eq!(true, wrapped.to_string().contains("10.1.2.3:8443"));
        assert_eq!(
            "the query can not be sent",
            client_error_message(&wrapped, 400)
        );
        // An error of the upstream that is no status has no message for
        // the client, as before.
        let failed = server.error_while_proxy(
            &peer,
            &mut session,
            pingora::Error::new_up(pingora::ErrorType::ConnectRefused),
            &mut Ctx::default(),
            false,
        );
        assert_eq!("Bad Gateway", client_error_message(&failed, 502));
    }

    /// A plugin that fails on a body leaves the plugins of the location
    /// where they are, for the error page that follows.
    #[tokio::test]
    async fn test_plugins_survive_a_failing_body_plugin() {
        struct Fails;
        impl Plugin for Fails {
            fn handle_upstream_response_body(
                &self,
                _session: &mut Session,
                _ctx: &mut Ctx,
                _body: &mut Option<Bytes>,
                _end_of_stream: bool,
            ) -> pingora::Result<pingap_core::ResponseBodyPluginResult>
            {
                Err(new_internal_error(500, "upstream body"))
            }
            fn handle_response_body(
                &self,
                _session: &mut Session,
                _ctx: &mut Ctx,
                _body: &mut Option<Bytes>,
                _end_of_stream: bool,
            ) -> pingora::Result<pingap_core::ResponseBodyPluginResult>
            {
                Err(new_internal_error(500, "body"))
            }
        }
        let server = new_server();
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\nHost: a\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        let plugins: Vec<pingap_core::NamedPlugin> =
            vec![("fails".into(), Arc::new(Fails))];
        ctx.plugins = Some(Arc::from(plugins));
        let mut body = Some(Bytes::from_static(b"abc"));
        assert_eq!(
            true,
            server
                .upstream_response_body_filter(
                    &mut session,
                    &mut body,
                    false,
                    &mut ctx
                )
                .is_err()
        );
        assert_eq!(true, ctx.plugins.is_some());
        assert_eq!(
            true,
            server
                .response_body_filter(&mut session, &mut body, false, &mut ctx)
                .is_err()
        );
        assert_eq!(true, ctx.plugins.is_some());
    }

    /// What a `bandwidth_limit` plugin left in the context is kept by the
    /// proxy for the bodies it passes on.
    #[tokio::test]
    async fn test_body_pace_of_the_proxy() {
        let server = new_server();
        let (mut session, _client) = new_duplex_session(
            "GET /vicanso/pingap HTTP/1.1\r\nHost: a\r\n\r\n",
        )
        .await;
        let chunk = |session: &mut Session, ctx: &mut Ctx, len: usize| {
            let mut body = Some(Bytes::from(vec![0u8; len]));
            server
                .response_body_filter(session, &mut body, false, ctx)
                .unwrap()
                .map(|delay| delay.as_millis())
        };
        let paced = || {
            let mut ctx = Ctx::default();
            ctx.features.get_or_insert_default().body_pace =
                Some(pingap_core::BodyPace::new(1000, 0));
            ctx
        };

        // No limit: nothing is held back.
        assert_eq!(None, chunk(&mut session, &mut Ctx::default(), 4000));

        // A thousand bytes a second. Nothing waits while no part of the
        // body is out: what pingora has read by then is filtered before
        // any of it is written, the header stays in the write buffer
        // until a part of the body follows, and a wait here held the
        // status back too.
        let mut ctx = paced();
        assert_eq!(None, chunk(&mut session, &mut ctx, 1000));
        let header = ResponseHeader::build(200, None).unwrap();
        session
            .as_mut()
            .write_response_header(Box::new(header))
            .await
            .unwrap();
        assert_eq!(None, chunk(&mut session, &mut ctx, 1000));
        session
            .as_mut()
            .write_response_body(Bytes::from_static(b"body"), false)
            .await
            .unwrap();
        // It is counted all the same, and what follows waits for it.
        // (The exact time is `test_body_pace`'s to check, on a clock of
        // its own: here a stall of the test runner is not to matter.)
        let delay = chunk(&mut session, &mut ctx, 500).unwrap();
        assert_eq!(true, (1000..=2000).contains(&delay), "{delay}");

        // Afterwards the first chunk still goes at once: the wait is
        // for what went before.
        let mut ctx = paced();
        assert_eq!(None, chunk(&mut session, &mut ctx, 3000));
        let delay = chunk(&mut session, &mut ctx, 3000).unwrap();
        assert_eq!(true, (2000..=3000).contains(&delay), "{delay}");
        // The end of a body that carries nothing asks for nothing.
        let mut body = None;
        assert_eq!(
            None,
            server
                .response_body_filter(&mut session, &mut body, true, &mut ctx)
                .unwrap()
        );
        // Nor is the proxy's own fetch of a cached response held back:
        // nobody is waiting for those bytes, and the entry is locked for
        // as long as it takes. The same chunk is late for a client.
        assert_eq!(true, chunk(&mut session, &mut ctx, 2000).is_some());
        session.subrequest_ctx =
            Some(Box::new(pingora::proxy::subrequest::Ctx::builder().build()));
        assert_eq!(None, chunk(&mut session, &mut ctx, 2000));
    }

    /// Where the body of a response from the cache ends without
    /// `response_body_filter` being told: for a stored response that is
    /// sent after the upstream was asked. Not for one that is read
    /// straight from the cache, which ends like any other - told twice,
    /// a plugin would write its last piece twice.
    #[tokio::test]
    async fn test_cached_body_ends_unsaid() {
        use pingora::cache::CachePhase;
        for (phase, stale_for_status, expected) in [
            // confirmed by a `304`
            (CachePhase::Revalidated, false, true),
            (
                CachePhase::RevalidatedNoCache(NoCacheReason::OriginNotCache),
                false,
                true,
            ),
            // stale for a `5xx` of the upstream
            (CachePhase::Stale, true, true),
            // stale for an upstream that could not be reached: read as
            // a hit is
            (CachePhase::Stale, false, false),
            (CachePhase::Hit, false, false),
            (CachePhase::StaleUpdating, false, false),
            (CachePhase::Miss, false, false),
            (CachePhase::Expired, false, false),
            (CachePhase::Bypass, false, false),
            (
                CachePhase::Disabled(NoCacheReason::NeverEnabled),
                false,
                false,
            ),
        ] {
            assert_eq!(
                expected,
                cached_body_ends_unsaid(phase, stale_for_status),
                "{phase:?} {stale_for_status}"
            );
        }

        // A failed connection the stale response is answered for is not
        // that case: `proxy_cache_hit` reads it, and says where it ends.
        let server = new_server();
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\nHost: a\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        let refused =
            pingora::Error::new_up(pingora::ErrorType::ConnectRefused);
        assert_eq!(
            true,
            server.should_serve_stale(&mut session, &mut ctx, Some(&refused))
        );
        assert_eq!(false, ctx.state.stale_for_status);
    }

    /// The plugins are told once that the body ends.
    #[tokio::test]
    async fn test_body_end_is_said_once() {
        #[derive(Default)]
        struct Ends(AtomicUsize);
        impl Plugin for Ends {
            fn handle_response_body(
                &self,
                _session: &mut Session,
                _ctx: &mut Ctx,
                _body: &mut Option<Bytes>,
                end_of_stream: bool,
            ) -> pingora::Result<pingap_core::ResponseBodyPluginResult>
            {
                if end_of_stream {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
                Ok(pingap_core::ResponseBodyPluginResult::Unchanged)
            }
        }
        let server = new_server();
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\nHost: a\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let ends = Arc::new(Ends::default());
        let mut ctx = Ctx::default();
        let plugins: Vec<pingap_core::NamedPlugin> =
            vec![("ends".into(), ends.clone())];
        ctx.plugins = Some(Arc::from(plugins));
        for (end, expected) in [(false, 0), (true, 1), (true, 1), (false, 1)] {
            let mut body = Some(Bytes::from_static(b"abc"));
            server
                .response_body_filter(&mut session, &mut body, end, &mut ctx)
                .unwrap();
            assert_eq!(expected, ends.0.load(Ordering::Relaxed), "{end}");
        }
    }

    /// The cookie of a `sticky` upstream goes on the response to the
    /// client.
    #[tokio::test]
    async fn test_sticky_cookie_of_the_response() {
        let server = new_server();
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\nHost: a\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        // The cookie: next to those of the upstream, once, and marked
        // for https only where the client came by it.
        for (tls, expected) in [
            (
                None,
                "route=00000000000000ab; Path=/; HttpOnly; SameSite=Lax",
            ),
            (
                Some("TLSv1.3".to_string()),
                "route=00000000000000ab; Path=/; HttpOnly; SameSite=Lax; Secure",
            ),
        ] {
            let mut ctx = Ctx::default();
            ctx.conn.tls_version = tls.map(std::borrow::Cow::Owned);
            ctx.upstream.sticky_cookie =
                Some("route=00000000000000ab".to_string());
            let mut resp = ResponseHeader::build(200, None).unwrap();
            resp.append_header("Set-Cookie", "session=abc").unwrap();
            server
                .response_filter(&mut session, &mut resp, &mut ctx)
                .await
                .unwrap();
            let cookies: Vec<&str> = resp
                .headers
                .get_all("Set-Cookie")
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect();
            assert_eq!(vec!["session=abc", expected], cookies);
            assert_eq!(None, ctx.upstream.sticky_cookie);
        }
        // The cookie is that of an attempt. One that failed sets none:
        // a stale response of the cache that is answered in its place
        // would keep the client on the backend that has just failed.
        let peer = HttpPeer::new("127.0.0.1:9", false, String::new());
        for connected in [false, true] {
            let mut ctx = Ctx::default();
            ctx.upstream.sticky_cookie =
                Some("route=00000000000000ab".to_string());
            let error =
                pingora::Error::new_up(pingora::ErrorType::ConnectRefused);
            if connected {
                server.error_while_proxy(
                    &peer,
                    &mut session,
                    error,
                    &mut ctx,
                    false,
                );
            } else {
                server.fail_to_connect(&mut session, &peer, &mut ctx, error);
            }
            assert_eq!(None, ctx.upstream.sticky_cookie, "{connected}");
        }
        // Nor does a `5xx` of the backend that a stale response is
        // answered for: pingora asks about that one straight from the
        // response header, and neither of the two above is called.
        let mut ctx = Ctx::default();
        ctx.upstream.sticky_cookie = Some("route=00000000000000ab".to_string());
        let status = pingora::Error::create(
            pingora::ErrorType::HTTPStatus(503),
            pingora::ErrorSource::Upstream,
            None,
            None,
        );
        assert_eq!(
            true,
            server.should_serve_stale(&mut session, &mut ctx, Some(&status))
        );
        assert_eq!(None, ctx.upstream.sticky_cookie);
        // And that is the stale answer whose end pingora does not say.
        assert_eq!(true, ctx.state.stale_for_status);
        // What is no error of the upstream is no reason for a stale
        // response, and leaves the cookie alone.
        ctx.upstream.sticky_cookie = Some("route=00000000000000ab".to_string());
        let refused = new_internal_error(503, "no backend");
        assert_eq!(
            false,
            server.should_serve_stale(&mut session, &mut ctx, Some(&refused))
        );
        assert_eq!(true, ctx.upstream.sticky_cookie.is_some());
        // An upstream that keeps nobody anywhere sets none.
        let mut resp = ResponseHeader::build(200, None).unwrap();
        server
            .response_filter(&mut session, &mut resp, &mut Ctx::default())
            .await
            .unwrap();
        assert_eq!(false, resp.headers.contains_key("Set-Cookie"));
    }

    /// Which failures send the retry of a request to another backend:
    /// those of the backend, not those of one connection to it.
    #[tokio::test]
    async fn test_failed_backend_is_remembered_for_the_retry() {
        use pingora::upstreams::peer::HttpPeer;
        use pingora::{Error, ErrorType, RetryType};
        let server = new_server();
        let peer = HttpPeer::new("127.0.0.1:9", false, String::new());
        let failed_after =
            async |etype: ErrorType, retry: RetryType, reused: bool| {
                let mock_io = Builder::new()
                    .read(b"GET /vicanso/pingap HTTP/1.1\r\nHost: a\r\n\r\n")
                    .build();
                let mut session = Session::new_h1(Box::new(mock_io));
                session.read_request().await.unwrap();
                let mut ctx = Ctx::default();
                ctx.upstream.address = "127.0.0.1:9".to_string();
                let mut e = Error::new_up(etype);
                e.retry = retry;
                let e = server.error_while_proxy(
                    &peer,
                    &mut session,
                    e,
                    &mut ctx,
                    reused,
                );
                (e.retry(), ctx.upstream.failed_addresses)
            };
        let remembered = vec!["127.0.0.1:9".to_string()];
        let none: Vec<String> = vec![];

        // A connection that is retried because the backend failed it.
        assert_eq!(
            (true, remembered.clone()),
            failed_after(ErrorType::ReadError, RetryType::Decided(true), false)
                .await
        );
        // A connection that had been kept and was closed in the meantime:
        // the backend is as good as it was.
        assert_eq!(
            (true, none.clone()),
            failed_after(ErrorType::ReadError, RetryType::ReusedOnly, true)
                .await
        );
        // Regression: so is one whose HTTP/2 connection is being retired
        // (GOAWAY, a refused stream), or that is to be asked by HTTP/1.1.
        // The retry was sent elsewhere, off the backend a hash keeps the
        // client on.
        for etype in [
            ErrorType::H2Error,
            ErrorType::H2Downgrade,
            ErrorType::InvalidH2,
        ] {
            assert_eq!(
                (true, none.clone()),
                failed_after(etype.clone(), RetryType::Decided(true), true)
                    .await,
                "{etype:?}"
            );
        }
        // What is not tried again leaves nothing to remember.
        assert_eq!(
            (false, none.clone()),
            failed_after(
                ErrorType::ReadError,
                RetryType::Decided(false),
                false
            )
            .await
        );
    }

    /// Regression: a target without a slash in front was routed and
    /// cached as `/` and sent to the upstream as it came.
    #[tokio::test]
    async fn test_target_that_is_no_path_is_refused() {
        let server = new_server();
        let filter = async |target: &str| {
            let input = format!("GET {target} HTTP/1.1\r\nHost: a\r\n\r\n");
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let routable = has_routable_target(session.req_header());
            let mut ctx = Ctx::default();
            let result =
                server.early_request_filter(&mut session, &mut ctx).await;
            (routable, result.map_err(|e| format!("{:?}", e.etype())))
        };
        for target in ["secret/report", "nf", "robots.txt?a=1", "a:b"] {
            let (routable, result) = filter(target).await;
            assert_eq!(false, routable, "{target}");
            assert_eq!(Err("HTTPStatus(400)".to_string()), result, "{target}");
        }
        for target in [
            "/",
            "/vicanso/pingap?size=1",
            "?size=1",
            "*",
            "http://a/vicanso/pingap?size=1",
        ] {
            let (routable, result) = filter(target).await;
            assert_eq!(true, routable, "{target}");
            assert_eq!(Ok(()), result, "{target}");
        }
    }

    /// A cache whose key is made of a part of the query asks the upstream
    /// with that part. The request itself stays as the client sent it,
    /// which is what the access log shows.
    #[tokio::test]
    async fn test_upstream_is_asked_with_the_query_of_the_cache_key() {
        let server = new_server();
        let mock_io = Builder::new()
            .read(b"GET /list?utm_source=mail&p%61ge=2&a=1 HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut upstream_request = session.req_header().clone();
        let mut ctx = Ctx::default();
        ctx.cache.get_or_insert_default().key_query = Some("a=1".to_string());
        server
            .upstream_request_filter(
                &mut session,
                &mut upstream_request,
                &mut ctx,
            )
            .await
            .unwrap();
        assert_eq!("/list?a=1", upstream_request.uri.to_string());
        assert_eq!(
            "/list?utm_source=mail&p%61ge=2&a=1",
            session.req_header().uri.to_string()
        );

        // No cache, or one without a rule for the query: as it came.
        for cache in [None, Some(Box::default())] {
            let mut upstream_request = session.req_header().clone();
            let mut ctx = Ctx {
                cache,
                ..Default::default()
            };
            server
                .upstream_request_filter(
                    &mut session,
                    &mut upstream_request,
                    &mut ctx,
                )
                .await
                .unwrap();
            assert_eq!(
                "/list?utm_source=mail&p%61ge=2&a=1",
                upstream_request.uri.to_string()
            );
        }
    }

    /// Regression: pingora asks for the peer again when a reused
    /// connection turns out to be dead, without a failed connect in
    /// between. Told apart by the count of those, the second call looked
    /// like a first: the upstream's processing count went up twice and
    /// came down once, and the body sent again was added to what was
    /// counted of it the first time.
    #[tokio::test]
    async fn test_retry_is_counted_once() {
        let server = new_server();
        let upstream = server.upstream_provider.get("charts").unwrap();
        let mock_io = Builder::new()
            .read(b"POST /vicanso/pingap HTTP/1.1\r\nContent-Length: 4\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        server
            .early_request_filter(&mut session, &mut ctx)
            .await
            .unwrap();
        server.upstream_peer(&mut session, &mut ctx).await.unwrap();
        assert_eq!(1, upstream.stats().processing);
        server
            .request_body_filter(
                &mut session,
                &mut Some(Bytes::from_static(b"body")),
                true,
                &mut ctx,
            )
            .await
            .unwrap();
        assert_eq!(4, ctx.state.payload_size);

        // The retry: the same request, the same context, no failed connect.
        assert_eq!(0, ctx.upstream.retries);
        server.upstream_peer(&mut session, &mut ctx).await.unwrap();
        assert_eq!(1, upstream.stats().processing);
        assert_eq!(0, ctx.state.payload_size);

        server.logging(&mut session, None, &mut ctx).await;
        assert_eq!(0, upstream.stats().processing);
    }

    /// Regression: the ids of a request were set on the response in
    /// `upstream_response_filter`, ahead of the cache. Stored with the
    /// response, they were what every later hit carried: the ids of the
    /// request that had filled the cache. They are set on the way out.
    #[tokio::test]
    async fn test_request_id_is_not_stored_with_the_response() {
        let server = new_server();
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.state.request_id = Some("first".to_string());

        // What the cache stores is the header as this filter leaves it.
        let mut resp = ResponseHeader::build_no_case(200, None).unwrap();
        server
            .upstream_response_filter(&mut session, &mut resp, &mut ctx)
            .await
            .unwrap();
        assert_eq!(false, resp.headers.contains_key("x-request-id"));

        // A hit comes back through `response_filter` only, with the stored
        // header and the context of the request it answers.
        let mut hit_ctx = Ctx::default();
        hit_ctx.state.request_id = Some("second".to_string());
        server
            .response_filter(&mut session, &mut resp, &mut hit_ctx)
            .await
            .unwrap();
        assert_eq!("second", resp.headers.get("x-request-id").unwrap());
    }

    /// The cookies of a request are one field by the time anything reads
    /// them, see `merge_cookie_headers`.
    #[tokio::test]
    async fn test_early_request_filter_merges_cookies() {
        let server = new_server();
        let mock_io = Builder::new()
            .read(b"GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        server
            .early_request_filter(&mut session, &mut Ctx::default())
            .await
            .unwrap();
        assert_eq!(
            Some("2"),
            pingap_core::get_cookie_value(session.req_header(), "b")
        );
        assert_eq!(
            1,
            session
                .req_header()
                .headers
                .get_all("cookie")
                .iter()
                .count()
        );
    }

    /// The upstream's processing count is only taken back for a request
    /// that was counted: a 503 for want of a backend used to push it one
    /// below the truth each time.
    #[tokio::test]
    async fn test_no_backend_keeps_upstream_processing_straight() {
        // a port nothing listens on, so the health check fails
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let toml =
            TEST_TOML.replace("127.0.0.1:5000", &format!("127.0.0.1:{port}"));
        let server = new_server_from(&toml, None);
        let upstream = server.upstream_provider.get("charts").unwrap();
        async fn run(server: &Server) -> (Ctx, bool) {
            let mock_io = Builder::new()
                .read(b"GET /vicanso/pingap HTTP/1.1\r\n\r\n")
                .build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            server
                .early_request_filter(&mut session, &mut ctx)
                .await
                .unwrap();
            let found =
                server.upstream_peer(&mut session, &mut ctx).await.is_ok();
            let counted = ctx.upstream.upstream_instance.is_some();
            server.logging(&mut session, None, &mut ctx).await;
            (ctx, found && counted)
        }

        // A request that gets a peer is counted, and uncounted when logged.
        let (ctx, counted) = run(&server).await;
        assert_eq!(true, counted);
        assert_eq!(Some(0), ctx.upstream.processing_count);
        assert_eq!(0, upstream.stats().processing);

        // No backend left: 503, and nothing to take back.
        let _ = upstream.run_health_check().await;
        for _ in 0..3 {
            let (ctx, counted) = run(&server).await;
            assert_eq!(false, counted);
            assert_eq!(None, ctx.upstream.processing_count);
            assert_eq!("charts", &*ctx.upstream.name);
        }
        assert_eq!(0, upstream.stats().processing);
    }

    #[test]
    fn test_cache_variance() {
        let request = |accept_encoding: Option<&str>, accept: Option<&str>| {
            let mut req = RequestHeader::build("GET", b"/", None).unwrap();
            if let Some(value) = accept_encoding {
                req.append_header("Accept-Encoding", value).unwrap();
            }
            if let Some(value) = accept {
                req.append_header("Accept", value).unwrap();
            }
            req
        };
        let response = |vary: &[&str]| {
            let mut resp = ResponseHeader::build(200, None).unwrap();
            for value in vary {
                resp.append_header("Vary", *value).unwrap();
            }
            resp
        };

        // No Vary: nothing varies, the single-slot behaviour stays.
        assert_eq!(
            None,
            cache_variance(
                &response(&[]).headers,
                &request(Some("gzip"), None),
                None
            )
        );

        // The same headers give the same variance, different values differ,
        // and a missing header is a value of its own.
        let vary_resp = response(&["Accept-Encoding, Accept"]);
        let resp = &vary_resp.headers;
        let gzip = cache_variance(resp, &request(Some("gzip"), None), None);
        assert_eq!(true, gzip.is_some());
        assert_eq!(
            gzip,
            cache_variance(resp, &request(Some("gzip"), None), None)
        );
        assert_ne!(
            gzip,
            cache_variance(resp, &request(Some("br"), None), None)
        );
        assert_ne!(gzip, cache_variance(resp, &request(None, None), None));
        assert_ne!(
            gzip,
            cache_variance(
                resp,
                &request(Some("gzip"), Some("text/html")),
                None
            )
        );

        // Header names are case-insensitive and may be split over several
        // Vary headers.
        assert_eq!(
            gzip,
            cache_variance(
                &response(&["accept-encoding", "ACCEPT"]).headers,
                &request(Some("gzip"), None),
                None
            )
        );

        // An allow list drops the headers it does not name: Accept no longer
        // splits the cache, an unlisted-only Vary varies nothing.
        let allowed = vec!["accept-encoding".to_string()];
        assert_eq!(
            cache_variance(resp, &request(Some("gzip"), None), Some(&allowed)),
            cache_variance(
                resp,
                &request(Some("gzip"), Some("text/html")),
                Some(&allowed)
            )
        );
        assert_eq!(
            None,
            cache_variance(
                &response(&["Cookie"]).headers,
                &request(Some("gzip"), None),
                Some(&allowed)
            )
        );
    }

    fn create_session(path: &str) -> Session {
        let headers = ["Host: example.com"].join("\r\n");
        let input_header =
            format!("GET {} HTTP/1.1\r\n{headers}\r\n\r\n", path);
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        Session::new_h1(Box::new(mock_io))
    }

    #[tokio::test]
    async fn test_handle_acme_challenge_not_enabled() {
        let server = new_server();

        let mut session = create_session("/");
        session.read_request().await.unwrap();

        let result = server
            .handle_acme_challenge(&mut session, &mut Ctx::default())
            .await;
        assert!(
            result.is_none(),
            "When ACME not enabled, should return None"
        );
    }

    #[tokio::test]
    async fn test_handle_acme_challenge_non_challenge_returns_none() {
        let mut server = new_server();
        server.enable_lets_encrypt();

        let test_paths = ["/", "/api", "/test.html", "/normal/path"];

        for path in test_paths {
            let mut session = create_session(path);
            session.read_request().await.unwrap();

            let result = server
                .handle_acme_challenge(&mut session, &mut Ctx::default())
                .await;
            assert!(
                result.is_none(),
                "Path '{}' should return None to continue processing (bug returns Some(Ok(false)))",
                path
            );
        }
    }

    /// A location's processing count is decremented in `logging` for every
    /// request that recorded the instance, so the instance must only be
    /// recorded once the request has been counted: a 413 used to leave the
    /// count one too low each time, and a 429 has to be undone the same
    /// way as any completed request.
    #[tokio::test]
    async fn test_rejected_requests_keep_location_counters_straight() {
        let toml = TEST_TOML.replace(
            "weight = 1024",
            "weight = 1024\nclient_max_body_size = \"1kb\"\nmax_processing = 1",
        );
        let server = new_server_from(&toml, None);
        let location = server.location_provider.get("lo").unwrap();
        async fn run(
            server: &Server,
            request: &str,
        ) -> (Session, Ctx, pingora::Result<()>) {
            let mock_io = Builder::new().read(request.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            let result =
                server.early_request_filter(&mut session, &mut ctx).await;
            (session, ctx, result)
        }

        // Too large a body: rejected before the location counts it, so
        // there is nothing for `logging` to undo.
        let (mut session, mut ctx, result) = run(
            &server,
            "POST /vicanso/pingap HTTP/1.1\r\nContent-Length: 2048\r\n\r\n",
        )
        .await;
        let err = result.unwrap_err();
        assert_eq!(
            true,
            matches!(err.etype(), pingora::ErrorType::HTTPStatus(413)),
            "{err}"
        );
        assert_eq!("lo", ctx.upstream.location.as_ref());
        assert_eq!(true, ctx.upstream.location_instance.is_none());
        assert_eq!(0, location.stats().processing);
        server.logging(&mut session, None, &mut ctx).await;
        assert_eq!(0, location.stats().processing);

        // Over `max_processing`: counted, rejected, undone once logged.
        let (mut first_session, mut first_ctx, result) =
            run(&server, "GET /vicanso/pingap HTTP/1.1\r\n\r\n").await;
        result.unwrap();
        assert_eq!(1, location.stats().processing);
        let (mut session, mut ctx, result) =
            run(&server, "GET /vicanso/pingap HTTP/1.1\r\n\r\n").await;
        let err = result.unwrap_err();
        assert_eq!(
            true,
            matches!(err.etype(), pingora::ErrorType::HTTPStatus(429)),
            "{err}"
        );
        assert_eq!(true, ctx.upstream.location_instance.is_some());
        assert_eq!(2, location.stats().processing);
        server.logging(&mut session, None, &mut ctx).await;
        assert_eq!(1, location.stats().processing);
        server
            .logging(&mut first_session, None, &mut first_ctx)
            .await;
        assert_eq!(0, location.stats().processing);
    }

    /// Answers at the EarlyRequest step and counts every call at any step.
    struct EarlyResponder {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Plugin for EarlyResponder {
        async fn handle_request(
            &self,
            step: PluginStep,
            _session: &mut Session,
            _ctx: &mut Ctx,
        ) -> pingora::Result<RequestPluginResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(if step == PluginStep::EarlyRequest {
                RequestPluginResult::Respond(pingap_core::HttpResponse::text(
                    "early",
                ))
            } else {
                RequestPluginResult::Continue
            })
        }
    }

    /// pingora only lets a request stop at `request_filter`, so a response
    /// sent by an EarlyRequest plugin has to be recognised there: the
    /// request is reported as handled, and no later step runs on top of
    /// the answer.
    #[tokio::test]
    async fn test_early_plugin_response_is_final() {
        let calls = Arc::new(AtomicUsize::new(0));
        let server = new_server_with(Some(Arc::new(CountingPluginProvider {
            plugin: Arc::new(EarlyResponder {
                calls: calls.clone(),
            }),
        })));
        let (mut session, client) =
            new_duplex_session("GET /vicanso/pingap HTTP/1.1\r\n\r\n").await;
        let mut ctx = Ctx::default();
        server
            .early_request_filter(&mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(true, session.response_written().is_some());
        assert_eq!(
            true,
            server.request_filter(&mut session, &mut ctx).await.unwrap()
        );
        assert_eq!(1, calls.load(Ordering::SeqCst));
        assert_eq!(Some(StatusCode::OK), ctx.state.status);
        drop(session);
        let response = read_response(client).await;
        assert_eq!(
            true,
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "{response}"
        );
        assert_eq!(true, response.ends_with("early"), "{response}");
    }

    /// Regression: a response that a plugin answers with goes out from the
    /// request step, and had none of the headers the response step adds: a
    /// cross-origin 401 without the CORS headers never reaches the page.
    /// The plugins that ask for it set their headers on it, the one that
    /// answered and the ones that did not ask do not.
    #[tokio::test]
    async fn test_plugin_response_gets_the_headers_asked_for() {
        struct Adder {
            header: &'static str,
            asks: bool,
        }
        #[async_trait::async_trait]
        impl Plugin for Adder {
            async fn handle_response(
                &self,
                _session: &mut Session,
                _ctx: &mut Ctx,
                resp: &mut ResponseHeader,
            ) -> pingora::Result<ResponsePluginResult> {
                resp.insert_header(self.header, "1")?;
                Ok(ResponsePluginResult::Modified)
            }
            fn handles_plugin_response(&self) -> bool {
                self.asks
            }
        }
        let adder = |header, asks| -> Arc<dyn Plugin> {
            Arc::new(Adder { header, asks })
        };
        let plugins: Vec<pingap_core::NamedPlugin> = vec![
            ("cors".into(), adder("X-Cors", true)),
            ("auth".into(), adder("X-Auth", true)),
            ("other".into(), adder("X-Other", false)),
        ];
        let send = async |plugins: &[pingap_core::NamedPlugin],
                          responder: usize| {
            let (mut session, client) =
                new_duplex_session("GET / HTTP/1.1\r\n\r\n").await;
            let mut resp = pingap_core::HttpResponse::text("denied");
            resp.status = StatusCode::UNAUTHORIZED;
            send_plugin_response(
                &mut session,
                &mut Ctx::default(),
                plugins,
                responder,
                resp,
            )
            .await
            .unwrap();
            drop(session);
            read_response(client).await.to_lowercase()
        };

        // `auth`, the second plugin, is the one that answers.
        let response = send(&plugins, 1).await;
        assert_eq!(true, response.starts_with("http/1.1 401 "), "{response}");
        assert_eq!(true, response.contains("x-cors: 1"), "{response}");
        assert_eq!(false, response.contains("x-auth"), "{response}");
        assert_eq!(false, response.contains("x-other"), "{response}");
        assert_eq!(true, response.contains("content-length: 6"), "{response}");
        assert_eq!(true, response.ends_with("denied"), "{response}");

        // Nobody asks: sent as it is.
        let response = send(&plugins[1..], 0).await;
        assert_eq!(true, response.starts_with("http/1.1 401 "), "{response}");
        assert_eq!(false, response.contains("x-"), "{response}");
    }

    /// A backend that takes the connection and then fails the request is
    /// reported to its statistics, once, and only when this request is
    /// what failed.
    #[tokio::test]
    async fn test_error_while_proxy_reports_to_the_backend() {
        use pingap_core::UpstreamInstance;
        use pingora::{Error, ErrorType, RetryType};

        #[derive(Default)]
        struct Recorder(AtomicUsize);
        impl UpstreamInstance for Recorder {
            fn on_transport_failure(&self, _address: &str) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn on_response(&self, _address: &str, _status: StatusCode) {}
            fn completed(&self) -> i32 {
                0
            }
        }

        let server = new_server();
        let peer = HttpPeer::new("127.0.0.1:5000", false, String::new());
        // Returns how often the failure was reported, and whether the
        // request is retried.
        let run = async |method: &str,
                         e: Box<Error>,
                         status: Option<StatusCode>,
                         reused: bool| {
            let mock_io = Builder::new()
                .read(format!("{method} / HTTP/1.1\r\n\r\n").as_bytes())
                .build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let recorder = Arc::new(Recorder::default());
            let mut ctx = Ctx::default();
            ctx.upstream.upstream_instance = Some(recorder.clone());
            ctx.upstream.status = status;
            let e = server.error_while_proxy(
                &peer,
                &mut session,
                e,
                &mut ctx,
                reused,
            );
            (recorder.0.load(Ordering::Relaxed), e.retry())
        };
        let timeout = || Error::new(ErrorType::ReadTimedout).into_up();
        let closed = || {
            let mut e = Error::new(ErrorType::ConnectionClosed).into_up();
            e.retry = RetryType::ReusedOnly;
            e
        };

        // The backend never answered.
        assert_eq!((1, false), run("GET", timeout(), None, false).await);
        assert_eq!((1, false), run("GET", timeout(), None, true).await);
        // It closed a fresh connection before answering.
        assert_eq!((1, false), run("GET", closed(), None, false).await);
        // A reused connection it had already closed says nothing about the
        // backend, retried (GET) or not (POST).
        assert_eq!((0, true), run("GET", closed(), None, true).await);
        assert_eq!((0, false), run("POST", closed(), None, true).await);
        // On a fresh connection the same error is the backend's doing.
        assert_eq!((1, false), run("POST", closed(), None, false).await);
        // The response header came, `on_response` has counted it.
        assert_eq!(
            (0, false),
            run("GET", timeout(), Some(StatusCode::OK), false).await
        );
        // The client's doing.
        assert_eq!(
            (0, false),
            run(
                "GET",
                Error::new(ErrorType::ReadError).into_down(),
                None,
                false
            )
            .await
        );
    }

    #[test]
    fn test_classify_proxy_error() {
        use pingora::ErrorType::*;
        let down = pingora::Error::new_down;
        let up = pingora::Error::new_up;
        assert_eq!(
            (404, false),
            classify_proxy_error(&new_internal_error(404, "no route"))
        );
        assert_eq!((502, false), classify_proxy_error(&up(ConnectRefused)));
        // An upstream that went away mid-transfer is still ours to report.
        assert_eq!((502, false), classify_proxy_error(&up(ReadError)));
        // Regression: one that did not answer in time was a 502 as well,
        // the same as one that is down.
        for timeout in [
            ConnectTimedout,
            ReadTimedout,
            WriteTimedout,
            TLSHandshakeTimedout,
        ] {
            assert_eq!((504, false), classify_proxy_error(&up(timeout)));
        }
        assert_eq!((499, true), classify_proxy_error(&down(ConnectionClosed)));
        assert_eq!((499, true), classify_proxy_error(&down(ReadError)));
        assert_eq!((499, true), classify_proxy_error(&down(WriteError)));
        assert_eq!((499, true), classify_proxy_error(&down(WriteTimedout)));
        assert_eq!((408, false), classify_proxy_error(&down(ReadTimedout)));
        assert_eq!(
            (400, false),
            classify_proxy_error(&down(InvalidHTTPHeader))
        );
        assert_eq!((500, false), classify_proxy_error(&down(UnknownError)));
        assert_eq!(
            (500, false),
            classify_proxy_error(&pingora::Error::new_in(InternalError))
        );
    }

    #[test]
    fn test_error_response_header() {
        // Prebuilt or generated, the header is the same one.
        for code in [404, 418] {
            let prebuilt = error_response_header(code);
            let generated = error_resp::gen_error_response(code);
            assert_eq!(generated.status, prebuilt.status);
            assert_eq!(generated.headers, prebuilt.headers);
        }
    }

    /// The connection is dead or stuck: nothing is written (the mock has no
    /// write expectation and panics on one), and the access log gets a 499.
    #[tokio::test]
    async fn test_dead_client_gets_no_error_page() {
        use pingora::ErrorType::*;
        let server = new_server();
        for error_type in
            [ConnectionClosed, ReadError, WriteError, WriteTimedout]
        {
            let mock_io = Builder::new()
                .read(b"GET /vicanso/pingap HTTP/1.1\r\n\r\n")
                .build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            let result = server
                .fail_to_proxy(
                    &mut session,
                    &pingora::Error::new_down(error_type),
                    &mut ctx,
                )
                .await;
            assert_eq!(499, result.error_code);
            assert_eq!(false, result.can_reuse_downstream);
            assert_eq!(
                Some(StatusCode::from_u16(499).unwrap()),
                ctx.state.status
            );
            assert_eq!(true, session.response_written().is_none());
        }
    }

    /// A downstream read timeout is the client's slowness: 408, with the
    /// page from the template.
    /// The page says what a 4xx was about and nothing about the inside:
    /// an upstream failure or a 5xx only names the status.
    #[test]
    fn test_client_error_message() {
        let not_found = new_internal_error(404, "No matching location, host:a");
        assert_eq!(
            "No matching location, host:a",
            client_error_message(&not_found, 404)
        );
        let too_many = new_internal_error(429, "Too many requests");
        assert_eq!("Too many requests", client_error_message(&too_many, 429));

        // A 5xx of pingap's own: its message may quote a path or a name.
        let unavailable =
            new_internal_error(503, "No available upstream for api");
        assert_eq!(
            "Service Unavailable",
            client_error_message(&unavailable, 503)
        );
        // An upstream failure carries the peer's address.
        let connect = pingora::Error::explain(
            pingora::ErrorType::ConnectTimedout,
            "timeout 300ms connecting to server addr: 10.9.8.7:65001",
        )
        .into_up();
        assert_eq!(
            true,
            connect.to_string().contains("10.9.8.7"),
            "the error itself keeps the detail for the log"
        );
        assert_eq!("Bad Gateway", client_error_message(&connect, 502));
        // A client error pingora found has no message for the client.
        let timeout =
            pingora::Error::new_down(pingora::ErrorType::ReadTimedout);
        assert_eq!("Request Timeout", client_error_message(&timeout, 408));
    }

    /// What the client put in its request comes back escaped, and an
    /// upstream failure does not show where the upstream is.
    #[tokio::test]
    async fn test_error_page_content() {
        let server = new_server();
        let page = async |e: Box<pingora::Error>| {
            let (mut session, client) = new_duplex_session(
                "GET /vicanso/pingap HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .await;
            let mut ctx = Ctx::default();
            server.fail_to_proxy(&mut session, &e, &mut ctx).await;
            drop(session);
            read_response(client).await
        };

        let response = page(new_internal_error(
            404,
            "No matching location, host:<img src=x onerror=alert(1)> path:/a\"b",
        ))
        .await;
        assert_eq!(
            true,
            response.contains(
                "No matching location, host:&lt;img src=x onerror=alert(1)&gt; path:/a&quot;b"
            ),
            "{response}"
        );
        assert_eq!(false, response.contains("<img"), "{response}");

        let response = page(
            pingora::Error::explain(
                pingora::ErrorType::ConnectTimedout,
                "timeout 300ms connecting to server addr: 10.9.8.7:65001",
            )
            .into_up(),
        )
        .await;
        assert_eq!(
            true,
            response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"),
            "{response}"
        );
        assert_eq!(
            true,
            response.contains("X-Pingap-EType: ConnectTimedout\r\n"),
            "{response}"
        );
        assert_eq!(true, response.contains(">Gateway Timeout<"), "{response}");
        assert_eq!(false, response.contains("10.9.8.7"), "{response}");
    }

    #[tokio::test]
    async fn test_read_timeout_gets_408_page() {
        let server = new_server();
        let (mut session, client) = new_duplex_session(
            "GET /vicanso/pingap HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;
        let mut ctx = Ctx::default();
        let result = server
            .fail_to_proxy(
                &mut session,
                &pingora::Error::new_down(pingora::ErrorType::ReadTimedout),
                &mut ctx,
            )
            .await;
        assert_eq!(408, result.error_code);
        assert_eq!(Some(StatusCode::REQUEST_TIMEOUT), ctx.state.status);
        drop(session);
        let response = read_response(client).await;
        assert_eq!(
            true,
            response.starts_with("HTTP/1.1 408 Request Timeout\r\n"),
            "{response}"
        );
        assert_eq!(
            true,
            response.contains("X-Pingap-EType: ReadTimedout\r\n"),
            "{response}"
        );
        assert_eq!(
            true,
            response.contains("Content-Type: text/html; charset=utf-8\r\n"),
            "{response}"
        );
    }

    /// Regression: the log and the metrics took the upstream's status for
    /// the response's. On a revalidation the upstream says 304 and the
    /// client gets the stored 200.
    #[tokio::test]
    async fn test_logging_records_the_status_the_client_got() {
        let server = new_server();
        let (mut session, _client) =
            new_duplex_session("GET /vicanso/pingap HTTP/1.1\r\n\r\n").await;
        let mut ctx = Ctx::default();
        // As `upstream_response_filter` leaves it on a revalidation.
        ctx.state.status = Some(StatusCode::NOT_MODIFIED);
        let mut header = ResponseHeader::build(200, None).unwrap();
        header.insert_header("Content-Length", "0").unwrap();
        session
            .as_mut()
            .write_response_header(Box::new(header))
            .await
            .unwrap();
        server.logging(&mut session, None, &mut ctx).await;
        assert_eq!(Some(StatusCode::OK), ctx.state.status);

        // Nothing was sent: what was noted stays, a 499 for instance.
        let (mut session, _client) =
            new_duplex_session("GET /vicanso/pingap HTTP/1.1\r\n\r\n").await;
        let mut ctx = Ctx::default();
        ctx.state.status = StatusCode::from_u16(499).ok();
        server.logging(&mut session, None, &mut ctx).await;
        assert_eq!(StatusCode::from_u16(499).ok(), ctx.state.status);
    }

    /// Regression: every error page closed the connection it was sent
    /// over, so a client that was refused made a new one, handshake and
    /// all, for each request. It is kept when the request is all read and
    /// the failure is not one of reading it.
    #[tokio::test]
    async fn test_error_page_keeps_the_connection() {
        let server = new_server();
        let fail = async |request: &str,
                          error: Box<pingora::Error>,
                          proxying: bool| {
            let (mut session, client) = new_duplex_session(request).await;
            // As the proxy does for a request that asks to be kept alive.
            session.set_keepalive(Some(60));
            let mut ctx = Ctx::default();
            ctx.state.proxying = proxying;
            let result =
                server.fail_to_proxy(&mut session, &error, &mut ctx).await;
            drop(session);
            (result, read_response(client).await.to_lowercase())
        };
        let no_location =
            || pingap_core::new_internal_error(404, "No matching location");
        let get = "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n";

        let (result, response) = fail(get, no_location(), false).await;
        assert_eq!(404, result.error_code);
        assert_eq!(true, result.can_reuse_downstream);
        assert_eq!(false, response.contains("connection: close"), "{response}");

        // On its way to an upstream: pingora closes the connection after
        // such a failure whatever is answered, so the page says so.
        for error in [
            pingora::Error::new_up(pingora::ErrorType::ConnectRefused),
            pingap_core::new_internal_error(503, "No available upstream"),
        ] {
            let (result, response) = fail(get, error, true).await;
            assert_eq!(false, result.can_reuse_downstream);
            assert_eq!(
                true,
                response.contains("connection: close"),
                "{response}"
            );
        }

        // A body that was not read is not read for the sake of an error.
        let (result, response) = fail(
            "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n\r\nhello",
            no_location(),
            false,
        )
        .await;
        assert_eq!(false, result.can_reuse_downstream);
        assert_eq!(true, response.contains("connection: close"), "{response}");

        // What went wrong was the reading itself.
        let (result, response) = fail(
            get,
            pingora::Error::new_down(pingora::ErrorType::InvalidHTTPHeader),
            false,
        )
        .await;
        assert_eq!(400, result.error_code);
        assert_eq!(false, result.can_reuse_downstream);
        assert_eq!(true, response.contains("connection: close"), "{response}");
    }

    /// The error page of a request that had a location carries what the
    /// plugins of that location set on the responses of other plugins.
    /// Without them a `502` had no CORS headers, so the page never saw
    /// the status, and none of the security headers of the site.
    #[tokio::test]
    async fn test_error_page_carries_the_headers_of_the_location() {
        struct Marks {
            asks: bool,
        }
        #[async_trait]
        impl pingap_core::Plugin for Marks {
            fn handles_plugin_response(&self) -> bool {
                self.asks
            }
            async fn handle_response(
                &self,
                _session: &mut Session,
                _ctx: &mut Ctx,
                upstream_response: &mut ResponseHeader,
            ) -> pingora::Result<pingap_core::ResponsePluginResult>
            {
                let name = if self.asks { "x-asked" } else { "x-not-asked" };
                upstream_response.insert_header(name, "1")?;
                Ok(pingap_core::ResponsePluginResult::Modified)
            }
        }
        let server = new_server();
        let page = async |plugins: Option<Vec<pingap_core::NamedPlugin>>| {
            let (mut session, client) =
                new_duplex_session("GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n")
                    .await;
            let mut ctx = Ctx::default();
            ctx.state.proxying = true;
            ctx.response_plugins = plugins.map(Arc::from);
            let error =
                pingora::Error::new_up(pingora::ErrorType::ConnectRefused);
            let result =
                server.fail_to_proxy(&mut session, &error, &mut ctx).await;
            drop(session);
            (
                result.error_code,
                read_response(client).await.to_lowercase(),
            )
        };
        let plugins: Vec<pingap_core::NamedPlugin> = vec![
            ("asks".into(), Arc::new(Marks { asks: true })),
            ("other".into(), Arc::new(Marks { asks: false })),
        ];
        let (code, response) = page(Some(plugins)).await;
        assert_eq!(502, code);
        assert_eq!(true, response.contains("x-asked: 1"), "{response}");
        assert_eq!(false, response.contains("x-not-asked"), "{response}");
        // The page is still the page.
        assert_eq!(true, response.contains("x-pingap-etype:"), "{response}");
        // No location, no plugins: as before.
        let (code, response) = page(None).await;
        assert_eq!(502, code);
        assert_eq!(false, response.contains("x-asked"), "{response}");
    }

    /// Once a final header is out the rest of the response is not ours to
    /// replace: the status stays what the client saw, and no page is
    /// appended to the body.
    #[tokio::test]
    async fn test_no_error_page_after_response_started() {
        let server = new_server();
        let (mut session, client) =
            new_duplex_session("GET /vicanso/pingap HTTP/1.1\r\n\r\n").await;
        let mut ctx = Ctx::default();
        let mut header = ResponseHeader::build(200, None).unwrap();
        header.insert_header("Content-Length", "100").unwrap();
        session
            .as_mut()
            .write_response_header(Box::new(header))
            .await
            .unwrap();
        ctx.state.status = Some(StatusCode::OK);
        let result = server
            .fail_to_proxy(
                &mut session,
                &pingora::Error::new_up(pingora::ErrorType::ReadError),
                &mut ctx,
            )
            .await;
        assert_eq!(502, result.error_code);
        assert_eq!(Some(StatusCode::OK), ctx.state.status);
        drop(session);
        let response = read_response(client).await;
        assert_eq!(
            true,
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "{response}"
        );
        assert_eq!(false, response.contains("ReadError"), "{response}");
    }
}
