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

use super::dynamic_certificate::DynamicCertificate;
use super::logger::Parser;
use super::upstream::get_upstream;
use super::ServerConf;
use crate::acme::handle_lets_encrypt;
use crate::config;
use crate::config::PluginStep;
use crate::http_extra::{HttpResponse, HTTP_HEADER_NAME_X_REQUEST_ID};
#[cfg(feature = "full")]
use crate::otel;
use crate::plugin::{get_plugin, ADMIN_SERVER_PLUGIN};
use crate::proxy::dynamic_certificate::TlsSettingParams;
use crate::proxy::location::get_location;
use crate::service::CommonServiceTask;
#[cfg(feature = "full")]
use crate::state::OtelTracer;
use crate::state::{accept_request, end_request};
#[cfg(feature = "full")]
use crate::state::{new_prometheus, new_prometheus_push_service, Prometheus};
use crate::state::{CompressionStat, State};
use crate::util;
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
use pingora::modules::http::compression::ResponseCompression;
use pingora::protocols::http::error_resp;
use pingora::protocols::Digest;
use pingora::protocols::TimingDigest;
use pingora::proxy::{http_proxy_service, HttpProxy};
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::configuration;
use pingora::services::listening::Service;
use pingora::upstreams::peer::{HttpPeer, Peer};
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

type ServerLocations = AHashMap<String, Arc<Vec<String>>>;
static LOCATION_MAP: Lazy<ArcSwap<ServerLocations>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

/// Try to init the locations of server,
/// the locations are order by weight
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
    LOCATION_MAP.store(Arc::new(server_locations));
    Ok(updated_servers)
}

#[inline]
fn get_server_locations(name: &str) -> Option<Arc<Vec<String>>> {
    LOCATION_MAP.load().get(name).cloned()
}

pub struct Server {
    name: String,
    admin: bool,
    addr: String,
    accepted: AtomicU64,
    processing: AtomicI32,
    log_parser: Option<Parser>,
    error_template: String,
    threads: Option<usize>,
    tls_cipher_list: Option<String>,
    tls_ciphersuites: Option<String>,
    tls_min_version: Option<String>,
    tls_max_version: Option<String>,
    enabled_h2: bool,
    lets_encrypt_enabled: bool,
    global_certificates: bool,
    tcp_socket_options: Option<TcpSocketOptions>,
    #[cfg(feature = "full")]
    prometheus: Option<Arc<Prometheus>>,
    prometheus_push_mode: bool,
    prometheus_metrics: String,
    enabled_otel: bool,
}

pub struct ServerServices {
    pub lb: Service<HttpProxy<Server>>,
}

const META_DEFAULTS: CacheMetaDefaults =
    CacheMetaDefaults::new(|_| Some(1), 1, 1);

static HTTP_500_RESPONSE: Lazy<ResponseHeader> =
    Lazy::new(|| error_resp::gen_error_response(500));

impl Server {
    /// Create a new server for http proxy.
    pub fn new(conf: &ServerConf) -> Result<Self> {
        debug!(config = conf.to_string(), "new server",);
        let mut p = None;
        if let Some(access_log) = &conf.access_log {
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
            enabled_otel: conf.otlp_exporter.is_some(),
            prometheus_metrics,
            #[cfg(feature = "full")]
            prometheus,
        };
        Ok(s)
    }
    /// Enable lets encrypt proxy plugin for `/.well-known/acme-challenge` handle.
    pub fn enable_lets_encrypt(&mut self) {
        self.lets_encrypt_enabled = true;
    }
    /// Get the prometheus push service
    pub fn get_prometheus_push_service(&self) -> Option<CommonServiceTask> {
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
                    Ok(serivce) => Some(serivce),
                    Err(e) => {
                        error!(
                            error = e.to_string(),
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

    /// Add TCP/TLS listening endpoint.
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
            dynamic_cert = Some(DynamicCertificate::new_global());
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
        // support listen multi adddress
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
    async fn serve_admin(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<()> {
        if let Some(plugin) = get_plugin(ADMIN_SERVER_PLUGIN.as_str()) {
            let result = plugin
                .handle_request(PluginStep::Request, session, ctx)
                .await?;
            if let Some(resp) = result {
                ctx.status = Some(resp.status);
                resp.send(session).await?;
            } else {
                return Err(util::new_internal_error(
                    500,
                    "Admin server is unavailable".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct DigestDeailt {
    connection_reused: bool,
    connection_time: u64,
    tcp_established: u64,
    tls_established: u64,
    tls_version: Option<String>,
    tls_cipher: Option<String>,
}

#[inline]
fn get_digest_detail(digest: &Digest) -> DigestDeailt {
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
        connection_time = util::now().as_millis() as u64 - tcp_established;
    }
    let connection_reused = connection_time > 100;

    let Some(ssl_digest) = &digest.ssl_digest else {
        return DigestDeailt {
            connection_reused,
            tcp_established,
            connection_time,
            ..Default::default()
        };
    };

    DigestDeailt {
        connection_reused,
        tcp_established,
        connection_time,
        tls_established: get_established(digest.timing_digest.get(1)),
        tls_version: Some(ssl_digest.version.to_string()),
        tls_cipher: Some(ssl_digest.cipher.to_string()),
    }
}

#[async_trait]
impl ProxyHttp for Server {
    type CTX = State;
    fn new_ctx(&self) -> Self::CTX {
        State::new()
    }
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
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
        if let Some((remote_addr, remote_port)) = util::get_remote_addr(session)
        {
            ctx.remote_addr = Some(remote_addr);
            ctx.remote_port = Some(remote_port);
        }

        let header = session.req_header_mut();
        let host = util::get_host(header).unwrap_or_default();
        let path = header.uri.path();

        // enable open telemtery

        #[cfg(feature = "full")]
        if self.enabled_otel {
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

        // set perometheus stats
        #[cfg(feature = "full")]
        if let Some(prom) = &self.prometheus {
            prom.before();
        }

        // locations not found
        let Some(locations) = get_server_locations(&self.name) else {
            return Ok(());
        };

        for name in locations.iter() {
            let Some(location) = get_location(name) else {
                continue;
            };
            if location.matched(host, path) {
                ctx.location = Some(location);
                break;
            }
        }
        if let Some(location) = &ctx.location {
            ctx.location_accepted =
                location.accepted.fetch_add(1, Ordering::Relaxed) + 1;
            ctx.location_processing =
                location.processing.fetch_add(1, Ordering::Relaxed) + 1;
            let _ = location
                .clone()
                .handle_request_plugin(PluginStep::EarlyRequest, session, ctx)
                .await?;
        }
        Ok(())
    }
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        if self.admin {
            self.serve_admin(session, ctx).await?;
            return Ok(true);
        }
        // only enable for http 80
        if self.lets_encrypt_enabled {
            let done = handle_lets_encrypt(session, ctx).await?;
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
            let body =
                self.prometheus.as_ref().unwrap().metrics().map_err(|e| {
                    util::new_internal_error(500, e.to_string())
                })?;
            HttpResponse::text(body.into()).send(session).await?;
            return Ok(true);
        }

        let Some(location) = &ctx.location else {
            let host = util::get_host(header).unwrap_or_default();
            HttpResponse::unknown_error(Bytes::from(format!(
                "Location not found, host:{host} path:{}",
                header.uri.path(),
            )))
            .send(session)
            .await?;
            return Ok(true);
        };

        debug!(name = location.name, "location is matched");
        location.rewrite(header);

        // body limit
        location.client_body_size_limit(Some(header), ctx)?;

        let done = location
            .clone()
            .handle_request_plugin(PluginStep::Request, session, ctx)
            .await?;

        if done {
            return Ok(true);
        }

        Ok(false)
    }

    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
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

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Box<HttpPeer>> {
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
                up.new_http_peer(session, ctx)
            } else {
                None
            }
        } else {
            None
        }
        .ok_or_else(|| {
            util::new_internal_error(
                503,
                format!("No available upstream for {location_name}"),
            )
        })?;

        ctx.upstream_connect_time =
            util::get_latency(&ctx.upstream_connect_time);

        Ok(Box::new(peer))
    }
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        peer: &HttpPeer,
        _fd: std::os::unix::io::RawFd,
        digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if !reused {
            if let Some(digest) = digest {
                let detail = get_digest_detail(digest);
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
        }

        ctx.upstream_reused = reused;
        ctx.upstream_address = peer.address().to_string();
        ctx.upstream_connect_time =
            util::get_latency(&ctx.upstream_connect_time);
        ctx.upstream_processing_time =
            util::get_latency(&ctx.upstream_processing_time);

        Ok(())
    }
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(location) = &ctx.location {
            location.set_append_proxy_headers(session, ctx, upstream_response);
        }
        Ok(())
    }
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
        if let Some(buf) = body {
            ctx.payload_size += buf.len();
            if let Some(location) = &ctx.location {
                location.client_body_size_limit(None, ctx)?;
            }
        }
        Ok(())
    }
    fn cache_key_callback(
        &self,
        session: &Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<CacheKey> {
        let key = util::get_cache_key(
            &ctx.cache_prefix.clone().unwrap_or_default(),
            session.req_header().method.as_ref(),
            &session.req_header().uri,
        );
        debug!(key = format!("{key:?}"), "cache key callback");
        Ok(key)
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<RespCacheable> {
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

        Ok(resp_cacheable(cc.as_ref(), resp, false, &META_DEFAULTS))
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
        if ctx.status.is_none() {
            ctx.status = Some(upstream_response.status);
            ctx.upstream_response_time =
                util::get_latency(&ctx.upstream_response_time);
        }
        if let Some(id) = &ctx.request_id {
            let _ = upstream_response
                .insert_header(HTTP_HEADER_NAME_X_REQUEST_ID.clone(), id);
        }
        ctx.upstream_processing_time =
            util::get_latency(&ctx.upstream_processing_time);
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) {
        if end_of_stream {
            ctx.upstream_response_time =
                util::get_latency(&ctx.upstream_response_time);
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
    }

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

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> u16
    where
        Self::CTX: Send + Sync,
    {
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
            .replace("{{version}}", util::get_pkg_version())
            .replace("{{content}}", &e.to_string())
            .replace("{{error_ype}}", error_type);
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
            error = e.to_string(),
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
                    error = e.to_string(),
                    "send error response to downstream fail"
                );
            });

        let _ = server_session.write_response_body(buf, true).await;
        code
    }
    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) where
        Self::CTX: Send + Sync,
    {
        end_request();
        self.processing.fetch_sub(1, Ordering::Relaxed);
        if let Some(location) = &ctx.location {
            location.processing.fetch_sub(1, Ordering::Relaxed);
            if let Some(up) = get_upstream(&location.upstream) {
                ctx.upstream_processing = Some(up.completed());
            }
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
                let ip = util::get_client_ip(session);
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
            ssl_digest: None,
            ..Default::default()
        };
        let result = get_digest_detail(&digest);
        assert_eq!(10000, result.tcp_established);
    }

    fn new_server() -> Server {
        let toml_data = include_bytes!("../../conf/pingap.toml");
        let pingap_conf = PingapConf::try_from(toml_data.as_ref()).unwrap();
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
                cache_prefix: Some("ss:".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(
            r#"Ok(CacheKey { namespace: "GET:ss:", primary: "/vicanso/pingap?size=1", primary_bin_override: None, variance: None, user_tag: "" })"#,
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
