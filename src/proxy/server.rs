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
use crate::acme::get_certificate_info;
use crate::acme::CertificateInfo;
use crate::acme::{get_lets_encrypt_cert, handle_lets_encrypt};
use crate::config;
use crate::config::PluginStep;
use crate::http_extra::{HttpResponse, HTTP_HEADER_NAME_X_REQUEST_ID};
use crate::plugin::get_plugins;
use crate::proxy::dynamic_certificate::TlsSettingParams;
use crate::proxy::location::get_location;
use crate::state::CompressionStat;
use crate::state::State;
use crate::util;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::StatusCode;
use once_cell::sync::Lazy;
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
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, error, info};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Error {category} {message}"))]
    Common { category: String, message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

type ServerLocations = AHashMap<String, Arc<Vec<String>>>;
static LOCATION_MAP: Lazy<ArcSwap<ServerLocations>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

pub fn try_init_server_locations(
    servers: &HashMap<String, config::ServerConf>,
    locations: &HashMap<String, config::LocationConf>,
) -> Result<()> {
    let mut location_weights = HashMap::new();
    for (name, item) in locations.iter() {
        location_weights.insert(name.to_string(), item.get_weight());
    }
    let mut server_locations = AHashMap::new();
    for (name, server) in servers.iter() {
        if let Some(items) = &server.locations {
            let mut items = items.clone();
            items.sort_by_key(|item| {
                let weight = location_weights
                    .get(item.as_str())
                    .map(|value| value.to_owned())
                    .unwrap_or_default();
                std::cmp::Reverse(weight)
            });
            server_locations.insert(name.to_string(), Arc::new(items));
        }
    }
    LOCATION_MAP.store(Arc::new(server_locations));
    Ok(())
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
    tls_cert: Option<Vec<u8>>,
    tls_key: Option<Vec<u8>>,
    tls_cipher_list: Option<String>,
    tls_ciphersuites: Option<String>,
    tls_min_version: Option<String>,
    tls_max_version: Option<String>,
    enbaled_h2: bool,
    lets_encrypt_enabled: bool,
    global_certificates: bool,
    certificate_file: PathBuf,
    tls_from_lets_encrypt: bool,
    tcp_socket_options: Option<TcpSocketOptions>,
}

pub struct ServerServices {
    pub tls_cert_info: Option<CertificateInfo>,
    pub lb: Service<HttpProxy<Server>>,
}

const META_DEFAULTS: CacheMetaDefaults =
    CacheMetaDefaults::new(|_| Some(1), 1, 1);

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
        let s = Server {
            name: conf.name.clone(),
            admin: conf.admin,
            accepted: AtomicU64::new(0),
            processing: AtomicI32::new(0),
            addr: conf.addr.clone(),
            log_parser: p,
            error_template: conf.error_template.clone(),
            tls_key: conf.tls_key.clone(),
            tls_cert: conf.tls_cert.clone(),
            tls_cipher_list: conf.tls_cipher_list.clone(),
            tls_ciphersuites: conf.tls_ciphersuites.clone(),
            tls_min_version: conf.tls_min_version.clone(),
            tls_max_version: conf.tls_max_version.clone(),
            threads: conf.threads,
            lets_encrypt_enabled: false,
            certificate_file: conf.get_certificate_file(),
            global_certificates: conf.global_certificates,
            enbaled_h2: conf.enbaled_h2,
            tcp_socket_options,
            tls_from_lets_encrypt: conf.lets_encrypt.is_some(),
        };
        Ok(s)
    }
    /// Enable lets encrypt proxy plugin for `/.well-known/acme-challenge` handle.
    pub fn enable_lets_encrypt(&mut self) {
        self.lets_encrypt_enabled = true;
    }

    /// Add TCP/TLS listening endpoint.
    pub fn run(
        self,
        conf: &Arc<configuration::ServerConf>,
    ) -> Result<ServerServices> {
        let tls_from_lets_encrypt = self.tls_from_lets_encrypt;
        let addr = self.addr.clone();
        let tcp_socket_options = self.tcp_socket_options.clone();

        let name = self.name.clone();
        let mut dynamic_cert = None;
        let mut tls_cert_info = None;
        // tls
        if self.global_certificates {
            dynamic_cert = Some(DynamicCertificate::new_global());
        } else {
            let mut tls_cert = self.tls_cert.clone();
            let mut tls_key = self.tls_key.clone();

            if tls_cert.is_none() && tls_from_lets_encrypt {
                match get_lets_encrypt_cert(&self.certificate_file) {
                    Ok(cert_info) => {
                        tls_cert = Some(cert_info.get_cert());
                        tls_key = Some(cert_info.get_key());
                    },
                    Err(e) => error!(
                        error = e.to_string(),
                        name, "get lets encrypt cert fail"
                    ),
                };
            }
            if tls_cert.is_some() {
                let cert = tls_cert.unwrap_or_default();
                if let Ok(info) = get_certificate_info(&cert) {
                    tls_cert_info = Some(info)
                }

                let d = DynamicCertificate::new(
                    &cert,
                    &tls_key.unwrap_or_default(),
                )
                .map_err(|e| Error::Common {
                    category: "tls".to_string(),
                    message: e.to_string(),
                })?;
                dynamic_cert = Some(d);
            };
        }

        let is_tls = dynamic_cert.is_some();

        let enbaled_h2 = self.enbaled_h2;
        let mut threads = self.threads;
        if threads.unwrap_or_default() == 0 {
            threads = Some(1);
        }
        info!(
            name,
            addr,
            threads = format!("{threads:?}"),
            is_tls,
            h2 = enbaled_h2,
            "server is listening"
        );
        let cipher_list = self.tls_cipher_list.clone();
        let ciphersuites = self.tls_ciphersuites.clone();
        let tls_min_version = self.tls_min_version.clone();
        let tls_max_version = self.tls_max_version.clone();
        let mut lb = http_proxy_service(conf, self);
        // use h2c if not tls and enable http2
        if !is_tls && enbaled_h2 {
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
                        enbaled_h2,
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
        Ok(ServerServices { tls_cert_info, lb })
    }
    async fn serve_admin(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<()> {
        if let Some(plugins) = get_plugins() {
            if let Some(plugin) =
                plugins.get(util::ADMIN_SERVER_PLUGIN.as_str())
            {
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
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct DigestDeailt {
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
    let Some(ssl_digest) = &digest.ssl_digest else {
        return DigestDeailt {
            tcp_established,
            ..Default::default()
        };
    };

    DigestDeailt {
        tcp_established,
        tls_established: get_established(digest.timing_digest.get(1)),
        tls_version: Some(ssl_digest.version.to_string()),
        tls_cipher: Some(ssl_digest.cipher.to_string()),
    }
}

#[async_trait]
impl ProxyHttp for Server {
    type CTX = State;
    fn new_ctx(&self) -> Self::CTX {
        State {
            ..Default::default()
        }
    }
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(digest) = session.digest() {
            let digest_detail = get_digest_detail(digest);
            ctx.connection_time = util::now().as_millis() as u64
                - digest_detail
                    .tcp_established
                    .max(digest_detail.tls_established);

            if ctx.connection_time > 10 {
                ctx.connection_reused = true;
            }
            if !ctx.connection_reused
                && digest_detail.tls_established
                    >= digest_detail.tcp_established
            {
                ctx.tls_handshake_time = digest_detail.tls_established
                    - digest_detail.tcp_established;
            }
            ctx.tls_cipher = digest_detail.tls_cipher;
            ctx.tls_version = digest_detail.tls_version;
        };
        ctx.processing = self.processing.fetch_add(1, Ordering::Relaxed) + 1;
        ctx.accepted = self.accepted.fetch_add(1, Ordering::Relaxed) + 1;
        ctx.remote_addr = util::get_remote_addr(session);

        // locations not found
        let Some(locations) = get_server_locations(&self.name) else {
            return Ok(());
        };
        let header = session.req_header_mut();
        let host = util::get_host(header).unwrap_or_default();
        let path = header.uri.path();
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
        _digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        ctx.reused = reused;
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
        let key = CacheKey::new(
            ctx.cache_prefix.clone().unwrap_or_default(),
            format!("{}", session.req_header().uri),
            "".to_string(),
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
            let _ = location
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
                    pingora::ErrorType::WriteError
                    | pingora::ErrorType::ReadError => 500,
                    // client close the connection
                    pingora::ErrorType::ConnectionClosed => 499,
                    _ => 400,
                },
                pingora::ErrorSource::Internal
                | pingora::ErrorSource::Unset => 500,
            },
        };
        let mut resp = match code {
            502 => error_resp::HTTP_502_RESPONSE.clone(),
            400 => error_resp::HTTP_400_RESPONSE.clone(),
            _ => error_resp::gen_error_response(code),
        };

        let content = self
            .error_template
            .replace("{{version}}", util::get_pkg_version())
            .replace("{{content}}", &e.to_string());
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
        let _ = resp
            .insert_header(http::header::CONTENT_LENGTH, buf.len().to_string());

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
        self.processing.fetch_sub(1, Ordering::Relaxed);
        if let Some(location) = &ctx.location {
            location.processing.fetch_sub(1, Ordering::Relaxed);
        }
        if ctx.status.is_none() {
            if let Some(header) = session.response_written() {
                ctx.status = Some(header.status);
            }
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
    use pingora::protocols::{ssl::SslDigest, Digest, TimingDigest};
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
                version: "1.3",
                cipher: "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                organization: None,
                serial_number: None,
                cert_digest: vec![],
            })),
            ..Default::default()
        };
        let result = get_digest_detail(&digest);
        assert_eq!(10000, result.tcp_established);
        assert_eq!("1.3", result.tls_version.unwrap_or_default());
        assert_eq!(
            "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            result.tls_cipher.unwrap_or_default()
        );
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
            r#"Ok(CacheKey { namespace: "ss:", primary: "/vicanso/pingap?size=1", primary_bin_override: None, variance: None, user_tag: "" })"#,
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
