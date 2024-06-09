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

use super::dynamic_cert::DynamicCert;
use super::logger::Parser;
use super::upstream::get_upstream;
use super::Location;
use super::ServerConf;
use crate::acme::{get_lets_encrypt_cert, handle_lets_encrypt, parse_x509_validity};
use crate::config;
use crate::config::PluginStep;
use crate::http_extra::{HttpResponse, HTTP_HEADER_NAME_X_REQUEST_ID};
use crate::plugin::get_proxy_plugin;
use crate::proxy::location::get_location;
use crate::state::State;
use crate::util;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::StatusCode;
use log::{debug, error, info};
use once_cell::sync::Lazy;
use pingora::cache::cache_control::CacheControl;
use pingora::cache::filters::resp_cacheable;
use pingora::cache::{CacheKey, CacheMetaDefaults, NoCacheReason, RespCacheable};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::listeners::{TcpSocketOptions, TlsSettings};
use pingora::protocols::http::error_resp;
use pingora::protocols::Digest;
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

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Error {category} {message}"))]
    Common { category: String, message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

fn get_hour_duration() -> u32 {
    (util::now().as_millis() % (3600 * 1000)) as u32
}
fn get_latency(value: &Option<u32>) -> Option<u32> {
    if let Some(value) = value {
        let value = value.to_owned();
        let d = get_hour_duration();
        let value = if d >= value {
            d - value
        } else {
            d + (3600 * 1000) - value
        };
        Some(value)
    } else {
        Some(get_hour_duration())
    }
}

type ServerLocations = HashMap<String, Arc<Vec<String>>>;
static LOCATION_MAP: Lazy<ArcSwap<ServerLocations>> =
    Lazy::new(|| ArcSwap::from_pointee(HashMap::new()));

pub fn try_init_server_locations(
    servers: &HashMap<String, config::ServerConf>,
    locations: &HashMap<String, config::LocationConf>,
) -> Result<()> {
    let mut location_weights = HashMap::new();
    for (name, item) in locations.iter() {
        location_weights.insert(name.to_string(), item.get_weight());
    }
    let mut server_locations = HashMap::new();
    for (name, server) in servers.iter() {
        if let Some(items) = &server.locations {
            let mut items = items.clone();
            items.sort_by_key(|item| {
                let weight = if let Some(weight) = location_weights.get(item.as_str()) {
                    weight.to_owned()
                } else {
                    0
                };
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
    enbaled_h2: bool,
    lets_encrypt_enabled: bool,
    tls_from_lets_encrypt: bool,
    tcp_socket_options: Option<TcpSocketOptions>,
}

pub struct ServerServices {
    pub tls_validity: Option<x509_parser::certificate::Validity>,
    pub lb: Service<HttpProxy<Server>>,
}

const META_DEFAULTS: CacheMetaDefaults = CacheMetaDefaults::new(|_| Some(1), 1, 1);

impl Server {
    /// Create a new server for http proxy.
    pub fn new(conf: &ServerConf) -> Result<Self> {
        debug!("Server: {conf}");
        let mut p = None;
        if let Some(access_log) = &conf.access_log {
            p = Some(Parser::from(access_log.as_str()));
        }
        let tcp_socket_options = if conf.tcp_fastopen.is_some() || conf.tcp_keepalive.is_some() {
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
            threads: conf.threads,
            lets_encrypt_enabled: false,
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
    #[inline]
    fn get_location(&self, index: Option<usize>) -> Option<Arc<Location>> {
        if let Some(locations) = get_server_locations(&self.name) {
            if let Some(index) = index {
                return get_location(&locations[index]);
            }
        }
        None
    }
    /// New all background services and add a TCP/TLS listening endpoint.
    pub fn run(self, conf: &Arc<configuration::ServerConf>) -> Result<ServerServices> {
        let tls_from_lets_encrypt = self.tls_from_lets_encrypt;
        let addr = self.addr.clone();
        let tcp_socket_options = self.tcp_socket_options.clone();

        // tls
        let mut tls_cert = self.tls_cert.clone();
        let mut tls_key = self.tls_key.clone();
        if tls_cert.is_none() && tls_from_lets_encrypt {
            match get_lets_encrypt_cert() {
                Ok(cert_info) => {
                    tls_cert = Some(cert_info.get_cert());
                    tls_key = Some(cert_info.get_key());
                }
                Err(e) => error!("get lets encrypt cert fail, {e}"),
            };
        }
        let is_tls = tls_cert.is_some();
        let mut tls_validity = None;
        let dynamic_cert = if is_tls {
            let cert = tls_cert.unwrap_or_default();
            if let Ok(validity) = parse_x509_validity(&cert) {
                tls_validity = Some(validity)
            }

            Some(
                DynamicCert::new(&cert, &tls_key.unwrap_or_default()).map_err(|e| {
                    Error::Common {
                        category: "tls".to_string(),
                        message: e.to_string(),
                    }
                })?,
            )
        } else {
            None
        };

        let enbaled_h2 = self.enbaled_h2;
        let mut threads = self.threads;
        if threads.unwrap_or_default() == 0 {
            threads = Some(1);
        }
        info!(
            "Server({}) is linsten on:{addr}, threads:{threads:?}, tls:{is_tls}",
            &self.name
        );
        let mut lb = http_proxy_service(conf, self);
        lb.threads = threads;
        // support listen multi adddress
        for addr in addr.split(',') {
            // tls
            if let Some(dynamic_cert) = &dynamic_cert {
                let mut tls_settings =
                    TlsSettings::with_callbacks(dynamic_cert.clone()).map_err(|e| {
                        Error::Common {
                            category: "tls".to_string(),
                            message: e.to_string(),
                        }
                    })?;

                if enbaled_h2 {
                    tls_settings.enable_h2();
                }
                if let Some(min_version) = tls_settings.min_proto_version() {
                    info!("Tls min proto version:{min_version:?}");
                }
                if let Some(max_version) = tls_settings.max_proto_version() {
                    info!("Tls max proto version:{max_version:?}");
                }
                lb.add_tls_with_settings(addr, tcp_socket_options.clone(), tls_settings);
            } else if let Some(opt) = &tcp_socket_options {
                lb.add_tcp_with_settings(addr, opt.clone());
            } else {
                lb.add_tcp(addr);
            }
        }
        Ok(ServerServices {
            tls_validity,
            lb,
            // bg_services,
        })
    }
    async fn serve_admin(&self, session: &mut Session, ctx: &mut State) -> pingora::Result<()> {
        if let Some(plugin) = get_proxy_plugin(util::ADMIN_SERVER_PLUGIN.as_str()) {
            let result = plugin.handle(PluginStep::Request, session, ctx).await?;
            if let Some(resp) = result {
                ctx.status = Some(resp.status);
                ctx.response_body_size = resp.send(session).await?;
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

#[inline]
fn get_digest_detail(digest: &Digest) -> (u64, Option<String>) {
    let mut established = 0;
    let mut tls_version = None;
    if let Some(item) = digest.timing_digest.first() {
        if let Some(item) = item.as_ref() {
            established = item
                .established_ts
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
        }
    }
    if let Some(item) = &digest.ssl_digest {
        tls_version = Some(item.version.to_string());
    }
    (established, tls_version)
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
        let header = session.req_header_mut();
        let host = util::get_host(header).unwrap_or_default();

        let mut location_index = None;
        if let Some(locations) = get_server_locations(&self.name) {
            let path = header.uri.path();
            for (index, name) in locations.iter().enumerate() {
                if let Some(lo) = get_location(name) {
                    if lo.matched(host, path) {
                        location_index = Some(index);
                        break;
                    }
                }
            }
        }
        ctx.location_index = location_index;
        if let Some(lo) = self.get_location(location_index) {
            let _ = lo
                .exec_proxy_plugins(session, ctx, PluginStep::EarlyRequest)
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
        if let Some(digest) = session.digest() {
            let (established, tls_version) = get_digest_detail(digest);
            ctx.established = established;
            ctx.tls_version = tls_version;
        };
        ctx.processing = self.processing.fetch_add(1, Ordering::Relaxed) + 1;
        ctx.accepted = self.accepted.fetch_add(1, Ordering::Relaxed) + 1;
        ctx.remote_addr = util::get_remote_addr(session);
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
        let host = util::get_host(header).unwrap_or_default();

        let location = self.get_location(ctx.location_index);
        if location.is_none() {
            HttpResponse::unknown_error(Bytes::from(format!(
                "Location not found, host:{host} path:{}",
                header.uri.path(),
            )))
            .send(session)
            .await?;
            return Ok(true);
        }
        let lo = location.unwrap();

        debug!("Location {} is matched", lo.name);
        lo.rewrite(header);

        // body limit
        lo.client_body_size_limit(Some(header), ctx)?;

        ctx.location.clone_from(&lo.name);
        ctx.upstream_connected = lo.upstream_connected();
        ctx.location_accepted = lo.accepted.fetch_add(1, Ordering::Relaxed) + 1;
        ctx.location_processing = lo.processing.fetch_add(1, Ordering::Relaxed) + 1;

        let done = lo
            .exec_proxy_plugins(session, ctx, PluginStep::Request)
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
        if let Some(lo) = self.get_location(ctx.location_index) {
            let done = lo
                .exec_proxy_plugins(session, ctx, PluginStep::ProxyUpstream)
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
        let peer = if let Some(lo) = self.get_location(ctx.location_index) {
            let up = get_upstream(&lo.upstream).ok_or(util::new_internal_error(
                503,
                format!("No upstream({}:{})", lo.name, lo.upstream),
            ))?;
            up.new_http_peer(session, ctx)
        } else {
            None
        }
        .ok_or_else(|| util::new_internal_error(503, "No available upstream".to_string()))?;

        ctx.upstream_connect_time = get_latency(&ctx.upstream_connect_time);

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
        ctx.upstream_connect_time = get_latency(&ctx.upstream_connect_time);
        ctx.upstream_processing_time = get_latency(&ctx.upstream_processing_time);
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
            if let Some(lo) = self.get_location(ctx.location_index) {
                lo.client_body_size_limit(None, ctx)?;
            }
        }
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
        if let Some(lo) = self.get_location(ctx.location_index) {
            lo.set_append_proxy_headers(session, ctx, upstream_response);
        }
        Ok(())
    }

    fn cache_key_callback(
        &self,
        session: &Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<CacheKey> {
        Ok(CacheKey::new(
            ctx.cache_prefix.clone().unwrap_or_default(),
            format!("{}", session.req_header().uri),
            "".to_string(),
        ))
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<RespCacheable> {
        let cc = CacheControl::from_resp_headers(resp);
        if let Some(c) = &cc {
            if c.no_cache() || c.no_store() || c.private() {
                return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
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
            let _ =
                upstream_response.insert_header("X-Cache-Status", session.cache.phase().as_str());
            if let Some(d) = session.cache.lock_duration() {
                let _ =
                    upstream_response.insert_header("X-Cache-Lock", format!("{}ms", d.as_millis()));
                ctx.cache_lock_duration = Some(d);
            }
        }

        if let Some(lo) = self.get_location(ctx.location_index) {
            lo.exec_response_plugins(session, ctx, upstream_response, PluginStep::Response)
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
        }
        if let Some(id) = &ctx.request_id {
            let _ = upstream_response.insert_header(HTTP_HEADER_NAME_X_REQUEST_ID.clone(), id);
        }
        ctx.upstream_processing_time = get_latency(&ctx.upstream_processing_time);
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) {
        if let Some(body) = body {
            ctx.response_body_size += body.len();
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
                    pingora::ErrorType::WriteError | pingora::ErrorType::ReadError => 500,
                    // client close the connection
                    pingora::ErrorType::ConnectionClosed => 499,
                    _ => 400,
                },
                pingora::ErrorSource::Internal | pingora::ErrorSource::Unset => 500,
            },
        };
        // TODO better error handler(e.g. json response)
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
        ctx.status = Some(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
        ctx.response_body_size = buf.len();
        let _ = resp.insert_header(http::header::CONTENT_TYPE, "text/html; charset=utf-8");
        let _ = resp.insert_header(http::header::CONTENT_LENGTH, buf.len().to_string());

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
                error!("failed to send error response to downstream: {e}");
            });

        let _ = server_session.write_response_body(buf, true).await;
        code
    }
    async fn logging(&self, session: &mut Session, _e: Option<&pingora::Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        self.processing.fetch_sub(1, Ordering::Relaxed);
        if let Some(lo) = self.get_location(ctx.location_index) {
            lo.processing.fetch_sub(1, Ordering::Relaxed);
        }
        if ctx.status.is_none() {
            if let Some(header) = session.response_written() {
                ctx.status = Some(header.status);
            }
        }

        if let Some(p) = &self.log_parser {
            info!("{}", p.format(session, ctx));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{get_latency, Server};
    use crate::config::PingapConf;
    use crate::proxy::server::get_digest_detail;
    use crate::proxy::{
        try_init_locations, try_init_server_locations, try_init_upstreams, ServerConf,
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
    fn test_get_latency() {
        let d = get_latency(&None);
        assert_eq!(true, d.is_some());
        assert_eq!(true, get_latency(&d).is_some());
    }

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
                cipher: "",
                organization: None,
                serial_number: None,
                cert_digest: vec![],
            })),
            ..Default::default()
        };
        let result = get_digest_detail(&digest);
        assert_eq!(10000, result.0);
        assert_eq!("1.3", result.1.unwrap_or_default());
    }

    fn new_server() -> Server {
        let toml_data = include_bytes!("../../conf/pingap.toml");
        let pingap_conf = PingapConf::try_from(toml_data.as_ref()).unwrap();
        try_init_upstreams(&pingap_conf.upstreams).unwrap();
        try_init_locations(&pingap_conf.locations).unwrap();
        try_init_server_locations(&pingap_conf.servers, &pingap_conf.locations).unwrap();
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
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut ctx = State::default();
        server
            .early_request_filter(&mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(0, ctx.location_index.unwrap());
    }

    #[tokio::test]
    async fn test_request_filter() {
        let server = new_server();

        let headers = [""].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut ctx = State {
            location_index: Some(0),
            ..Default::default()
        };
        let done = server.request_filter(&mut session, &mut ctx).await.unwrap();
        assert_eq!(false, done);
        assert_eq!("lo", ctx.location);
    }

    #[tokio::test]
    async fn test_cache_key_callback() {
        let server = new_server();

        let headers = [""].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
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
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut upstream_response = ResponseHeader::build_no_case(200, None).unwrap();
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

        let mut upstream_response = ResponseHeader::build_no_case(200, None).unwrap();
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

        let mut upstream_response = ResponseHeader::build_no_case(200, None).unwrap();
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

        let mut upstream_response = ResponseHeader::build_no_case(200, None).unwrap();
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
