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

use super::{get_hash_key, get_int_conf, get_str_conf, get_str_slice_conf};
use crate::certificates::new_certificate_provider;
use crate::config_manager::get_config_manager;
use crate::process::{get_start_time, restart_now};
use crate::upstreams::new_upstream_provider;
use async_trait::async_trait;
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use ctor::ctor;
use flate2::Compression;
use flate2::write::GzEncoder;
use hex::ToHex;
use hex::encode;
use http::Method;
use http::{HeaderValue, StatusCode, header};
use humantime::parse_duration;
use pingap_config::hcl::convert_toml_to_hcl;
use pingap_config::kdl::convert_toml_to_kdl;
use pingap_config::{
    BasicConf, CATEGORY_BASIC, CATEGORY_CERTIFICATE, CATEGORY_STORAGE,
    Category, CertificateConf, ConfigManager, LocationConf, PluginCategory,
    PluginConf, ServerConf, StorageConf, UpstreamConf, Validate,
    format_category,
};
use pingap_config::{
    CATEGORY_LOCATION, CATEGORY_PLUGIN, CATEGORY_SERVER, CATEGORY_UPSTREAM,
    PingapConfig, PingapTomlConfig,
};
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, TtlLruLimit,
};
use pingap_performance::get_process_system_info;
use pingap_performance::get_processing_accepted;
use pingap_plugin::{Error, get_plugin_factory};
use pingap_upstream::UpstreamHealthyStatus;
use pingap_util::base64_decode;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use rust_embed::EmbeddedFile;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::{LazyLock, RwLock};
use std::time::Duration;
use substring::Substring;
use tracing::{debug, error, warn};
use urlencoding::decode;

type Result<T> = std::result::Result<T, Error>;

static LOG_TARGET: &str = "main::admin";

#[derive(RustEmbed)]
#[folder = "dist/"]
struct AdminAsset;

/// A file of the admin UI, how long it may be cached, and whether the
/// client takes gzip.
pub struct EmbeddedStaticFile(pub Option<EmbeddedFile>, pub Duration, pub bool);

/// The gzip form of the embedded files, by the hash of their content, each
/// made the first time it is asked for.
///
/// It used to be made for every request: a few hundred kilobytes of
/// javascript put through gzip at its highest level on a worker thread,
/// each time a browser opened the admin.
static GZIPPED: LazyLock<RwLock<HashMap<[u8; 32], Bytes>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// More entries than there are files means the files are changing under a
/// debug build, which reads them from disk: start over.
const GZIPPED_LIMIT: usize = 256;

fn gzipped(file: &EmbeddedFile) -> Option<Bytes> {
    let key = file.metadata.sha256_hash();
    let cached = GZIPPED
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned();
    if cached.is_some() {
        return cached;
    }
    let mut encoder = GzEncoder::new(vec![], Compression::best());
    encoder.write_all(&file.data).ok()?;
    let data = Bytes::from(encoder.finish().ok()?);
    let mut cache = GZIPPED.write().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= GZIPPED_LIMIT {
        cache.clear();
    }
    cache.insert(key, data.clone());
    Some(data)
}

/// Text is worth compressing; an image or a font is compressed already.
fn is_compressible(mime_type: &str) -> bool {
    mime_type.starts_with("text/")
        || ["javascript", "json", "xml"]
            .iter()
            .any(|kind| mime_type.contains(kind))
}

impl From<EmbeddedStaticFile> for HttpResponse {
    fn from(value: EmbeddedStaticFile) -> Self {
        let Some(file) = value.0 else {
            return HttpResponse::not_found("Not Found");
        };
        // generate content hash
        let str = &encode(file.metadata.sha256_hash())[0..8];
        let mime_type = file.metadata.mimetype();
        // cut hash and file length as etag
        let entity_tag = format!(r#""{:x}-{str}""#, file.data.len());
        // html set no-cache
        let max_age = if mime_type.contains("text/html") {
            0
        } else {
            value.1.as_secs()
        };

        let mut headers = vec![];
        if let Ok(value) = HeaderValue::from_str(mime_type) {
            headers.push((header::CONTENT_TYPE, value));
        }
        if let Ok(value) = HeaderValue::from_str(&entity_tag) {
            headers.push((header::ETAG, value));
        }

        // Compressed for a client that takes gzip - it used to be sent to
        // one that does not as well - and only what gains from it.
        let mut gzip_body = None;
        if file.data.len() > 1024 && is_compressible(mime_type) {
            headers.push((
                header::VARY,
                HeaderValue::from_static("Accept-Encoding"),
            ));
            if value.2 {
                gzip_body = gzipped(&file);
            }
        }
        let body = match gzip_body {
            Some(data) => {
                headers.push((
                    header::CONTENT_ENCODING,
                    HeaderValue::from_static("gzip"),
                ));
                data
            },
            // A release build has the file in the binary: nothing to copy.
            None => match file.data {
                Cow::Borrowed(data) => Bytes::from_static(data),
                Cow::Owned(data) => Bytes::from(data),
            },
        };

        HttpResponse {
            status: StatusCode::OK,
            body,
            max_age: Some(max_age as u32),
            headers: Some(headers),
            ..Default::default()
        }
    }
}

pub struct AdminServe {
    pub path: String,
    pub authorizations: Vec<(String, String)>,
    pub plugin_step: PluginStep,
    manager: Arc<ConfigManager>,
    max_age: Duration,
    hash_value: String,
    ip_fail_limit: TtlLruLimit,
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct BasicInfo {
    start_time: u64,
    version: String,
    rustc_version: String,
    kernel: String,
    config_hash: String,
    pid: String,
    user: String,
    group: String,
    threads: i64,
    processing: i32,
    accepted: u64,
    memory_mb: usize,
    memory: String,
    arch: String,
    cpus: usize,
    physical_cpus: usize,
    total_memory: String,
    used_memory: String,
    features: Vec<String>,
    fd_count: usize,
    tcp_count: usize,
    tcp6_count: usize,
    supported_plugins: Vec<String>,
    upstream_healthy_status: HashMap<String, UpstreamHealthyStatus>,
    support_history: bool,
    git_hash: String,
    now: u64,
}

#[derive(Serialize, Deserialize)]
struct FullConfigJson {
    pub hcl: String,
    pub kdl: String,
    pub full: String,
    pub original: String,
}

impl TryFrom<&PluginConf> for AdminServe {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let mut authorizations = vec![];
        for item in get_str_slice_conf(value, "authorizations").iter() {
            if item.is_empty() {
                continue;
            }
            let data =
                base64_decode(item).map_err(|e| Error::Base64Decode {
                    category: PluginCategory::BasicAuth.to_string(),
                    source: e,
                })?;
            // An entry that is not `user:password` used to be dropped, and
            // an empty list means no authentication at all: a typo in the
            // only entry silently opened the admin to everyone.
            let text = std::string::String::from_utf8_lossy(&data);
            let Some((user, pass)) = text.split_once(':') else {
                return Err(Error::Invalid {
                    category: "admin".to_string(),
                    message: "authorization should be base64 of user:password"
                        .to_string(),
                });
            };
            if user.is_empty() || pass.is_empty() {
                return Err(Error::Invalid {
                    category: "admin".to_string(),
                    message: "authorization user and password can not be empty"
                        .to_string(),
                });
            }
            authorizations.push((user.to_string(), pass.to_string()));
        }
        let mut ip_fail_limit = get_int_conf(value, "ip_fail_limit");
        if ip_fail_limit <= 0 {
            ip_fail_limit = 10;
        }
        let max_age_value = &get_str_conf(value, "max_age");
        let mut max_age = Duration::from_secs(2 * 24 * 3600);
        if !max_age_value.is_empty() {
            max_age = parse_duration(max_age_value).map_err(|e| {
                Error::ParseDuration {
                    category: "admin".to_string(),
                    source: e,
                }
            })?;
        }
        let mut path = get_str_conf(value, "path");
        if path.len() > 1 && path.ends_with("/") {
            path = path.substring(0, path.len() - 1).to_string();
        }

        let params = AdminServe {
            hash_value,
            max_age,
            plugin_step: PluginStep::Request,
            path,
            ip_fail_limit: TtlLruLimit::new_compact(
                512,
                Duration::from_secs(5 * 60),
                ip_fail_limit as usize,
            ),
            manager: get_config_manager().map_err(|e| Error::Invalid {
                category: "config_manager".to_string(),
                message: e.to_string(),
            })?,
            authorizations,
        };

        Ok(params)
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct AesParams {
    category: String,
    key: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AesResp {
    value: String,
}

/// The largest request body the API reads. A whole configuration with its
/// certificates and keys inline is far below it; without a limit a request
/// was read into memory for as long as it kept coming.
const MAX_BODY_SIZE: usize = 8 * 1024 * 1024;

async fn get_request_body(session: &mut Session) -> pingora::Result<BytesMut> {
    let too_large = || {
        pingap_core::new_internal_error(
            413,
            format!("the request body is larger than {MAX_BODY_SIZE} bytes"),
        )
    };
    // What says so itself is turned away before any of it is read.
    let declared = session
        .req_header()
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|len| len > MAX_BODY_SIZE) {
        return Err(too_large());
    }
    let mut buf = BytesMut::with_capacity(4096);
    while let Some(value) = session.read_request_body().await? {
        if buf.len() + value.len() > MAX_BODY_SIZE {
            return Err(too_large());
        }
        buf.put(value.as_ref());
    }
    Ok(buf)
}

/// The authority a request names: the one of its target (HTTP/2, or an
/// absolute form), or else its `Host`.
fn request_authority(header: &RequestHeader) -> String {
    header
        .uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            header
                .headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or_default()
        .to_string()
}

/// The host of an authority, without the port and the brackets of an ipv6
/// address.
fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    }
}

/// Whether a browser sent this request from a page of another origin.
///
/// Browsers say so themselves in `Sec-Fetch-Site`; where they do not (it is
/// only sent to https and to localhost) the `Origin` they add to a request
/// that changes something has to be the host the request is for. A client
/// that sends neither is not a browser, and nobody's page.
fn is_cross_site(header: &RequestHeader, authority: &str) -> bool {
    if let Some(site) = header.headers.get("sec-fetch-site") {
        return !matches!(site.as_bytes(), b"same-origin" | b"none");
    }
    let Some(origin) = header.headers.get(header::ORIGIN) else {
        return false;
    };
    // `null`, or anything else that names no host, is nobody's origin.
    origin
        .to_str()
        .ok()
        .and_then(|origin| origin.split_once("://"))
        .is_none_or(|(_, origin)| !origin.eq_ignore_ascii_case(authority))
}

/// Whether `host` is a name that only ever means this machine or the
/// address that was dialled: an ip address, `localhost`, or a name under
/// `.localhost`. No DNS answer can make any other name's page a page of
/// these.
fn is_literal_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || host.eq_ignore_ascii_case("localhost")
        || host
            .len()
            .checked_sub(".localhost".len())
            .and_then(|at| host.get(at..))
            .is_some_and(|tail| tail.eq_ignore_ascii_case(".localhost"))
}

/// Why an API request to an admin without credentials is refused, if it
/// is. Such an admin takes whatever reaches it, and a browser on the same
/// machine reaches it for any page the user has open:
///
/// - a page of another site can send a request that changes something
///   (a form, or a `fetch` in `no-cors` mode) without being able to read
///   the answer, which is all a new config or a restart needs;
/// - a page under a name its owner then points at 127.0.0.1 (DNS
///   rebinding) is, to the browser, the admin's own page, and reads the
///   configuration with its keys as well.
///
/// With credentials neither gets anywhere: the token every request needs
/// is a header the first cannot add and a secret the second does not have.
fn refuse_without_credentials(
    header: &RequestHeader,
    authority: &str,
    server_addr: Option<&str>,
) -> Option<&'static str> {
    let reads = matches!(header.method, Method::GET | Method::HEAD);
    if !reads && is_cross_site(header, authority) {
        return Some(
            "Forbidden, a request from another site to an admin without credentials",
        );
    }
    // Only where the connection came to a loopback address, which is where
    // the name is `localhost` or the address for everyone but a rebound
    // page. An admin on another address is reached by whatever name its
    // network gives it.
    //
    // A listener on `[::]` takes ipv4 connections as well, and names their
    // addresses `::ffff:127.0.0.1`, which is not what `::1` is.
    let loopback = server_addr
        .and_then(|addr| addr.parse::<std::net::IpAddr>().ok())
        .is_some_and(|addr| addr.to_canonical().is_loopback());
    let host = authority_host(authority);
    if loopback && !host.is_empty() && !is_literal_host(host) {
        return Some(
            "Forbidden, an admin without credentials is reached on this machine by localhost or its address only",
        );
    }
    None
}

/// What `/certificates` says of a loaded certificate.
///
/// The certificate itself was written out, its chain and its private key
/// among the fields: a key that the configuration only names the file of
/// was read from that file and handed to whoever asked.
#[derive(Serialize)]
struct CertificateInfo<'a> {
    domains: &'a [String],
    acme: Option<&'a str>,
    not_after: i64,
    not_before: i64,
    issuer: &'a str,
}

impl<'a> From<&'a pingap_certificate::Certificate> for CertificateInfo<'a> {
    fn from(certificate: &'a pingap_certificate::Certificate) -> Self {
        Self {
            domains: &certificate.domains,
            acme: certificate.acme.as_deref(),
            not_after: certificate.not_after,
            not_before: certificate.not_before,
            issuer: &certificate.issuer,
        }
    }
}

/// What `/certificates` answers with: the loaded certificates by name.
fn certificate_infos(
    certificates: &pingap_certificate::DynamicCertificates,
) -> HashMap<&String, CertificateInfo<'_>> {
    certificates
        .iter()
        .filter_map(|(name, certificate)| {
            let info = certificate.info.as_ref()?;
            let name = certificate.name.as_ref().unwrap_or(name);
            Some((name, CertificateInfo::from(info)))
        })
        .collect()
}

/// How far ahead of this clock the time in a token may be: what the clock
/// of a browser may be off by. A time further ahead is not one a login
/// made now would carry, and a token made with it would outlive `max_age`
/// by as much.
const TOKEN_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

/// Whether a token that says it was made at `issued_at` is one to look at
/// further, at `now`: no older than `max_age`, and from no further in the
/// future than [`TOKEN_CLOCK_SKEW`] - or `max_age`, where that is less.
fn token_time_is_current(now: u64, issued_at: &str, max_age: Duration) -> bool {
    // Nothing but digits: `parse` takes a sign as well, and `+5` and `5`
    // would be two tokens for one moment.
    if issued_at.is_empty() || !issued_at.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(issued_at) = issued_at.parse::<u64>() else {
        return false;
    };
    let max_age = max_age.as_secs();
    if issued_at > now {
        issued_at - now <= max_age.min(TOKEN_CLOCK_SKEW.as_secs())
    } else {
        now - issued_at <= max_age
    }
}

/// Why a request to the API was turned away.
#[derive(Debug, PartialEq, Clone, Copy)]
enum TokenRejection {
    /// No `Authorization` at all: a page asking before the login.
    Missing,
    /// Not `token:time`.
    Malformed,
    /// A time that is too old, or ahead of this clock: see
    /// [`token_time_is_current`]. The token itself was not looked at.
    Time,
    /// The token is not the one of any of the accounts for that time.
    Mismatch,
}

impl TokenRejection {
    /// Whether this was a try at the credentials, to be counted against
    /// the address it came from. A request without credentials is not one
    /// (see where this is used), and neither is one refused for its time:
    /// nothing was compared, so nothing was guessed - and it is what a
    /// correct password gets while the two clocks disagree, which ten
    /// tries later would have locked its owner out.
    fn counts_as_a_failed_login(self) -> bool {
        matches!(self, Self::Malformed | Self::Mismatch)
    }
    /// What the client is told. Only the time gets an explanation: it is
    /// the one refusal that the right credentials do not fix, and it says
    /// nothing the client did not send itself.
    fn message(self) -> &'static [u8] {
        match self {
            Self::Time => {
                b"The time of this login is too old or ahead of the server's clock: check the clock of this device and the server's, then log in again"
            },
            _ => b"",
        }
    }
}

impl AdminServe {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(target: LOG_TARGET, params = pingap_config::masked_toml(params), "new admin server plugin");
        let serve = AdminServe::try_from(params)?;

        Ok(serve)
    }
    /// Checks the signed token of an API request. Only API routes come
    /// here: what is served without a token is decided by [`api_route`], in
    /// one place, so the exemption and the router cannot drift apart.
    fn auth_validate(
        &self,
        req_header: &RequestHeader,
    ) -> std::result::Result<(), TokenRejection> {
        if self.authorizations.is_empty() {
            return Ok(());
        }
        let path = req_header.uri.path();
        let value =
            pingap_core::get_req_header_value(req_header, "Authorization")
                .unwrap_or_default();
        if value.is_empty() {
            error!(target: LOG_TARGET, path, "auth validate fail: missing authorization header");
            return Err(TokenRejection::Missing);
        }
        let Some((token, ts)) = value.split_once(':') else {
            error!(target: LOG_TARGET, path, "auth validate fail: malformed authorization, expect token:ts");
            return Err(TokenRejection::Malformed);
        };
        let now = pingap_core::now_sec();
        if !token_time_is_current(now, ts, self.max_age) {
            error!(
                target: LOG_TARGET,
                path,
                ts,
                now,
                max_age = self.max_age.as_secs(),
                max_ahead = TOKEN_CLOCK_SKEW.as_secs(),
                "auth validate fail: timestamp is older than max_age, or ahead of this clock"
            );
            return Err(TokenRejection::Time);
        }

        for (user, pass) in self.authorizations.iter() {
            let mut hasher = Sha256::new();
            hasher.update(format!("{user}:{pass}:{ts}").as_bytes());
            let hash256 = hasher.finalize();
            if pingap_core::constant_time_eq(
                hash256.encode_hex::<String>().as_bytes(),
                token.as_bytes(),
            ) {
                return Ok(());
            }
        }
        error!(
            target: LOG_TARGET,
            path,
            ts,
            authorizations = self.authorizations.len(),
            "auth validate fail: token hash mismatch"
        );
        Err(TokenRejection::Mismatch)
    }
    async fn load_config(
        &self,
        replace_include: bool,
    ) -> pingora::Result<PingapConfig> {
        let config = self.manager.load_all().await.map_err(|e| {
            error!(target: LOG_TARGET, "failed to load config: {e}");
            pingap_core::new_internal_error(400, e)
        })?;
        let config = config.to_pingap_config(replace_include).map_err(|e| {
            error!(target: LOG_TARGET, "failed to convert config: {e}");
            pingap_core::new_internal_error(400, e)
        })?;
        Ok(config)
    }
    async fn get_config(
        &self,
        category: &str,
    ) -> pingora::Result<HttpResponse> {
        let conf = self.load_config(false).await?;
        if category == "full" {
            let full_conf = self.load_config(true).await?;
            let mut full_toml = toml::to_string_pretty(&full_conf)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            if let Ok(value) = pingap_util::toml_omit_empty_value(&full_toml) {
                full_toml = value;
            };
            let hcl = convert_toml_to_hcl(&full_toml)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            let kdl = convert_toml_to_kdl(&full_toml)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            let mut original_toml = toml::to_string_pretty(&conf)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            if let Ok(value) =
                pingap_util::toml_omit_empty_value(&original_toml)
            {
                original_toml = value;
            };
            return HttpResponse::try_from_json(&FullConfigJson {
                hcl,
                kdl,
                full: full_toml,
                original: original_toml,
            });
        }
        let resp = match category {
            CATEGORY_UPSTREAM => HttpResponse::try_from_json(&conf.upstreams)?,
            CATEGORY_LOCATION => HttpResponse::try_from_json(&conf.locations)?,
            CATEGORY_SERVER => HttpResponse::try_from_json(&conf.servers)?,
            CATEGORY_PLUGIN => HttpResponse::try_from_json(&conf.plugins)?,
            CATEGORY_CERTIFICATE => {
                HttpResponse::try_from_json(&conf.certificates)?
            },
            _ => HttpResponse::try_from_json(&conf)?,
        };
        Ok(resp)
    }

    async fn remove_config(
        &self,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        let category = Category::from_str(category)
            .map_err(|e| pingap_core::new_internal_error(400, e))?;
        self.manager.delete(category, name).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "delete config fail");
            pingap_core::new_internal_error(400, e)
        })?;
        Ok(HttpResponse::no_content())
    }
    async fn handle_update_config<T>(
        &self,
        name: &str,
        buf: &[u8],
        category: Category,
    ) -> pingora::Result<()>
    where
        T: DeserializeOwned + Serialize + Send + Sync + Validate,
    {
        let conf: T = serde_json::from_slice(buf).map_err(|e| {
            error!(
                target: LOG_TARGET,
                error = e.to_string(),
                "parse {} config fail",
                category.to_string()
            );
            pingap_core::new_internal_error(400, e)
        })?;
        conf.validate().map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "validate config fail");
            pingap_core::new_internal_error(400, e)
        })?;

        // Not only the entry: the configuration the storage would hold
        // with it, checked the way `--test` checks one. A location with a
        // regex that does not compile, or a plugin option of the wrong
        // type, used to be stored; every reload after that failed, and so
        // did the next start.
        self.manager
            .update_checked(
                category,
                name,
                &conf,
                Some(crate::validate::check_change),
            )
            .await
            .map_err(|e| {
                error!(target: LOG_TARGET, error = e.to_string(), "update config fail");
                pingap_core::new_internal_error(400, e)
            })?;

        Ok(())
    }

    async fn update_config(
        &self,
        session: &mut Session,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        if name.is_empty() {
            return Err(pingap_core::new_internal_error(
                400,
                "name is empty".to_string(),
            ));
        }
        let buf = get_request_body(session).await?;

        match category {
            CATEGORY_UPSTREAM => {
                self.handle_update_config::<UpstreamConf>(
                    name,
                    &buf,
                    Category::Upstream,
                )
                .await?;
            },
            CATEGORY_LOCATION => {
                self.handle_update_config::<LocationConf>(
                    name,
                    &buf,
                    Category::Location,
                )
                .await?;
            },
            CATEGORY_SERVER => {
                self.handle_update_config::<ServerConf>(
                    name,
                    &buf,
                    Category::Server,
                )
                .await?;
            },
            CATEGORY_PLUGIN => {
                self.handle_update_config::<PluginConf>(
                    name,
                    &buf,
                    Category::Plugin,
                )
                .await?;
            },
            CATEGORY_CERTIFICATE => {
                self.handle_update_config::<CertificateConf>(
                    name,
                    &buf,
                    Category::Certificate,
                )
                .await?;
            },
            CATEGORY_STORAGE => {
                self.handle_update_config::<StorageConf>(
                    name,
                    &buf,
                    Category::Storage,
                )
                .await?;
            },
            // `pingap` is what the admin page posts the basic config as.
            CATEGORY_BASIC | "pingap" => {
                self.handle_update_config::<BasicConf>(
                    "",
                    &buf,
                    Category::Basic,
                )
                .await?;
            },
            // Anything else used to be stored as the basic config, which a
            // body meant for another category - `upstreams/x` for
            // `upstream/x` - then replaced with an empty one.
            _ => {
                return Err(pingap_core::new_internal_error(
                    400,
                    format!("invalid category: {category}"),
                ));
            },
        };

        Ok(HttpResponse::no_content())
    }
    async fn import_config(
        &self,
        session: &mut Session,
    ) -> pingora::Result<HttpResponse> {
        let buf = get_request_body(session).await?;
        let refuse = |message: String| {
            error!(target: LOG_TARGET, error = message, "import config fail");
            pingap_core::new_internal_error(400, message)
        };
        let table: toml::Table =
            toml::from_slice(&buf).map_err(|e| refuse(e.to_string()))?;
        // An import replaces what is stored. One with nothing in it, or
        // with its sections under names pingap does not read
        // (`[upstream.x]` for `[upstreams.x]`), reads as an empty
        // configuration and would replace everything with nothing.
        if table.is_empty() {
            return Err(refuse("the config to import is empty".to_string()));
        }
        if let Some(key) = table
            .keys()
            .find(|key| !IMPORT_SECTIONS.contains(&key.as_str()))
        {
            return Err(refuse(format!(
                "unknown section: {key}, expect one of {}",
                IMPORT_SECTIONS.join(", ")
            )));
        }
        let config: PingapTomlConfig = toml::Value::Table(table)
            .try_into()
            .map_err(|e: toml::de::Error| refuse(e.to_string()))?;
        // And it has to stand on its own, checked the way `--test` checks
        // a configuration. It used to be written as it came.
        let config = tokio::task::spawn_blocking(move || {
            crate::validate::validate_stored(&config)
                .map(|_| config)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| refuse(e.to_string()))?
        .map_err(refuse)?;
        self.manager.save_all(&config).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "import config fail");
            pingap_core::new_internal_error(400, e)
        })?;

        Ok(HttpResponse::no_content())
    }
}

/// The answer to a config request that failed: the status the error was
/// made with, and its message.
///
/// Every failure used to be a 500 - a body that is not JSON, a config that
/// does not validate - and the message was the error as pingora prints it,
/// `HTTPStatus context: ... cause:  InternalError`.
/// The top level sections of a configuration, which an import may have.
const IMPORT_SECTIONS: [&str; 7] = [
    "basic",
    "servers",
    "upstreams",
    "locations",
    "plugins",
    "certificates",
    "storages",
];

fn config_error_response(err: &pingora::Error) -> HttpResponse {
    let status = match err.etype() {
        pingora::ErrorType::HTTPStatus(code) => StatusCode::from_u16(*code)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let message = match &err.context {
        Some(context) => context.as_str().to_string(),
        None => err.to_string(),
    };
    HttpResponse::try_from_json_status(&ErrorResponse { message }, status)
        .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
}

/// The API route of an admin path (prefix already removed): `/api/basic`
/// gives `/basic`. `None` for everything else, which is a static file.
///
/// Both the authentication and the router go by this one answer. They used
/// to decide separately - the router also took `/configs/...` without the
/// `/api` prefix, authentication exempted any non-`/api` path ending in
/// `.js`, `.css` or `.png` - so `GET /configs/x.js` returned the whole
/// configuration to anyone.
fn api_route(path: &str) -> Option<&str> {
    let route = path.strip_prefix("/api")?;
    (route.is_empty() || route.starts_with('/')).then_some(route)
}

fn static_file(path: &str, gzip: bool) -> HttpResponse {
    let mut file = path.substring(1, path.len());
    if file.is_empty() {
        file = "index.html";
    }
    EmbeddedStaticFile(
        AdminAsset::get(file),
        Duration::from_secs(365 * 24 * 3600),
        gzip,
    )
    .into()
}

fn get_method_path(session: &Session) -> (Method, String) {
    let req_header = session.req_header();
    let method = req_header.method.clone();
    let path = req_header.uri.path();
    (method, path.to_string())
}

async fn handle_request_admin(
    plugin: &AdminServe,
    session: &mut Session,
    ctx: &mut Ctx,
) -> pingora::Result<Option<HttpResponse>> {
    let header = session.req_header_mut();
    // Before the target is rewritten below, which leaves only the path.
    let authority = request_authority(header);
    let path = header.uri.path();
    // What is left always starts with `/`. Cutting `plugin.path` by length
    // took the leading `/` along when the admin is mounted at `/`, and let
    // `/pingapfoo` through for a prefix of `/pingap`.
    let prefix = plugin.path.trim_end_matches('/');
    let Some(rest) = path
        .strip_prefix(prefix)
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
    else {
        // Not under the prefix, so not the admin's to answer: on a server
        // shared with an application, `/pingapple` belongs to that.
        return Ok(None);
    };
    let mut new_path = rest.to_string();
    if !prefix.is_empty() && new_path.is_empty() {
        new_path = format!("{path}/");
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        let resp = HttpResponse::redirect(&new_path)?;
        return Ok(Some(resp));
    }
    if let Some(query) = header.uri.query() {
        new_path = format!("{new_path}?{query}");
    }
    // ignore parse error
    if let Ok(uri) = new_path.parse::<http::Uri>() {
        header.set_uri(uri);
    }
    let (method, path) = get_method_path(session);
    // Everything outside `/api` is an embedded file of the UI: public, and
    // needed before the user can log in.
    let Some(route) = api_route(&path) else {
        let gzip = session
            .req_header()
            .headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                pingap_plugin::accepts_encoding(value, "gzip")
            });
        return Ok(Some(static_file(&path, gzip)));
    };
    if plugin.authorizations.is_empty()
        && let Some(reason) = refuse_without_credentials(
            session.req_header(),
            &authority,
            ctx.conn.server_addr.as_deref(),
        )
    {
        warn!(
            target: LOG_TARGET,
            path,
            host = authority,
            origin = pingap_core::get_req_header_value(
                session.req_header(),
                "origin"
            ),
            "{reason}"
        );
        return Ok(Some(HttpResponse {
            status: StatusCode::FORBIDDEN,
            body: Bytes::from_static(reason.as_bytes()),
            ..Default::default()
        }));
    }
    // Failed logins are counted by an address the client cannot choose:
    // the client ip behind trusted proxies, the peer's own without them.
    // The client ip alone is, without trusted proxies, whatever
    // `X-Forwarded-For` says, and a new address with every guess was never
    // locked out.
    //
    // The lock stands in front of the API only. Checked ahead of the
    // routing it also took the pages of the UI away, and on a server
    // shared with an application the paths that are not the admin's.
    let ip = pingap_core::ensure_verified_client_ip(session, ctx);
    if !plugin.ip_fail_limit.validate(ip) {
        return Ok(Some(HttpResponse {
            status: StatusCode::FORBIDDEN,
            body: Bytes::from_static(b"Forbidden, too many failures"),
            ..Default::default()
        }));
    }
    if let Err(rejection) = plugin.auth_validate(session.req_header()) {
        // A failed login is one that was tried. A request without
        // credentials - the page polling before the login, or after its
        // token ran out - is turned away and not counted: ten of those
        // locked the administrator out, and anyone who could make their
        // browser send ten requests could do it for them.
        if rejection.counts_as_a_failed_login() {
            plugin.ip_fail_limit.inc(ip);
        }
        return Ok(Some(HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            body: Bytes::from_static(rejection.message()),
            ..Default::default()
        }));
    }
    let path = route.to_string();
    let params: Vec<String> = path
        .split('/')
        .map(|item| decode(item).unwrap_or_default().to_string())
        .collect();
    let mut category = "";
    if params.len() >= 3 {
        category = &params[2];
    }
    let resp = if path.starts_with("/configs") {
        match method {
            Method::POST => {
                if category == "import" {
                    plugin.import_config(session).await
                } else if params.len() < 4 {
                    Err(pingap_core::new_internal_error(
                        400,
                        "Url is invalid(no name)",
                    ))
                } else {
                    plugin.update_config(session, category, &params[3]).await
                }
            },
            Method::DELETE => {
                if params.len() < 4 {
                    Err(pingap_core::new_internal_error(
                        400,
                        "Url is invalid(no name)",
                    ))
                } else {
                    plugin.remove_config(category, &params[3]).await
                }
            },
            _ => plugin.get_config(category).await,
        }
        .unwrap_or_else(|err| config_error_response(&err))
    } else if path.starts_with("/config-history") {
        let category = Category::from_str(category).map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "get config category fail");
            pingap_core::new_internal_error(400, e)
        })?;
        // The name segment is optional in the url but not in the code below,
        // so reject a short url instead of indexing past the end of `params`.
        let Some(name) = params.get(3).cloned() else {
            return Err(pingap_core::new_internal_error(
                400,
                "Url is invalid(no name)",
            ));
        };
        let arr = plugin.manager.history(category.clone(), &name).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "get config history fail");
            pingap_core::new_internal_error(400, e)
        })?.unwrap_or_default();

        let mut history = vec![];
        for item in arr {
            let data:toml::Table = toml::from_str(&item.data).map_err(|e| {
                error!(target: LOG_TARGET, error = e.to_string(), "get config history fail");
                pingap_core::new_internal_error(400, e)
            })?;
            let key = format_category(&category);
            let Some(data) = data.get(key).cloned() else {
                continue;
            };
            let data = if name.is_empty() {
                data
            } else {
                let Some(data) = data.get(&name).cloned() else {
                    continue;
                };
                data
            };
            history.push(json!({
                "created_at": item.created_at,
                "data": data,
            }));
        }
        HttpResponse::try_from_json(&json!({
            "history": history,
        }))
        .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/basic" {
        // What is running, where something is. The page asks every five
        // seconds, and each time the storage was read, parsed and its
        // includes expanded for two fields, and every entry of the running
        // configuration written out for a hash of it. A control panel node
        // runs nothing: there the two fields are the stored ones.
        let (current_config, config_hash) =
            match plugin.manager.current_config_hash() {
                Some(hash) => {
                    (plugin.manager.get_current_config(), hash.as_ref().clone())
                },
                None => {
                    let stored = Arc::new(plugin.load_config(true).await?);
                    let hash = plugin
                        .manager
                        .get_current_config()
                        .hash()
                        .unwrap_or_default();
                    (stored, hash)
                },
            };
        let info = get_process_system_info();

        let (processing, accepted) = get_processing_accepted();

        let mut basic_info = BasicInfo {
            start_time: get_start_time(),
            version: pingap_util::get_pkg_version().to_string(),
            rustc_version: pingap_util::get_rustc_version().to_string(),
            config_hash,
            user: current_config.basic.user.clone().unwrap_or_default(),
            group: current_config.basic.group.clone().unwrap_or_default(),
            pid: info.pid.to_string(),
            threads: info.threads,
            accepted,
            processing,
            kernel: info.kernel,
            memory_mb: info.memory_mb,
            memory: info.memory,
            arch: info.arch,
            cpus: info.cpus,
            physical_cpus: info.physical_cpus,
            total_memory: info.total_memory,
            used_memory: info.used_memory,
            features: vec![],
            fd_count: info.fd_count,
            tcp_count: info.tcp_count,
            tcp6_count: info.tcp6_count,
            supported_plugins: get_plugin_factory().supported_plugins(),
            upstream_healthy_status: new_upstream_provider().healthy_status(),
            support_history: plugin.manager.support_history(),
            git_hash: crate::git_hash().to_string(),
            now: pingap_core::now_sec(),
        };
        basic_info.features.push("default".to_string());
        // TLS backend name (`openssl` or `rustls`) so the admin UI can disable
        // settings the active binary cannot honour and show it on the home page.
        basic_info
            .features
            .push(pingap_certificate::TLS_BACKEND.to_string());

        cfg_if::cfg_if! {
            if #[cfg(feature = "tracing")] {
                basic_info.features.push("tracing".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "full")] {
                basic_info.features.push("full".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "pyro")] {
                basic_info.features.push("pyroscope".to_string());
            }
        }

        HttpResponse::try_from_json(&basic_info)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/restart" && method == Method::POST {
        if let Err(e) = restart_now().await {
            error!(target: LOG_TARGET, error = e.to_string(), "Restart fail");
            HttpResponse::bad_request(e.to_string())
        } else {
            HttpResponse::no_content()
        }
    } else if path == "/aes" {
        let buf = get_request_body(session).await?;
        let params: AesParams = serde_json::from_slice(buf.as_ref())
            .map_err(|e| pingap_core::new_internal_error(400, e))?;
        let value = if params.category == "encrypt" {
            pingap_util::aes_encrypt(&params.key, &params.data)
        } else {
            pingap_util::aes_decrypt(&params.key, &params.data)
        }
        .map_err(|e| pingap_core::new_internal_error(400, e))?;
        HttpResponse::try_from_json(&AesResp { value })
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/certificates" {
        let certificates = new_certificate_provider().list();
        HttpResponse::try_from_json(&certificate_infos(&certificates))
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else {
        HttpResponse::not_found("Not Found")
    };
    Ok(Some(resp))
}

#[async_trait]
impl Plugin for AdminServe {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if self.plugin_step != step {
            return Ok(RequestPluginResult::Skipped);
        }
        if !session.req_header().uri.path().starts_with(&self.path) {
            return Ok(RequestPluginResult::Skipped);
        }
        let resp = handle_request_admin(self, session, _ctx).await?;
        if let Some(resp) = resp {
            return Ok(RequestPluginResult::Respond(resp));
        }
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor(unsafe)]
fn init() {
    get_plugin_factory()
        .register("admin", |params| Ok(Arc::new(AdminServe::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::{
        AdminAsset, AdminServe, EmbeddedStaticFile, api_route,
        certificate_infos, handle_request_admin, token_time_is_current,
    };
    use crate::config_manager::try_init_config_manager;
    use hex::ToHex;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, HttpResponse};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_test::io::Builder;

    #[test]
    fn test_admin_params() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let params = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = [
        "YWRtaW46MTIzMTIz",
        "cGluZ2FwOjEyMzEyMw=="
    ]
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on
        assert_eq!(
            "admin:123123,pingap:123123",
            params
                .authorizations
                .iter()
                .map(|item| format!("{}:{}", item.0, item.1))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!("/", params.path);

        let result = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = [
        "123",
    ]
    "#,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin basic_auth, base64 decode error Invalid padding",
            result.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_embedded_static_file() {
        let file = AdminAsset::get("index.html").unwrap();
        let resp: HttpResponse =
            EmbeddedStaticFile(Some(file), Duration::from_secs(60), false)
                .into();
        assert_eq!(true, !resp.body.is_empty());
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(0, resp.max_age.unwrap_or_default());
        assert_eq!(
            r#"("content-type", "text/html")"#,
            format!("{:?}", resp.headers.unwrap_or_default()[0])
        );

        let resp: HttpResponse =
            EmbeddedStaticFile(None, Duration::from_secs(60), false).into();
        assert_eq!(404, resp.status.as_u16())
    }

    /// Regression: every request put the file through gzip again, and
    /// answered with gzip whether the client took it or not.
    #[test]
    fn test_embedded_static_file_gzip() {
        let script = AdminAsset::iter()
            .find(|name| name.ends_with(".js"))
            .expect("the admin ui has a script");
        let get = |gzip: bool| -> HttpResponse {
            EmbeddedStaticFile(
                AdminAsset::get(&script),
                Duration::from_secs(60),
                gzip,
            )
            .into()
        };
        let header = |resp: &HttpResponse, name: &str| {
            resp.headers
                .iter()
                .flatten()
                .find(|(key, _)| key.as_str() == name)
                .map(|(_, value)| value.to_str().unwrap().to_string())
        };
        let plain = get(false);
        assert_eq!(None, header(&plain, "content-encoding"));
        assert_eq!(Some("Accept-Encoding".to_string()), header(&plain, "vary"));

        let first = get(true);
        assert_eq!(
            Some("gzip".to_string()),
            header(&first, "content-encoding")
        );
        assert_eq!(true, first.body.len() < plain.body.len());
        // The same bytes the second time, not another run of gzip.
        let second = get(true);
        assert_eq!(first.body.as_ptr(), second.body.as_ptr());

        // An image is sent as it is, to whoever asks.
        let image: HttpResponse = EmbeddedStaticFile(
            AdminAsset::get("pingap.png"),
            Duration::from_secs(60),
            true,
        )
        .into();
        assert_eq!(None, header(&image, "content-encoding"));
        assert_eq!(None, header(&image, "vary"));
    }

    #[test]
    fn test_config_error_response() {
        let message = |resp: &pingap_core::HttpResponse| {
            serde_json::from_slice::<serde_json::Value>(&resp.body).unwrap()
                ["message"]
                .as_str()
                .unwrap()
                .to_string()
        };
        // Regression: a bad request was answered 500, with the error as
        // pingora prints it for a message.
        let bad_json =
            serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let expected = bad_json.to_string();
        let resp = super::config_error_response(
            &pingap_core::new_internal_error(400, bad_json),
        );
        assert_eq!(400, resp.status.as_u16());
        assert_eq!(expected, message(&resp));

        // Not one of ours: a 500, and whatever it says.
        let resp = super::config_error_response(&pingora::Error::new_str(
            "disk on fire",
        ));
        assert_eq!(500, resp.status.as_u16());
        assert_eq!(true, message(&resp).contains("disk on fire"));
    }

    #[test]
    fn test_api_route() {
        // Static files of the UI: served without a token.
        assert_eq!(None, api_route("/"));
        assert_eq!(None, api_route("/assets/index.js"));
        assert_eq!(None, api_route("/pingap.png"));
        // Not the api: these used to reach the config handlers.
        assert_eq!(None, api_route("/configs/x.js"));
        assert_eq!(None, api_route("/configs/import/x.js"));
        assert_eq!(None, api_route("/apix/configs"));

        assert_eq!(Some(""), api_route("/api"));
        assert_eq!(Some("/basic"), api_route("/api/basic"));
        assert_eq!(Some("/configs/x.js"), api_route("/api/configs/x.js"));
    }

    async fn new_admin_session(req: &str) -> Session {
        let mock_io = Builder::new().read(req.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    /// Regression: with a password set, `/configs/...` without the `/api`
    /// prefix was routed to the config handlers, and a `.js` suffix skipped
    /// authentication.
    #[tokio::test]
    async fn test_admin_requires_auth_for_api_only() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let admin = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on

        let status = async |req: &str| {
            let mut session = new_admin_session(req).await;
            handle_request_admin(&admin, &mut session, &mut Ctx::default())
                .await
                .unwrap()
                .unwrap()
                .status
                .as_u16()
        };

        // The UI loads without a token.
        assert_eq!(200, status("GET / HTTP/1.1\r\n\r\n").await);
        assert_eq!(200, status("GET /pingap.png HTTP/1.1\r\n\r\n").await);
        // Not a file of the UI and not the api: nothing to serve.
        assert_eq!(404, status("GET /configs/x.js HTTP/1.1\r\n\r\n").await);
        assert_eq!(
            404,
            status("POST /configs/import/x.js HTTP/1.1\r\n\r\n").await
        );
        // The api always asks for the token, whatever the suffix.
        for path in [
            "/api/configs",
            "/api/configs/x.js",
            "/api/configs/upstream/x.css",
            "/api/certificates.png",
            "/api/basic",
            "/api",
        ] {
            assert_eq!(
                401,
                status(&format!("GET {path} HTTP/1.1\r\n\r\n")).await,
                "{path}"
            );
        }
    }

    /// Regression: the time in a token could be as far ahead of the clock
    /// as `max_age` allows it to be behind, so a token made with a time two
    /// days from now was good for four.
    #[test]
    fn test_token_time_is_current() {
        let now = 1_800_000_000_u64;
        let day = Duration::from_secs(24 * 3600);
        let at = |offset: i64, max_age: Duration| {
            let issued_at = now as i64 + offset;
            token_time_is_current(now, &issued_at.to_string(), max_age)
        };
        assert_eq!(true, at(0, day));
        // No older than `max_age`.
        assert_eq!(true, at(-24 * 3600, day));
        assert_eq!(false, at(-24 * 3600 - 1, day));
        // Ahead by what a clock may be off by, and no more.
        assert_eq!(true, at(5 * 60, day));
        assert_eq!(false, at(5 * 60 + 1, day));
        assert_eq!(false, at(24 * 3600, day));
        // A `max_age` below that bounds both sides.
        let minute = Duration::from_secs(60);
        assert_eq!(true, at(60, minute));
        assert_eq!(false, at(61, minute));
        assert_eq!(false, at(-61, minute));

        // Not a time, or a second way to write one.
        for issued_at in [
            "",
            "soon",
            "+1800000000",
            "-1",
            "1800000000.5",
            " 1800000000",
            "99999999999999999999999999",
            "-9223372036854775808",
        ] {
            assert_eq!(
                false,
                token_time_is_current(now, issued_at, day),
                "{issued_at}"
            );
        }
    }

    /// The same through the API: a token for a time an hour from now is
    /// refused, one for now is taken. The refusal says why, and is not
    /// counted as a failed login: it is what the right password gets while
    /// the two clocks disagree, and nothing was guessed.
    #[tokio::test]
    async fn test_admin_refuses_a_token_from_the_future() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let admin = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    ip_fail_limit = 2
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on
        let request = async |password: &str, issued_at: u64| {
            let mut hasher = Sha256::new();
            hasher.update(format!("admin:{password}:{issued_at}").as_bytes());
            let token = hasher.finalize().encode_hex::<String>();
            let mut session = new_admin_session(&format!(
                "GET /api/certificates HTTP/1.1\r\nAuthorization: {token}:{issued_at}\r\n\r\n"
            ))
            .await;
            let resp =
                handle_request_admin(&admin, &mut session, &mut Ctx::default())
                    .await
                    .unwrap()
                    .unwrap();
            (
                resp.status.as_u16(),
                String::from_utf8_lossy(&resp.body).to_string(),
            )
        };
        let now = pingap_core::now_sec();
        assert_eq!(200, request("123123", now).await.0);
        assert_eq!(200, request("123123", now - 3600).await.0);
        // More of them than `ip_fail_limit` allows of failed logins.
        for _ in 0..5 {
            let (status, body) = request("123123", now + 3600).await;
            assert_eq!(401, status);
            assert_eq!(true, body.contains("ahead of the server's clock"));
        }
        // Too old is the other side of it, and told the same.
        let (status, body) = request("123123", now - 3 * 24 * 3600).await;
        assert_eq!(401, status);
        assert_eq!(true, body.contains("too old"), "{body}");
        assert_eq!(200, request("123123", now).await.0);

        // A wrong password is a failed login: no explanation, and counted.
        assert_eq!((401, String::new()), request("guess", now).await);
        assert_eq!((401, String::new()), request("guess", now).await);
        assert_eq!(403, request("guess", now).await.0);
        assert_eq!(403, request("123123", now).await.0);
    }

    /// Regression: `/certificates` wrote out each loaded certificate as it
    /// is held, the chain and the private key included.
    #[test]
    fn test_certificates_are_listed_without_their_keys() {
        let certificate = pingap_certificate::Certificate {
            domains: vec!["example.com".to_string()],
            pem: b"-----BEGIN CERTIFICATE-----".to_vec(),
            key: b"-----BEGIN PRIVATE KEY-----".to_vec(),
            acme: Some("lets_encrypt".to_string()),
            not_after: 1_900_000_000,
            not_before: 1_800_000_000,
            issuer: "C=US, O=Let's Encrypt, CN=E5".to_string(),
        };
        let mut certificates = pingap_certificate::DynamicCertificates::new();
        certificates.insert(
            "example.com".to_string(),
            Arc::new(pingap_certificate::TlsCertificate {
                name: Some("site".to_string()),
                info: Some(certificate),
                ..Default::default()
            }),
        );
        // One that was not parsed has nothing to list.
        certificates.insert(
            "broken.example.com".to_string(),
            Arc::new(pingap_certificate::TlsCertificate::default()),
        );
        // What the handler writes out.
        let listed =
            serde_json::to_value(certificate_infos(&certificates)).unwrap();
        assert_eq!(
            serde_json::json!({
                "site": {
                    "domains": ["example.com"],
                    "acme": "lets_encrypt",
                    "not_after": 1_900_000_000_i64,
                    "not_before": 1_800_000_000_i64,
                    "issuer": "C=US, O=Let's Encrypt, CN=E5",
                }
            }),
            listed
        );
    }

    /// Mounted under a prefix: the prefix is removed on a segment boundary.
    #[tokio::test]
    async fn test_admin_path_prefix() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let admin = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/pingap/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on
        let status = async |path: &str| {
            let mut session =
                new_admin_session(&format!("GET {path} HTTP/1.1\r\n\r\n"))
                    .await;
            handle_request_admin(&admin, &mut session, &mut Ctx::default())
                .await
                .unwrap()
                .map(|resp| resp.status.as_u16())
        };
        assert_eq!(Some(307), status("/pingap").await);
        assert_eq!(Some(200), status("/pingap/").await);
        assert_eq!(Some(401), status("/pingap/api/configs").await);
        assert_eq!(Some(404), status("/pingap/configs/x.js").await);
        // Shares the first characters only: not under the prefix, and left
        // to whatever else the server has for it.
        assert_eq!(None, status("/pingapapi/configs").await);
        assert_eq!(None, status("/pingapple").await);
    }

    #[test]
    fn test_admin_rejects_malformed_authorization() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        let new_admin = |authorization: &str| {
            AdminServe::try_from(
                &toml::from_str::<PluginConf>(&format!(
                    "category = \"admin\"\nauthorizations = [\"{authorization}\"]"
                ))
                .unwrap(),
            )
            .map(|admin| admin.authorizations.len())
            .map_err(|e| e.to_string())
        };
        // spellchecker:off
        // "root": valid base64, but not `user:password`. It used to be
        // dropped, leaving no credentials and so no authentication.
        assert_eq!(
            "Plugin admin invalid, message: authorization should be base64 of user:password",
            new_admin("root").unwrap_err()
        );
        // "root:"
        assert_eq!(
            "Plugin admin invalid, message: authorization user and password can not be empty",
            new_admin("cm9vdDo=").unwrap_err()
        );
        assert_eq!(Ok(1), new_admin("YWRtaW46MTIzMTIz"));
        // spellchecker:on
        // No entry at all is the documented way to run without a password.
        assert_eq!(Ok(0), new_admin(""));
    }

    /// An admin without credentials on a config file of its own. The
    /// manager the plugin is built with is the one of the process, shared
    /// by every test; a test that writes gets its own.
    fn new_admin_on(
        file: &std::path::Path,
        conf: &str,
    ) -> (AdminServe, Arc<pingap_config::ConfigManager>) {
        try_init_config_manager(&file.to_string_lossy()).unwrap();
        let mut admin = AdminServe::try_from(
            &toml::from_str::<PluginConf>(&format!(
                "category = \"admin\"\n{conf}"
            ))
            .unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            pingap_config::new_config_manager(&file.to_string_lossy()).unwrap(),
        );
        admin.manager = manager.clone();
        (admin, manager)
    }

    async fn post(admin: &AdminServe, path: &str, body: &str) -> (u16, String) {
        let mut session = new_admin_session(&format!(
            "POST {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ))
        .await;
        let resp =
            handle_request_admin(admin, &mut session, &mut Ctx::default())
                .await
                .unwrap()
                .unwrap();
        // The message of an error, or the body as it is.
        let body = String::from_utf8_lossy(&resp.body).into_owned();
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value.get("message")?.as_str().map(str::to_string)
            })
            .unwrap_or(body);
        (resp.status.as_u16(), message)
    }

    /// The answer of `admin` to `request`, which came in on `server_addr`.
    async fn answer(
        admin: &AdminServe,
        server_addr: &str,
        request: &str,
    ) -> (u16, String) {
        let mut session = new_admin_session(request).await;
        let mut ctx = Ctx::default();
        ctx.conn.server_addr = Some(server_addr.to_string());
        let resp = handle_request_admin(admin, &mut session, &mut ctx)
            .await
            .unwrap()
            .unwrap();
        (
            resp.status.as_u16(),
            String::from_utf8_lossy(&resp.body).into_owned(),
        )
    }

    /// Regression: an admin without credentials took a write from any page
    /// the user had open - `fetch(url, {method: "POST", mode: "no-cors"})`
    /// stored a config - and answered a page whose name had been pointed at
    /// 127.0.0.1 as if it were its own.
    #[tokio::test]
    async fn test_admin_without_credentials_refuses_other_sites() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(file.path(), STORED).unwrap();
        let (admin, manager) = new_admin_on(file.path(), "");
        let upstream = r#"{"addrs":["127.0.0.1:5001"]}"#;
        let write = |headers: &str| {
            format!(
                "POST /api/configs/upstream/x HTTP/1.1\r\nHost: 127.0.0.1:3018\r\n{headers}Content-Length: {}\r\n\r\n{upstream}",
                upstream.len()
            )
        };
        let stored = async || {
            let config = manager.load_all().await.unwrap();
            config
                .to_pingap_config(false)
                .unwrap()
                .upstreams
                .contains_key("x")
        };

        // What a page of another site can send without a preflight.
        for headers in [
            "Origin: https://evil.test\r\nContent-Type: text/plain\r\n",
            "Origin: null\r\n",
            // Another port of the same host is another origin.
            "Origin: http://127.0.0.1:8080\r\n",
            "Sec-Fetch-Site: cross-site\r\nOrigin: https://evil.test\r\n",
            "Sec-Fetch-Site: same-site\r\nOrigin: http://127.0.0.1:8080\r\n",
            // The browser's word counts where it gives it, not the origin.
            "Sec-Fetch-Site: cross-site\r\nOrigin: http://127.0.0.1:3018\r\n",
        ] {
            let (status, body) =
                answer(&admin, "127.0.0.1", &write(headers)).await;
            assert_eq!(403, status, "{headers}: {body}");
            assert_eq!(true, body.contains("another site"), "{body}");
            assert_eq!(false, stored().await, "{headers}");
        }
        let (status, _) = answer(
            &admin,
            "127.0.0.1",
            "POST /api/restart HTTP/1.1\r\nHost: 127.0.0.1:3018\r\nOrigin: https://evil.test\r\n\r\n",
        )
        .await;
        assert_eq!(403, status);
        let (status, _) = answer(
            &admin,
            "127.0.0.1",
            "DELETE /api/configs/upstream/u1 HTTP/1.1\r\nHost: 127.0.0.1:3018\r\nOrigin: https://evil.test\r\n\r\n",
        )
        .await;
        assert_eq!(403, status);

        // A read from another site has nothing to show for it: the browser
        // keeps the answer from the page.
        let (status, _) = answer(
            &admin,
            "127.0.0.1",
            "GET /api/configs/toml HTTP/1.1\r\nHost: 127.0.0.1:3018\r\nSec-Fetch-Site: cross-site\r\n\r\n",
        )
        .await;
        assert_eq!(200, status);

        // The admin's own page, and a client that is not a browser.
        for headers in [
            "Origin: http://127.0.0.1:3018\r\n",
            "Sec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1:3018\r\n",
            "",
        ] {
            let (status, body) =
                answer(&admin, "127.0.0.1", &write(headers)).await;
            assert_eq!(204, status, "{headers}: {body}");
        }
        assert_eq!(true, stored().await);

        // DNS rebinding: to the browser the page and the admin are one
        // origin, and what gives it away is the name.
        let read = |host: &str| {
            format!("GET /api/configs/toml HTTP/1.1\r\nHost: {host}\r\n\r\n")
        };
        for host in ["evil.test:3018", "evil.test", "localhost.evil.test"] {
            let (status, body) = answer(&admin, "127.0.0.1", &read(host)).await;
            assert_eq!(403, status, "{host}");
            assert_eq!(true, body.contains("localhost"), "{body}");
            for server_addr in ["::1", "::ffff:127.0.0.1"] {
                let (status, _) =
                    answer(&admin, server_addr, &read(host)).await;
                assert_eq!(403, status, "{host} on {server_addr}");
            }
        }
        for host in [
            "127.0.0.1:3018",
            "localhost:3018",
            "LOCALHOST",
            "admin.localhost:3018",
            "[::1]:3018",
            "192.168.1.5:3018",
        ] {
            let (status, _) = answer(&admin, "127.0.0.1", &read(host)).await;
            assert_eq!(200, status, "{host}");
        }
        // The pages themselves are public, under any name.
        let (status, _) = answer(
            &admin,
            "127.0.0.1",
            "GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n",
        )
        .await;
        assert_eq!(200, status);
        // On an address of the network the admin is reached by the names
        // that network has for it.
        let (status, _) =
            answer(&admin, "192.168.1.5", &read("pingap.internal:3018")).await;
        assert_eq!(200, status);
    }

    /// With credentials the token is what keeps another site out, and a
    /// request that has it is not asked where it comes from.
    #[tokio::test]
    async fn test_admin_with_credentials_goes_by_the_token() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(file.path(), STORED).unwrap();
        // spellchecker:off
        let (admin, _) = new_admin_on(
            file.path(),
            r#"authorizations = ["YWRtaW46MTIzMTIz"]"#,
        );
        // spellchecker:on
        let ts = pingap_core::now_sec();
        let mut hasher = Sha256::new();
        hasher.update(format!("admin:123123:{ts}").as_bytes());
        let token = hasher.finalize().encode_hex::<String>();
        let request = |authorization: &str| {
            format!(
                "GET /api/configs/toml HTTP/1.1\r\nHost: admin.example.com\r\nOrigin: https://other.example.com\r\n{authorization}\r\n"
            )
        };
        let (status, _) = answer(&admin, "127.0.0.1", &request("")).await;
        assert_eq!(401, status);
        let (status, _) = answer(
            &admin,
            "127.0.0.1",
            &request(&format!("Authorization: {token}:{ts}\r\n")),
        )
        .await;
        assert_eq!(200, status);
    }

    /// Regression: the body of a request was read into memory however
    /// large it was.
    #[tokio::test]
    async fn test_request_body_has_a_limit() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(file.path(), STORED).unwrap();
        let (admin, _) = new_admin_on(file.path(), "");

        // Says so itself: refused before any of it is read.
        let (status, body) = answer(
            &admin,
            "192.168.1.5",
            &format!(
                "POST /api/configs/import HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                super::MAX_BODY_SIZE + 1
            ),
        )
        .await;
        assert_eq!(413, status, "{body}");

        // Does not say: refused once it has grown past the limit, with
        // the rest of it still on its way.
        let chunk = "a".repeat(64 * 1024);
        let mut request = String::from(
            "POST /api/configs/import HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        for _ in 0..=super::MAX_BODY_SIZE / chunk.len() {
            request.push_str(&format!("{:x}\r\n{chunk}\r\n", chunk.len()));
        }
        request.push_str("0\r\n\r\n");
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = client.write_all(request.as_bytes()).await;
        });
        let mut session = Session::new_h1(Box::new(server));
        session.read_request().await.unwrap();
        let resp =
            handle_request_admin(&admin, &mut session, &mut Ctx::default())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(413, resp.status.as_u16());
    }

    const STORED: &str = r#"[basic]
name = "pingap"
threads = 2

[upstreams.u1]
addrs = ["127.0.0.1:5000"]

[locations.l1]
upstream = "u1"
path = "/api"
"#;

    /// Regression: a post to a category the admin does not know was stored
    /// as the basic config. With the body of another category - a typo,
    /// `upstreams/x` for `upstream/x` - that left `[basic]` empty.
    #[tokio::test]
    async fn test_update_config_knows_its_categories() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(file.path(), STORED).unwrap();
        let (admin, manager) = new_admin_on(file.path(), "");
        let basic = async || {
            let config = manager.load_all().await.unwrap();
            config.to_pingap_config(false).unwrap().basic
        };

        let upstream = r#"{"addrs":["127.0.0.1:5001"]}"#;
        for category in ["upstreams", "unknown", "full"] {
            let (status, body) =
                post(&admin, &format!("/api/configs/{category}/x"), upstream)
                    .await;
            assert_eq!(400, status, "{category}: {body}");
            assert_eq!(
                true,
                body.contains(&format!("invalid category: {category}")),
                "{body}"
            );
        }
        assert_eq!(Some("pingap".to_string()), basic().await.name);
        assert_eq!(Some(2), basic().await.threads);

        // The two names the basic config is posted under: the page's, and
        // the one of the category.
        for (category, name) in [("pingap", "first"), ("basic", "second")] {
            let (status, body) = post(
                &admin,
                &format!("/api/configs/{category}/basic"),
                &format!(r#"{{"name":"{name}","threads":2}}"#),
            )
            .await;
            assert_eq!(204, status, "{category}: {body}");
            assert_eq!(Some(name.to_string()), basic().await.name);
        }
        // The right category still works.
        let (status, body) =
            post(&admin, "/api/configs/upstream/x", upstream).await;
        assert_eq!(204, status, "{body}");
    }

    /// Regression: the admin stored what startup refuses. Only the entry
    /// itself was looked at, and only as far as its own `validate` goes: a
    /// location with a regex that does not compile, a plugin option of the
    /// wrong type and a reference to nothing all went in, and an import
    /// was not looked at at all.
    #[tokio::test]
    async fn test_admin_refuses_what_startup_would() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(file.path(), STORED).unwrap();
        let (admin, _) = new_admin_on(file.path(), "");
        let stored = || std::fs::read_to_string(file.path()).unwrap();

        for (path, body, expected) in [
            (
                "/api/configs/location/bad",
                r#"{"upstream":"u1","path":"~ ^/api/("}"#,
                "location \"bad\" is invalid",
            ),
            (
                "/api/configs/plugin/limiter",
                r#"{"category":"limit","type":"inflight","tag":"ip","max":"100"}"#,
                "plugin \"limiter\" is invalid",
            ),
            (
                "/api/configs/location/lost",
                r#"{"upstream":"u2"}"#,
                "upstream(u2) is not found",
            ),
            (
                "/api/configs/import",
                "[locations.bad]\nupstream = \"u1\"\n",
                "upstream(u1) is not found",
            ),
        ] {
            let (status, message) = post(&admin, path, body).await;
            assert_eq!(400, status, "{path}: {message}");
            assert_eq!(true, message.contains(expected), "{path}: {message}");
            assert_eq!(STORED, stored(), "{path}");
        }

        // An import with nothing pingap reads in it would replace what is
        // stored with nothing.
        for (body, expected) in [
            ("", "the config to import is empty"),
            ("# only a comment\n", "the config to import is empty"),
            (
                "[upstream.u1]\naddrs = [\"127.0.0.1:5000\"]\n",
                "unknown section: upstream",
            ),
        ] {
            let (status, message) =
                post(&admin, "/api/configs/import", body).await;
            assert_eq!(400, status, "{body}: {message}");
            assert_eq!(true, message.contains(expected), "{message}");
            assert_eq!(STORED, stored());
        }

        // A cache plugin that is refused has made no directory, and one
        // that is stored has not either: that is for the reload.
        let cache_dir = file.path().with_extension("cache");
        for (extra, expected) in [(r#","max_ttl":"oops""#, 400), ("", 204)] {
            let (status, message) = post(
                &admin,
                "/api/configs/plugin/c",
                &format!(
                    r#"{{"category":"cache","directory":"{}?inactive=1m"{extra}}}"#,
                    cache_dir.display()
                ),
            )
            .await;
            assert_eq!(expected, status, "{message}");
            assert_eq!(false, cache_dir.exists());
        }

        // What is right is stored as before.
        let (status, message) = post(
            &admin,
            "/api/configs/location/good",
            r#"{"upstream":"u1","path":"~ ^/v[0-9]+/"}"#,
        )
        .await;
        assert_eq!(204, status, "{message}");
        let (status, message) =
            post(&admin, "/api/configs/import", STORED).await;
        assert_eq!(204, status, "{message}");
    }

    /// A storage that does not pass as it is takes changes: that is the
    /// admin being used to repair it.
    #[tokio::test]
    async fn test_admin_can_repair_a_broken_config() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(
            file.path(),
            format!("{STORED}\n[locations.lost]\nupstream = \"u2\"\n"),
        )
        .unwrap();
        let (admin, manager) = new_admin_on(file.path(), "");

        // Still broken after this one, and taken all the same.
        let (status, message) = post(
            &admin,
            "/api/configs/location/other",
            r#"{"upstream":"u3"}"#,
        )
        .await;
        assert_eq!(204, status, "{message}");
        for (name, upstream) in [("lost", "u1"), ("other", "u1")] {
            let (status, message) = post(
                &admin,
                &format!("/api/configs/location/{name}"),
                &format!(r#"{{"upstream":"{upstream}"}}"#),
            )
            .await;
            assert_eq!(204, status, "{message}");
        }
        // Repaired, and from here on a change has to keep it that way.
        let config = manager.load_all().await.unwrap();
        assert_eq!(true, crate::validate::validate_stored(&config).is_ok());
        let (status, _) = post(
            &admin,
            "/api/configs/location/other",
            r#"{"upstream":"u3"}"#,
        )
        .await;
        assert_eq!(400, status);
    }

    /// Regression: a request without credentials counted as a failed
    /// login, and the lock was looked at before anything else. Ten of them
    /// - the page polling after its token ran out - locked the address out
    /// of the admin, the pages of the UI included.
    #[tokio::test]
    async fn test_admin_lock_counts_failed_logins_only() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        // spellchecker:off
        let (admin, _) = new_admin_on(
            file.path(),
            "path = \"/admin/\"\nauthorizations = [\"YWRtaW46MTIzMTIz\"]",
        );
        // spellchecker:on
        let status = async |path: &str, authorization: Option<&str>| {
            let header = authorization
                .map(|value| format!("Authorization: {value}\r\n"))
                .unwrap_or_default();
            let mut session = new_admin_session(&format!(
                "GET {path} HTTP/1.1\r\n{header}\r\n"
            ))
            .await;
            let mut ctx = Ctx::default();
            ctx.conn.remote_addr = Some("192.0.2.7".to_string());
            handle_request_admin(&admin, &mut session, &mut ctx)
                .await
                .unwrap()
                .map(|resp| resp.status.as_u16())
        };
        let token = || {
            let ts = pingap_core::now_sec();
            let mut hasher = Sha256::new();
            hasher.update(format!("admin:123123:{ts}").as_bytes());
            format!("{}:{ts}", hasher.finalize().encode_hex::<String>())
        };

        // Not logins: turned away, and not held against the address.
        for _ in 0..30 {
            assert_eq!(Some(401), status("/admin/api/basic", None).await);
        }
        assert_eq!(Some(200), status("/admin/api/basic", Some(&token())).await);

        // Failed logins are, up to the limit of ten.
        let wrong = format!("{}:{}", "0".repeat(64), pingap_core::now_sec());
        for _ in 0..10 {
            assert_eq!(
                Some(401),
                status("/admin/api/basic", Some(&wrong)).await
            );
        }
        assert_eq!(Some(403), status("/admin/api/basic", Some(&wrong)).await);
        assert_eq!(Some(403), status("/admin/api/basic", Some(&token())).await);
        // The lock is on the API. The pages still load, and what is not
        // under the admin's prefix was never its to refuse.
        assert_eq!(Some(200), status("/admin/", None).await);
        assert_eq!(None, status("/app/orders", None).await);
    }

    /// Regression: `/config-history/{category}` without the trailing name used
    /// to index past the end of the split url and panic the request task.
    #[tokio::test]
    async fn test_config_history_without_name() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        let admin = AdminServe::try_from(
            &toml::from_str::<PluginConf>(r#"category = "admin""#).unwrap(),
        )
        .unwrap();

        let mock_io = Builder::new()
            .read(b"GET /api/config-history/upstream HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let err =
            handle_request_admin(&admin, &mut session, &mut Ctx::default())
                .await
                .err()
                .unwrap();
        assert_eq!(
            true,
            err.to_string().contains("Url is invalid(no name)"),
            "unexpected error: {err}"
        );
    }
}
