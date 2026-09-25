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

use super::{Error, get_duration_conf, get_hash_key, get_str_conf};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Bytes, BytesMut};
use http::StatusCode;
use humantime::parse_duration;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, ModifyResponseBody, Plugin, PluginStep, RequestPluginResult,
    ResponseBodyPluginResult, ResponsePluginResult,
};
use pingap_core::{
    HTTP_HEADER_CONTENT_JSON, HTTP_HEADER_TRANSFER_CHUNKED, HttpResponse,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use serde::Deserialize;
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::time::sleep;
use tracing::debug;
use tracing::error;

const PLUGIN_ID: &str = "_jwt_";

type Result<T, E = Error> = std::result::Result<T, E>;

/// The token's `alg`. `typ` is optional in RFC 7519; this struct used to
/// require it, so a token without one was refused as unsigned.
#[derive(Debug, Default, Deserialize)]
struct JwtHeader {
    alg: String,
}

/// The claims a verified token is checked against; everything else is
/// ignored. Both are numbers in the spec, and some issuers write them as
/// floats, which a `u64` field would refuse.
#[derive(Debug, Default, Deserialize)]
struct Claims {
    exp: Option<f64>,
    nbf: Option<f64>,
}

/// The claims type for the `jsonwebtoken` paths: those verify the signature
/// and the time claims themselves, and nothing here reads the rest.
#[derive(Deserialize)]
struct NoClaims {}

/// Why an HMAC token was refused; the body of the 401 says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HmacRejection {
    Format,
    Signature,
    Expired,
    NotYetValid,
}

impl HmacRejection {
    fn message(self) -> Bytes {
        Bytes::from_static(match self {
            Self::Format => b"Jwt authorization format is invalid",
            Self::Signature => b"Jwt authorization is invalid",
            Self::Expired => b"Jwt authorization is expired",
            Self::NotYetValid => b"Jwt authorization is not yet valid",
        })
    }
}

/// The token after an RFC 6750 `Bearer` scheme, which is case-insensitive;
/// a value without the scheme is taken as the bare token.
fn strip_bearer(value: &str) -> &str {
    match value.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => {
            token.trim_start()
        },
        _ => value,
    }
}

/// Whether `signature` is the base64url of `hash`, compared in constant
/// time; `encoded` is scratch for the encoding, sized for HMAC-SHA512.
fn signature_matches(
    hash: &[u8],
    signature: &str,
    encoded: &mut [u8; 86],
) -> bool {
    match URL_SAFE_NO_PAD.encode_slice(hash, encoded) {
        Ok(len) => {
            pingap_core::constant_time_eq(&encoded[..len], signature.as_bytes())
        },
        Err(_) => false,
    }
}

/// Verifies an HMAC token: its shape, the signature under `secret` with the
/// algorithm its header names (which must equal `pinned_alg` when that is
/// set), then `exp` and `nbf` against `now`.
///
/// The signed part is a prefix of the token itself and the signature is
/// compared as encoded bytes, so nothing here copies the token; the payload
/// is read into the two claims rather than a full JSON tree.
fn verify_hmac_token(
    token: &str,
    secret: &[u8],
    pinned_alg: &str,
    now: u64,
) -> std::result::Result<(), HmacRejection> {
    let Some((header, rest)) = token.split_once('.') else {
        return Err(HmacRejection::Format);
    };
    let Some((payload, signature)) = rest.split_once('.') else {
        return Err(HmacRejection::Format);
    };
    if signature.contains('.') {
        return Err(HmacRejection::Format);
    }
    let jwt_header: JwtHeader = URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default();
    let alg = jwt_header.alg.as_str();
    // An explicitly configured algorithm is pinned: a token must not
    // downgrade HS512 to HS256 just by saying so in its own header. An
    // unset `algorithm` keeps accepting either, since that is what existing
    // configurations rely on.
    if !pinned_alg.is_empty() && alg != pinned_alg {
        return Err(HmacRejection::Signature);
    }
    let content = &token.as_bytes()[..header.len() + 1 + payload.len()];
    let mut encoded = [0u8; 86];
    let valid = match alg {
        "HS256" => {
            let hash = hmac_sha256::HMAC::mac(content, secret);
            signature_matches(&hash, signature, &mut encoded)
        },
        "HS512" => {
            let hash = hmac_sha512::HMAC::mac(content, secret);
            signature_matches(&hash, signature, &mut encoded)
        },
        // Unknown / unsupported algorithms (including "none") are rejected
        // rather than silently falling back to HS256.
        _ => false,
    };
    if !valid {
        return Err(HmacRejection::Signature);
    }
    // Signed by us or by someone holding the secret, so a payload that is
    // not a JSON object is a broken token rather than a lenient one.
    let claims: Claims = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .ok_or(HmacRejection::Format)?;
    let now = now as f64;
    if claims.exp.is_some_and(|exp| exp < now) {
        return Err(HmacRejection::Expired);
    }
    if claims.nbf.is_some_and(|nbf| nbf > now) {
        return Err(HmacRejection::NotYetValid);
    }
    Ok(())
}

/// JwtAuth struct holds configuration for JWT authentication and validation.
///
/// This plugin provides JWT-based authentication with the following features:
/// - Token generation endpoint at a configurable path
/// - Support for multiple token locations (header, query param, or cookie)
/// - HMAC-based signatures using HS256 or HS512
/// - Token expiration validation
/// - Protection against timing attacks
///
/// # Token Locations
/// Tokens can be extracted from one of:
/// - HTTP header (typically "Authorization: Bearer <token>")
/// - Query parameter (e.g., "?token=<token>")
/// - Cookie value
///
/// # Security Features
/// - Configurable HMAC algorithms (HS256/HS512)
/// - Optional delay on authentication failures to prevent timing attacks
/// - Automatic expiration checking via "exp" claim
///
/// # Example Configuration
/// ```toml
/// secret = "your-secret-key"
/// header = "Authorization"
/// auth_path = "/login"
/// algorithm = "HS256"
/// delay = "100ms"
/// ```
pub struct JwtAuth {
    /// Plugin execution step (must be Request)
    plugin_step: PluginStep,

    /// Endpoint path for generating new JWT tokens (e.g., "/login")
    /// When this path is accessed, the plugin will sign the response data as a JWT
    auth_path: String,

    /// Secret key used for HMAC signing/verification
    /// This should be kept secure and consistent across all instances
    secret: String,

    /// HTTP header name to extract JWT from (typically "Authorization")
    /// Supports both "Bearer <token>" and raw token formats
    header: Option<String>,

    /// Query parameter name to extract JWT from
    /// Token will be read from ?{query}=<token>
    query: Option<String>,

    /// Cookie name to extract JWT from
    /// Token will be read from the specified cookie value
    cookie: Option<String>,

    /// HMAC algorithm selection: "HS256" (default) or "HS512"
    /// HS512 provides stronger hashing but may be slower
    algorithm: String,

    /// Pre-parsed decoding key and the validation pinned to its algorithm,
    /// for asymmetric verification (RS*/ES*/PS*). `Some` when an asymmetric
    /// `algorithm` and `public_key` are configured; HMAC algorithms leave
    /// this `None` and use `secret`.
    decoding_key: Option<(DecodingKey, Validation)>,

    /// Remote JWKS source (`Some` when `jwks_url` is configured). Verifies
    /// asymmetric tokens against keys fetched from the issuer, selected by
    /// their `kid`.
    jwks: Option<Arc<JwksSource>>,

    /// Optional delay on authentication failure
    /// Helps prevent timing attacks by making success/failure responses take similar time
    delay: Option<Duration>,

    /// Template for 401 Unauthorized responses
    /// Used when token is missing, invalid, or expired
    unauthorized_resp: HttpResponse,

    /// Unique identifier for this plugin instance
    /// Used for internal plugin management
    hash_value: String,
}

/// Builds a decoding key for an asymmetric `algorithm` from a PEM `public_key`.
/// Returns `Ok(None)` for HMAC (or unset) algorithms, which use the shared
/// `secret` path instead.
fn build_asymmetric_key(
    algorithm: &str,
    public_key: &str,
) -> Result<Option<(DecodingKey, Validation)>> {
    let Ok(alg) = Algorithm::from_str(algorithm) else {
        // Unknown or empty algorithm -> treated as HMAC (secret) below.
        return Ok(None);
    };
    let is_asymmetric = matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
    );
    if !is_asymmetric {
        return Ok(None);
    }
    if public_key.is_empty() {
        return Err(Error::Invalid {
            category: PluginCategory::Jwt.to_string(),
            message: "public_key is required for asymmetric algorithms"
                .to_string(),
        });
    }
    let key = match alg {
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(public_key.as_bytes())
        },
        _ => DecodingKey::from_rsa_pem(public_key.as_bytes()),
    }
    .map_err(|e| Error::Invalid {
        category: PluginCategory::Jwt.to_string(),
        message: format!("invalid public_key: {e}"),
    })?;
    Ok(Some((key, jwks_validation(alg))))
}

/// One key of a JWKS. `kid` is optional in RFC 7517, and a single-key set
/// often leaves it out; such keys used to be dropped at fetch time.
struct JwkEntry {
    kid: Option<String>,
    key: DecodingKey,
}

/// Cached JWKS decoding keys plus the fetch time.
struct JwksCache {
    keys: Vec<JwkEntry>,
    fetched_at: Instant,
}

impl JwksCache {
    /// The keys a token may have been signed with: those under its `kid`,
    /// or every key when it names none.
    fn candidates<'a>(
        &'a self,
        kid: Option<&'a str>,
    ) -> impl Iterator<Item = &'a DecodingKey> {
        self.keys
            .iter()
            .filter(move |entry| {
                kid.is_none_or(|kid| entry.kid.as_deref() == Some(kid))
            })
            .map(|entry| &entry.key)
    }

    fn verify(
        &self,
        token: &str,
        kid: Option<&str>,
        validation: &Validation,
    ) -> bool {
        self.candidates(kid)
            .any(|key| decode::<NoClaims>(token, key, validation).is_ok())
    }
}

/// A remote JWKS endpoint with a TTL cache, single-flight refresh and key
/// rotation. Verification serves cached keys lock-free; only a cache miss /
/// expiry / unknown `kid` triggers a rate-limited refetch.
struct JwksSource {
    url: String,
    ttl: Duration,
    /// Minimum spacing between refetches, to bound refetching on unknown kids.
    cooldown: Duration,
    client: reqwest::Client,
    cache: ArcSwapOption<JwksCache>,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl JwksSource {
    async fn fetch(&self) -> std::result::Result<JwksCache, String> {
        let resp = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let set = resp.json::<JwkSet>().await.map_err(|e| e.to_string())?;
        let keys = set
            .keys
            .iter()
            .filter_map(|jwk| {
                DecodingKey::from_jwk(jwk).ok().map(|key| JwkEntry {
                    kid: jwk.common.key_id.clone(),
                    key,
                })
            })
            .collect();
        Ok(JwksCache {
            keys,
            fetched_at: Instant::now(),
        })
    }

    /// Refreshes the cache with single-flight + rate limiting. On fetch failure
    /// the previous cache is kept (graceful degradation).
    async fn refresh(&self) {
        let _guard = self.refresh_lock.lock().await;
        // Re-check after acquiring the lock: a peer may have just refreshed, or
        // we may still be inside the cooldown window (bounds unknown-kid churn).
        if let Some(cache) = self.cache.load_full()
            && cache.fetched_at.elapsed() < self.cooldown
        {
            return;
        }
        match self.fetch().await {
            Ok(cache) => self.cache.store(Some(Arc::new(cache))),
            Err(e) => {
                error!(category = "jwt", error = e, "fetch jwks failed");
            },
        }
    }

    async fn verify(&self, token: &str) -> bool {
        let Ok(header) = decode_header(token) else {
            return false;
        };
        // Only asymmetric algorithms are accepted, so a token cannot be signed
        // with symmetric HMAC using the public key as the secret (algorithm
        // confusion). `decode` also rejects an alg that mismatches the JWK's
        // key type.
        if !is_asymmetric_alg(header.alg) {
            return false;
        }
        let validation = jwks_validation(header.alg);
        let kid = header.kid.as_deref();
        // Fresh cache hit: verify without touching the network.
        if let Some(cache) = self.cache.load_full()
            && cache.fetched_at.elapsed() <= self.ttl
            && cache.verify(token, kid, &validation)
        {
            return true;
        }
        // Miss / expired / rotated kid: refresh (rate-limited), then retry with
        // whatever we have (including a stale cache if the refetch failed).
        self.refresh().await;
        self.cache
            .load_full()
            .is_some_and(|cache| cache.verify(token, kid, &validation))
    }
}

/// Validation pinned to the JWK's declared algorithm, enforcing signature and
/// `exp` while ignoring `aud`.
fn jwks_validation(alg: Algorithm) -> Validation {
    let mut validation = Validation::new(alg);
    validation.validate_aud = false;
    validation
}

/// Returns true for signature algorithms usable with a public key.
fn is_asymmetric_alg(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

/// Builds a remote JWKS source when `jwks_url` is configured (`Ok(None)`
/// otherwise). `jwks_ttl` controls the cache lifetime (default 1h).
fn build_jwks_source(value: &PluginConf) -> Result<Option<Arc<JwksSource>>> {
    let url = get_str_conf(value, "jwks_url");
    if url.is_empty() {
        return Ok(None);
    }
    reqwest::Url::parse(&url).map_err(|e| Error::Invalid {
        category: PluginCategory::Jwt.to_string(),
        message: format!("invalid jwks_url: {e}"),
    })?;
    let ttl = get_duration_conf(value, "jwks_ttl")
        .unwrap_or(Duration::from_secs(3600));
    let cooldown = ttl.min(Duration::from_secs(10));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| Error::Invalid {
            category: PluginCategory::Jwt.to_string(),
            message: e.to_string(),
        })?;
    Ok(Some(Arc::new(JwksSource {
        url,
        ttl,
        cooldown,
        client,
        cache: ArcSwapOption::empty(),
        refresh_lock: tokio::sync::Mutex::new(()),
    })))
}

impl TryFrom<&PluginConf> for JwtAuth {
    type Error = Error;

    /// Attempts to create a JwtAuth instance from plugin configuration
    ///
    /// # Arguments
    /// * `value` - Plugin configuration
    ///
    /// # Returns
    /// * `Result<Self>` - Valid JwtAuth instance or configuration error
    ///
    /// # Errors
    /// * When no token location (header/query/cookie) is specified
    /// * When secret is empty
    /// * When plugin step is not Request
    /// * When delay duration is invalid
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let header = get_str_conf(value, "header");
        let query = get_str_conf(value, "query");
        let cookie = get_str_conf(value, "cookie");
        if header.is_empty() && query.is_empty() && cookie.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::Jwt.to_string(),
                message: "Jwt key or key type is not allowed empty".to_string(),
            });
        }
        let header = if header.is_empty() {
            None
        } else {
            Some(header)
        };
        let query = if query.is_empty() { None } else { Some(query) };
        let cookie = if cookie.is_empty() {
            None
        } else {
            Some(cookie)
        };
        let delay = get_str_conf(value, "delay");
        let delay = if !delay.is_empty() {
            let d = parse_duration(&delay).map_err(|e| Error::Invalid {
                category: PluginCategory::Jwt.to_string(),
                message: e.to_string(),
            })?;
            Some(d)
        } else {
            None
        };
        let algorithm = get_str_conf(value, "algorithm");
        let decoding_key = build_asymmetric_key(
            &algorithm,
            &get_str_conf(value, "public_key"),
        )?;
        let jwks = build_jwks_source(value)?;

        let params = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            secret: get_str_conf(value, "secret"),
            auth_path: get_str_conf(value, "auth_path"),
            algorithm,
            decoding_key,
            jwks,
            delay,
            header,
            query,
            cookie,
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from_static(b"Invalid or expired jwt"),
                ..Default::default()
            },
        };

        // HMAC algorithms need a shared secret; asymmetric ones use the parsed
        // public key or a remote JWKS instead.
        if params.decoding_key.is_none() && params.jwks.is_none() {
            if params.secret.is_empty() {
                return Err(Error::Invalid {
                    category: PluginCategory::Jwt.to_string(),
                    message: "Jwt secret is not allowed empty".to_string(),
                });
            }
            // Only HS256 and HS512 are implemented on the secret path. Anything
            // else (HS384, or an asymmetric algorithm without a key) would
            // otherwise be accepted here and then reject every single token.
            if !matches!(params.algorithm.as_str(), "" | "HS256" | "HS512") {
                return Err(Error::Invalid {
                    category: PluginCategory::Jwt.to_string(),
                    message: format!(
                        "Jwt algorithm({}) is not supported, expect HS256 or HS512, or set public_key/jwks_url",
                        params.algorithm
                    ),
                });
            }
        }

        Ok(params)
    }
}

impl JwtAuth {
    /// Creates a new JwtAuth plugin instance from the provided configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration containing JWT settings
    ///
    /// # Returns
    /// * `Result<Self>` - New JwtAuth instance or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new jwt auth plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for JwtAuth {
    /// Returns unique identifier for this plugin instance
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming requests by validating JWT tokens
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - Current HTTP session
    /// * `_ctx` - Plugin state context
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - None if authentication succeeds, or error response if it fails
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        let req_header = session.req_header();
        if req_header.uri.path() == self.auth_path {
            return Ok(RequestPluginResult::Skipped);
        }
        let value = if let Some(key) = &self.header {
            strip_bearer(
                pingap_core::get_req_header_value(req_header, key)
                    .unwrap_or_default(),
            )
        } else if let Some(key) = &self.cookie {
            pingap_core::get_cookie_value(req_header, key).unwrap_or_default()
        } else if let Some(key) = &self.query {
            pingap_core::get_query_value(req_header, key).unwrap_or_default()
        } else {
            ""
        };
        if value.is_empty() {
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is missing");
            return Ok(RequestPluginResult::Respond(resp));
        }
        // Asymmetric verification: the configured algorithm is pinned (the
        // token's own `alg` header is not trusted, preventing algorithm
        // confusion), and jsonwebtoken checks the signature and `exp` together.
        if let Some((key, validation)) = &self.decoding_key {
            if decode::<NoClaims>(value, key, validation).is_ok() {
                return Ok(RequestPluginResult::Continue);
            }
            if let Some(d) = self.delay {
                sleep(d).await;
            }
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is invalid");
            return Ok(RequestPluginResult::Respond(resp));
        }
        // Remote JWKS verification: the key is selected by the token's `kid`
        // and pinned to that JWK's algorithm.
        if let Some(jwks) = &self.jwks {
            if jwks.verify(value).await {
                return Ok(RequestPluginResult::Continue);
            }
            if let Some(d) = self.delay {
                sleep(d).await;
            }
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is invalid");
            return Ok(RequestPluginResult::Respond(resp));
        }
        match verify_hmac_token(
            value,
            self.secret.as_bytes(),
            &self.algorithm,
            pingap_core::now_sec(),
        ) {
            Ok(()) => Ok(RequestPluginResult::Continue),
            Err(rejection) => {
                // Only a bad signature is worth slowing down: it is the one
                // outcome a guess can produce.
                if rejection == HmacRejection::Signature
                    && let Some(d) = self.delay
                {
                    sleep(d).await;
                }
                let mut resp = self.unauthorized_resp.clone();
                resp.body = rejection.message();
                Ok(RequestPluginResult::Respond(resp))
            },
        }
    }

    /// Handles responses for the token generation endpoint
    ///
    /// # Arguments
    /// * `session` - Current HTTP session
    /// * `ctx` - Plugin state context
    /// * `upstream_response` - Response headers from upstream
    ///
    /// # Returns
    /// * `pingora::Result<()>` - Success or error
    #[inline]
    async fn handle_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if session.req_header().uri.path() != self.auth_path {
            return Ok(ResponsePluginResult::Unchanged);
        }
        // The body is signed verbatim, so only a successful response may be
        // turned into a token. An error body carries no `exp`, and the request
        // path only checks the signature and `exp`, so signing it would mint a
        // token that never expires.
        if !upstream_response.status.is_success() {
            return Ok(ResponsePluginResult::Unchanged);
        }
        upstream_response.remove_header(&http::header::CONTENT_LENGTH);
        let json = HTTP_HEADER_CONTENT_JSON.clone();
        let _ = upstream_response.insert_header(json.0, json.1);

        // no error
        let _ = upstream_response.insert_header(
            http::header::TRANSFER_ENCODING,
            HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
        );

        ctx.add_modify_body_handler(
            PLUGIN_ID,
            Box::new(Sign {
                algorithm: self.algorithm.clone(),
                secret: self.secret.clone(),
                buffer: BytesMut::new(),
            }),
        );

        Ok(ResponsePluginResult::Modified)
    }
    fn handle_response_body(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        if let Some(modifier) = ctx.get_modify_body_handler(PLUGIN_ID) {
            modifier.handle(session, body, end_of_stream)?;
            let result = if end_of_stream {
                ResponseBodyPluginResult::FullyReplaced
            } else {
                ResponseBodyPluginResult::PartialReplaced
            };
            Ok(result)
        } else {
            Ok(ResponseBodyPluginResult::Unchanged)
        }
    }
}

/// Handles JWT token signing for the token generation endpoint
struct Sign {
    secret: String,
    algorithm: String,
    buffer: BytesMut,
}

impl ModifyResponseBody for Sign {
    /// Signs and formats response data into a JWT token
    ///
    /// # Arguments
    /// * `data` - Response payload to be encoded in the JWT
    ///
    /// # Returns
    /// * `Bytes` - JSON response containing the signed JWT token
    fn handle(
        &mut self,
        _session: &Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if let Some(data) = body {
            self.buffer.extend(&data[..]);
            data.clear();
        }
        if !end_of_stream {
            return Ok(());
        }
        let is_hs512 = self.algorithm == "HS512";
        let alg = if is_hs512 { "HS512" } else { "HS256" };
        // spellchecker:off
        let header = URL_SAFE_NO_PAD
            .encode(r#"{"alg": ""#.to_owned() + alg + r#"","typ": "JWT"}"#);
        // spellchecker:on
        let payload = URL_SAFE_NO_PAD.encode(&self.buffer);
        let content = format!("{header}.{payload}");
        let secret = self.secret.as_bytes();
        let sign = if is_hs512 {
            let hash = hmac_sha512::HMAC::mac(content.as_bytes(), secret);
            URL_SAFE_NO_PAD.encode(hash)
        } else {
            let hash = hmac_sha256::HMAC::mac(content.as_bytes(), secret);
            URL_SAFE_NO_PAD.encode(hash)
        };
        let token = format!("{content}.{sign}");
        *body = Some(Bytes::from(r#"{"token": "{}"}"#.replace("{}", &token)));
        Ok(())
    }
    fn name(&self) -> &str {
        "jwt_sign"
    }
}

register_plugin!("jwt", JwtAuth);

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// Tests JWT authentication parameter validation
    #[test]
    fn test_jwt_auth_params() {
        let params = JwtAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
cookie = "jwt"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("jwt", params.cookie.unwrap_or_default());
        assert_eq!("123123", params.secret);

        let result = JwtAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
cookie = "jwt"
"###,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin jwt invalid, message: Jwt secret is not allowed empty",
            result.err().unwrap().to_string()
        );

        let result = JwtAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
"###,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin jwt invalid, message: Jwt key or key type is not allowed empty",
            result.err().unwrap().to_string()
        );
    }

    /// Tests creation of new JWT auth instances
    #[test]
    fn test_new_jwt() {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
cookie = "jwt"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("jwt", auth.cookie.unwrap());

        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
cookie = "jwt"
auth_path = "/login"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("jwt", auth.cookie.unwrap());
        assert_eq!("/login", auth.auth_path);
    }

    /// Tests asymmetric (ES256) verification with a static public key.
    #[tokio::test]
    async fn test_jwt_asymmetric() {
        use jsonwebtoken::{EncodingKey, Header, encode};

        let public_key = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECE/4ox+pGq+yiB3RqIXINmlHJp+l
6V8vXffF5UzI/h3RPK3l9MphCKS2wg50uVoWlBITXMRhh5LVB/93vQZa0Q==
-----END PUBLIC KEY-----"#;
        // spellchecker:off
        let private_key = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6V2VwZk30Az6VKMF
Bt6nfEa2r4hCQuuMB6azsjMB7xmhRANCAAQIT/ijH6kar7KIHdGohcg2aUcmn6Xp
Xy9d98XlTMj+HdE8reX0ymEIpLbCDnS5WhaUEhNcxGGHktUH/3e9BlrR
-----END PRIVATE KEY-----"#;
        // spellchecker:on

        // An asymmetric algorithm requires a public key.
        let err = JwtAuth::try_from(
            &toml::from_str::<PluginConf>(
                "header = \"Authorization\"\nalgorithm = \"ES256\"\n",
            )
            .unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(true, err.to_string().contains("public_key is required"));

        // A malformed public key is rejected.
        let err = JwtAuth::try_from(
            &toml::from_str::<PluginConf>(
                "header = \"Authorization\"\nalgorithm = \"ES256\"\npublic_key = \"not a pem\"\n",
            )
            .unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(true, err.to_string().contains("invalid public_key"));

        // Valid asymmetric config (no secret needed).
        let cfg = format!(
            "header = \"Authorization\"\nalgorithm = \"ES256\"\npublic_key = \"\"\"\n{public_key}\n\"\"\"\n"
        );
        let auth =
            JwtAuth::new(&toml::from_str::<PluginConf>(&cfg).unwrap()).unwrap();
        assert_eq!(true, auth.decoding_key.is_some());

        let sign = |exp: u64| {
            let claims = serde_json::json!({ "sub": "u1", "exp": exp });
            encode(
                &Header::new(Algorithm::ES256),
                &claims,
                &EncodingKey::from_ec_pem(private_key.as_bytes()).unwrap(),
            )
            .unwrap()
        };
        let run = async |token: String| {
            let input = format!(
                "GET / HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n"
            );
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            auth.handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap()
        };

        // A token signed by the matching private key is accepted.
        let ok = run(sign(pingap_core::now_sec() + 3600)).await;
        assert_eq!(true, ok == RequestPluginResult::Continue);

        // An expired token is rejected.
        let expired = run(sign(pingap_core::now_sec() - 3600)).await;
        assert_eq!(true, matches!(expired, RequestPluginResult::Respond(_)));
    }

    /// Tests remote-JWKS verification with a pre-populated (in-memory) cache,
    /// exercising kid selection and expiry without any network I/O.
    #[tokio::test]
    async fn test_jwt_jwks() {
        use jsonwebtoken::{EncodingKey, Header, encode};

        let public_key = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECE/4ox+pGq+yiB3RqIXINmlHJp+l
6V8vXffF5UzI/h3RPK3l9MphCKS2wg50uVoWlBITXMRhh5LVB/93vQZa0Q==
-----END PUBLIC KEY-----"#;
        // spellchecker:off
        let private_key = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6V2VwZk30Az6VKMF
Bt6nfEa2r4hCQuuMB6azsjMB7xmhRANCAAQIT/ijH6kar7KIHdGohcg2aUcmn6Xp
Xy9d98XlTMj+HdE8reX0ymEIpLbCDnS5WhaUEhNcxGGHktUH/3e9BlrR
-----END PRIVATE KEY-----"#;
        // spellchecker:on

        // A JWKS source with a pre-populated cache (no network): the URL
        // points nowhere, so a refetch fails and the cache stays as it is.
        let new_source = |keys: Vec<JwkEntry>| JwksSource {
            url: "http://127.0.0.1:1/jwks".to_string(),
            ttl: Duration::from_secs(3600),
            cooldown: Duration::from_secs(10),
            client: reqwest::Client::new(),
            cache: ArcSwapOption::new(Some(Arc::new(JwksCache {
                keys,
                fetched_at: Instant::now(),
            }))),
            refresh_lock: tokio::sync::Mutex::new(()),
        };
        let entry = |kid: Option<&str>| JwkEntry {
            kid: kid.map(|k| k.to_string()),
            key: DecodingKey::from_ec_pem(public_key.as_bytes()).unwrap(),
        };
        let source = new_source(vec![entry(Some("kid-1"))]);

        let sign = |kid: Option<&str>, exp: u64| {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = kid.map(|k| k.to_string());
            let claims = serde_json::json!({ "sub": "u1", "exp": exp });
            encode(
                &header,
                &claims,
                &EncodingKey::from_ec_pem(private_key.as_bytes()).unwrap(),
            )
            .unwrap()
        };

        // Matching kid + valid signature + not expired -> accepted.
        let token = sign(Some("kid-1"), pingap_core::now_sec() + 3600);
        assert_eq!(true, source.verify(&token).await);

        // Expired -> rejected.
        let token = sign(Some("kid-1"), pingap_core::now_sec() - 3600);
        assert_eq!(false, source.verify(&token).await);

        // Unknown kid -> rejected (the cache has no such key).
        let token = sign(Some("kid-x"), pingap_core::now_sec() + 3600);
        assert_eq!(false, source.verify(&token).await);

        // A token without a kid is tried against every key.
        let token = sign(None, pingap_core::now_sec() + 3600);
        assert_eq!(true, source.verify(&token).await);

        // A key without a kid, the common single-key JWKS, is kept and
        // used; a token naming a kid still has to find it.
        let source = new_source(vec![entry(None)]);
        let token = sign(None, pingap_core::now_sec() + 3600);
        assert_eq!(true, source.verify(&token).await);
        let token = sign(Some("kid-1"), pingap_core::now_sec() + 3600);
        assert_eq!(false, source.verify(&token).await);
    }

    /// The HMAC path, claim by claim.
    #[test]
    fn test_verify_hmac_token() {
        use jsonwebtoken::{EncodingKey, Header, encode};
        let secret = b"123123";
        let key = EncodingKey::from_secret(secret);
        let now = pingap_core::now_sec();
        let sign = |alg: Algorithm, claims: serde_json::Value| {
            encode(&Header::new(alg), &claims, &key).unwrap()
        };

        assert_eq!(
            Ok(()),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({"exp": now + 60})),
                secret,
                "",
                now
            )
        );
        // A token without `typ` in its header is a valid token.
        let no_typ = {
            let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
            let payload = URL_SAFE_NO_PAD.encode(r#"{"exp":9999999999}"#);
            let content = format!("{header}.{payload}");
            let sig = URL_SAFE_NO_PAD
                .encode(hmac_sha256::HMAC::mac(content.as_bytes(), secret));
            format!("{content}.{sig}")
        };
        assert_eq!(Ok(()), verify_hmac_token(&no_typ, secret, "", now));
        // Float times, as some issuers write them.
        assert_eq!(
            Ok(()),
            verify_hmac_token(
                &sign(
                    Algorithm::HS512,
                    serde_json::json!({"exp": now as f64 + 60.5})
                ),
                secret,
                "HS512",
                now
            )
        );
        assert_eq!(
            Err(HmacRejection::Expired),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({"exp": now - 1})),
                secret,
                "",
                now
            )
        );
        assert_eq!(
            Err(HmacRejection::NotYetValid),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({"nbf": now + 60})),
                secret,
                "",
                now
            )
        );
        assert_eq!(
            Err(HmacRejection::Signature),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({})),
                b"other",
                "",
                now
            )
        );
        // Pinned algorithm, and `none`.
        assert_eq!(
            Err(HmacRejection::Signature),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({})),
                secret,
                "HS512",
                now
            )
        );
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode("{}")
        );
        assert_eq!(
            Err(HmacRejection::Signature),
            verify_hmac_token(&none, secret, "", now)
        );
        for token in ["a.b", "a.b.c.d", ""] {
            assert_eq!(
                Err(HmacRejection::Format),
                verify_hmac_token(token, secret, "", now),
                "{token}"
            );
        }
    }

    #[test]
    fn test_strip_bearer() {
        assert_eq!("abc", strip_bearer("Bearer abc"));
        assert_eq!("abc", strip_bearer("bearer  abc"));
        assert_eq!("abc", strip_bearer("abc"));
        assert_eq!("Basic abc", strip_bearer("Basic abc"));
    }

    /// Tests JWT token validation functionality
    #[tokio::test]
    async fn test_jwt_auth() {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
header = "Authorization"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        // auth success(hs256)
        let headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjIzNDgwNTUyNjV9.j6sYJ2dCCSxskwPmvHM7WniGCbkT30z2BrjfsuQLFJc"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();

        assert_eq!(true, result == RequestPluginResult::Continue);

        // auth success(hs512)
        let headers = ["Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjIzNDgwNTUyNjV9.HxFVxDd5ZiLsD1dWW1AywWMERhqk0Ck9IsdBHyD_1zap3w-waVOmFq0Yt1fWaYmh8HDtXLN6vlTd0HHYIYEGUw"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();

        assert_eq!(true, result == RequestPluginResult::Continue);

        // no auth token
        let headers = [""].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization is missing",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        // auth format invalid
        let headers = ["Authorization: Bearer a.b"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization format is invalid",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        let headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjE3MTcwODQ4MDB9.zz7VHuqt9t6UGLNr5RZdfzvqMDEei"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization is invalid",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        // expired
        let headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjE3MTY5MDMyNjV9.PRS-PZafcGsV_rCL8QQfJdOJAvL5fOI_Z14N16JEcng"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization is expired",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );
    }

    // Both tokens are signed with the secret `123123` and never expire.
    const HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjIzNDgwNTUyNjV9.j6sYJ2dCCSxskwPmvHM7WniGCbkT30z2BrjfsuQLFJc";
    const HS512_TOKEN: &str = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjIzNDgwNTUyNjV9.HxFVxDd5ZiLsD1dWW1AywWMERhqk0Ck9IsdBHyD_1zap3w-waVOmFq0Yt1fWaYmh8HDtXLN6vlTd0HHYIYEGUw";

    async fn verify_with_algorithm(
        algorithm: &str,
        token: &str,
    ) -> RequestPluginResult {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(&format!(
                r###"
secret = "123123"
header = "Authorization"
algorithm = "{algorithm}"
"###
            ))
            .unwrap(),
        )
        .unwrap();

        let input_header =
            format!("GET / HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        auth.handle_request(
            PluginStep::Request,
            &mut session,
            &mut Ctx::default(),
        )
        .await
        .unwrap()
    }

    /// Regression: an explicitly configured algorithm has to be enforced, so a
    /// token cannot pick a weaker one by saying so in its own header.
    #[tokio::test]
    async fn test_jwt_pins_configured_algorithm() {
        assert_eq!(
            true,
            verify_with_algorithm("HS256", HS256_TOKEN).await
                == RequestPluginResult::Continue
        );
        assert_eq!(
            true,
            verify_with_algorithm("HS512", HS512_TOKEN).await
                == RequestPluginResult::Continue
        );

        for (algorithm, token) in
            [("HS512", HS256_TOKEN), ("HS256", HS512_TOKEN)]
        {
            let result = verify_with_algorithm(algorithm, token).await;
            let RequestPluginResult::Respond(resp) = result else {
                panic!(
                    "{algorithm} accepted a token signed with another algorithm"
                );
            };
            assert_eq!(401, resp.status.as_u16());
        }

        // An unset algorithm keeps accepting either, as before.
        assert_eq!(
            true,
            verify_with_algorithm("", HS256_TOKEN).await
                == RequestPluginResult::Continue
        );
        assert_eq!(
            true,
            verify_with_algorithm("", HS512_TOKEN).await
                == RequestPluginResult::Continue
        );
    }

    /// An hmac algorithm the secret path cannot verify is rejected at startup
    /// rather than silently rejecting every request.
    #[test]
    fn test_jwt_unsupported_hmac_algorithm() {
        let err = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
header = "Authorization"
algorithm = "HS384"
"###,
            )
            .unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(
            "Plugin jwt invalid, message: Jwt algorithm(HS384) is not supported, expect HS256 or HS512, or set public_key/jwks_url",
            err.to_string()
        );
    }

    async fn new_auth_path_session() -> Session {
        let mock_io =
            Builder::new().read(b"GET /login HTTP/1.1\r\n\r\n").build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    /// Tests JWT token signing functionality
    #[tokio::test]
    async fn test_jwt_sign() {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
header = "Authorization"
auth_path = "/login"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let mut session = new_auth_path_session().await;
        let mut ctx = Ctx::default();
        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();
        let result = auth
            .handle_response(&mut session, &mut ctx, &mut upstream_response)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
        assert_eq!(
            r#"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"content-type": "application/json; charset=utf-8", "transfer-encoding": "chunked"} }, header_name_map: None, reason_phrase: None }"#,
            format!("{upstream_response:?}")
        );

        let mut body = Some(Bytes::from_static(b"Pingap"));
        let result = auth
            .handle_response_body(&mut session, &mut ctx, &mut body, true)
            .unwrap();
        assert_eq!(ResponseBodyPluginResult::FullyReplaced, result);
        assert_eq!(
            r#"{"token": "eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiAiSldUIn0.UGluZ2Fw.wRLT2HhM1R-J4rVz3XCWADNIrmeInLtRGQzfJZaz-qI"}"#,
            std::string::String::from_utf8_lossy(body.unwrap().as_ref())
        );
    }

    /// An upstream error at `auth_path` must not be signed into a token: the
    /// error body has no `exp`, so the resulting token would never expire.
    #[tokio::test]
    async fn test_jwt_sign_skips_error_response() {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
header = "Authorization"
auth_path = "/login"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let mut session = new_auth_path_session().await;
        let mut ctx = Ctx::default();
        let mut upstream_response =
            ResponseHeader::build_no_case(401, None).unwrap();
        let result = auth
            .handle_response(&mut session, &mut ctx, &mut upstream_response)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);

        let mut body = Some(Bytes::from_static(b"invalid user or password"));
        let result = auth
            .handle_response_body(&mut session, &mut ctx, &mut body, true)
            .unwrap();
        assert_eq!(ResponseBodyPluginResult::Unchanged, result);
        assert_eq!(
            b"invalid user or password".as_ref(),
            body.unwrap().as_ref()
        );
    }
}
