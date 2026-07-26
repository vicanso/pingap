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
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use substring::Substring;
use tokio::time::sleep;
use tracing::debug;
use tracing::error;

const PLUGIN_ID: &str = "_jwt_";

type Result<T, E = Error> = std::result::Result<T, E>;

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

    /// Pre-parsed decoding key + algorithm for asymmetric verification
    /// (RS*/ES*/PS*). `Some` when an asymmetric `algorithm` and `public_key`
    /// are configured; HMAC algorithms leave this `None` and use `secret`.
    decoding_key: Option<(DecodingKey, Algorithm)>,

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
) -> Result<Option<(DecodingKey, Algorithm)>> {
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
    Ok(Some((key, alg)))
}

/// Cached JWKS decoding keys (`kid` -> key) plus the fetch time.
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
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
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            if let Ok(dk) = DecodingKey::from_jwk(jwk) {
                keys.insert(kid, dk);
            }
        }
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

    fn key_for(&self, kid: &str, allow_stale: bool) -> Option<DecodingKey> {
        let cache = self.cache.load_full()?;
        if !allow_stale && cache.fetched_at.elapsed() > self.ttl {
            return None;
        }
        cache.keys.get(kid).cloned()
    }

    async fn verify(&self, token: &str) -> bool {
        let Ok(header) = decode_header(token) else {
            return false;
        };
        let Some(kid) = header.kid else {
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
        // Fresh cache hit: verify without touching the network.
        if let Some(key) = self.key_for(&kid, false)
            && decode::<serde_json::Value>(token, &key, &validation).is_ok()
        {
            return true;
        }
        // Miss / expired / rotated kid: refresh (rate-limited), then retry with
        // whatever we have (including a stale cache if the refetch failed).
        self.refresh().await;
        if let Some(key) = self.key_for(&kid, true) {
            return decode::<serde_json::Value>(token, &key, &validation)
                .is_ok();
        }
        false
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
                category: PluginCategory::KeyAuth.to_string(),
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

/// Header structure for JWT tokens containing algorithm and type information
#[derive(Debug, Default, Deserialize, Clone, Serialize)]
struct JwtHeader {
    alg: String,
    // spellchecker:off
    typ: String,
    // spellchecker:on
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
            let value = pingap_core::get_req_header_value(req_header, key)
                .unwrap_or_default();
            let bearer = "Bearer ";
            if value.starts_with(bearer) {
                value.substring(bearer.len(), value.len())
            } else {
                value
            }
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
        if let Some((key, alg)) = &self.decoding_key {
            let mut validation = Validation::new(*alg);
            validation.validate_aud = false;
            if decode::<serde_json::Value>(value, key, &validation).is_ok() {
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
        let arr: Vec<&str> = value.split('.').collect();
        if arr.len() != 3 {
            let mut resp = self.unauthorized_resp.clone();
            resp.body =
                Bytes::from_static(b"Jwt authorization format is invalid");
            return Ok(RequestPluginResult::Respond(resp));
        }
        let jwt_header = serde_json::from_slice::<JwtHeader>(
            &URL_SAFE_NO_PAD.decode(arr[0]).unwrap_or_default(),
        )
        .unwrap_or_default();
        let content = format!("{}.{}", arr[0], arr[1]);
        let secret = self.secret.as_bytes();
        let valid = match jwt_header.alg.as_str() {
            // An explicitly configured algorithm is pinned: a token must not
            // downgrade HS512 to HS256 just by saying so in its own header.
            // An unset `algorithm` keeps accepting either, since that is what
            // existing configurations rely on.
            alg if !self.algorithm.is_empty() && alg != self.algorithm => false,
            "HS256" => {
                let hash = hmac_sha256::HMAC::mac(content.as_bytes(), secret);
                pingap_core::constant_time_eq(
                    URL_SAFE_NO_PAD.encode(hash).as_bytes(),
                    arr[2].as_bytes(),
                )
            },
            "HS512" => {
                let hash = hmac_sha512::HMAC::mac(content.as_bytes(), secret);
                pingap_core::constant_time_eq(
                    URL_SAFE_NO_PAD.encode(hash).as_bytes(),
                    arr[2].as_bytes(),
                )
            },
            // Unknown / unsupported algorithms (including "none") are rejected
            // rather than silently falling back to HS256.
            _ => false,
        };
        if !valid {
            if let Some(d) = self.delay {
                sleep(d).await;
            }
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is invalid");
            return Ok(RequestPluginResult::Respond(resp));
        }
        let value: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(arr[1]).unwrap_or_default(),
        )
        .unwrap_or_default();
        if let Some(exp) = value.get("exp")
            && exp.as_u64().unwrap_or_default() < pingap_core::now_sec()
        {
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is expired");
            return Ok(RequestPluginResult::Respond(resp));
        }

        Ok(RequestPluginResult::Continue)
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
    fn name(&self) -> String {
        "jwt_sign".to_string()
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

        // A JWKS source with a pre-populated cache keyed by kid (no network).
        let mut keys = HashMap::new();
        keys.insert(
            "kid-1".to_string(),
            DecodingKey::from_ec_pem(public_key.as_bytes()).unwrap(),
        );
        let source = JwksSource {
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

        // Unknown kid -> rejected (fresh cache has no such key).
        let token = sign(Some("kid-x"), pingap_core::now_sec() + 3600);
        assert_eq!(false, source.verify(&token).await);

        // No kid at all -> rejected.
        let token = sign(None, pingap_core::now_sec() + 3600);
        assert_eq!(false, source.verify(&token).await);
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
