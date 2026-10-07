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
    Error, get_bool_conf, get_duration_conf, get_hash_key, get_str_conf,
    get_str_slice_conf,
};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Bytes, BytesMut};
use http::{HeaderName, HeaderValue, StatusCode};
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
    protect_from_connection_header,
};
use pingora::http::{RequestHeader, ResponseHeader};
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

/// Every claim of a token, for the rules that are about more than its
/// times.
type ClaimMap = serde_json::Map<String, serde_json::Value>;

/// What the claims of a token are held to once its signature and its times
/// have checked out, and what is passed on of them to the upstream.
///
/// A token used to be good for any location it was shown at as long as the
/// key was the right one: one issued for another service of the same
/// issuer, or by another tenant of the same identity provider, was let in.
/// And the upstream was told nothing of who it was for, and had to verify
/// the token a second time to find out.
#[derive(Default)]
struct ClaimRules {
    /// `iss` has to be one of these.
    issuers: Vec<String>,
    /// `aud`, or one entry of it, has to be one of these.
    audiences: Vec<String>,
    /// Claims a token has to have, whatever they say.
    required: Vec<String>,
    /// Claims to send to the upstream, and the header each goes in.
    to_headers: Vec<(String, HeaderName)>,
    /// The names of those headers. They are the proxy's: see
    /// `protect_from_connection_header`.
    own_headers: Vec<HeaderName>,
}

/// Why the claims of a token with a good signature were not enough.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaimRejection {
    Issuer,
    Audience,
    Missing(String),
}

impl ClaimRejection {
    fn message(&self) -> Bytes {
        match self {
            Self::Issuer => {
                Bytes::from_static(b"Jwt authorization issuer is not allowed")
            },
            Self::Audience => {
                Bytes::from_static(b"Jwt authorization audience is not allowed")
            },
            Self::Missing(name) => {
                Bytes::from(format!("Jwt authorization has no {name}"))
            },
        }
    }
}

/// A claim as the value of a header: text as it is, a number or a boolean
/// as it is written, a list of those joined by commas. `None` for what has
/// no such form - an object, a list of objects - and for text a header
/// cannot carry, a line break in it above all.
fn claim_header_value(value: &serde_json::Value) -> Option<HeaderValue> {
    use serde_json::Value;
    let scalar = |value: &Value| match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    };
    let text = match value {
        Value::Array(items) => items
            .iter()
            .map(scalar)
            .collect::<Option<Vec<_>>>()?
            .join(","),
        other => scalar(other)?,
    };
    HeaderValue::from_bytes(text.as_bytes()).ok()
}

impl ClaimRules {
    /// Whether there is anything to look at the claims for.
    fn is_empty(&self) -> bool {
        self.issuers.is_empty()
            && self.audiences.is_empty()
            && self.required.is_empty()
            && self.to_headers.is_empty()
    }

    fn check(
        &self,
        claims: &ClaimMap,
    ) -> std::result::Result<(), ClaimRejection> {
        use serde_json::Value;
        if !self.issuers.is_empty() {
            let allowed = claims
                .get("iss")
                .and_then(Value::as_str)
                .is_some_and(|iss| self.issuers.iter().any(|item| item == iss));
            if !allowed {
                return Err(ClaimRejection::Issuer);
            }
        }
        if !self.audiences.is_empty() {
            let is_allowed =
                |aud: &str| self.audiences.iter().any(|item| item == aud);
            // One audience, or a list of them of which one is enough.
            let allowed = match claims.get("aud") {
                Some(Value::String(aud)) => is_allowed(aud),
                Some(Value::Array(list)) => {
                    list.iter().filter_map(Value::as_str).any(is_allowed)
                },
                _ => false,
            };
            if !allowed {
                return Err(ClaimRejection::Audience);
            }
        }
        for name in &self.required {
            if matches!(claims.get(name), None | Some(Value::Null)) {
                return Err(ClaimRejection::Missing(name.clone()));
            }
        }
        Ok(())
    }

    /// Takes out of the request what the client sent under the names the
    /// claims go to.
    ///
    /// And under what an upstream may read as one of them. `X_User_Id` is
    /// another header than `X-User-Id` to a proxy, and the same variable
    /// (`HTTP_X_USER_ID`) to whatever sits behind CGI, WSGI, Rack or PHP:
    /// with only the one removed, the other reached such an upstream next
    /// to, or in place of, what the token says. nginx drops every header
    /// with an underscore for this reason; here it is the ones that would
    /// pass for a claim.
    fn strip(&self, header: &mut RequestHeader) {
        if self.own_headers.is_empty() {
            return;
        }
        let folded = |name: &str| {
            name.bytes()
                .map(|byte| if byte == b'_' { b'-' } else { byte })
                .collect::<Vec<u8>>()
        };
        let own: Vec<Vec<u8>> = self
            .own_headers
            .iter()
            .map(|name| folded(name.as_str()))
            .collect();
        let sent: Vec<HeaderName> = header
            .headers
            .keys()
            .filter(|name| own.contains(&folded(name.as_str())))
            .cloned()
            .collect();
        for name in sent {
            header.remove_header(&name);
        }
    }

    /// Puts the claims on the request, each under its header. What the
    /// client sent under one of these names is removed first, whether or
    /// not the token has the claim: the header says what the token says,
    /// and nothing when the token says nothing.
    fn apply(&self, claims: &ClaimMap, header: &mut RequestHeader) {
        if self.to_headers.is_empty() {
            return;
        }
        self.strip(header);
        for (claim, name) in &self.to_headers {
            if let Some(value) = claims.get(claim).and_then(claim_header_value)
            {
                let _ = header.insert_header(name, value);
            }
        }
        protect_from_connection_header(header, &self.own_headers);
    }
}

/// The claims of a token whose signature has been checked.
fn decode_claims(token: &str) -> Option<ClaimMap> {
    let payload = token.split('.').nth(1)?;
    let raw = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Why an HMAC token was refused; the body of the 401 says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HmacRejection {
    Format,
    Signature,
    Expired,
    NotYetValid,
    NoExpiry,
}

impl HmacRejection {
    fn message(self) -> Bytes {
        Bytes::from_static(match self {
            Self::Format => b"Jwt authorization format is invalid",
            Self::Signature => b"Jwt authorization is invalid",
            Self::Expired => b"Jwt authorization is expired",
            Self::NotYetValid => b"Jwt authorization is not yet valid",
            Self::NoExpiry => b"Jwt authorization has no exp",
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

/// Whether `payload`, the JSON a token is about to be made of, names an
/// expiry that the verifying side can read.
fn has_exp(payload: &[u8]) -> bool {
    parse_claims(payload).is_some_and(|claims| claims.exp.is_some())
}

/// The claims of a payload, which has to be a JSON object. The check is
/// made here: the derived deserializer also takes an array for the struct,
/// its fields in order, and `[9999999999]` is nobody's claims.
fn parse_claims(payload: &[u8]) -> Option<Claims> {
    let is_object = payload
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'{');
    if !is_object {
        return None;
    }
    serde_json::from_slice(payload).ok()
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
/// set), then `exp` and `nbf` against `now`. With `require_exp` a token
/// that names no expiry is refused: it would be valid for as long as the
/// secret is, which is what the public key paths never allowed.
///
/// `leeway` is how many seconds the two clocks may differ by, see
/// `JwtAuth::leeway`: a token is expired once `exp` is more than that
/// behind `now`, and not yet valid while `nbf` is more than that ahead.
///
/// The signed part is a prefix of the token itself and the signature is
/// compared as encoded bytes, so nothing here copies the token; the payload
/// is read into the two claims rather than a full JSON tree.
fn verify_hmac_token(
    token: &str,
    secret: &[u8],
    pinned_alg: &str,
    now: u64,
    require_exp: bool,
    leeway: u64,
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
        "HS384" => {
            let hash = hmac_sha512::sha384::HMAC::mac(content, secret);
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
    let claims = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|raw| parse_claims(&raw))
        .ok_or(HmacRejection::Format)?;
    // The comparisons jsonwebtoken makes on the public key paths.
    let (now, leeway) = (now as f64, leeway as f64);
    match claims.exp {
        Some(exp) if exp < now - leeway => {
            return Err(HmacRejection::Expired);
        },
        None if require_exp => return Err(HmacRejection::NoExpiry),
        _ => {},
    }
    if claims.nbf.is_some_and(|nbf| nbf > now + leeway) {
        return Err(HmacRejection::NotYetValid);
    }
    Ok(())
}

/// What `exp` and `nbf` are given when `leeway` is not set.
const DEFAULT_LEEWAY: Duration = Duration::from_secs(60);

/// The most `leeway` may be set to. It is there for two clocks that are
/// not quite the same, and a day is far more than that; without a bound a
/// value of decades made the paths disagree, the library taking it off the
/// time in whole seconds and running out of them.
const MAX_LEEWAY: Duration = Duration::from_secs(24 * 3600);

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
    /// The name this instance keeps its body handler under, see
    /// `new_body_handler_id`.
    handler_id: String,
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

    /// Whether a token has to carry `exp`, on every verification path, and
    /// whether the response at `auth_path` has to before it is signed.
    /// On unless `require_exp = false`.
    require_exp: bool,

    /// How far the clock of whoever issued a token may be from this one's:
    /// `exp` and `nbf` are given this much, on every verification path.
    /// The public key paths always had the library's 60 seconds while the
    /// secret path had none, so an issuer a second ahead had its tokens
    /// refused as not yet valid by one configuration and not by another.
    leeway: Duration,

    /// What the claims are held to and which of them go to the upstream.
    claim_rules: ClaimRules,

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
    require_exp: bool,
    leeway: Duration,
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
            | Algorithm::EdDSA
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
        Algorithm::EdDSA => DecodingKey::from_ed_pem(public_key.as_bytes()),
        _ => DecodingKey::from_rsa_pem(public_key.as_bytes()),
    }
    .map_err(|e| Error::Invalid {
        category: PluginCategory::Jwt.to_string(),
        message: format!("invalid public_key: {e}"),
    })?;
    Ok(Some((key, jwks_validation(alg, require_exp, leeway))))
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

    /// `Some` for a token one of the keys verifies, with its claims when
    /// they are asked for.
    fn verify(
        &self,
        token: &str,
        kid: Option<&str>,
        validation: &Validation,
        with_claims: bool,
    ) -> Option<Option<ClaimMap>> {
        self.candidates(kid).find_map(|key| {
            verify_with_key(token, key, validation, with_claims)
        })
    }
}

/// Verifies `token` under `key`: `None` when it does not check out,
/// otherwise its claims when they are asked for. They are only put into a
/// map for a plugin that has rules about them.
fn verify_with_key(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
    with_claims: bool,
) -> Option<Option<ClaimMap>> {
    if with_claims {
        decode::<ClaimMap>(token, key, validation)
            .ok()
            .map(|data| Some(data.claims))
    } else {
        decode::<NoClaims>(token, key, validation)
            .ok()
            .map(|_| None)
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
    /// See `JwtAuth::require_exp`.
    require_exp: bool,
    /// See `JwtAuth::leeway`.
    leeway: Duration,
    cache: ArcSwapOption<JwksCache>,
    /// Serializes refetches, and holds when the last one was started.
    refresh_lock: tokio::sync::Mutex<Option<Instant>>,
}

impl JwksSource {
    async fn fetch(&self) -> std::result::Result<JwksCache, String> {
        let resp = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        let set = resp
            .json::<JwkSet>()
            .await
            .map_err(|e| e.without_url().to_string())?;
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
        let mut last_attempt = self.refresh_lock.lock().await;
        // Re-check after acquiring the lock: a peer may have just refreshed, or
        // we may still be inside the cooldown window (bounds unknown-kid churn).
        //
        // The window starts at the last attempt, whether it worked or not.
        // It used to start at the last success: while the endpoint was down
        // nothing ever opened it, and every request waited its turn at the
        // lock to spend the client's whole timeout on a fetch of its own.
        if last_attempt.is_some_and(|at| at.elapsed() < self.cooldown) {
            return;
        }
        *last_attempt = Some(Instant::now());
        match self.fetch().await {
            Ok(cache) => self.cache.store(Some(Arc::new(cache))),
            Err(e) => {
                error!(category = "jwt", error = e, "fetch jwks failed");
            },
        }
    }

    #[cfg(test)]
    async fn verify(&self, token: &str) -> bool {
        self.verify_claims(token, false).await.is_some()
    }

    /// `Some` for a token that checks out, with its claims when they are
    /// asked for.
    async fn verify_claims(
        &self,
        token: &str,
        with_claims: bool,
    ) -> Option<Option<ClaimMap>> {
        let header = decode_header(token).ok()?;
        // Only asymmetric algorithms are accepted, so a token cannot be signed
        // with symmetric HMAC using the public key as the secret (algorithm
        // confusion). `decode` also rejects an alg that mismatches the JWK's
        // key type.
        if !is_asymmetric_alg(header.alg) {
            return None;
        }
        let validation =
            jwks_validation(header.alg, self.require_exp, self.leeway);
        let kid = header.kid.as_deref();
        // Fresh cache hit: verify without touching the network.
        if let Some(cache) = self.cache.load_full()
            && cache.fetched_at.elapsed() <= self.ttl
            && let Some(claims) =
                cache.verify(token, kid, &validation, with_claims)
        {
            return Some(claims);
        }
        // Miss / expired / rotated kid: refresh (rate-limited), then retry with
        // whatever we have (including a stale cache if the refetch failed).
        self.refresh().await;
        self.cache.load_full().and_then(|cache| {
            cache.verify(token, kid, &validation, with_claims)
        })
    }
}

/// Validation pinned to the JWK's declared algorithm, enforcing signature,
/// `exp` and `nbf` while ignoring `aud`. Without `require_exp` a token may
/// leave `exp` out; one that has it is still held to it. `leeway` is what
/// the two claims are given, see `JwtAuth::leeway`.
fn jwks_validation(
    alg: Algorithm,
    require_exp: bool,
    leeway: Duration,
) -> Validation {
    let mut validation = Validation::new(alg);
    validation.validate_aud = false;
    validation.leeway = leeway.as_secs();
    if !require_exp {
        validation.required_spec_claims.clear();
    }
    // Off by default in the library, so a token that was not valid yet
    // passed here while the HMAC path refused it.
    validation.validate_nbf = true;
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
fn build_jwks_source(
    value: &PluginConf,
    require_exp: bool,
    leeway: Duration,
) -> Result<Option<Arc<JwksSource>>> {
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
        require_exp,
        leeway,
        cache: ArcSwapOption::empty(),
        refresh_lock: tokio::sync::Mutex::new(None),
    })))
}

/// The settings that are about the claims of a token: `issuers`,
/// `audiences`, `required_claims` and `claims_to_headers`.
fn parse_claim_rules(value: &PluginConf) -> Result<ClaimRules> {
    let invalid = |message: String| Error::Invalid {
        category: PluginCategory::Jwt.to_string(),
        message,
    };
    // An entry that is empty would be a rule that nothing can meet, or
    // that everything does: it is a slip of the configuration either way.
    let names = |key: &str| -> Result<Vec<String>> {
        get_str_slice_conf(value, key)
            .into_iter()
            .map(|item| {
                let item = item.trim().to_string();
                if item.is_empty() {
                    return Err(invalid(format!("{key}: an entry is empty")));
                }
                Ok(item)
            })
            .collect()
    };
    let to_headers = get_str_slice_conf(value, "claims_to_headers")
        .iter()
        .map(|item| {
            // At the last colon: a header name has none, and the name of
            // a claim may - the namespaced ones are urls
            // (`https://example.com/roles`).
            let (claim, header) = item
                .rsplit_once(':')
                .map(|(claim, header)| (claim.trim(), header.trim()))
                .filter(|(claim, _)| !claim.is_empty())
                .ok_or_else(|| {
                    invalid(format!(
                        "claims_to_headers: {item:?} should be claim:Header-Name"
                    ))
                })?;
            let name =
                HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                    invalid(format!(
                        "claims_to_headers: {header:?} is not a header name"
                    ))
                })?;
            // What frames the body or names the upstream is not a place
            // for something a token says.
            if [
                http::header::CONTENT_LENGTH,
                http::header::TRANSFER_ENCODING,
                http::header::HOST,
                http::header::CONNECTION,
            ]
            .contains(&name)
            {
                return Err(invalid(format!(
                    "claims_to_headers: {name} is not a header for a claim"
                )));
            }
            Ok((claim.to_string(), name))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ClaimRules {
        issuers: names("issuers")?,
        audiences: names("audiences")?,
        required: names("required_claims")?,
        own_headers: to_headers.iter().map(|(_, name)| name.clone()).collect(),
        to_headers,
    })
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
        // On by default. A token without `exp` never stops being valid, and
        // the secret path used to take one while the public key paths
        // refused it.
        let require_exp = !value.contains_key("require_exp")
            || get_bool_conf(value, "require_exp");
        // Sixty seconds unless said otherwise, which is what the public
        // key paths have always had.
        let leeway = get_str_conf(value, "leeway");
        let leeway = if leeway.is_empty() {
            DEFAULT_LEEWAY
        } else {
            parse_duration(&leeway).map_err(|e| Error::Invalid {
                category: PluginCategory::Jwt.to_string(),
                message: format!("invalid leeway: {e}"),
            })?
        };
        if leeway > MAX_LEEWAY {
            return Err(Error::Invalid {
                category: PluginCategory::Jwt.to_string(),
                message: "invalid leeway: it is at most 1d".to_string(),
            });
        }
        let claim_rules = parse_claim_rules(value)?;
        let decoding_key = build_asymmetric_key(
            &algorithm,
            &get_str_conf(value, "public_key"),
            require_exp,
            leeway,
        )?;
        let jwks = build_jwks_source(value, require_exp, leeway)?;

        let params = Self {
            hash_value,
            handler_id: crate::new_body_handler_id(PLUGIN_ID),
            plugin_step: PluginStep::Request,
            secret: get_str_conf(value, "secret"),
            auth_path: get_str_conf(value, "auth_path"),
            algorithm,
            require_exp,
            leeway,
            claim_rules,
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
            // HS256, HS384 and HS512 are what the secret path does. Anything
            // else (an asymmetric algorithm without a key, a name that is
            // not an algorithm) would otherwise be accepted here and then
            // reject every single token.
            if !matches!(
                params.algorithm.as_str(),
                "" | "HS256" | "HS384" | "HS512"
            ) {
                return Err(Error::Invalid {
                    category: PluginCategory::Jwt.to_string(),
                    message: format!(
                        "Jwt algorithm({}) is not supported, expect HS256, HS384 or HS512, or set public_key/jwks_url",
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
        debug!(
            params = pingap_config::masked_toml(params),
            "new jwt auth plugin"
        );
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
        if session.req_header().uri.path() == self.auth_path {
            // The upstream's answer to this request becomes the payload of
            // the token, byte for byte, so it is asked for without a
            // content coding. With the client's `Accept-Encoding` passed
            // on, an upstream that compresses had its gzip stream signed.
            session
                .req_header_mut()
                .remove_header(&http::header::ACCEPT_ENCODING);
            // No token is asked for here, so there is no claim to pass
            // on: the headers that carry them are the client's own, and
            // do not go to an upstream that takes them for the proxy's.
            self.claim_rules.strip(session.req_header_mut());
            return Ok(RequestPluginResult::Skipped);
        }
        let req_header = session.req_header();
        let query_value;
        let value = if let Some(key) = &self.header {
            strip_bearer(
                pingap_core::get_req_header_value(req_header, key)
                    .unwrap_or_default(),
            )
        } else if let Some(key) = &self.cookie {
            pingap_core::get_cookie_value(req_header, key).unwrap_or_default()
        } else if let Some(key) = &self.query {
            query_value = super::decode_query_value(
                pingap_core::get_query_value(req_header, key)
                    .unwrap_or_default(),
            );
            query_value.as_ref()
        } else {
            ""
        };
        if value.is_empty() {
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is missing");
            return Ok(RequestPluginResult::Respond(resp));
        }
        // The claims are only read out for a plugin that has rules about
        // them.
        let with_claims = !self.claim_rules.is_empty();
        const INVALID: &[u8] = b"Jwt authorization is invalid";
        // What the token turned out to be: its claims, where they are
        // wanted, or what to answer and whether to wait before answering.
        let verified = if let Some((key, validation)) = &self.decoding_key {
            // Asymmetric verification: the configured algorithm is pinned
            // (the token's own `alg` header is not trusted, preventing
            // algorithm confusion), and jsonwebtoken checks the signature
            // and `exp` together.
            verify_with_key(value, key, validation, with_claims)
                .ok_or((Bytes::from_static(INVALID), true))
        } else if let Some(jwks) = &self.jwks {
            // Remote JWKS verification: the key is selected by the token's
            // `kid` and pinned to that JWK's algorithm.
            jwks.verify_claims(value, with_claims)
                .await
                .ok_or((Bytes::from_static(INVALID), true))
        } else {
            match verify_hmac_token(
                value,
                self.secret.as_bytes(),
                &self.algorithm,
                pingap_core::now_sec(),
                self.require_exp,
                self.leeway.as_secs(),
            ) {
                Ok(()) if with_claims => decode_claims(value)
                    .map(Some)
                    .ok_or((HmacRejection::Format.message(), false)),
                Ok(()) => Ok(None),
                // Only a bad signature is worth slowing down: it is the
                // one outcome a guess can produce.
                Err(rejection) => Err((
                    rejection.message(),
                    rejection == HmacRejection::Signature,
                )),
            }
        };
        let refuse = |body: Bytes| {
            let mut resp = self.unauthorized_resp.clone();
            resp.body = body;
            Ok(RequestPluginResult::Respond(resp))
        };
        let claims = match verified {
            Ok(claims) => claims,
            Err((body, slow)) => {
                if slow && let Some(d) = self.delay {
                    sleep(d).await;
                }
                return refuse(body);
            },
        };
        if let Some(claims) = &claims {
            // A token that is good, and not for here.
            if let Err(rejection) = self.claim_rules.check(claims) {
                return refuse(rejection.message());
            }
            self.claim_rules.apply(claims, session.req_header_mut());
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
        // turned into a token: an error body is nobody's claims.
        if !upstream_response.status.is_success() {
            return Ok(ResponsePluginResult::Unchanged);
        }
        // Asked for without a coding, see `handle_request`. An upstream
        // that sends one all the same has nothing here that can be signed:
        // better no token than one whose payload is a gzip stream.
        let coded = upstream_response
            .headers
            .get(http::header::CONTENT_ENCODING)
            .is_some_and(|value| {
                !value.as_bytes().eq_ignore_ascii_case(b"identity")
            });
        if coded {
            return Err(pingap_core::new_internal_error(
                502,
                "jwt: the response to sign has a content encoding",
            ));
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
            &self.handler_id,
            Box::new(Sign {
                algorithm: self.algorithm.clone(),
                secret: self.secret.clone(),
                require_exp: self.require_exp,
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
        if let Some(modifier) = ctx.get_modify_body_handler(&self.handler_id) {
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
    require_exp: bool,
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
        // Signed as it is, so what the upstream leaves out is left out of
        // the token: without `exp` it would be valid for good, and the
        // request path would refuse it anyway. Better no token.
        if self.require_exp && !has_exp(&self.buffer) {
            return Err(pingap_core::new_internal_error(
                502,
                "jwt: the response to sign has no exp",
            ));
        }
        let alg = match self.algorithm.as_str() {
            "HS384" => "HS384",
            "HS512" => "HS512",
            _ => "HS256",
        };
        // spellchecker:off
        let header = URL_SAFE_NO_PAD
            .encode(r#"{"alg": ""#.to_owned() + alg + r#"","typ": "JWT"}"#);
        // spellchecker:on
        let payload = URL_SAFE_NO_PAD.encode(&self.buffer);
        let content = format!("{header}.{payload}");
        let secret = self.secret.as_bytes();
        let sign = match alg {
            "HS384" => URL_SAFE_NO_PAD.encode(hmac_sha512::sha384::HMAC::mac(
                content.as_bytes(),
                secret,
            )),
            "HS512" => URL_SAFE_NO_PAD
                .encode(hmac_sha512::HMAC::mac(content.as_bytes(), secret)),
            _ => URL_SAFE_NO_PAD
                .encode(hmac_sha256::HMAC::mac(content.as_bytes(), secret)),
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

        // One that expired half a minute ago is within the leeway, here as
        // on the secret path, and outside it once the leeway is taken away.
        let just_expired = sign(pingap_core::now_sec() - 30);
        let ok = run(just_expired.clone()).await;
        assert_eq!(true, ok == RequestPluginResult::Continue);
        let strict = JwtAuth::new(
            &toml::from_str::<PluginConf>(&format!("{cfg}leeway = \"0s\"\n"))
                .unwrap(),
        )
        .unwrap();
        let input = format!(
            "GET / HTTP/1.1\r\nAuthorization: Bearer {just_expired}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let refused = strict
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, matches!(refused, RequestPluginResult::Respond(_)));
    }

    /// Regression: `exp` and `nbf` were given sixty seconds on the public
    /// key paths and none on the secret path, so an issuer whose clock was
    /// a second ahead had its tokens refused as not yet valid by one
    /// configuration and taken by another.
    #[test]
    fn test_leeway_is_the_same_on_every_path() {
        use jsonwebtoken::{EncodingKey, Header, encode};
        use serde_json::json;
        let secret = b"123123";
        let key = EncodingKey::from_secret(secret);
        let now = pingap_core::now_sec();
        let check = |claims: serde_json::Value, leeway: u64| {
            let token =
                encode(&Header::new(Algorithm::HS256), &claims, &key).unwrap();
            verify_hmac_token(&token, secret, "", now, true, leeway)
        };
        // An issuer two seconds ahead.
        let ahead = json!({"exp": now + 3600, "nbf": now + 2});
        assert_eq!(Err(HmacRejection::NotYetValid), check(ahead.clone(), 0));
        assert_eq!(Ok(()), check(ahead, 60));
        // What the leeway covers, to the second, and what it does not.
        assert_eq!(
            Ok(()),
            check(json!({"exp": now + 3600, "nbf": now + 60}), 60)
        );
        assert_eq!(
            Err(HmacRejection::NotYetValid),
            check(json!({"exp": now + 3600, "nbf": now + 61}), 60)
        );
        assert_eq!(Ok(()), check(json!({"exp": now - 60}), 60));
        assert_eq!(
            Err(HmacRejection::Expired),
            check(json!({"exp": now - 61}), 60)
        );
        assert_eq!(
            Err(HmacRejection::Expired),
            check(json!({"exp": now - 1}), 0)
        );

        // Sixty seconds unless said otherwise, for the public key paths
        // as for the secret one.
        let new = |extra: &str| {
            JwtAuth::try_from(
                &toml::from_str::<PluginConf>(&format!(
                    "secret = \"123123\"\ncookie = \"jwt\"\n{extra}"
                ))
                .unwrap(),
            )
        };
        assert_eq!(Duration::from_secs(60), new("").unwrap().leeway);
        assert_eq!(Duration::ZERO, new("leeway = \"0s\"").unwrap().leeway);
        assert_eq!(
            Duration::from_secs(5),
            new("leeway = \"5s\"").unwrap().leeway
        );
        let invalid = new("leeway = \"soon\"").err().unwrap().to_string();
        assert_eq!(true, invalid.contains("invalid leeway"), "{invalid}");
        // A day at most: decades of it took the public key paths, which
        // count in whole seconds, past the beginning of time.
        assert_eq!(
            Duration::from_secs(24 * 3600),
            new("leeway = \"1d\"").unwrap().leeway
        );
        assert_eq!(
            "Plugin jwt invalid, message: invalid leeway: it is at most 1d",
            new("leeway = \"60y\"").err().unwrap().to_string()
        );
        assert_eq!(
            5,
            jwks_validation(Algorithm::RS256, true, Duration::from_secs(5))
                .leeway
        );
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
            require_exp: true,
            leeway: Duration::ZERO,
            cache: ArcSwapOption::new(Some(Arc::new(JwksCache {
                keys,
                fetched_at: Instant::now(),
            }))),
            refresh_lock: tokio::sync::Mutex::new(None),
        };
        let entry = |kid: Option<&str>| JwkEntry {
            kid: kid.map(|k| k.to_string()),
            key: DecodingKey::from_ec_pem(public_key.as_bytes()).unwrap(),
        };
        let source = new_source(vec![entry(Some("kid-1"))]);

        let sign_claims = |kid: Option<&str>, claims: serde_json::Value| {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = kid.map(|k| k.to_string());
            encode(
                &header,
                &claims,
                &EncodingKey::from_ec_pem(private_key.as_bytes()).unwrap(),
            )
            .unwrap()
        };
        let sign = |kid: Option<&str>, exp: u64| {
            sign_claims(kid, serde_json::json!({ "sub": "u1", "exp": exp }))
        };

        // Regression: `nbf` was not looked at on this path. A token that
        // is not valid yet is rejected, one whose time has come is not.
        let now = pingap_core::now_sec();
        let not_yet = sign_claims(
            Some("kid-1"),
            serde_json::json!({ "exp": now + 7200, "nbf": now + 3600 }),
        );
        assert_eq!(false, source.verify(&not_yet).await);
        let started = sign_claims(
            Some("kid-1"),
            serde_json::json!({ "exp": now + 7200, "nbf": now - 3600 }),
        );
        assert_eq!(true, source.verify(&started).await);

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

        // No `exp`: refused, unless the plugin was told not to ask for one,
        // and then a token that has one is still held to it.
        let no_exp =
            sign_claims(Some("kid-1"), serde_json::json!({ "sub": "u1" }));
        assert_eq!(false, source.verify(&no_exp).await);
        let lenient = JwksSource {
            require_exp: false,
            ..new_source(vec![entry(Some("kid-1"))])
        };
        assert_eq!(true, lenient.verify(&no_exp).await);
        let token = sign(Some("kid-1"), pingap_core::now_sec() - 3600);
        assert_eq!(false, lenient.verify(&token).await);

        // `leeway` here as on the other two paths: a token that expired
        // half a minute ago is taken with a minute of it, not with none.
        let just_expired = sign(Some("kid-1"), pingap_core::now_sec() - 30);
        assert_eq!(false, source.verify(&just_expired).await);
        let with_leeway = JwksSource {
            leeway: Duration::from_secs(60),
            ..new_source(vec![entry(Some("kid-1"))])
        };
        assert_eq!(true, with_leeway.verify(&just_expired).await);
        let not_yet = sign_claims(
            Some("kid-1"),
            serde_json::json!({ "exp": now + 7200, "nbf": now + 30 }),
        );
        assert_eq!(false, source.verify(&not_yet).await);
        assert_eq!(true, with_leeway.verify(&not_yet).await);

        // A key without a kid, the common single-key JWKS, is kept and
        // used; a token naming a kid still has to find it.
        let source = new_source(vec![entry(None)]);
        let token = sign(None, pingap_core::now_sec() + 3600);
        assert_eq!(true, source.verify(&token).await);
        let token = sign(Some("kid-1"), pingap_core::now_sec() + 3600);
        assert_eq!(false, source.verify(&token).await);
    }

    /// The HMAC path, claim by claim.
    /// Regression: after a refetch that failed the next request tried
    /// again at once, and so did every request after it, one at a time,
    /// each for as long as the endpoint took to fail.
    #[tokio::test]
    async fn test_jwks_refetch_cools_down_after_a_failure() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // An endpoint that takes the connection and closes it.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::Relaxed);
                drop(stream);
            }
        });

        let source = JwksSource {
            url: format!("http://{addr}/jwks"),
            ttl: Duration::from_secs(3600),
            cooldown: Duration::from_millis(300),
            client: reqwest::Client::new(),
            require_exp: true,
            leeway: Duration::ZERO,
            cache: ArcSwapOption::empty(),
            refresh_lock: tokio::sync::Mutex::new(None),
        };
        for _ in 0..5 {
            source.refresh().await;
        }
        assert_eq!(1, attempts.load(Ordering::Relaxed));
        assert_eq!(true, source.cache.load().is_none());

        // Once the window has passed the endpoint is asked again.
        tokio::time::sleep(Duration::from_millis(350)).await;
        source.refresh().await;
        assert_eq!(2, attempts.load(Ordering::Relaxed));
    }

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
                now,
                true,
                0
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
        assert_eq!(
            Ok(()),
            verify_hmac_token(&no_typ, secret, "", now, true, 0)
        );
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
                now,
                true,
                0
            )
        );
        assert_eq!(
            Err(HmacRejection::Expired),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({"exp": now - 1})),
                secret,
                "",
                now,
                true,
                0
            )
        );
        assert_eq!(
            Err(HmacRejection::NotYetValid),
            verify_hmac_token(
                &sign(
                    Algorithm::HS256,
                    serde_json::json!({"exp": now + 3600, "nbf": now + 60})
                ),
                secret,
                "",
                now,
                true,
                0
            )
        );
        assert_eq!(
            Err(HmacRejection::Signature),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({})),
                b"other",
                "",
                now,
                true,
                0
            )
        );
        // Pinned algorithm, and `none`.
        assert_eq!(
            Err(HmacRejection::Signature),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({})),
                secret,
                "HS512",
                now,
                true,
                0
            )
        );
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode("{}")
        );
        assert_eq!(
            Err(HmacRejection::Signature),
            verify_hmac_token(&none, secret, "", now, true, 0)
        );
        // Regression: a token that names no expiry was taken, and stayed
        // valid for as long as the secret did.
        let no_exp = sign(Algorithm::HS256, serde_json::json!({"sub": "u1"}));
        assert_eq!(
            Err(HmacRejection::NoExpiry),
            verify_hmac_token(&no_exp, secret, "", now, true, 0)
        );
        assert_eq!(
            Err(HmacRejection::NoExpiry),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({"exp": null})),
                secret,
                "",
                now,
                true,
                0
            )
        );
        // `require_exp = false` is the old behaviour, and a token that has
        // an expiry is still held to it.
        assert_eq!(
            Ok(()),
            verify_hmac_token(&no_exp, secret, "", now, false, 0)
        );
        assert_eq!(
            Err(HmacRejection::Expired),
            verify_hmac_token(
                &sign(Algorithm::HS256, serde_json::json!({"exp": now - 1})),
                secret,
                "",
                now,
                false,
                0
            )
        );
        for token in ["a.b", "a.b.c.d", ""] {
            assert_eq!(
                Err(HmacRejection::Format),
                verify_hmac_token(token, secret, "", now, true, 0),
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

    /// One request through a plugin: what it was answered with, or the
    /// headers it goes on to the upstream with, sorted.
    async fn through(
        auth: &JwtAuth,
        token: &str,
        headers: &str,
    ) -> std::result::Result<Vec<String>, (u16, String)> {
        let input = format!(
            "GET / HTTP/1.1\r\nAuthorization: Bearer {token}\r\n{headers}\r\n"
        );
        let mock_io = Builder::new().read(input.as_bytes()).build();
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
        if let RequestPluginResult::Respond(resp) = result {
            return Err((
                resp.status.as_u16(),
                String::from_utf8_lossy(&resp.body).to_string(),
            ));
        }
        let mut headers: Vec<String> = session
            .req_header()
            .headers
            .iter()
            .filter(|(name, _)| *name != "authorization")
            .map(|(name, value)| {
                format!("{name}: {}", String::from_utf8_lossy(value.as_bytes()))
            })
            .collect();
        headers.sort();
        Ok(headers)
    }

    /// `issuers`, `audiences` and `required_claims`: a token with a good
    /// signature is still not one for here unless it says so. And
    /// `claims_to_headers`: the upstream is told who the token is for,
    /// by the token and by nobody else.
    #[tokio::test]
    async fn test_jwt_claim_rules() {
        use jsonwebtoken::{EncodingKey, Header, encode};
        use serde_json::json;
        let key = EncodingKey::from_secret(b"123123");
        let exp = pingap_core::now_sec() + 3600;
        let sign = |mut claims: serde_json::Value| {
            claims["exp"] = json!(exp);
            encode(&Header::new(Algorithm::HS256), &claims, &key).unwrap()
        };
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r#"
secret = "123123"
header = "Authorization"
issuers = ["https://id.example.com", "https://id2.example.com"]
audiences = ["api"]
required_claims = ["sub"]
claims_to_headers = ["sub:X-User-Id", "roles:X-User-Roles", "tenant:X-Tenant", "name:X-User-Name"]
"#,
            )
            .unwrap(),
        )
        .unwrap();
        let good = json!({
            "iss": "https://id.example.com",
            "aud": ["web", "api"],
            "sub": "u-42",
            "roles": ["admin", "dev"],
            "name": "José",
        });

        // What the token says goes to the upstream; what the client said
        // under those names does not, also where the token says nothing
        // (`tenant`). And the client does not get to drop one of them by
        // calling it hop-by-hop.
        let headers = through(
            &auth,
            &sign(good.clone()),
            "X-User-Id: admin\r\nX-Tenant: other\r\nX-Mine: 1\r\nConnection: X-User-Id, keep-alive\r\n",
        )
        .await
        .unwrap();
        assert_eq!(
            vec![
                "connection: keep-alive",
                "x-mine: 1",
                "x-user-id: u-42",
                "x-user-name: José",
                "x-user-roles: admin,dev",
            ],
            headers
        );
        // Nor under a name that only differs by an underscore, which is
        // the same variable to an upstream behind CGI or WSGI. A header
        // that is no claim's keeps its underscore.
        let headers = through(
            &auth,
            &sign(good.clone()),
            "X_User_Id: admin\r\nx_user-id: root\r\nX_Tenant: other\r\nX_Mine: 2\r\n",
        )
        .await
        .unwrap();
        assert_eq!(
            vec![
                "x-user-id: u-42",
                "x-user-name: José",
                "x-user-roles: admin,dev",
                "x_mine: 2",
            ],
            headers
        );
        // One audience as a string is the same as a list of one.
        let mut single = good.clone();
        single["aud"] = json!("api");
        assert_eq!(true, through(&auth, &sign(single), "").await.is_ok());

        let refused = async |change: fn(&mut serde_json::Value)| {
            let mut claims = good.clone();
            change(&mut claims);
            through(&auth, &sign(claims), "").await.unwrap_err()
        };
        let unauthorized = |body: &str| (401, body.to_string());
        assert_eq!(
            unauthorized("Jwt authorization issuer is not allowed"),
            refused(|claims| claims["iss"] = json!("https://evil.example"))
                .await
        );
        assert_eq!(
            unauthorized("Jwt authorization issuer is not allowed"),
            refused(|claims| {
                claims.as_object_mut().unwrap().remove("iss");
            })
            .await
        );
        assert_eq!(
            unauthorized("Jwt authorization audience is not allowed"),
            refused(|claims| claims["aud"] = json!(["web"])).await
        );
        assert_eq!(
            unauthorized("Jwt authorization audience is not allowed"),
            refused(|claims| claims["aud"] = json!("apis")).await
        );
        assert_eq!(
            unauthorized("Jwt authorization has no sub"),
            refused(|claims| claims["sub"] = json!(null)).await
        );
        // A claim that cannot be a header is left off, not sent broken.
        let mut broken = good.clone();
        broken["sub"] = json!("u-42\r\nX-Admin: 1");
        broken["roles"] = json!({"a": 1});
        let headers = through(&auth, &sign(broken), "").await.unwrap();
        assert_eq!(vec!["x-user-name: José"], headers);

        // Without rules the claims are not looked at, as before.
        let plain = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                "secret = \"123123\"\nheader = \"Authorization\"",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(true, plain.claim_rules.is_empty());
        let headers = through(
            &plain,
            &sign(json!({"iss": "anyone"})),
            "X-User-Id: kept\r\n",
        )
        .await
        .unwrap();
        assert_eq!(vec!["x-user-id: kept"], headers);
    }

    /// The same rules on the public key paths, and EdDSA with a key from
    /// the configuration.
    #[tokio::test]
    async fn test_jwt_claim_rules_with_public_keys() {
        use jsonwebtoken::{EncodingKey, Header, encode};
        use serde_json::json;
        // spellchecker:off
        let private_key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJJTTQkyOiwPTX0NvxGAoNi6WosIFJJbFpt9ivsmWJM6\n-----END PRIVATE KEY-----";
        let public_key = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAjKwmFJwgUVvShgVbDiUw8Er4IKACUnfHr9XbsU7SmTo=\n-----END PUBLIC KEY-----";
        // spellchecker:on
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(&format!(
                "header = \"Authorization\"\nalgorithm = \"EdDSA\"\npublic_key = \"\"\"\n{public_key}\n\"\"\"\naudiences = [\"api\"]\nclaims_to_headers = [\"sub:X-User-Id\"]\n"
            ))
            .unwrap(),
        )
        .unwrap();
        let exp = pingap_core::now_sec() + 3600;
        let sign = |claims: serde_json::Value| {
            encode(
                &Header::new(Algorithm::EdDSA),
                &claims,
                &EncodingKey::from_ed_pem(private_key.as_bytes()).unwrap(),
            )
            .unwrap()
        };
        assert_eq!(
            Ok(vec!["x-user-id: u-7".to_string()]),
            through(
                &auth,
                &sign(json!({"exp": exp, "aud": "api", "sub": "u-7"})),
                "X-User-Id: admin\r\n"
            )
            .await
        );
        assert_eq!(
            Err((401, "Jwt authorization audience is not allowed".to_string())),
            through(&auth, &sign(json!({"exp": exp, "aud": "web"})), "").await
        );
        // The times are still the library's to check.
        assert_eq!(
            Err((401, "Jwt authorization is invalid".to_string())),
            through(&auth, &sign(json!({"exp": exp - 7200, "aud": "api"})), "")
                .await
        );
    }

    /// HS384 on the secret path, verified and minted.
    #[test]
    fn test_jwt_hs384() {
        use jsonwebtoken::{EncodingKey, Header, encode};
        let secret = b"123123";
        let now = pingap_core::now_sec();
        let token = encode(
            &Header::new(Algorithm::HS384),
            &serde_json::json!({"exp": now + 60}),
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        assert_eq!(Ok(()), verify_hmac_token(&token, secret, "", now, true, 0));
        assert_eq!(
            Ok(()),
            verify_hmac_token(&token, secret, "HS384", now, true, 0)
        );
        // Pinned to another algorithm, or under another secret.
        assert_eq!(
            Err(HmacRejection::Signature),
            verify_hmac_token(&token, secret, "HS256", now, true, 0)
        );
        assert_eq!(
            Err(HmacRejection::Signature),
            verify_hmac_token(&token, b"other", "HS384", now, true, 0)
        );
    }

    #[test]
    fn test_jwt_claim_rules_params() {
        let error = |conf: &str| {
            JwtAuth::new(
                &toml::from_str::<PluginConf>(&format!(
                    "secret = \"123123\"\nheader = \"Authorization\"\n{conf}"
                ))
                .unwrap(),
            )
            .err()
            .map(|e| e.to_string())
        };
        let prefix = "Plugin jwt invalid, message: ";
        for (conf, message) in [
            ("issuers = [\"\"]", "issuers: an entry is empty"),
            ("audiences = [\" \"]", "audiences: an entry is empty"),
            (
                "claims_to_headers = [\"sub\"]",
                r#"claims_to_headers: "sub" should be claim:Header-Name"#,
            ),
            (
                "claims_to_headers = [\":X-User\"]",
                r#"claims_to_headers: ":X-User" should be claim:Header-Name"#,
            ),
            (
                "claims_to_headers = [\"sub:X User\"]",
                r#"claims_to_headers: "X User" is not a header name"#,
            ),
            (
                "claims_to_headers = [\"sub:Host\"]",
                "claims_to_headers: host is not a header for a claim",
            ),
        ] {
            assert_eq!(
                Some(format!("{prefix}{message}")),
                error(conf),
                "{conf}"
            );
        }
        assert_eq!(None, error("claims_to_headers = [\"sub: X-User-Id\"]"));
        // The name of a claim may have colons in it, a header name none.
        assert_eq!(
            None,
            error(
                "claims_to_headers = [\"https://example.com/roles:X-Roles\"]"
            )
        );
    }

    /// A claim named by a url, as identity providers name their own, and
    /// the request to `auth_path`, which carries no token: the headers of
    /// the claims are not the client's to set there either.
    #[tokio::test]
    async fn test_jwt_namespaced_claim_and_auth_path() {
        use jsonwebtoken::{EncodingKey, Header, encode};
        use serde_json::json;
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r#"
secret = "123123"
header = "Authorization"
auth_path = "/login"
claims_to_headers = ["https://example.com/roles:X-Roles", "sub:X-User-Id"]
"#,
            )
            .unwrap(),
        )
        .unwrap();
        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({
                "exp": pingap_core::now_sec() + 3600,
                "sub": "u-42",
                "https://example.com/roles": ["dev", "ops"],
            }),
            &EncodingKey::from_secret(b"123123"),
        )
        .unwrap();
        assert_eq!(
            vec!["x-roles: dev,ops", "x-user-id: u-42"],
            through(&auth, &token, "X-Roles: root\r\n").await.unwrap()
        );

        let mock_io = Builder::new()
            .read(b"POST /login HTTP/1.1\r\nX-User-Id: admin\r\nX_Roles: root\r\nX-Mine: 1\r\n\r\n")
            .build();
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
        assert_eq!(true, result == RequestPluginResult::Skipped);
        let names: Vec<&str> = session
            .req_header()
            .headers
            .keys()
            .map(|name| name.as_str())
            .collect();
        assert_eq!(vec!["x-mine"], names);
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
algorithm = "HS1024"
"###,
            )
            .unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(
            "Plugin jwt invalid, message: Jwt algorithm(HS1024) is not supported, expect HS256, HS384 or HS512, or set public_key/jwks_url",
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

    /// Signs `body` as the response at `auth_path` of a plugin configured
    /// with `extra`, and gives what the client is sent.
    async fn sign_at_auth_path(
        extra: &str,
        body: &'static [u8],
    ) -> pingora::Result<String> {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(&format!(
                r###"
secret = "123123"
header = "Authorization"
auth_path = "/login"
{extra}
"###
            ))
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

        let mut body = Some(Bytes::from_static(body));
        let result =
            auth.handle_response_body(&mut session, &mut ctx, &mut body, true)?;
        assert_eq!(ResponseBodyPluginResult::FullyReplaced, result);
        Ok(String::from_utf8_lossy(body.unwrap().as_ref()).to_string())
    }

    /// Tests JWT token signing functionality
    #[tokio::test]
    async fn test_jwt_sign() {
        let signed = sign_at_auth_path("", br#"{"id":"u1","exp":4102444800}"#)
            .await
            .unwrap();
        let token = signed
            .strip_prefix(r#"{"token": ""#)
            .and_then(|rest| rest.strip_suffix(r#""}"#))
            .unwrap();
        let payload = token.split('.').nth(1).unwrap();
        assert_eq!(
            br#"{"id":"u1","exp":4102444800}"#.as_ref(),
            URL_SAFE_NO_PAD.decode(payload).unwrap()
        );
        // What is signed here is what the request path takes.
        assert_eq!(
            Ok(()),
            verify_hmac_token(
                token,
                b"123123",
                "HS256",
                pingap_core::now_sec(),
                true,
                0
            )
        );

        // Signed byte for byte, whatever it is, when no expiry is asked for.
        assert_eq!(
            r#"{"token": "eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiAiSldUIn0.UGluZ2Fw.wRLT2HhM1R-J4rVz3XCWADNIrmeInLtRGQzfJZaz-qI"}"#,
            sign_at_auth_path("require_exp = false", b"Pingap")
                .await
                .unwrap()
        );
    }

    /// Regression: the response at `auth_path` was signed whatever it
    /// held. Claims without `exp` gave a token that was valid for good.
    #[tokio::test]
    async fn test_jwt_sign_asks_for_an_expiry() {
        for body in [
            br#"{"id":"u1"}"#.as_ref(),
            br#"{"id":"u1","exp":null}"#,
            br#"{"id":"u1","exp":"tomorrow"}"#,
            // An array is not claims, whatever its first element is.
            b"[4102444800]",
            b"Pingap",
            b"",
        ] {
            let err = sign_at_auth_path("", body).await.expect_err("signed");
            assert_eq!(
                true,
                err.to_string().contains("has no exp"),
                "{err} for {}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(
                pingora::ErrorType::HTTPStatus(502),
                err.etype().clone()
            );
        }
        // Switched off, the claims are signed as they are.
        assert_eq!(
            true,
            sign_at_auth_path("require_exp = false", br#"{"id":"u1"}"#)
                .await
                .is_ok()
        );
    }

    /// An upstream error at `auth_path` must not be signed into a token: an
    /// error body is nobody's claims.
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

    /// Regression: the response at `auth_path` is signed as it comes. With
    /// the client's `Accept-Encoding` passed on, an upstream that compresses
    /// had its compressed bytes signed into the token.
    #[tokio::test]
    async fn test_auth_path_is_requested_and_signed_uncoded() {
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

        let mock_io = Builder::new()
            .read(b"GET /login HTTP/1.1\r\nAccept-Encoding: gzip, br\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        let result = auth
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Skipped);
        assert_eq!(
            false,
            session.req_header().headers.contains_key("accept-encoding")
        );

        // Coded all the same: no token is made of it.
        let mut coded = ResponseHeader::build_no_case(200, None).unwrap();
        coded.insert_header("Content-Encoding", "gzip").unwrap();
        assert_eq!(
            true,
            auth.handle_response(&mut session, &mut ctx, &mut coded)
                .await
                .is_err()
        );
        let mut plain = ResponseHeader::build_no_case(200, None).unwrap();
        plain.insert_header("Content-Encoding", "identity").unwrap();
        let result = auth
            .handle_response(&mut session, &mut ctx, &mut plain)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
    }
}
