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
    Error, get_bool_conf, get_hash_key, get_str_conf, get_str_slice_conf,
};
use arc_swap::ArcSwap;
use argon2::PasswordVerifier;
use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use http::StatusCode;
use humantime::parse_duration;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_NO_STORE, HttpResponse, Plugin, PluginStep,
    RequestPluginResult, TtlLruLimit, ensure_verified_client_ip,
};
use pingap_util::base64_decode;
use pingora::proxy::Session;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// How long failures are counted, and so the longest block, when
/// `ip_fail_window` is not set.
const DEFAULT_IP_FAIL_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Client IPs whose failures are tracked at once. Beyond this the least
/// used are forgotten, which only ever lets an IP off early.
const IP_FAIL_CAPACITY: usize = 4096;

/// How long credentials that passed a hash stay verified. Until then a
/// request with the same credentials is not hashed again.
const VERIFIED_TTL: Duration = Duration::from_secs(5 * 60);
/// Credentials kept as verified at once. One entry per account in use;
/// beyond this the oldest are let go and verified again when they come.
const VERIFIED_CAPACITY: usize = 1024;

/// The hash functions an `htpasswd` entry may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    /// `$2a$`, `$2b$`, `$2x$`, `$2y$`: what `htpasswd -B` writes.
    Bcrypt,
    /// `$argon2id$`, `$argon2i$`, `$argon2d$`.
    Argon2,
}

/// The kind of `hash`, by how it starts.
fn hash_kind(hash: &str) -> Option<HashKind> {
    if ["$2a$", "$2b$", "$2x$", "$2y$"]
        .iter()
        .any(|prefix| hash.starts_with(prefix))
    {
        return Some(HashKind::Bcrypt);
    }
    hash.starts_with("$argon2").then_some(HashKind::Argon2)
}

/// Whether `password` is the one `hash` was made of. Tens of
/// milliseconds of one core, by design of the hash: not for a thread that
/// serves requests.
fn verify_hash(kind: HashKind, password: &[u8], hash: &str) -> bool {
    match kind {
        HashKind::Bcrypt => bcrypt::verify(password, hash).unwrap_or(false),
        HashKind::Argon2 => argon2::Argon2::default()
            .verify_password(password, hash)
            .is_ok(),
    }
}

/// An account of `htpasswd`: its password is kept as a hash.
struct HashedAccount {
    user: Vec<u8>,
    kind: HashKind,
    hash: String,
}

/// The accounts whose passwords are hashes, and what keeps a request
/// from costing a hash each time.
///
/// A hash of this kind is slow on purpose, so that a stolen configuration
/// does not give the passwords away. Verified on every request it would
/// be the proxy that pays: an API client sends its credentials with each
/// call. So credentials that passed are remembered for a while, by a
/// digest of them that is keyed with something only this process has -
/// what is in memory is of no more use to whoever reads it than the hash
/// in the configuration.
struct Hashed {
    accounts: Arc<Vec<HashedAccount>>,
    /// The digest of credentials that were verified, with the time, in
    /// seconds, until which that holds.
    verified: ArcSwap<HashMap<[u8; 32], u64>>,
    key: [u8; 32],
    /// How many hashes are computed at once. A request with credentials
    /// that are not verified yet costs one whoever sends it, and without
    /// a bound enough of them would take every thread there is for
    /// blocking work.
    slots: Semaphore,
}

impl Hashed {
    fn new(accounts: Vec<HashedAccount>) -> Self {
        let slots = std::thread::available_parallelism()
            .map_or(2, |cores| cores.get().max(2));
        Self {
            accounts: Arc::new(accounts),
            verified: ArcSwap::from_pointee(HashMap::new()),
            key: rand::random(),
            slots: Semaphore::new(slots),
        }
    }

    #[inline]
    fn digest(&self, credentials: &[u8]) -> [u8; 32] {
        hmac_sha256::HMAC::mac(credentials, self.key)
    }

    /// Whether `credentials`, as they are in the header, passed a hash
    /// not long ago.
    #[inline]
    fn is_verified(&self, credentials: &[u8]) -> bool {
        self.verified
            .load()
            .get(&self.digest(credentials))
            .is_some_and(|until| *until > pingap_core::now_sec())
    }

    fn remember(&self, credentials: &[u8]) {
        let digest = self.digest(credentials);
        let now = pingap_core::now_sec();
        let until = now + VERIFIED_TTL.as_secs();
        self.verified.rcu(|current| {
            let mut next: HashMap<[u8; 32], u64> = current
                .iter()
                .filter(|(_, until)| **until > now)
                .map(|(digest, until)| (*digest, *until))
                .collect();
            // Full of credentials that still hold: start over. Each of
            // them is verified once more, which is all it costs.
            if next.len() >= VERIFIED_CAPACITY {
                next.clear();
            }
            next.insert(digest, until);
            next
        });
    }

    /// Whether `credentials` (`user:password`, decoded) are those of an
    /// account. Computes a hash, off the thread that serves the request.
    ///
    /// For a user that is not there as well, against the hash of another
    /// account: answered at once, "no such user" could be told from
    /// "wrong password" by the time it takes, and the names of the
    /// accounts read off one by one.
    ///
    /// `still_allowed` is asked once the request has its turn, before
    /// anything is computed. The wait for a turn is where requests pile
    /// up: a client that sent a thousand guesses at once had every one of
    /// them past the check of its failures before the first had failed,
    /// and each of them hashed. `None` when it says no.
    async fn verify(
        &self,
        credentials: Vec<u8>,
        still_allowed: impl FnOnce() -> bool,
    ) -> Option<bool> {
        let Ok(_slot) = self.slots.acquire().await else {
            return Some(false);
        };
        if !still_allowed() {
            return None;
        }
        Some(self.verify_now(credentials).await)
    }

    async fn verify_now(&self, credentials: Vec<u8>) -> bool {
        let accounts = self.accounts.clone();
        tokio::task::spawn_blocking(move || {
            let (user, password) =
                match credentials.iter().position(|byte| *byte == b':') {
                    Some(index) => {
                        (&credentials[..index], &credentials[index + 1..])
                    },
                    None => (&credentials[..], &[][..]),
                };
            let account = accounts
                .iter()
                .find(|account| account.user.as_slice() == user);
            match account.or(accounts.first()) {
                Some(found) => {
                    verify_hash(found.kind, password, &found.hash)
                        && account.is_some()
                },
                None => false,
            }
        })
        .await
        .unwrap_or(false)
    }
}

/// `realm` as the quoted string of a `WWW-Authenticate` header.
fn quoted_realm(realm: &str) -> Option<HeaderValue> {
    if realm.chars().any(|c| c.is_control()) {
        return None;
    }
    let escaped = realm.replace('\\', "\\\\").replace('"', "\\\"");
    HeaderValue::from_str(&format!("Basic realm=\"{escaped}\"")).ok()
}

/// BasicAuth implements HTTP Basic Authentication functionality for HTTP requests.
///
/// # Security Features
/// - Validates base64-encoded credentials against a predefined list
/// - Optional rate limiting through configurable delays to prevent brute force attacks
/// - Can hide credentials from upstream services to prevent credential leakage
/// - Returns standard HTTP 401 responses with WWW-Authenticate headers
///
/// # Configuration
/// Expects configuration in TOML format with the following options:
/// - authorizations: List of base64-encoded "username:password" strings
/// - delay: Optional duration string for rate limiting (e.g., "10s")
/// - hide_credentials: Boolean to control credential forwarding
pub struct BasicAuth {
    /// The plugin execution step (should always be Request for BasicAuth)
    /// This ensures authentication happens before request processing
    plugin_step: PluginStep,

    /// The base64 `username:password` of every account, without the
    /// scheme: `admin:password` is stored as `YWRtaW46cGFzc3dvcmQ=`.
    authorizations: Vec<Vec<u8>>,

    /// The accounts of `htpasswd`, whose passwords are kept as hashes;
    /// `None` when there are none.
    hashed: Option<Hashed>,

    /// When true, removes the Authorization header after successful authentication
    /// This is a security feature to prevent credential leakage to backend services
    /// Recommended to set to true unless the upstream service specifically needs credentials
    hide_credentials: bool,

    /// HTTP response returned when the Authorization header is missing
    /// Includes WWW-Authenticate header to prompt browser's authentication dialog
    /// Body contains a user-friendly message about missing authorization
    miss_authorization_resp: HttpResponse,

    /// HTTP response returned when provided credentials are invalid
    /// Also includes WWW-Authenticate header but with a different message
    /// The delay (if configured) is applied before sending this response
    unauthorized_resp: HttpResponse,

    /// Optional delay duration before responding to invalid credentials
    /// Security feature to make brute force attacks impractical
    /// Example values: "1s", "500ms", "2s"
    delay: Option<Duration>,

    /// Wrong credentials counted per client IP; `None` unless
    /// `ip_fail_limit` is set. An IP that reaches the limit is refused
    /// until its window, which starts at its first counted failure, ends.
    ip_fail_limit: Option<TtlLruLimit>,

    /// The response to a client IP that has been blocked
    too_many_failures_resp: HttpResponse,

    /// Unique hash value for the plugin instance
    /// Used for internal plugin management and caching
    /// Generated from plugin configuration to ensure consistent behavior
    hash_value: String,
}

impl TryFrom<&PluginConf> for BasicAuth {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate a unique hash for this plugin instance based on configuration
        // This ensures consistent plugin behavior across restarts
        let hash_value = get_hash_key(value);

        // Parse optional delay duration for rate limiting
        // Supports human-readable duration strings like "10s", "1m", etc.
        // Returns None if delay is not specified
        let delay = get_str_conf(value, "delay");
        let delay = if !delay.is_empty() {
            let d = parse_duration(&delay).map_err(|e| Error::Invalid {
                category: PluginCategory::BasicAuth.to_string(),
                message: e.to_string(),
            })?;
            Some(d)
        } else {
            None
        };

        // Process and validate the list of authorized credentials
        // Each credential must be a valid base64 string
        // Invalid base64 strings will cause initialization to fail
        let mut authorizations = vec![];
        for item in get_str_slice_conf(value, "authorizations").iter() {
            // Validate base64 format - this ensures we don't store invalid credentials
            let _ = base64_decode(item).map_err(|e| Error::Base64Decode {
                category: PluginCategory::BasicAuth.to_string(),
                source: e,
            })?;
            authorizations.push(item.as_bytes().to_vec());
        }

        let invalid = |message: String| Error::Invalid {
            category: PluginCategory::BasicAuth.to_string(),
            message,
        };
        // The accounts whose password is a hash: `user:hash`, the line
        // `htpasswd -nbB user password` prints.
        let mut hashed = vec![];
        for item in get_str_slice_conf(value, "htpasswd").iter() {
            let (user, hash) = item
                .trim()
                .split_once(':')
                .filter(|(user, hash)| !user.is_empty() && !hash.is_empty())
                .ok_or_else(|| {
                    invalid(
                        "htpasswd: an entry should be user:hash".to_string(),
                    )
                })?;
            // Said by the name of the account and not by the hash: the
            // message ends up in a log.
            let kind = hash_kind(hash).ok_or_else(|| {
                invalid(format!(
                    "htpasswd: the hash of {user} is not bcrypt ($2y$) or argon2 ($argon2id$)"
                ))
            })?;
            let readable = match kind {
                // With a cost bcrypt can be run at: one outside of that
                // parses, and is then a password nothing ever matches.
                HashKind::Bcrypt => hash
                    .parse::<bcrypt::HashParts>()
                    .is_ok_and(|parts| (4..=31).contains(&parts.get_cost())),
                HashKind::Argon2 => argon2::PasswordHash::new(hash).is_ok(),
            };
            if !readable {
                return Err(invalid(format!(
                    "htpasswd: the hash of {user} can not be read"
                )));
            }
            if hashed
                .iter()
                .any(|account: &HashedAccount| account.user == user.as_bytes())
            {
                return Err(invalid(format!(
                    "htpasswd: {user} is there twice"
                )));
            }
            hashed.push(HashedAccount {
                user: user.as_bytes().to_vec(),
                kind,
                hash: hash.to_string(),
            });
        }

        // Ensure at least one account is configured
        if authorizations.is_empty() && hashed.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::BasicAuth.to_string(),
                message: "basic authorizations can't be empty".to_string(),
            });
        }
        // Wrong passwords per client IP; 0 (the default) turns it off.
        let ip_fail_limit = match value.get("ip_fail_limit") {
            None => 0,
            Some(limit) => limit
                .as_integer()
                .filter(|limit| *limit >= 0)
                .ok_or_else(|| {
                    invalid(format!(
                        "ip_fail_limit({limit}) must be a non-negative integer"
                    ))
                })?,
        };
        let ip_fail_window = get_str_conf(value, "ip_fail_window");
        let ip_fail_window = if ip_fail_window.is_empty() {
            DEFAULT_IP_FAIL_WINDOW
        } else {
            let window = parse_duration(&ip_fail_window)
                .map_err(|e| invalid(format!("invalid ip_fail_window: {e}")))?;
            if window.is_zero() {
                return Err(invalid(
                    "ip_fail_window must be greater than zero".to_string(),
                ));
            }
            window
        };
        let ip_fail_limit = (ip_fail_limit > 0).then(|| {
            TtlLruLimit::new_compact(
                IP_FAIL_CAPACITY,
                ip_fail_window,
                ip_fail_limit as usize,
            )
        });

        let realm = get_str_conf(value, "realm");
        let challenge = if realm.is_empty() {
            HeaderValue::from_static(
                r###"Basic realm="Access to the staging site""###,
            )
        } else {
            quoted_realm(&realm).ok_or_else(|| {
                invalid("realm can not be put into a header".to_string())
            })?
        };
        let www_authenticate =
            Some(vec![(http::header::WWW_AUTHENTICATE, challenge)]);

        let params = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            delay,
            hide_credentials: get_bool_conf(value, "hide_credentials"),
            authorizations,
            hashed: (!hashed.is_empty()).then(|| Hashed::new(hashed)),
            miss_authorization_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: www_authenticate.clone(),
                body: Bytes::from_static(b"Authorization is missing"),
                ..Default::default()
            },
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: www_authenticate,
                body: Bytes::from_static(b"Invalid user or password"),
                ..Default::default()
            },
            ip_fail_limit,
            too_many_failures_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
                body: Bytes::from_static(b"Forbidden, too many failures"),
                ..Default::default()
            },
        };

        Ok(params)
    }
}

/// The credentials of a `Basic` authorization header value. The scheme is
/// case-insensitive (RFC 7235 §2.1) and whitespace may follow it; a
/// literal `Basic ` comparison used to turn `basic ...` away.
fn basic_credentials(value: &[u8]) -> Option<&[u8]> {
    let (scheme, credentials) =
        value.split_at(value.iter().position(|b| *b == b' ')?);
    scheme
        .eq_ignore_ascii_case(b"basic")
        .then(|| credentials.trim_ascii())
}

impl BasicAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new basic auth plugin"
        );
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for BasicAuth {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // Verify we're in the request phase - authentication must happen before processing
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // A blocked IP is refused before its credentials are looked at, so
        // guessing stops paying off even when a guess would be right.
        //
        // Counted by an address the client cannot choose: the client ip
        // behind trusted proxies, the peer's own without them. It used to
        // be the client ip either way, which without trusted proxies is
        // whatever `X-Forwarded-For` says - a new address with every guess
        // was never blocked, and someone else's address got them blocked.
        if let Some(limit) = &self.ip_fail_limit
            && !limit.validate(ensure_verified_client_ip(session, ctx))
        {
            return Ok(RequestPluginResult::Respond(
                self.too_many_failures_resp.clone(),
            ));
        }

        // Extract and validate Authorization header
        // An empty value means the header is missing entirely
        let value = session.get_header_bytes(http::header::AUTHORIZATION);
        if value.is_empty() {
            return Ok(RequestPluginResult::Respond(
                self.miss_authorization_resp.clone(),
            ));
        }

        // Validate credentials against our authorized list, comparing in
        // constant time so a match position is not leaked via timing.
        let credentials = basic_credentials(value);
        let mut authorized = credentials.is_some_and(|credentials| {
            self.authorizations
                .iter()
                .any(|auth| pingap_core::constant_time_eq(auth, credentials))
        });
        // Then the accounts whose password is a hash: by what was
        // verified a moment ago, or by computing the hash.
        if !authorized
            && let Some(hashed) = &self.hashed
            && let Some(credentials) = credentials
        {
            authorized = hashed.is_verified(credentials);
            if !authorized && let Ok(decoded) = base64_decode(credentials) {
                let credentials = credentials.to_vec();
                // The address the failures are counted by, taken now:
                // the session is not there to ask while the hash waits
                // for its turn.
                let ip = self.ip_fail_limit.as_ref().map(|_| {
                    ensure_verified_client_ip(session, ctx).to_string()
                });
                let verified = hashed
                    .verify(decoded, || {
                        match (&self.ip_fail_limit, ip.as_deref()) {
                            (Some(limit), Some(ip)) => limit.validate(ip),
                            _ => true,
                        }
                    })
                    .await;
                let Some(verified) = verified else {
                    return Ok(RequestPluginResult::Respond(
                        self.too_many_failures_resp.clone(),
                    ));
                };
                authorized = verified;
                if authorized {
                    hashed.remember(&credentials);
                }
            }
        }
        if !authorized {
            // Only wrong credentials count. A missing header does not: it is
            // how every browser starts, before the login prompt.
            if let Some(limit) = &self.ip_fail_limit {
                limit.inc(ensure_verified_client_ip(session, ctx));
            }
            // If configured, apply rate limiting delay
            // This helps prevent automated brute force attempts
            if let Some(d) = self.delay {
                sleep(d).await;
            }
            return Ok(RequestPluginResult::Respond(
                self.unauthorized_resp.clone(),
            ));
        }

        // On successful authentication, optionally remove credentials
        // This prevents credential leakage to upstream services
        if self.hide_credentials {
            session
                .req_header_mut()
                .remove_header(&http::header::AUTHORIZATION);
        }

        // Authentication successful - continue request processing
        return Ok(RequestPluginResult::Continue);
    }
}

register_plugin!("basic_auth", BasicAuth);

#[cfg(test)]
mod tests {
    use super::{
        BasicAuth, HashKind, Hashed, HashedAccount, Plugin, VERIFIED_CAPACITY,
    };
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep, RequestPluginResult};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_test::io::Builder;

    #[test]
    fn test_basic_auth_params() {
        // spellchecker:off
        let params = BasicAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
"MTIz",
"NDU2",
]
delay = "10s"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on
        assert_eq!("request", params.plugin_step.to_string());
        // spellchecker:off
        assert_eq!(
            "MTIz,NDU2",
            params
                .authorizations
                .iter()
                .map(|item| std::string::String::from_utf8_lossy(item))
                .collect::<Vec<_>>()
                .join(","),
        );
        // spellchecker:on
        assert_eq!(Duration::from_secs(10), params.delay.unwrap());
        assert_eq!("AC7E9E03", params.config_key());

        let result = BasicAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
"1"
]
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin basic_auth, base64 decode error Invalid input length: 1",
            result.err().unwrap().to_string()
        );
    }

    #[tokio::test]
    async fn test_basic_auth() {
        // spellchecker:off
        let auth = BasicAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
    "YWRtaW46MTIzMTIz"
]
hide_credentials = true
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on

        // auth success
        // spellchecker:off
        let headers = ["Authorization: Basic YWRtaW46MTIzMTIz"].join("\r\n");
        // spellchecker:on
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
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
        assert_eq!(
            false,
            session.req_header().headers.contains_key("Authorization")
        );

        // auth fail
        // spellchecker:off
        let headers = ["Authorization: Basic YWRtaW46MTIzMTIa"].join("\r\n");
        // spellchecker:on
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
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
        assert_eq!(resp.status, http::StatusCode::UNAUTHORIZED);
    }

    /// The scheme is case-insensitive and may be followed by more than one
    /// space; another scheme is not Basic at all.
    #[test]
    fn test_basic_credentials() {
        use super::basic_credentials;
        assert_eq!(Some(&b"abc"[..]), basic_credentials(b"Basic abc"));
        assert_eq!(Some(&b"abc"[..]), basic_credentials(b"basic  abc "));
        assert_eq!(None, basic_credentials(b"Bearer abc"));
        assert_eq!(None, basic_credentials(b"Basicabc"));
    }
    #[test]
    fn test_ip_fail_limit_params() {
        // spellchecker:off
        let conf = |extra: &str| {
            toml::from_str::<PluginConf>(&format!(
                "authorizations = [\"YWRtaW46MTIzMTIz\"]\n{extra}"
            ))
            .unwrap()
        };
        // spellchecker:on
        // Off unless asked for.
        let params = BasicAuth::try_from(&conf("")).unwrap();
        assert_eq!(true, params.ip_fail_limit.is_none());
        let params = BasicAuth::try_from(&conf("ip_fail_limit = 0")).unwrap();
        assert_eq!(true, params.ip_fail_limit.is_none());
        let params = BasicAuth::try_from(&conf(
            "ip_fail_limit = 3\nip_fail_window = \"10m\"",
        ))
        .unwrap();
        assert_eq!(true, params.ip_fail_limit.is_some());

        for (extra, expect) in [
            ("ip_fail_limit = -1", "must be a non-negative integer"),
            ("ip_fail_limit = \"five\"", "must be a non-negative integer"),
            ("ip_fail_window = \"soon\"", "invalid ip_fail_window"),
            ("ip_fail_window = \"0s\"", "must be greater than zero"),
        ] {
            let err =
                BasicAuth::try_from(&conf(extra)).err().unwrap().to_string();
            assert_eq!(true, err.contains(expect), "{extra}: {err}");
        }
    }

    /// A request from the peer `client_ip`, which is what the failures are
    /// counted by when no trusted proxies are configured.
    async fn request(
        auth: &BasicAuth,
        client_ip: &str,
        authorization: Option<&str>,
    ) -> RequestPluginResult {
        request_with(auth, client_ip, "", authorization).await
    }

    /// The same, with an `X-Forwarded-For` of the client's choosing.
    async fn request_with(
        auth: &BasicAuth,
        peer: &str,
        forwarded_for: &str,
        authorization: Option<&str>,
    ) -> RequestPluginResult {
        let mut headers = vec!["Host: example.com".to_string()];
        if !forwarded_for.is_empty() {
            headers.push(format!("X-Forwarded-For: {forwarded_for}"));
        }
        if let Some(value) = authorization {
            headers.push(format!("Authorization: {value}"));
        }
        let input =
            format!("GET / HTTP/1.1\r\n{}\r\n\r\n", headers.join("\r\n"));
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some(peer.to_string());
        auth.handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap()
    }

    fn status(result: &RequestPluginResult) -> u16 {
        match result {
            RequestPluginResult::Respond(resp) => resp.status.as_u16(),
            _ => 0,
        }
    }

    fn basic(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            pingap_util::base64_encode(format!("{user}:{password}"))
        )
    }

    fn argon2_hash(password: &str) -> String {
        use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
        // As small as the parameters go: a test does not need them to be
        // slow.
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(8, 1, 1, None).unwrap(),
        )
        .hash_password(password.as_bytes())
        .unwrap()
        .to_string()
    }

    /// `htpasswd`: accounts whose password is kept as a hash, next to the
    /// ones of `authorizations` or without them.
    #[tokio::test]
    async fn test_htpasswd() {
        let bcrypt_hash = bcrypt::hash("b-secret", 4).unwrap();
        // The prefix of `htpasswd -B`.
        let bcrypt_hash = bcrypt_hash.replacen("$2b$", "$2y$", 1);
        let auth = BasicAuth::new(
            &toml::from_str::<PluginConf>(&format!(
                "authorizations = [\"{}\"]\nhtpasswd = [\"alice:{bcrypt_hash}\", \"bob:{}\"]\nip_fail_limit = 100\n",
                pingap_util::base64_encode("plain:p-secret"),
                argon2_hash("a-secret"),
            ))
            .unwrap(),
        )
        .unwrap();
        let hashed = auth.hashed.as_ref().unwrap();
        let attempt = async |user: &str, password: &str| {
            status(
                &request(&auth, "1.1.1.1", Some(&basic(user, password))).await,
            )
        };
        // Each kind of account with its own password.
        assert_eq!(0, attempt("plain", "p-secret").await);
        assert_eq!(0, attempt("alice", "b-secret").await);
        assert_eq!(0, attempt("bob", "a-secret").await);
        // Not with another's, not with none, and no account that is not
        // there - also not with the password of the account whose hash
        // stands in for it.
        assert_eq!(401, attempt("alice", "a-secret").await);
        assert_eq!(401, attempt("bob", "b-secret").await);
        assert_eq!(401, attempt("alice", "").await);
        assert_eq!(401, attempt("carol", "b-secret").await);
        assert_eq!(401, attempt("", "b-secret").await);
        assert_eq!(401, attempt("alice:b-secret", "").await);
        // A password with a colon in it is everything after the first.
        let with_colon = BasicAuth::new(
            &toml::from_str::<PluginConf>(&format!(
                "htpasswd = [\"dave:{}\"]",
                bcrypt::hash("a:b", 4).unwrap()
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            0,
            status(
                &request(&with_colon, "1.1.1.1", Some(&basic("dave", "a:b")))
                    .await
            )
        );

        // What passed is remembered, so the next request with it costs no
        // hash; what did not pass is not.
        let header = basic("alice", "b-secret");
        let credentials = header.strip_prefix("Basic ").unwrap().as_bytes();
        assert_eq!(true, hashed.is_verified(credentials));
        let wrong = basic("alice", "a-secret");
        assert_eq!(
            false,
            hashed
                .is_verified(wrong.strip_prefix("Basic ").unwrap().as_bytes())
        );
        // By a digest that is this plugin's own: nothing of the
        // credentials is kept.
        let kept = hashed.verified.load();
        assert_eq!(2, kept.len());
        assert_eq!(true, kept.contains_key(&hashed.digest(credentials)));
        assert_eq!(
            false,
            kept.contains_key(&hmac_sha256::Hash::hash(credentials))
        );
    }

    /// Regression: the failures of an address were looked at before a
    /// request waited for its turn to be hashed, and counted after. A
    /// thousand guesses sent at once were all past the check before the
    /// first had failed, and every one of them was hashed.
    #[tokio::test]
    async fn test_failures_are_checked_when_a_hash_gets_its_turn() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        const LIMIT: usize = 3;
        const GUESSES: usize = 40;
        let hashed = Arc::new(Hashed::new(vec![HashedAccount {
            user: b"alice".to_vec(),
            kind: HashKind::Bcrypt,
            hash: bcrypt::hash("secret", 4).unwrap(),
        }]));
        let failures = Arc::new(AtomicUsize::new(0));
        let mut tasks = vec![];
        for index in 0..GUESSES {
            let hashed = hashed.clone();
            let failures = failures.clone();
            tasks.push(tokio::spawn(async move {
                let verified = hashed
                    .verify(format!("alice:guess-{index}").into_bytes(), || {
                        failures.load(Ordering::Relaxed) < LIMIT
                    })
                    .await;
                if verified == Some(false) {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
                verified
            }));
        }
        let mut computed = 0;
        for task in tasks {
            if task.await.unwrap().is_some() {
                computed += 1;
            }
        }
        // The limit, and what was being computed while it was reached.
        let slots = std::thread::available_parallelism()
            .map_or(2, |cores| cores.get().max(2));
        assert_eq!(
            true,
            computed <= LIMIT + slots && computed < GUESSES,
            "{computed} of {GUESSES} guesses were hashed"
        );
        // The right password is still taken where the address is allowed.
        assert_eq!(
            Some(true),
            hashed.verify(b"alice:secret".to_vec(), || true).await
        );
        assert_eq!(
            None,
            hashed.verify(b"alice:secret".to_vec(), || false).await
        );
    }

    /// What is remembered as verified is let go when its time is up or
    /// there is no room left.
    #[test]
    fn test_verified_credentials_are_bounded() {
        let hashed = Hashed::new(vec![]);
        hashed.remember(b"first");
        assert_eq!(true, hashed.is_verified(b"first"));
        // Its time is up: not verified any more, and dropped by the next
        // one that is remembered.
        hashed.verified.store(Arc::new(HashMap::from([(
            hashed.digest(b"first"),
            pingap_core::now_sec() - 1,
        )])));
        assert_eq!(false, hashed.is_verified(b"first"));
        hashed.remember(b"second");
        assert_eq!(1, hashed.verified.load().len());

        for index in 0..VERIFIED_CAPACITY + 10 {
            hashed.remember(format!("user-{index}").as_bytes());
        }
        assert_eq!(true, hashed.verified.load().len() <= VERIFIED_CAPACITY);
        assert_eq!(
            true,
            hashed.is_verified(
                format!("user-{}", VERIFIED_CAPACITY + 9).as_bytes()
            )
        );
    }

    #[test]
    fn test_htpasswd_and_realm_params() {
        let error = |conf: &str| {
            BasicAuth::new(&toml::from_str::<PluginConf>(conf).unwrap())
                .err()
                .map(|e| e.to_string())
        };
        let prefix = "Plugin basic_auth invalid, message: ";
        let bcrypt_hash = bcrypt::hash("secret", 4).unwrap();
        // On its own, without `authorizations`.
        assert_eq!(None, error(&format!("htpasswd = [\"a:{bcrypt_hash}\"]")));
        for (conf, message) in [
            (
                "htpasswd = [\"nocolon\"]",
                "htpasswd: an entry should be user:hash",
            ),
            (
                "htpasswd = [\":x\"]",
                "htpasswd: an entry should be user:hash",
            ),
            (
                "htpasswd = [\"a:\"]",
                "htpasswd: an entry should be user:hash",
            ),
            // The default of `htpasswd` without `-B`, and a password as
            // it is: neither is a hash that is slow to try.
            (
                "htpasswd = [\"a:$apr1$abcd$0123456789abcdefghijkl\"]",
                "htpasswd: the hash of a is not bcrypt ($2y$) or argon2 ($argon2id$)",
            ),
            (
                "htpasswd = [\"a:secret\"]",
                "htpasswd: the hash of a is not bcrypt ($2y$) or argon2 ($argon2id$)",
            ),
            (
                "htpasswd = [\"a:$2y$10$short\"]",
                "htpasswd: the hash of a can not be read",
            ),
            (
                "htpasswd = [\"a:$argon2id$broken\"]",
                "htpasswd: the hash of a can not be read",
            ),
            // a cost bcrypt does not run at: it would never match
            (
                "htpasswd = [\"a:$2y$03$k6jyd5p6IGayudQCa5NLHuOeIKLGQyn1F2tqUkslMvPI6ZMCmmtxC\"]",
                "htpasswd: the hash of a can not be read",
            ),
            ("", "basic authorizations can't be empty"),
        ] {
            assert_eq!(
                Some(format!("{prefix}{message}")),
                error(conf),
                "{conf}"
            );
        }
        assert_eq!(
            Some(format!("{prefix}htpasswd: a is there twice")),
            error(&format!(
                "htpasswd = [\"a:{bcrypt_hash}\", \"a:{bcrypt_hash}\"]"
            ))
        );
        assert_eq!(
            Some(format!("{prefix}realm can not be put into a header")),
            error(&format!(
                "htpasswd = [\"a:{bcrypt_hash}\"]\nrealm = \"a\\nb\""
            ))
        );

        let challenge = |realm: &str| {
            let auth = BasicAuth::new(
                &toml::from_str::<PluginConf>(&format!(
                    "htpasswd = [\"a:{bcrypt_hash}\"]\n{realm}"
                ))
                .unwrap(),
            )
            .unwrap();
            let headers = auth.miss_authorization_resp.headers.unwrap();
            headers[0].1.to_str().unwrap().to_string()
        };
        // As it always was when none is set.
        assert_eq!(
            r#"Basic realm="Access to the staging site""#,
            challenge("")
        );
        assert_eq!(
            r#"Basic realm="Internal""#,
            challenge("realm = \"Internal\"")
        );
        assert_eq!(
            r#"Basic realm="the \"A\" team""#,
            challenge("realm = 'the \"A\" team'")
        );
    }

    /// After `ip_fail_limit` wrong passwords an IP is refused, correct
    /// credentials included; a missing header does not count, and other
    /// IPs are unaffected.
    #[tokio::test]
    async fn test_ip_fail_limit() {
        // spellchecker:off
        let good = "Basic YWRtaW46MTIzMTIz";
        let bad = "Basic YWRtaW46MTIzMTIa";
        // spellchecker:on
        let auth = BasicAuth::new(
            &toml::from_str::<PluginConf>(&format!(
                "authorizations = [\"{}\"]\nip_fail_limit = 2\nip_fail_window = \"1m\"",
                &good["Basic ".len()..]
            ))
            .unwrap(),
        )
        .unwrap();

        // Two wrong passwords: still answered 401.
        assert_eq!(401, status(&request(&auth, "1.1.1.1", Some(bad)).await));
        assert_eq!(401, status(&request(&auth, "1.1.1.1", Some(bad)).await));
        // Now blocked, whatever it sends.
        let blocked = request(&auth, "1.1.1.1", Some(good)).await;
        assert_eq!(403, status(&blocked));
        let RequestPluginResult::Respond(resp) = blocked else {
            panic!("a blocked ip must be answered");
        };
        assert_eq!(
            b"Forbidden, too many failures".as_ref(),
            resp.body.as_ref()
        );
        assert_eq!(403, status(&request(&auth, "1.1.1.1", None).await));

        // Another IP is not affected.
        assert_eq!(
            true,
            request(&auth, "2.2.2.2", Some(good)).await
                == RequestPluginResult::Continue
        );

        // Missing credentials are the browser's first request, not a guess.
        for _ in 0..5 {
            assert_eq!(401, status(&request(&auth, "3.3.3.3", None).await));
        }
        assert_eq!(
            true,
            request(&auth, "3.3.3.3", Some(good)).await
                == RequestPluginResult::Continue
        );
    }

    /// Regression: the failures were counted by the client ip, which
    /// without trusted proxies is what `X-Forwarded-For` says. A new
    /// address with every guess was never blocked, and naming somebody
    /// else's address got that address blocked.
    #[tokio::test]
    async fn test_ip_fail_limit_ignores_a_forged_address() {
        // spellchecker:off
        let good = "Basic YWRtaW46MTIzMTIz";
        let bad = "Basic YWRtaW46MTIzMTIa";
        // spellchecker:on
        let auth = BasicAuth::new(
            &toml::from_str::<PluginConf>(&format!(
                "authorizations = [\"{}\"]\nip_fail_limit = 2\nip_fail_window = \"1m\"",
                &good["Basic ".len()..]
            ))
            .unwrap(),
        )
        .unwrap();

        // One peer guessing, under a different address each time.
        for forged in ["7.7.7.1", "7.7.7.2"] {
            assert_eq!(
                401,
                status(
                    &request_with(&auth, "1.1.1.1", forged, Some(bad)).await
                )
            );
        }
        assert_eq!(
            403,
            status(
                &request_with(&auth, "1.1.1.1", "7.7.7.3", Some(good)).await
            )
        );
        // The addresses it named are not the ones that are blocked.
        assert_eq!(
            true,
            request(&auth, "7.7.7.1", Some(good)).await
                == RequestPluginResult::Continue
        );
    }
}
