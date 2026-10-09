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

use super::jwt::{
    ClaimMap, JwksSource, claim_header_value, parse_claims_to_headers,
    strip_claim_headers,
};
use super::{Error, get_duration_conf, get_hash_key, get_str_conf};
use super::{get_step_conf, get_str_slice_conf};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::header::{ACCEPT, AUTHORIZATION, CACHE_CONTROL, HOST, SET_COOKIE};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use jsonwebtoken::{Algorithm, Validation};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    constant_time_eq, get_cookie_value, now_sec,
    protect_from_connection_header,
};
use pingora::proxy::Session;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "oidc";
const DEFAULT_REDIRECT_PATH: &str = "/oauth2/callback";
const DEFAULT_COOKIE_NAME: &str = "pingap_oidc";
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// How long somebody has to log in at the provider: from the redirect to
/// it to the request that comes back.
const LOGIN_TTL: Duration = Duration::from_secs(600);
/// How long what the provider says of itself is taken for true.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
/// How long the provider is left alone after it was asked, when it did
/// not answer.
const DISCOVERY_COOLDOWN: Duration = Duration::from_secs(10);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// How far the clock of the provider may be from this one.
const LEEWAY: u64 = 60;
/// The most a query of the provider's answer is taken for: a code, a
/// state, an error name.
const MAX_QUERY_VALUE: usize = 4096;
/// The most a cookie is made: a browser takes 4096 bytes of name, value
/// and attributes together.
const MAX_COOKIE_VALUE: usize = 3800;
/// How many cookies of logins that were never finished are cleared when
/// one is.
const MAX_STALE_LOGINS: usize = 16;

/// Lets in who has logged in at an OpenID Connect provider.
///
/// A browser that asks for a page without a session is sent to the
/// provider (authorization code flow, with PKCE). It comes back to
/// `redirect_path` with a code, which is traded at the provider for an ID
/// token; the token is verified with the provider's keys, and a session is
/// made of what it says of the user. The session lives in a cookie that
/// is encrypted with `cookie_secret`, so every instance with that secret
/// reads it and nothing is stored on this side.
pub struct Oidc {
    hash_value: String,
    plugin_step: PluginStep,
    /// The provider, as it names itself: no slash at the end.
    issuer: String,
    client_id: String,
    client_secret: String,
    /// Where the provider sends a browser back to.
    redirect_path: String,
    /// The same as the provider is to see it, when that is not what the
    /// request says: behind another proxy, or a CDN.
    redirect_url: Option<String>,
    /// Ends the session, when set.
    logout_path: Option<String>,
    /// The scopes asked for, with spaces between.
    scopes: String,
    cookie_name: String,
    key: [u8; 32],
    session_ttl: Duration,
    /// The claims of the user that go to the upstream, and the header
    /// each goes in.
    claims_to_headers: Vec<(String, HeaderName)>,
    /// The headers of `claims_to_headers`: what a client does not get to
    /// write, or to take away.
    own_headers: Vec<HeaderName>,
    client: reqwest::Client,
    provider: ArcSwapOption<Provider>,
    /// One discovery at a time, and when the last one was started.
    discovery_lock: tokio::sync::Mutex<Option<Instant>>,
}

/// What the provider says of itself, at
/// `/.well-known/openid-configuration`.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

struct Provider {
    authorization_endpoint: String,
    token_endpoint: String,
    end_session_endpoint: Option<String>,
    /// Whether the client says who it is in `Authorization` (which is
    /// what a provider takes when it does not say otherwise) or in the
    /// form.
    basic_auth: bool,
    jwks: Arc<JwksSource>,
    fetched_at: Instant,
}

/// What is kept of a login while the browser is at the provider.
#[derive(Serialize, Deserialize)]
struct Login {
    state: String,
    verifier: String,
    nonce: String,
    /// Where the browser was going: a path of this site.
    url: String,
    exp: u64,
}

/// A session: what the provider said of the user, and until when it is
/// taken for it.
#[derive(Serialize, Deserialize)]
struct SessionData {
    exp: u64,
    claims: ClaimMap,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

/// `N` random bytes, as text that goes into a url or a cookie.
fn random<const N: usize>() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; N]>())
}

/// A path of this site and nothing else: `//host` and `/\host` are other
/// sites to a browser.
fn local_path(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'/')
        || matches!(bytes.get(1), Some(b'/') | Some(b'\\'))
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return "/";
    }
    value
}

fn is_http_url(value: &str) -> bool {
    url::Url::parse(value)
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
}

fn is_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
        })
}

impl TryFrom<&PluginConf> for Oidc {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let plugin_step = get_step_conf(value, PluginStep::Request);
        if plugin_step != PluginStep::Request {
            return Err(invalid(
                "oidc plugin should be executed at request step".to_string(),
            ));
        }
        let issuer = get_str_conf(value, "issuer")
            .trim()
            .trim_end_matches('/')
            .to_string();
        if !is_http_url(&issuer) {
            return Err(invalid(
                "issuer is required: the url of the provider, http or https"
                    .to_string(),
            ));
        }
        let client_id = get_str_conf(value, "client_id").trim().to_string();
        if client_id.is_empty() {
            return Err(invalid("client_id is required".to_string()));
        }
        let client_secret = get_str_conf(value, "client_secret");
        let cookie_secret = get_str_conf(value, "cookie_secret");
        if cookie_secret.len() < 16 {
            return Err(invalid(
                "cookie_secret is required, 16 characters at least: the sessions are encrypted with it"
                    .to_string(),
            ));
        }
        let path = |name: &str, default: &str| -> Result<String> {
            let path = get_str_conf(value, name);
            let path = if path.is_empty() {
                default.to_string()
            } else {
                path
            };
            let plain = !path.is_empty()
                && path == local_path(&path)
                && path.len() > 1
                && !path.contains(['?', '#']);
            if !path.is_empty() && !plain {
                return Err(invalid(format!(
                    "{name}: {path:?} is not a path, as /oauth2/callback is"
                )));
            }
            Ok(path)
        };
        let redirect_path = path("redirect_path", DEFAULT_REDIRECT_PATH)?;
        let logout_path = Some(path("logout_path", "")?)
            .filter(|logout_path| !logout_path.is_empty());
        if logout_path.as_deref() == Some(redirect_path.as_str()) {
            return Err(invalid(
                "logout_path can not be the redirect_path".to_string(),
            ));
        }
        let redirect_url = Some(get_str_conf(value, "redirect_url"))
            .filter(|url| !url.is_empty());
        if let Some(url) = &redirect_url {
            let path_is_ours = url::Url::parse(url)
                .is_ok_and(|url| url.path() == redirect_path);
            if !is_http_url(url) || !path_is_ours {
                return Err(invalid(format!(
                    "redirect_url should be an http or https url whose path is the redirect_path ({redirect_path})"
                )));
            }
        }
        let mut scopes = vec!["openid".to_string()];
        for scope in get_str_slice_conf(value, "scopes") {
            let scope = scope.trim().to_string();
            if scope.is_empty() || scope.contains(char::is_whitespace) {
                return Err(invalid(format!(
                    "scopes: {scope:?} is not a scope"
                )));
            }
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
        let cookie_name = Some(get_str_conf(value, "cookie_name"))
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| DEFAULT_COOKIE_NAME.to_string());
        if !is_cookie_name(&cookie_name) {
            return Err(invalid(format!(
                "cookie_name: {cookie_name:?} should be letters, digits, '-', '_' or '.'"
            )));
        }
        // A browser takes a `__Host-` cookie for the path `/` alone, and
        // the cookie of a login is for the redirect_path: with such a
        // name no login would ever be finished.
        if cookie_name.starts_with("__Host-") {
            return Err(invalid(
                "cookie_name can not begin with __Host-: the cookie of a login is for the redirect_path"
                    .to_string(),
            ));
        }
        let session_ttl = get_duration_conf(value, "session_ttl")
            .unwrap_or(DEFAULT_SESSION_TTL);
        if session_ttl < Duration::from_secs(60) {
            return Err(invalid(
                "session_ttl should be at least 1m".to_string(),
            ));
        }
        let claims_to_headers = parse_claims_to_headers(value, &invalid)?;
        let own_headers = claims_to_headers
            .iter()
            .map(|(_, header)| header.clone())
            .collect();
        // Made of the secret and of whom the sessions are from and for: a
        // second plugin with the same secret and another provider, or
        // another client of it, does not take them for its own.
        let key: [u8; 32] = Sha256::new()
            .chain_update(cookie_secret.as_bytes())
            .chain_update([0])
            .chain_update(issuer.as_bytes())
            .chain_update([0])
            .chain_update(client_id.as_bytes())
            .finalize()
            .into();
        let client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            // What the provider sends is taken from the provider, not
            // from where it points to.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| invalid(e.to_string()))?;
        Ok(Self {
            hash_value,
            plugin_step,
            issuer,
            client_id,
            client_secret,
            redirect_path,
            redirect_url,
            logout_path,
            scopes: scopes.join(" "),
            cookie_name,
            key,
            session_ttl,
            claims_to_headers,
            own_headers,
            client,
            provider: ArcSwapOption::empty(),
            discovery_lock: tokio::sync::Mutex::new(None),
        })
    }
}

/// Why a request that came back from the provider is not a login.
#[derive(Debug, PartialEq)]
enum Refusal {
    /// The request is not one this plugin sent out for: no such login is
    /// under way, or it took too long.
    Request(&'static str),
    /// The provider would not log the user in, and says why.
    Denied(String),
    /// The provider did not do its part.
    Provider(String),
}

impl Oidc {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new oidc plugin"
        );
        Self::try_from(params)
    }

    fn seal<T: Serialize>(&self, value: &T) -> Option<String> {
        let data = serde_json::to_vec(value).ok()?;
        pingap_util::seal(&self.key, rand::random(), &data).ok()
    }

    fn unseal<T: for<'a> Deserialize<'a>>(&self, value: &str) -> Option<T> {
        let data = pingap_util::unseal(&self.key, value)?;
        serde_json::from_slice(&data).ok()
    }

    /// The session of a request, when it has one that still holds.
    fn session(&self, session: &Session, now: u64) -> Option<SessionData> {
        let cookie = get_cookie_value(session.req_header(), &self.cookie_name)?;
        self.unseal::<SessionData>(cookie)
            .filter(|data| now < data.exp)
    }

    /// The cookie a login is kept in. Its name has some of the state in
    /// it: two tabs that log in at the same time each have their own.
    fn login_cookie_name(&self, state: &str) -> String {
        let tag: String = state
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(8)
            .collect();
        format!("{}_{tag}", self.cookie_name)
    }

    fn cookie(
        &self,
        name: &str,
        value: &str,
        path: &str,
        max_age: u64,
        secure: bool,
    ) -> Option<(HeaderName, HeaderValue)> {
        let secure = if secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
        ))
        .ok()
        .map(|value| (SET_COOKIE, value))
    }

    /// Whether the cookies are for a site that is reached over TLS.
    fn is_secure(&self, ctx: &Ctx) -> bool {
        match &self.redirect_url {
            Some(url) => url.starts_with("https://"),
            None => ctx.conn.tls_version.is_some(),
        }
    }

    /// Where the provider is to send the browser back to.
    fn redirect_uri(&self, session: &Session, ctx: &Ctx) -> Option<String> {
        if let Some(url) = &self.redirect_url {
            return Some(url.clone());
        }
        let header = session.req_header();
        let host = header
            .uri
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| header.headers.get(HOST)?.to_str().ok())?;
        let scheme = if ctx.conn.tls_version.is_some() {
            "https"
        } else {
            "http"
        };
        Some(format!("{scheme}://{host}{}", self.redirect_path))
    }

    async fn discover(&self) -> std::result::Result<Provider, String> {
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !response.status().is_success() {
            return Err(format!("discovery answers {}", response.status()));
        }
        let discovery = response
            .json::<Discovery>()
            .await
            .map_err(|e| e.without_url().to_string())?;
        // Who answers has to be who was asked: the tokens are held to
        // this name.
        if discovery.issuer.trim_end_matches('/') != self.issuer {
            return Err(format!(
                "the provider calls itself {:?}, not {:?}",
                discovery.issuer, self.issuer
            ));
        }
        for (name, url) in [
            ("authorization_endpoint", &discovery.authorization_endpoint),
            ("token_endpoint", &discovery.token_endpoint),
            ("jwks_uri", &discovery.jwks_uri),
        ] {
            if !is_http_url(url) {
                return Err(format!("{name} of the provider is not a url"));
            }
        }
        let basic_auth = discovery
            .token_endpoint_auth_methods_supported
            .is_none_or(|methods| {
                methods.iter().any(|method| method == "client_secret_basic")
            });
        Ok(Provider {
            authorization_endpoint: discovery.authorization_endpoint,
            token_endpoint: discovery.token_endpoint,
            end_session_endpoint: discovery
                .end_session_endpoint
                .filter(|url| is_http_url(url)),
            basic_auth,
            jwks: Arc::new(JwksSource::new(
                discovery.jwks_uri,
                self.client.clone(),
            )),
            fetched_at: Instant::now(),
        })
    }

    /// The provider: what it said of itself the last time, asked again
    /// when that was long ago. What there is stays when it does not
    /// answer.
    async fn provider(&self) -> Option<Arc<Provider>> {
        let fresh = |provider: &Arc<Provider>| {
            provider.fetched_at.elapsed() < DISCOVERY_TTL
        };
        if let Some(provider) = self.provider.load_full().filter(fresh) {
            return Some(provider);
        }
        let mut last_attempt = self.discovery_lock.lock().await;
        if let Some(provider) = self.provider.load_full().filter(fresh) {
            return Some(provider);
        }
        if last_attempt.is_none_or(|at| at.elapsed() >= DISCOVERY_COOLDOWN) {
            match self.discover().await {
                Ok(provider) => self.provider.store(Some(Arc::new(provider))),
                Err(e) => {
                    error!(
                        category = CATEGORY,
                        issuer = self.issuer,
                        error = e,
                        "oidc discovery failed"
                    );
                },
            }
            // From the end of the attempt: one that ran into the timeout
            // has used up as long as the wait is, and counted from its
            // start the next request in line would ask at once - each
            // one holding its client for the whole timeout.
            *last_attempt = Some(Instant::now());
        }
        self.provider.load_full()
    }

    /// Sends a browser to the provider, and keeps what is needed to take
    /// it back.
    fn to_provider(
        &self,
        session: &Session,
        ctx: &Ctx,
        provider: &Provider,
    ) -> Option<HttpResponse> {
        let url = request_uri(session, ctx)
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let mut login = Login {
            state: random::<16>(),
            verifier: random::<32>(),
            nonce: random::<16>(),
            url: local_path(url).to_string(),
            exp: now_sec() + LOGIN_TTL.as_secs(),
        };
        let mut sealed = self.seal(&login)?;
        // A page with an address so long that the login would not fit a
        // cookie: the browser would drop it, and the login could never
        // be finished. The login is worth more than the way back.
        if sealed.len() > MAX_COOKIE_VALUE {
            login.url = "/".to_string();
            sealed = self.seal(&login)?;
        }
        let challenge =
            URL_SAFE_NO_PAD.encode(Sha256::digest(login.verifier.as_bytes()));
        let redirect_uri = self.redirect_uri(session, ctx)?;
        let separator = if provider.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let location = format!(
            "{}{separator}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={challenge}&code_challenge_method=S256",
            provider.authorization_endpoint,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode(&self.scopes),
            login.state,
            login.nonce,
        );
        let cookie = self.cookie(
            &self.login_cookie_name(&login.state),
            &sealed,
            &self.redirect_path,
            LOGIN_TTL.as_secs(),
            self.is_secure(ctx),
        )?;
        let mut response = HttpResponse::redirect(&location).ok()?;
        response.headers.get_or_insert_default().push(cookie);
        Some(no_store(response))
    }

    /// The ID token for `code`, with what it says: verified with the
    /// keys of the provider, issued by it, for this client, and for the
    /// login that asked.
    async fn exchange(
        &self,
        provider: &Provider,
        code: &str,
        login: &Login,
        redirect_uri: &str,
    ) -> std::result::Result<ClaimMap, String> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", login.verifier.as_str()),
        ];
        let mut request = self.client.post(&provider.token_endpoint);
        if self.client_secret.is_empty() {
            form.push(("client_id", self.client_id.as_str()));
        } else if provider.basic_auth {
            // The two are form-encoded before they are put together
            // (RFC 6749, 2.3.1).
            let credentials = format!(
                "{}:{}",
                urlencoding::encode(&self.client_id),
                urlencoding::encode(&self.client_secret)
            );
            let value = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(credentials)
            );
            request = request.header(AUTHORIZATION, value);
        } else {
            form.push(("client_id", self.client_id.as_str()));
            form.push(("client_secret", self.client_secret.as_str()));
        }
        let body = form
            .iter()
            .map(|(name, value)| {
                format!("{name}={}", urlencoding::encode(value))
            })
            .collect::<Vec<_>>()
            .join("&");
        let response = request
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(ACCEPT, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        let status = response.status();
        if !status.is_success() {
            // What it says is not written out: it may name the code.
            return Err(format!("the token endpoint answers {status}"));
        }
        let token = response
            .json::<TokenResponse>()
            .await
            .map_err(|e| e.without_url().to_string())?
            .id_token
            .ok_or_else(|| "no id_token in the answer".to_string())?;
        let claims = provider
            .jwks
            .verify_with(&token, |algorithm: Algorithm| {
                let mut validation = Validation::new(algorithm);
                validation.leeway = LEEWAY;
                validation.validate_nbf = true;
                validation.set_audience(&[self.client_id.as_str()]);
                validation.set_issuer(&[
                    self.issuer.as_str(),
                    &format!("{}/", self.issuer),
                ]);
                validation
                    .set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
                validation
            })
            .await
            .ok_or_else(|| "the id_token does not verify".to_string())?;
        // The token is the answer to this login and to no other.
        let nonce = claims
            .get("nonce")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if !constant_time_eq(nonce.as_bytes(), login.nonce.as_bytes()) {
            return Err("the id_token is not for this login".to_string());
        }
        Ok(claims)
    }

    /// A browser that comes back from the provider.
    async fn callback(
        &self,
        session: &Session,
        ctx: &Ctx,
    ) -> std::result::Result<HttpResponse, Refusal> {
        let header = session.req_header();
        let uri = request_uri(session, ctx);
        let query = |name: &str| {
            uri.query()
                .unwrap_or_default()
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value)
                .filter(|value| value.len() <= MAX_QUERY_VALUE)
                .map(|value| {
                    urlencoding::decode(value)
                        .map(|value| value.to_string())
                        .unwrap_or_default()
                })
                .unwrap_or_default()
        };
        let error = query("error");
        if !error.is_empty() {
            // The name of the error, which is one of a few words: not
            // what else the provider or anybody else put in the query.
            let known = error.len() <= 64
                && error
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
            return Err(Refusal::Denied(format!(
                "Login refused: {}",
                if known { error.as_str() } else { "error" }
            )));
        }
        let (code, state) = (query("code"), query("state"));
        if code.is_empty() || state.is_empty() {
            return Err(Refusal::Request("no login to finish"));
        }
        let cookie_name = self.login_cookie_name(&state);
        let login = get_cookie_value(header, &cookie_name)
            .and_then(|cookie| self.unseal::<Login>(cookie))
            .filter(|login| {
                constant_time_eq(login.state.as_bytes(), state.as_bytes())
            })
            .ok_or(Refusal::Request(
                "this login was not started here, or was finished already",
            ))?;
        if login.exp <= now_sec() {
            return Err(Refusal::Request("the login took too long"));
        }
        let provider = self.provider().await.ok_or_else(|| {
            Refusal::Provider("the provider can not be reached".to_string())
        })?;
        let redirect_uri = self
            .redirect_uri(session, ctx)
            .ok_or(Refusal::Request("the request has no host"))?;
        let claims = self
            .exchange(&provider, &code, &login, &redirect_uri)
            .await
            .map_err(Refusal::Provider)?;

        // What is kept of the user: who it is, and what goes upstream.
        let mut kept = ClaimMap::new();
        for name in std::iter::once("sub").chain(
            self.claims_to_headers
                .iter()
                .map(|(claim, _)| claim.as_str()),
        ) {
            if let Some(value) = claims.get(name) {
                kept.insert(name.to_string(), value.clone());
            }
        }
        let data = SessionData {
            exp: now_sec() + self.session_ttl.as_secs(),
            claims: kept,
        };
        let secure = self.is_secure(ctx);
        let too_large = || {
            Refusal::Provider("the session does not fit a cookie".to_string())
        };
        let sealed = self
            .seal(&data)
            .filter(|value| value.len() <= MAX_COOKIE_VALUE);
        let session_cookie = sealed
            .and_then(|value| {
                self.cookie(
                    &self.cookie_name,
                    &value,
                    "/",
                    self.session_ttl.as_secs(),
                    secure,
                )
            })
            .ok_or_else(too_large)?;
        let mut response = HttpResponse::redirect(local_path(&login.url))
            .map_err(|e| Refusal::Provider(e.to_string()))?;
        let headers = response.headers.get_or_insert_default();
        headers.push(session_cookie);
        // The login is done with: its cookie goes, and with it those of
        // the logins of this browser that were started and left.
        let prefix = format!("{}_", self.cookie_name);
        let stale = header
            .headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .map(|(name, _)| name)
            .filter(|name| name.starts_with(&prefix) && *name != cookie_name)
            .take(MAX_STALE_LOGINS);
        for name in std::iter::once(cookie_name.as_str()).chain(stale) {
            if is_cookie_name(name)
                && let Some(cookie) =
                    self.cookie(name, "", &self.redirect_path, 0, secure)
            {
                headers.push(cookie);
            }
        }
        Ok(no_store(response))
    }

    /// Ends the session: the cookie goes, and the browser is sent to
    /// where the provider ends its own, when it has such a place.
    async fn logout(&self, ctx: &Ctx) -> HttpResponse {
        let end_session = self
            .provider()
            .await
            .and_then(|provider| provider.end_session_endpoint.clone());
        let mut response = end_session
            .and_then(|url| {
                let separator = if url.contains('?') { '&' } else { '?' };
                HttpResponse::redirect(&format!(
                    "{url}{separator}client_id={}",
                    urlencoding::encode(&self.client_id)
                ))
                .ok()
            })
            .unwrap_or_else(|| {
                HttpResponse::builder(StatusCode::OK)
                    .body("Logged out")
                    .finish()
            });
        if let Some(cookie) =
            self.cookie(&self.cookie_name, "", "/", 0, self.is_secure(ctx))
        {
            response.headers.get_or_insert_default().push(cookie);
        }
        no_store(response)
    }

    /// Puts what the session says of the user into the headers it is
    /// configured to go in, and takes out whatever the client wrote
    /// there itself.
    ///
    /// Whatever passes for one of them to an upstream goes as well: the
    /// same name with `_` for `-`. And the client does not get to take
    /// one of them away by naming it in `Connection`.
    fn set_claim_headers(&self, session: &mut Session, data: &SessionData) {
        let header = session.req_header_mut();
        strip_claim_headers(header, &self.own_headers);
        for (claim, name) in self.claims_to_headers.iter() {
            if let Some(value) =
                data.claims.get(claim).and_then(claim_header_value)
            {
                let _ = header.insert_header(name.clone(), value);
            }
        }
        protect_from_connection_header(header, &self.own_headers);
    }
}

/// The address of a request as the client wrote it: a location may have
/// rewritten the one the request header has by now.
fn request_uri<'a>(session: &'a Session, ctx: &'a Ctx) -> &'a http::Uri {
    ctx.features
        .as_ref()
        .and_then(|features| features.original_uri.as_ref())
        .unwrap_or(&session.req_header().uri)
}

/// A response that is one user's, and one moment's.
fn no_store(mut response: HttpResponse) -> HttpResponse {
    let headers = response.headers.get_or_insert_default();
    headers.retain(|(name, _)| name != CACHE_CONTROL);
    headers.push((CACHE_CONTROL, HeaderValue::from_static("no-store")));
    response
}

fn text(status: StatusCode, message: &str) -> HttpResponse {
    no_store(
        HttpResponse::builder(status)
            .body(message.to_string())
            .finish(),
    )
}

/// Whether a request is a browser going to a page: that can be sent on
/// to the provider. A script that fetches, or a form that is posted, can
/// not follow there and is told that it has no session.
fn is_navigation(session: &Session) -> bool {
    let header = session.req_header();
    if header.method != Method::GET {
        return false;
    }
    let value = |name: &str| {
        header
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    };
    match value("sec-fetch-mode") {
        "" => value("accept").contains("text/html"),
        mode => mode == "navigate",
    }
}

#[async_trait]
impl Plugin for Oidc {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        // The path the client asked for: a rewrite of the location is not
        // what the provider was told to come back to.
        let path = request_uri(session, ctx).path().to_string();
        if path == self.redirect_path {
            let response = match self.callback(session, ctx).await {
                Ok(response) => response,
                Err(Refusal::Request(message)) => {
                    text(StatusCode::BAD_REQUEST, message)
                },
                Err(Refusal::Denied(message)) => {
                    text(StatusCode::FORBIDDEN, &message)
                },
                Err(Refusal::Provider(message)) => {
                    warn!(
                        category = CATEGORY,
                        issuer = self.issuer,
                        error = message,
                        "oidc login failed"
                    );
                    text(StatusCode::BAD_GATEWAY, "Login failed")
                },
            };
            return Ok(RequestPluginResult::Respond(response));
        }
        if self.logout_path.as_deref() == Some(path.as_str()) {
            return Ok(RequestPluginResult::Respond(self.logout(ctx).await));
        }
        if let Some(data) = self.session(session, now_sec()) {
            self.set_claim_headers(session, &data);
            return Ok(RequestPluginResult::Continue);
        }
        // Not what a client without a session gets to say of itself.
        strip_claim_headers(session.req_header_mut(), &self.own_headers);
        if !is_navigation(session) {
            return Ok(RequestPluginResult::Respond(text(
                StatusCode::UNAUTHORIZED,
                "Login required",
            )));
        }
        let response = match self.provider().await {
            Some(provider) => self.to_provider(session, ctx, &provider),
            None => None,
        };
        Ok(RequestPluginResult::Respond(response.unwrap_or_else(
            || text(StatusCode::BAD_GATEWAY, "Login is not available"),
        )))
    }
}

register_plugin!("oidc", Oidc);

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use pretty_assertions::assert_eq;
    use std::sync::Mutex;
    use tokio_test::io::Builder;

    const BASE: &str = "issuer = \"https://idp.test/\"\nclient_id = \"pingap\"\nclient_secret = \"s3cret\"\ncookie_secret = \"0123456789abcdef0123456789abcdef\"\n";

    const PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECE/4ox+pGq+yiB3RqIXINmlHJp+l
6V8vXffF5UzI/h3RPK3l9MphCKS2wg50uVoWlBITXMRhh5LVB/93vQZa0Q==
-----END PUBLIC KEY-----"#;
    // spellchecker:off
    const PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6V2VwZk30Az6VKMF
Bt6nfEa2r4hCQuuMB6azsjMB7xmhRANCAAQIT/ijH6kar7KIHdGohcg2aUcmn6Xp
Xy9d98XlTMj+HdE8reX0ymEIpLbCDnS5WhaUEhNcxGGHktUH/3e9BlrR
-----END PRIVATE KEY-----"#;
    // spellchecker:on

    /// A client that asks the servers of the tests themselves, whatever
    /// proxy the environment names.
    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    fn new_plugin(extra: &str) -> Result<Oidc> {
        let conf = format!("{BASE}{extra}");
        let mut plugin =
            Oidc::new(&toml::from_str::<PluginConf>(&conf).unwrap())?;
        plugin.client = test_client();
        Ok(plugin)
    }

    async fn new_session(request: &str) -> Session {
        let mock_io = Builder::new().read(request.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    /// A provider whose token endpoint is `token_endpoint`, with the key
    /// of the tests.
    fn provider(token_endpoint: &str) -> Arc<Provider> {
        Arc::new(Provider {
            authorization_endpoint: "https://idp.test/authorize".to_string(),
            token_endpoint: token_endpoint.to_string(),
            end_session_endpoint: Some("https://idp.test/logout".to_string()),
            basic_auth: true,
            jwks: Arc::new(JwksSource::with_ec_key(PUBLIC_KEY)),
            fetched_at: Instant::now(),
        })
    }

    fn header_of<'a>(response: &'a HttpResponse, name: &str) -> Vec<&'a str> {
        response
            .headers
            .iter()
            .flatten()
            .filter(|(key, _)| key.as_str() == name)
            .filter_map(|(_, value)| value.to_str().ok())
            .collect()
    }

    #[test]
    fn test_oidc_params() {
        let plugin = new_plugin("").unwrap();
        // As the provider names itself, without the slash.
        assert_eq!("https://idp.test", plugin.issuer);
        assert_eq!(DEFAULT_REDIRECT_PATH, plugin.redirect_path);
        assert_eq!("openid", plugin.scopes);
        assert_eq!(DEFAULT_COOKIE_NAME, plugin.cookie_name);
        assert_eq!(DEFAULT_SESSION_TTL, plugin.session_ttl);
        assert_eq!(None, plugin.logout_path);
        assert_eq!(true, plugin.claims_to_headers.is_empty());

        let plugin = new_plugin(
            "redirect_path = \"/auth/back\"\nredirect_url = \"https://app.test/auth/back\"\nlogout_path = \"/auth/bye\"\nscopes = [\"email\", \"openid\", \"profile\"]\ncookie_name = \"sid\"\nsession_ttl = \"30m\"\nclaims_to_headers = [\"email:X-User-Email\", \"sub: X-User\"]",
        )
        .unwrap();
        assert_eq!("/auth/back", plugin.redirect_path);
        assert_eq!(Some("/auth/bye".to_string()), plugin.logout_path);
        assert_eq!("openid email profile", plugin.scopes);
        assert_eq!("sid", plugin.cookie_name);
        assert_eq!(Duration::from_secs(1800), plugin.session_ttl);
        assert_eq!(
            vec![
                ("email".to_string(), HeaderName::from_static("x-user-email")),
                ("sub".to_string(), HeaderName::from_static("x-user")),
            ],
            plugin.claims_to_headers
        );

        let new = |conf: &str| {
            Oidc::new(&toml::from_str::<PluginConf>(conf).unwrap())
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        };
        for (conf, message) in [
            ("client_id = \"a\"", "issuer is required"),
            (
                "issuer = \"idp.test\"\nclient_id = \"a\"",
                "issuer is required",
            ),
            ("issuer = \"https://idp.test\"", "client_id is required"),
            (
                "issuer = \"https://idp.test\"\nclient_id = \"a\"\ncookie_secret = \"short\"",
                "cookie_secret is required, 16 characters at least",
            ),
        ] {
            let error = new(conf);
            assert_eq!(true, error.contains(message), "{conf}: {error}");
        }
        for (extra, message) in [
            ("step = \"response\"", "should be executed at request step"),
            ("redirect_path = \"callback\"", "is not a path"),
            ("redirect_path = \"//evil.test/x\"", "is not a path"),
            ("redirect_path = \"/cb?x=1\"", "is not a path"),
            ("redirect_path = \"/\"", "is not a path"),
            (
                "logout_path = \"/oauth2/callback\"",
                "logout_path can not be the redirect_path",
            ),
            (
                "redirect_url = \"https://app.test/elsewhere\"",
                "whose path is the redirect_path",
            ),
            (
                "redirect_url = \"/oauth2/callback\"",
                "redirect_url should be",
            ),
            ("scopes = [\"a b\"]", "is not a scope"),
            ("cookie_name = \"a=b\"", "cookie_name"),
            ("session_ttl = \"10s\"", "session_ttl should be at least 1m"),
            (
                "claims_to_headers = [\"email\"]",
                "should be claim:Header-Name",
            ),
            (
                "claims_to_headers = [\"email:X User\"]",
                "is not a header name",
            ),
        ] {
            let error = new_plugin(extra)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert_eq!(true, error.contains(message), "{extra}: {error}");
        }
    }

    #[test]
    fn test_local_path() {
        for (value, expected) in [
            ("/app/page?x=1", "/app/page?x=1"),
            ("/", "/"),
            // Another site, to a browser.
            ("//evil.test/x", "/"),
            ("/\\evil.test/x", "/"),
            ("https://evil.test/", "/"),
            ("evil.test", "/"),
            ("/a\r\nSet-Cookie: x=1", "/"),
            ("", "/"),
        ] {
            assert_eq!(expected, local_path(value), "{value:?}");
        }
    }

    /// What is sealed is read by who has the secret, as it was written.
    #[test]
    fn test_sealed_values() {
        let plugin = new_plugin("").unwrap();
        let data = SessionData {
            exp: 42,
            claims: ClaimMap::from_iter([(
                "sub".to_string(),
                serde_json::json!("u-1"),
            )]),
        };
        let sealed = plugin.seal(&data).unwrap();
        // Not the same text twice, and nothing of the content in it.
        assert_eq!(true, sealed != plugin.seal(&data).unwrap());
        assert_eq!(false, sealed.contains("u-1"));
        let opened = plugin.unseal::<SessionData>(&sealed).unwrap();
        assert_eq!(42, opened.exp);
        assert_eq!(Some(&serde_json::json!("u-1")), opened.claims.get("sub"));

        // One character of it changed, or cut off.
        let mut changed = sealed.clone().into_bytes();
        let last = changed.len() - 1;
        changed[last] = if changed[last] == b'A' { b'B' } else { b'A' };
        let changed = String::from_utf8(changed).unwrap();
        assert_eq!(true, plugin.unseal::<SessionData>(&changed).is_none());
        assert_eq!(
            true,
            plugin
                .unseal::<SessionData>(&sealed[..sealed.len() - 4])
                .is_none()
        );
        assert_eq!(true, plugin.unseal::<SessionData>("").is_none());
        // Another secret, or the same one with another provider or
        // another client: not its sessions.
        for (from, to) in [
            ("0123456789abcdef", "fedcba9876543210"),
            ("https://idp.test/", "https://idp2.test/"),
            ("client_id = \"pingap\"", "client_id = \"other\""),
        ] {
            let other = Oidc::new(
                &toml::from_str::<PluginConf>(&BASE.replace(from, to)).unwrap(),
            )
            .unwrap();
            assert_eq!(
                true,
                other.unseal::<SessionData>(&sealed).is_none(),
                "{to}"
            );
        }
        // The same settings: the same sessions, on any instance.
        let same = new_plugin("session_ttl = \"1h\"").unwrap();
        assert_eq!(true, same.unseal::<SessionData>(&sealed).is_some());
        // A login is not a session.
        let login = Login {
            state: "s".to_string(),
            verifier: "v".to_string(),
            nonce: "n".to_string(),
            url: "/".to_string(),
            exp: u64::MAX,
        };
        let sealed = plugin.seal(&login).unwrap();
        assert_eq!(true, plugin.unseal::<SessionData>(&sealed).is_none());
    }

    /// Who has no session is sent to the provider, or told so; who has
    /// one goes on, with what the provider said of them in the headers.
    #[tokio::test]
    async fn test_oidc_request() {
        let plugin = new_plugin(
            "claims_to_headers = [\"email:X-User-Email\", \"groups:X-User-Groups\"]\nlogout_path = \"/bye\"",
        )
        .unwrap();
        plugin
            .provider
            .store(Some(provider("http://127.0.0.1:1/token")));
        let handle = |request: String, tls: bool| {
            let plugin = &plugin;
            async move {
                let mut session = new_session(&request).await;
                let mut ctx = Ctx::default();
                if tls {
                    ctx.conn.tls_version = Some("TLSv1.3".into());
                }
                let result = plugin
                    .handle_request(PluginStep::Request, &mut session, &mut ctx)
                    .await
                    .unwrap();
                (result, session)
            }
        };
        let page = "GET /app/page?x=1 HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\n\r\n";

        // A page: to the provider, with the login kept in a cookie.
        let (result, _) = handle(page.to_string(), false).await;
        let RequestPluginResult::Respond(response) = result else {
            panic!("no response");
        };
        assert_eq!(true, response.status.is_redirection());
        let location = header_of(&response, "location")[0].to_string();
        assert_eq!(
            true,
            location.starts_with(
                "https://idp.test/authorize?response_type=code&client_id=pingap&redirect_uri=http%3A%2F%2Fapp.test%2Foauth2%2Fcallback&scope=openid&state="
            ),
            "{location}"
        );
        assert_eq!(true, location.contains("&code_challenge_method=S256"));
        assert_eq!(vec!["no-store"], header_of(&response, "cache-control"));
        let cookie = header_of(&response, "set-cookie")[0].to_string();
        assert_eq!(true, cookie.starts_with("pingap_oidc_"), "{cookie}");
        assert_eq!(
            true,
            cookie.ends_with(
                "; Path=/oauth2/callback; Max-Age=600; HttpOnly; SameSite=Lax"
            ),
            "{cookie}"
        );
        // What the cookie keeps is what the url says, and where to go
        // back to.
        let (name, sealed) = cookie
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .unwrap();
        let login = plugin.unseal::<Login>(sealed).unwrap();
        assert_eq!("/app/page?x=1", login.url);
        assert_eq!(true, location.contains(&format!("&state={}", login.state)));
        assert_eq!(true, location.contains(&format!("&nonce={}", login.nonce)));
        assert_eq!(name, plugin.login_cookie_name(&login.state));
        let challenge =
            URL_SAFE_NO_PAD.encode(Sha256::digest(login.verifier.as_bytes()));
        assert_eq!(
            true,
            location.contains(&format!("&code_challenge={challenge}&"))
        );
        // Over TLS the provider is given an https address, and the cookie
        // is for TLS alone.
        let (result, _) = handle(page.to_string(), true).await;
        let RequestPluginResult::Respond(response) = result else {
            panic!("no response");
        };
        assert_eq!(
            true,
            header_of(&response, "location")[0].contains(
                "redirect_uri=https%3A%2F%2Fapp.test%2Foauth2%2Fcallback"
            )
        );
        assert_eq!(
            true,
            header_of(&response, "set-cookie")[0].ends_with("; Secure")
        );

        // What can not follow to the provider is told it has no session:
        // a script, a form that is posted.
        for request in [
            "GET /api HTTP/1.1\r\nHost: app.test\r\nAccept: application/json\r\n\r\n",
            "GET /api HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nSec-Fetch-Mode: cors\r\n\r\n",
            "POST /form HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nContent-Length: 0\r\n\r\n",
        ] {
            let (result, _) = handle(request.to_string(), false).await;
            let RequestPluginResult::Respond(response) = result else {
                panic!("no response");
            };
            assert_eq!(StatusCode::UNAUTHORIZED, response.status, "{request}");
        }

        // With a session: on to the upstream, and the headers say who it
        // is - whatever the client wrote into them.
        let session_of = |exp: u64| {
            let claims = ClaimMap::from_iter([
                ("sub".to_string(), serde_json::json!("u-1")),
                ("email".to_string(), serde_json::json!("ada@example.test")),
                ("groups".to_string(), serde_json::json!(["dev", "ops"])),
            ]);
            plugin.seal(&SessionData { exp, claims }).unwrap()
        };
        let request = |cookie: &str| {
            format!(
                "GET /api HTTP/1.1\r\nHost: app.test\r\nAccept: application/json\r\nX-User-Email: mallory@evil.test\r\nX-User-Groups: admin\r\nCookie: a=b; pingap_oidc={cookie}\r\n\r\n"
            )
        };
        let (result, session) =
            handle(request(&session_of(now_sec() + 60)), false).await;
        assert_eq!(true, matches!(result, RequestPluginResult::Continue));
        let headers = &session.req_header().headers;
        assert_eq!("ada@example.test", headers["x-user-email"]);
        assert_eq!("dev,ops", headers["x-user-groups"]);
        assert_eq!(1, headers.get_all("x-user-email").iter().count());

        // A session that has run out, or is none: no session, and
        // nothing of what the client claims goes on.
        for cookie in [session_of(now_sec() - 1), "junk".to_string()] {
            let (result, session) = handle(request(&cookie), false).await;
            let RequestPluginResult::Respond(response) = result else {
                panic!("no response");
            };
            assert_eq!(StatusCode::UNAUTHORIZED, response.status);
            assert_eq!(
                false,
                session.req_header().headers.contains_key("x-user-email")
            );
        }

        // Logout: the cookie goes, the browser to the provider.
        let (result, _) = handle(
            "GET /bye HTTP/1.1\r\nHost: app.test\r\n\r\n".to_string(),
            false,
        )
        .await;
        let RequestPluginResult::Respond(response) = result else {
            panic!("no response");
        };
        assert_eq!(
            vec!["https://idp.test/logout?client_id=pingap"],
            header_of(&response, "location")
        );
        assert_eq!(
            vec!["pingap_oidc=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"],
            header_of(&response, "set-cookie")
        );

        // At another step it is not this plugin's turn.
        let mut session = new_session(page).await;
        let result = plugin
            .handle_request(
                PluginStep::ProxyUpstream,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, matches!(result, RequestPluginResult::Skipped));
    }

    /// What a token endpoint of a test answers with, and what it was
    /// asked.
    #[derive(Default)]
    struct TokenEndpoint {
        answer: Mutex<String>,
        requests: Mutex<Vec<String>>,
    }

    async fn serve(endpoint: Arc<TokenEndpoint>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut request = vec![];
                let mut buf = [0u8; 4096];
                loop {
                    let Ok(count) = stream.read(&mut buf).await else {
                        return;
                    };
                    request.extend_from_slice(&buf[..count]);
                    let text = String::from_utf8_lossy(&request).to_lowercase();
                    let done = text.split_once("\r\n\r\n").is_some_and(
                        |(head, body)| {
                            let length = head
                                .lines()
                                .find_map(|line| {
                                    line.strip_prefix("content-length:")
                                })
                                .and_then(|value| value.trim().parse().ok())
                                .unwrap_or(0usize);
                            body.len() >= length
                        },
                    );
                    if done || count == 0 {
                        break;
                    }
                }
                endpoint
                    .requests
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request).to_string());
                let answer = endpoint.answer.lock().unwrap().clone();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        format!("http://{addr}/token")
    }

    /// A browser that comes back from the provider: the code is traded
    /// for a token, and a session is made of a token that is the
    /// provider's, for this client and for this login - and of no other.
    #[tokio::test]
    async fn test_oidc_callback() {
        let endpoint = Arc::new(TokenEndpoint::default());
        let token_url = serve(endpoint.clone()).await;
        let plugin =
            new_plugin("claims_to_headers = [\"email:X-User-Email\"]").unwrap();
        plugin.provider.store(Some(provider(&token_url)));

        let login = |exp: u64| Login {
            state: "state-0123456789".to_string(),
            verifier: "the-verifier".to_string(),
            nonce: "the-nonce".to_string(),
            url: "/app/page?x=1".to_string(),
            exp,
        };
        // The answer of the token endpoint with a token of these claims.
        let answer = |claims: serde_json::Value| {
            let token = encode(
                &Header::new(Algorithm::ES256),
                &claims,
                &EncodingKey::from_ec_pem(PRIVATE_KEY.as_bytes()).unwrap(),
            )
            .unwrap();
            *endpoint.answer.lock().unwrap() =
                serde_json::json!({"access_token": "at", "id_token": token})
                    .to_string();
        };
        let claims = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut claims = serde_json::json!({
                "iss": "https://idp.test",
                "aud": "pingap",
                "sub": "u-1",
                "exp": now_sec() + 300,
                "nonce": "the-nonce",
                "email": "ada@example.test",
                "name": "Ada",
            });
            change(&mut claims);
            claims
        };
        let callback = |query: &str, login: Option<Login>| {
            let plugin = &plugin;
            let cookie = login
                .map(|login| {
                    format!(
                        "Cookie: {}={}\r\n",
                        plugin.login_cookie_name(&login.state),
                        plugin.seal(&login).unwrap()
                    )
                })
                .unwrap_or_default();
            let request = format!(
                "GET /oauth2/callback?{query} HTTP/1.1\r\nHost: app.test\r\n{cookie}\r\n"
            );
            async move {
                let session = new_session(&request).await;
                plugin.callback(&session, &Ctx::default()).await
            }
        };
        let good = "code=c-1&state=state-0123456789";
        let later = now_sec() + 300;

        answer(claims(&|_| {}));
        let response = callback(good, Some(login(later))).await.unwrap();
        // Back to where the browser was going.
        assert_eq!(vec!["/app/page?x=1"], header_of(&response, "location"));
        let cookies = header_of(&response, "set-cookie");
        assert_eq!(2, cookies.len());
        // The session: who it is and what goes upstream, no more.
        let sealed = cookies[0]
            .strip_prefix("pingap_oidc=")
            .and_then(|rest| rest.split(';').next())
            .unwrap();
        let data = plugin.unseal::<SessionData>(sealed).unwrap();
        assert_eq!(
            vec!["email", "sub"],
            data.claims.keys().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(
            true,
            (now_sec() + 12 * 3600 - 5..=now_sec() + 12 * 3600)
                .contains(&data.exp)
        );
        assert_eq!(
            true,
            cookies[0]
                .ends_with("; Path=/; Max-Age=43200; HttpOnly; SameSite=Lax"),
            "{}",
            cookies[0]
        );
        // The login is done with.
        assert_eq!(
            "pingap_oidc_state012=; Path=/oauth2/callback; Max-Age=0; HttpOnly; SameSite=Lax",
            cookies[1]
        );
        // What the token endpoint was asked.
        {
            let requests = endpoint.requests.lock().unwrap();
            let request = requests.last().unwrap();
            assert_eq!(true, request.starts_with("POST /token HTTP/1.1"));
            // pingap:s3cret
            assert_eq!(
                true,
                request.contains("authorization: Basic cGluZ2FwOnMzY3JldA==")
            );
            assert_eq!(
                true,
                request.ends_with(
                    "grant_type=authorization_code&code=c-1&redirect_uri=http%3A%2F%2Fapp.test%2Foauth2%2Fcallback&code_verifier=the-verifier"
                ),
                "{request}"
            );
        }
        // `aud` may be a list with the client in it.
        answer(claims(&|claims| {
            claims["aud"] = serde_json::json!(["other", "pingap"]);
        }));
        assert_eq!(true, callback(good, Some(login(later))).await.is_ok());

        // A token that is not for this login, this client, from this
        // provider, or of now.
        type Change = Box<dyn Fn(&mut serde_json::Value)>;
        let changes: Vec<(Change, &str)> = vec![
            (
                Box::new(|claims| claims["nonce"] = "another".into()),
                "the id_token is not for this login",
            ),
            (
                Box::new(|claims| {
                    claims.as_object_mut().unwrap().remove("nonce");
                }),
                "the id_token is not for this login",
            ),
            (
                Box::new(|claims| claims["aud"] = "someone-else".into()),
                "the id_token does not verify",
            ),
            (
                Box::new(|claims| claims["iss"] = "https://evil.test".into()),
                "the id_token does not verify",
            ),
            (
                Box::new(|claims| claims["exp"] = (now_sec() - 3600).into()),
                "the id_token does not verify",
            ),
            (
                Box::new(|claims| {
                    claims.as_object_mut().unwrap().remove("sub");
                }),
                "the id_token does not verify",
            ),
        ];
        for (change, message) in changes {
            answer(claims(&*change));
            assert_eq!(
                Err(Refusal::Provider(message.to_string())),
                callback(good, Some(login(later))).await.map(|_| ())
            );
        }
        // No token at all.
        *endpoint.answer.lock().unwrap() = "{}".to_string();
        assert_eq!(
            Err(Refusal::Provider("no id_token in the answer".to_string())),
            callback(good, Some(login(later))).await.map(|_| ())
        );

        // A request that is not the end of a login started here. The
        // token endpoint is not asked for any of them.
        answer(claims(&|_| {}));
        let asked = endpoint.requests.lock().unwrap().len();
        let not_started = Err(Refusal::Request(
            "this login was not started here, or was finished already",
        ));
        assert_eq!(not_started, callback(good, None).await.map(|_| ()));
        // The state of another login, whose cookie this browser has not.
        assert_eq!(
            not_started,
            callback("code=c-1&state=state-01XXXXXXXX", Some(login(later)))
                .await
                .map(|_| ())
        );
        assert_eq!(
            Err(Refusal::Request("the login took too long")),
            callback(good, Some(login(now_sec() - 1))).await.map(|_| ())
        );
        assert_eq!(
            Err(Refusal::Request("no login to finish")),
            callback("state=state-0123456789", Some(login(later)))
                .await
                .map(|_| ())
        );
        // The provider would not: its word for it, and nothing else of
        // what the query says.
        assert_eq!(
            Err(Refusal::Denied("Login refused: access_denied".to_string())),
            callback("error=access_denied&state=x", None)
                .await
                .map(|_| ())
        );
        assert_eq!(
            Err(Refusal::Denied("Login refused: error".to_string())),
            callback("error=%3Cscript%3E", None).await.map(|_| ())
        );
        assert_eq!(asked, endpoint.requests.lock().unwrap().len());
    }

    /// What the settings refuse, of what an earlier version let through.
    #[test]
    fn test_oidc_params_of_headers_and_cookies() {
        // The name of a claim may have colons in it: the header is what
        // is after the last one.
        let plugin = new_plugin(
            "claims_to_headers = [\"https://example.com/roles:X-Roles\", \"cognito:groups:X-Groups\"]",
        )
        .unwrap();
        assert_eq!(
            vec![
                (
                    "https://example.com/roles".to_string(),
                    HeaderName::from_static("x-roles")
                ),
                (
                    "cognito:groups".to_string(),
                    HeaderName::from_static("x-groups")
                ),
            ],
            plugin.claims_to_headers
        );
        for (extra, message) in [
            // What frames the body or names the upstream.
            (
                "claims_to_headers = [\"sub:Host\"]",
                "is not a header for a claim",
            ),
            (
                "claims_to_headers = [\"sub:Transfer-Encoding\"]",
                "is not a header for a claim",
            ),
            // A cookie a browser takes for the path `/` alone.
            (
                "cookie_name = \"__Host-sid\"",
                "cookie_name can not begin with __Host-",
            ),
        ] {
            let error = new_plugin(extra)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert_eq!(true, error.contains(message), "{extra}: {error}");
        }
        assert_eq!(true, new_plugin("cookie_name = \"__Secure-sid\"").is_ok());
    }

    /// Regression: the client could take a header of a claim away from
    /// the upstream by naming it in `Connection`, and put its own beside
    /// it under a name with `_` for `-`, which is the same variable to
    /// what sits behind CGI, WSGI, Rack or PHP.
    #[tokio::test]
    async fn test_oidc_claim_headers_are_not_the_clients() {
        let plugin = new_plugin(
            "claims_to_headers = [\"email:X-User-Email\", \"address:X-User-Address\"]",
        )
        .unwrap();
        plugin
            .provider
            .store(Some(provider("http://127.0.0.1:1/token")));
        let claims = ClaimMap::from_iter([
            ("sub".to_string(), serde_json::json!("u-1")),
            ("email".to_string(), serde_json::json!("ada@example.test")),
            // Not something a header can say.
            ("address".to_string(), serde_json::json!({"city": "x"})),
        ]);
        let sealed = plugin
            .seal(&SessionData {
                exp: now_sec() + 60,
                claims,
            })
            .unwrap();
        for cookie in
            [format!("Cookie: pingap_oidc={sealed}\r\n"), String::new()]
        {
            let request = format!(
                "GET /api HTTP/1.1\r\nHost: app.test\r\nAccept: application/json\r\nConnection: keep-alive, X-User-Email\r\nX_User_Email: admin@corp.test\r\nx-user_address: nowhere\r\nX-Other: kept\r\n{cookie}\r\n"
            );
            let mut session = new_session(&request).await;
            let result = plugin
                .handle_request(
                    PluginStep::Request,
                    &mut session,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            let headers = &session.req_header().headers;
            // Nothing the client wrote under either spelling goes on.
            assert_eq!(false, headers.contains_key("x_user_email"));
            assert_eq!(false, headers.contains_key("x-user_address"));
            assert_eq!("kept", headers["x-other"]);
            if cookie.is_empty() {
                assert_eq!(
                    true,
                    matches!(result, RequestPluginResult::Respond(_))
                );
                assert_eq!(false, headers.contains_key("x-user-email"));
                continue;
            }
            assert_eq!(true, matches!(result, RequestPluginResult::Continue));
            assert_eq!("ada@example.test", headers["x-user-email"]);
            // A claim that is an object sends no header.
            assert_eq!(false, headers.contains_key("x-user-address"));
            // And the header is not one the proxy drops on the way out.
            assert_eq!("keep-alive", headers["connection"]);
        }
    }

    /// Regression: with a `rewrite` on the location the plugin went by
    /// the rewritten address. The callback was not recognised - a
    /// redirect to the provider again, round after round - and the way
    /// back after a login was a page outside the location.
    #[tokio::test]
    async fn test_oidc_goes_by_the_address_the_client_asked_for() {
        let plugin =
            new_plugin("redirect_path = \"/wiki/oauth2/callback\"").unwrap();
        plugin
            .provider
            .store(Some(provider("http://127.0.0.1:1/token")));
        let handle = |original: &'static str, rewritten: &'static str| {
            let plugin = &plugin;
            async move {
                let request = format!(
                    "GET {rewritten} HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\n\r\n"
                );
                let mut session = new_session(&request).await;
                let mut ctx = Ctx::default();
                ctx.features.get_or_insert_default().original_uri =
                    Some(original.parse().unwrap());
                let result = plugin
                    .handle_request(PluginStep::Request, &mut session, &mut ctx)
                    .await
                    .unwrap();
                let RequestPluginResult::Respond(response) = result else {
                    panic!("no response");
                };
                response
            }
        };
        // A page: the way back is the page as the browser knows it.
        let response = handle("/wiki/Home?x=1", "/Home?x=1").await;
        let cookie = header_of(&response, "set-cookie")[0].to_string();
        let sealed = cookie
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .map(|(_, value)| value)
            .unwrap();
        assert_eq!(
            "/wiki/Home?x=1",
            plugin.unseal::<Login>(sealed).unwrap().url
        );
        // The callback: taken for one, and its query read as it came.
        let response = handle(
            "/wiki/oauth2/callback?error=access_denied",
            "/oauth2/callback",
        )
        .await;
        assert_eq!(StatusCode::FORBIDDEN, response.status);
        assert_eq!("Login refused: access_denied", response.body);
        // What the plugin answers with for the other ways a login ends.
        let response =
            handle("/wiki/oauth2/callback?code=c&state=s", "/x").await;
        assert_eq!(StatusCode::BAD_REQUEST, response.status);
    }

    /// A page with an address too long to keep: the login goes on, and
    /// ends at the front page. The cookie of it was one a browser drops,
    /// and no such login could be finished.
    #[tokio::test]
    async fn test_oidc_login_fits_a_cookie() {
        let plugin = new_plugin("").unwrap();
        plugin
            .provider
            .store(Some(provider("http://127.0.0.1:1/token")));
        for (length, kept) in [(2000, true), (6000, false)] {
            let path = format!("/search?q={}", "a".repeat(length));
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: app.test\r\nSec-Fetch-Mode: navigate\r\n\r\n"
            );
            let mut session = new_session(&request).await;
            let result = plugin
                .handle_request(
                    PluginStep::Request,
                    &mut session,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            // `Sec-Fetch-Mode: navigate` is a browser going to a page,
            // whatever it accepts.
            let RequestPluginResult::Respond(response) = result else {
                panic!("no response");
            };
            assert_eq!(true, response.status.is_redirection());
            let cookie = header_of(&response, "set-cookie")[0].to_string();
            assert_eq!(true, cookie.len() < 4096, "{}", cookie.len());
            let sealed = cookie
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
                .map(|(_, value)| value)
                .unwrap();
            let login = plugin.unseal::<Login>(sealed).unwrap();
            assert_eq!(if kept { path.as_str() } else { "/" }, login.url);
        }
    }

    /// What the provider says of itself: taken when it is the provider
    /// that was asked, and asked again only after a while when it does
    /// not answer.
    #[tokio::test]
    async fn test_oidc_discovery() {
        let endpoint = Arc::new(TokenEndpoint::default());
        let base = serve(endpoint.clone())
            .await
            .trim_end_matches("/token")
            .to_string();
        let plugin_for = |issuer: &str| {
            let mut plugin = Oidc::new(
                &toml::from_str::<PluginConf>(
                    &BASE.replace("https://idp.test/", issuer),
                )
                .unwrap(),
            )
            .unwrap();
            plugin.client = test_client();
            plugin
        };
        let document = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut document = serde_json::json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "jwks_uri": format!("{base}/jwks"),
            });
            change(&mut document);
            *endpoint.answer.lock().unwrap() = document.to_string();
        };
        let asked = || endpoint.requests.lock().unwrap().len();

        document(&|_| {});
        let plugin = plugin_for(&base);
        let provider = plugin.provider().await.unwrap();
        assert_eq!(
            format!("{base}/authorize"),
            provider.authorization_endpoint
        );
        assert_eq!(format!("{base}/token"), provider.token_endpoint);
        assert_eq!(None, provider.end_session_endpoint);
        // Says nothing of how a client is to say who it is: in
        // `Authorization`.
        assert_eq!(true, provider.basic_auth);
        assert_eq!(
            true,
            endpoint.requests.lock().unwrap()[0]
                .starts_with("GET /.well-known/openid-configuration HTTP/1.1")
        );
        // Kept: not asked for the next request.
        plugin.provider().await.unwrap();
        assert_eq!(1, asked());

        document(&|document| {
            document["token_endpoint_auth_methods_supported"] =
                serde_json::json!(["client_secret_post"]);
            document["end_session_endpoint"] = format!("{base}/logout").into();
        });
        let provider = plugin_for(&base).provider().await.unwrap();
        assert_eq!(false, provider.basic_auth);
        assert_eq!(
            Some(format!("{base}/logout")),
            provider.end_session_endpoint
        );

        // Somebody else answering under the name, and a place to send
        // browsers to that is no address of the web.
        type Change = Box<dyn Fn(&mut serde_json::Value)>;
        let changes: Vec<Change> = vec![
            Box::new(|document| {
                document["issuer"] = "https://evil.test".into()
            }),
            Box::new(|document| {
                document["authorization_endpoint"] =
                    "javascript:alert(1)".into()
            }),
            Box::new(|document| {
                document.as_object_mut().unwrap().remove("jwks_uri");
            }),
        ];
        for change in changes {
            document(&*change);
            let plugin = plugin_for(&base);
            let before = asked();
            assert_eq!(true, plugin.provider().await.is_none());
            assert_eq!(before + 1, asked());
            // Left alone for a while after that: the next request does
            // not ask, and has no provider either.
            assert_eq!(true, plugin.provider().await.is_none());
            assert_eq!(before + 1, asked());
        }
    }

    /// The other ways a client says who it is at the token endpoint, and
    /// what is not a token of the provider at all.
    #[tokio::test]
    async fn test_oidc_token_request_and_signature() {
        use base64::engine::general_purpose::STANDARD;
        let endpoint = Arc::new(TokenEndpoint::default());
        let token_url = serve(endpoint.clone()).await;
        let login = Login {
            state: "state-0123456789".to_string(),
            verifier: "the-verifier".to_string(),
            nonce: "the-nonce".to_string(),
            url: "/".to_string(),
            exp: now_sec() + 300,
        };
        let claims = serde_json::json!({
            "iss": "https://idp.test",
            "aud": "pingap",
            "sub": "u-1",
            "exp": now_sec() + 300,
            "nonce": "the-nonce",
            "groups": vec!["g".repeat(50); 80],
        });
        let answer = |header: Header, key: &EncodingKey| {
            let token = encode(&header, &claims, key).unwrap();
            *endpoint.answer.lock().unwrap() =
                serde_json::json!({"id_token": token}).to_string();
        };
        let ours = EncodingKey::from_ec_pem(PRIVATE_KEY.as_bytes()).unwrap();
        async fn exchange(
            plugin: &Oidc,
            token_url: &str,
            login: &Login,
            basic_auth: bool,
        ) -> std::result::Result<ClaimMap, String> {
            let provider = Provider {
                authorization_endpoint: "https://idp.test/authorize"
                    .to_string(),
                token_endpoint: token_url.to_string(),
                end_session_endpoint: None,
                basic_auth,
                jwks: Arc::new(JwksSource::with_ec_key(PUBLIC_KEY)),
                fetched_at: Instant::now(),
            };
            plugin
                .exchange(&provider, "c-1", login, "https://app.test/cb")
                .await
        }
        let last =
            || endpoint.requests.lock().unwrap().last().cloned().unwrap();

        answer(Header::new(Algorithm::ES256), &ours);
        // A provider that takes the secret in the form alone.
        let plugin = new_plugin("").unwrap();
        assert_eq!(
            true,
            exchange(&plugin, &token_url, &login, false).await.is_ok()
        );
        let request = last();
        assert_eq!(false, request.to_lowercase().contains("authorization:"));
        assert_eq!(
            true,
            request.ends_with("&client_id=pingap&client_secret=s3cret"),
            "{request}"
        );
        // A client that has no secret says its name.
        let public = Oidc::new(
            &toml::from_str::<PluginConf>(
                &BASE.replace("client_secret = \"s3cret\"\n", ""),
            )
            .unwrap(),
        )
        .map(|mut plugin| {
            plugin.client = test_client();
            plugin
        })
        .unwrap();
        // Its sessions are not those of the client with the secret, but
        // the token is for the same name.
        assert_eq!(
            true,
            exchange(&public, &token_url, &login, true).await.is_ok()
        );
        let request = last();
        assert_eq!(false, request.to_lowercase().contains("authorization:"));
        assert_eq!(true, request.ends_with("&client_id=pingap"), "{request}");
        // In `Authorization`, the two are encoded before they are joined.
        let odd = Oidc::new(
            &toml::from_str::<PluginConf>(&BASE.replace("s3cret", "a:b c"))
                .unwrap(),
        )
        .map(|mut plugin| {
            plugin.client = test_client();
            plugin
        })
        .unwrap();
        assert_eq!(
            true,
            exchange(&odd, &token_url, &login, true).await.is_ok()
        );
        assert_eq!(
            true,
            last().contains(&format!(
                "authorization: Basic {}",
                STANDARD.encode("pingap:a%3Ab%20c")
            ))
        );

        // Signed with a key that is not the provider's.
        // spellchecker:off
        let theirs = EncodingKey::from_ec_pem(
            b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQxe2Zegg39ZXkM83
ixa2TiKskJY4xdsPqBaYUYazzW+hRANCAASlmtABQrD4Vvw1PxkFsHa5PjRnvW1p
Pz7glwkTfq+X/7U/TTdWanLivIQqzKjyNBu3kgzx7GeUYcjtuw4RKof6
-----END PRIVATE KEY-----",
        )
        .unwrap();
        // spellchecker:on
        answer(Header::new(Algorithm::ES256), &theirs);
        assert_eq!(
            Err("the id_token does not verify".to_string()),
            exchange(&plugin, &token_url, &login, true).await
        );
        // "Signed" with the public key of the provider as a secret,
        // which anybody has.
        answer(
            Header::new(Algorithm::HS256),
            &EncodingKey::from_secret(PUBLIC_KEY.as_bytes()),
        );
        assert_eq!(
            Err("the id_token does not verify".to_string()),
            exchange(&plugin, &token_url, &login, true).await
        );
        // An answer that is no token at all.
        *endpoint.answer.lock().unwrap() =
            "{\"id_token\": \"a.b.c\"}".to_string();
        assert_eq!(
            Err("the id_token does not verify".to_string()),
            exchange(&plugin, &token_url, &login, true).await
        );

        // A user with more to say than a cookie holds: no session, and
        // the reason for whoever reads the log.
        answer(Header::new(Algorithm::ES256), &ours);
        let plugin =
            new_plugin("claims_to_headers = [\"groups:X-Groups\"]").unwrap();
        plugin.provider.store(Some(provider(&token_url)));
        let request = format!(
            "GET /oauth2/callback?code=c-1&state={} HTTP/1.1\r\nHost: app.test\r\nCookie: {}={}\r\n\r\n",
            login.state,
            plugin.login_cookie_name(&login.state),
            plugin.seal(&login).unwrap()
        );
        let mut session = new_session(&request).await;
        assert_eq!(
            Err(Refusal::Provider(
                "the session does not fit a cookie".to_string()
            )),
            plugin.callback(&session, &Ctx::default()).await.map(|_| ())
        );
        // To the browser that is a login that failed, and no more.
        let result = plugin
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(response) = result else {
            panic!("no response");
        };
        assert_eq!(StatusCode::BAD_GATEWAY, response.status);
        assert_eq!("Login failed", response.body);
    }

    /// Where the provider is told to come back to when that is written
    /// down, and what logging out is without a place at the provider.
    #[tokio::test]
    async fn test_oidc_redirect_url_and_logout() {
        let plugin = new_plugin(
            "redirect_url = \"https://app.example.com/oauth2/callback\"\nlogout_path = \"/bye\"",
        )
        .unwrap();
        plugin.provider.store(Some(Arc::new(Provider {
            end_session_endpoint: None,
            authorization_endpoint: "https://idp.test/authorize".to_string(),
            token_endpoint: "http://127.0.0.1:1/token".to_string(),
            basic_auth: true,
            jwks: Arc::new(JwksSource::with_ec_key(PUBLIC_KEY)),
            fetched_at: Instant::now(),
        })));
        let handle = |request: &'static str| {
            let plugin = &plugin;
            async move {
                let mut session = new_session(request).await;
                let result = plugin
                    .handle_request(
                        PluginStep::Request,
                        &mut session,
                        &mut Ctx::default(),
                    )
                    .await
                    .unwrap();
                let RequestPluginResult::Respond(response) = result else {
                    panic!("no response");
                };
                response
            }
        };
        // The request came in plain, from the proxy in front: the
        // address and the cookie are those of the site as browsers
        // reach it.
        let response = handle(
            "GET /page HTTP/1.1\r\nHost: 10.0.0.5:8080\r\nAccept: text/html\r\n\r\n",
        )
        .await;
        assert_eq!(
            true,
            header_of(&response, "location")[0].contains(
                "redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth2%2Fcallback&"
            )
        );
        assert_eq!(
            true,
            header_of(&response, "set-cookie")[0].ends_with("; Secure")
        );

        let response = handle(
            "POST /bye HTTP/1.1\r\nHost: app.test\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert_eq!(StatusCode::OK, response.status);
        assert_eq!("Logged out", response.body);
        assert_eq!(
            vec![
                "pingap_oidc=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure"
            ],
            header_of(&response, "set-cookie")
        );
    }

    /// A login that is finished takes the cookies of the ones this
    /// browser started and left with it: each is ten minutes of a cookie
    /// that goes to the callback.
    #[tokio::test]
    async fn test_oidc_clears_the_logins_that_were_left() {
        let endpoint = Arc::new(TokenEndpoint::default());
        let token_url = serve(endpoint.clone()).await;
        let plugin = new_plugin("").unwrap();
        plugin.provider.store(Some(provider(&token_url)));
        let token = encode(
            &Header::new(Algorithm::ES256),
            &serde_json::json!({
                "iss": "https://idp.test",
                "aud": "pingap",
                "sub": "u-1",
                "exp": now_sec() + 300,
                "nonce": "the-nonce",
            }),
            &EncodingKey::from_ec_pem(PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        *endpoint.answer.lock().unwrap() =
            serde_json::json!({"id_token": token}).to_string();
        let login = Login {
            state: "state-0123456789".to_string(),
            verifier: "the-verifier".to_string(),
            nonce: "the-nonce".to_string(),
            url: "/".to_string(),
            exp: now_sec() + 300,
        };
        let request = format!(
            "GET /oauth2/callback?code=c-1&state={} HTTP/1.1\r\nHost: app.test\r\nCookie: other=1; pingap_oidc_aaaa1111=x; {}={}; pingap_oidc=old; pingap_oidc_bbbb2222=y\r\n\r\n",
            login.state,
            plugin.login_cookie_name(&login.state),
            plugin.seal(&login).unwrap()
        );
        let session = new_session(&request).await;
        let response =
            plugin.callback(&session, &Ctx::default()).await.unwrap();
        let cleared: Vec<_> = header_of(&response, "set-cookie")
            .into_iter()
            .filter(|cookie| cookie.contains("Max-Age=0"))
            .filter_map(|cookie| cookie.split('=').next())
            .collect();
        assert_eq!(
            vec![
                "pingap_oidc_state012",
                "pingap_oidc_aaaa1111",
                "pingap_oidc_bbbb2222"
            ],
            cleared
        );
    }
}
