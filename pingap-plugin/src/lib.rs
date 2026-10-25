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

use humantime::parse_duration;
use pingap_config::PluginConf;
use pingap_core::{Ctx, HttpResponse, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use snafu::Snafu;
use std::cell::RefCell;
use std::fmt::Write;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin {category} invalid, message: {message}"))]
    Invalid { category: String, message: String },
    #[snafu(display("Plugin {category} not found"))]
    NotFound { category: String },
    #[snafu(display("Plugin {category}, base64 decode error {source}"))]
    Base64Decode {
        category: String,
        source: base64::DecodeError,
    },
    #[snafu(display("Plugin {category}, exceed limit {value}/{max}"))]
    Exceed {
        category: String,
        max: f64,
        value: f64,
    },
    #[snafu(display("Plugin {category}, regex error {source}"))]
    Regex {
        category: String,
        source: Box<fancy_regex::Error>,
    },
    #[snafu(display("Plugin {category}, base64 decode error {source}"))]
    ParseDuration {
        category: String,
        source: humantime::DurationError,
    },
}

thread_local! {
    /// The config values of the plugin being built that were not of the
    /// type their key takes. `None` when no plugin is being built.
    static WRONG_TYPES: RefCell<Option<Vec<String>>> =
        const { RefCell::new(None) };
}

/// Notes that the value of `key` is not `expected`.
///
/// The getters below answer a value of the wrong type with the default:
/// `max = "100"` was a limit of 0, `encodings = ["gzip"]` no encoding at
/// all, a number in a list of keys a key that is not there. Nothing said
/// so. They still answer the default, and [`build_plugin`] turns the note
/// into the error of the plugin that is being built.
fn note_wrong_type(key: &str, expected: &str, value: &toml::Value) {
    WRONG_TYPES.with_borrow_mut(|notes| {
        if let Some(notes) = notes {
            // The value is what tells a typo apart, but not when it is a
            // credential: this note ends up in the log and in the
            // notification of a failed reload.
            let shown = if pingap_config::is_secret_key(key) {
                String::new()
            } else {
                format!(" {value}")
            };
            notes.push(format!(
                "{key} must be {expected}, got {}{shown}",
                value.type_str()
            ));
        }
    });
}

/// The error [`build_plugin`] is going to give for the values of the wrong
/// type noted so far, for a constructor that has something to hold back
/// until its configuration is known to be good.
pub(crate) fn wrong_types_error(category: &str) -> Option<Error> {
    WRONG_TYPES.with_borrow(|notes| {
        let notes = notes.as_ref().filter(|notes| !notes.is_empty())?;
        Some(Error::Invalid {
            category: category.to_string(),
            message: notes.join(", "),
        })
    })
}

/// Builds one plugin with `build`, and fails when a config value it read
/// was not of the type its key takes.
///
/// Building a plugin is one synchronous call, which is what lets the notes
/// be kept per thread instead of being handed through every getter.
pub(crate) fn build_plugin<T>(
    category: &str,
    build: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    /// Puts back what was there, on a panic too.
    struct Restore(Option<Vec<String>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            WRONG_TYPES.set(self.0.take());
        }
    }
    let restore = Restore(WRONG_TYPES.replace(Some(vec![])));
    let result = build();
    let notes = WRONG_TYPES.take().unwrap_or_default();
    drop(restore);
    // The plugin's own complaint comes first: it is the more specific.
    let plugin = result?;
    if notes.is_empty() {
        return Ok(plugin);
    }
    Err(Error::Invalid {
        category: category.to_string(),
        message: notes.join(", "),
    })
}

/// Helper functions for accessing plugin configuration values
pub fn get_str_conf(value: &PluginConf, key: &str) -> String {
    match value.get(key) {
        Some(toml::Value::String(item)) => item.clone(),
        Some(other) => {
            note_wrong_type(key, "a string", other);
            String::new()
        },
        None => String::new(),
    }
}

/// Helper functions for accessing plugin configuration values
pub fn get_duration_conf(value: &PluginConf, key: &str) -> Option<Duration> {
    let item = value.get(key)?;
    let duration = item.as_str().and_then(|s| parse_duration(s).ok());
    if duration.is_none() {
        note_wrong_type(key, "a duration such as \"10s\"", item);
    }
    duration
}

/// The name one plugin instance keeps something of a request under: its
/// response body handler, or the value it hands to a later step
/// (`Ctx::set_plugin_value`).
///
/// The handlers of a request are kept by name, and the name used to be the
/// plugin's category. Two plugins of one category on a location then shared
/// a single slot: the second replaced the handler of the first, and both ran
/// the one that was left, so its rules were applied twice and the other's
/// not at all.
pub fn new_body_handler_id(prefix: &str) -> String {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    format!("{prefix}{}", NEXT_ID.fetch_add(1, Ordering::Relaxed))
}

/// A list of strings. One string on its own is a list of one: that is how
/// a single value reads in KDL (`ip_list "1.2.3.4"`), and it used to count
/// as no list at all, which left an allow or deny list empty without a
/// word.
pub fn get_str_slice_conf(value: &PluginConf, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(toml::Value::Array(arr)) => arr
            .iter()
            .filter_map(|item| {
                let text = item.as_str();
                if text.is_none() {
                    note_wrong_type(key, "a list of strings", item);
                }
                text
            })
            .map(String::from) // same as .map(|s| s.to_string())
            .collect(),
        // An empty string is an empty list, not a list of one empty item.
        Some(toml::Value::String(item)) => {
            if item.is_empty() {
                vec![]
            } else {
                vec![item.clone()]
            }
        },
        Some(other) => {
            note_wrong_type(key, "a list of strings", other);
            vec![]
        },
        None => vec![],
    }
}

pub(crate) use pingap_core::decode_query_value;

pub(crate) fn get_bool_conf(value: &PluginConf, key: &str) -> bool {
    match value.get(key) {
        Some(toml::Value::Boolean(item)) => *item,
        Some(other) => {
            note_wrong_type(key, "true or false", other);
            false
        },
        None => false,
    }
}

pub fn get_int_conf(value: &PluginConf, key: &str) -> i64 {
    get_int_conf_or_default(value, key, 0)
}

pub fn get_int_conf_or_default(
    value: &PluginConf,
    key: &str,
    default_value: i64,
) -> i64 {
    match value.get(key) {
        Some(toml::Value::Integer(item)) => *item,
        Some(other) => {
            note_wrong_type(key, "an integer", other);
            default_value
        },
        None => default_value,
    }
}

pub fn get_step_conf(
    value: &PluginConf,
    default_value: PluginStep,
) -> PluginStep {
    value
        .get("step")
        .and_then(|v| v.as_str())
        .and_then(|s| PluginStep::from_str(s).ok())
        .unwrap_or(default_value)
}

/// Resolves `step`, rejecting a value the plugin does not implement.
///
/// `get_step_conf` falls back to the default for an unknown or unsupported
/// value, which turns a misconfigured `step` into a plugin that quietly never
/// runs. Plugins that implement only some of the steps should use this so the
/// mistake surfaces at `pingap -t` instead.
pub fn get_step_conf_in(
    value: &PluginConf,
    category: &str,
    default_value: PluginStep,
    allowed: &[PluginStep],
) -> Result<PluginStep, Error> {
    let Some(step) = value.get("step").and_then(|v| v.as_str()) else {
        return Ok(default_value);
    };
    let invalid = || Error::Invalid {
        category: category.to_string(),
        message: format!(
            "Invalid step({step}), expect one of: {}",
            allowed
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let step = PluginStep::from_str(step).map_err(|_| invalid())?;
    if !allowed.contains(&step) {
        return Err(invalid());
    }
    Ok(step)
}

/// Whether a restriction list is a whitelist or a blacklist.
///
/// Parsed rather than compared literally: `type` used to be tested against the
/// string `deny`, so every other spelling — including `Deny` — silently selected
/// allow mode and inverted the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RestrictionCategory {
    #[default]
    Allow,
    Deny,
}

impl RestrictionCategory {
    /// Given whether the request matched the configured list, returns whether
    /// it is allowed through.
    #[inline]
    pub(crate) fn allows(&self, found: bool) -> bool {
        match self {
            Self::Allow => found,
            Self::Deny => !found,
        }
    }
}

/// Parses the `type` of a restriction plugin. Absent means `allow`, which is
/// the documented default; anything that is not `allow` or `deny` is rejected.
pub(crate) fn get_restriction_category_conf(
    value: &PluginConf,
    category: &str,
) -> Result<RestrictionCategory, Error> {
    match get_str_conf(value, "type").to_lowercase().as_str() {
        "" | "allow" => Ok(RestrictionCategory::Allow),
        "deny" => Ok(RestrictionCategory::Deny),
        other => Err(Error::Invalid {
            category: category.to_string(),
            message: format!("Invalid type({other}), expect allow or deny"),
        }),
    }
}

/// The address a refusal is logged with: the one the plugins that go by
/// an address decide by. Through trusted proxies that is the client's,
/// without them the peer's own; `X-Forwarded-For` is then whatever the
/// client wrote in it.
fn verified_address(session: &Session, ctx: &Ctx) -> String {
    if pingap_core::has_trusted_proxies() {
        return ctx
            .conn
            .client_ip
            .clone()
            .unwrap_or_else(|| pingap_core::get_client_ip(session));
    }
    ctx.conn.remote_addr.clone().unwrap_or_default()
}

/// How many lines of one kind a plugin logs in a second of the clock: the
/// refusals of a dry run, the answers a mirror gave otherwise. The others
/// are counted, and the count goes with its next line: a rule that would
/// turn away a flood does not log one.
const LINES_PER_SECOND: u32 = 10;

/// What keeps the lines of one kind a plugin logs to [`LINES_PER_SECOND`].
#[derive(Default)]
pub(crate) struct LineBudget {
    /// The second whose lines `logged` counts.
    second: AtomicU64,
    logged: AtomicU32,
    /// The lines not logged since the last one that was.
    skipped: AtomicU64,
}

impl LineBudget {
    /// Whether a line in the second `now` is logged, and with the number
    /// of those before it that were not. Under contention a second may
    /// get a line or two more than its share.
    pub(crate) fn take_line(&self, now: u64) -> Option<u64> {
        let second = self.second.load(Ordering::Relaxed);
        if second != now
            && self
                .second
                .compare_exchange(
                    second,
                    now,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            self.logged.store(0, Ordering::Relaxed);
        }
        if self.logged.fetch_add(1, Ordering::Relaxed) < LINES_PER_SECOND {
            return Some(self.skipped.swap(0, Ordering::Relaxed));
        }
        self.skipped.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// The `dry_run` of a plugin that turns requests away.
#[derive(Default)]
pub(crate) struct DryRun {
    on: bool,
    lines: LineBudget,
}

impl DryRun {
    pub(crate) fn new(value: &PluginConf) -> Self {
        Self {
            on: get_bool_conf(value, "dry_run"),
            ..Default::default()
        }
    }

    pub(crate) fn is_on(&self) -> bool {
        self.on
    }

    /// What the plugin does with a request it would turn away: answers it
    /// with `response`, or - in a dry run - lets it through and logs what
    /// it would have answered, with `matched`, what of the request it went
    /// by. A new rule can be watched on real traffic that way before it
    /// refuses anyone. `matched` is only worked out for a line that is
    /// logged.
    pub(crate) fn refuse(
        &self,
        category: &str,
        session: &Session,
        ctx: &mut Ctx,
        response: HttpResponse,
        matched: impl FnOnce(&mut Ctx) -> String,
    ) -> RequestPluginResult {
        if !self.on {
            return RequestPluginResult::Respond(response);
        }
        let Some(skipped) = self.lines.take_line(pingap_core::now_sec()) else {
            return RequestPluginResult::Continue;
        };
        let matched = matched(ctx);
        let header = session.req_header();
        tracing::warn!(
            category,
            location = &*ctx.upstream.location,
            status = response.status.as_u16(),
            reason = %String::from_utf8_lossy(&response.body),
            matched,
            client_ip = verified_address(session, ctx),
            method = header.method.as_str(),
            uri = %header.uri,
            request_id = ctx.state.request_id.as_deref().unwrap_or_default(),
            skipped,
            "dry run, the request would have been refused"
        );
        RequestPluginResult::Continue
    }
}

/// What the plugin `conf` describes has that the plugin does not read: a
/// setting that has no effect, by the plugin's own account. For the check
/// of a configuration, which says it once.
pub fn unread_keys(conf: &PluginConf) -> Vec<String> {
    match get_str_conf(conf, "category").as_str() {
        "limit" => limit::unread_keys(conf),
        _ => vec![],
    }
}

/// Whether the plugin `conf` describes goes by the JA4 fingerprint of the
/// connection, which only a server with `ja4 = true` collects.
pub fn needs_ja4(conf: &PluginConf) -> bool {
    match get_str_conf(conf, "category").as_str() {
        "ja4_restriction" => true,
        "limit" => {
            matches!(get_str_conf(conf, "tag").as_str(), "ja4" | "ip_ja4")
        },
        _ => false,
    }
}

/// Whether the response is a part of a body and not the body: a `206`, or
/// anything that says which bytes it is.
///
/// A plugin that rewrites the body - compresses it, substitutes in it,
/// encodes it anew - has nothing to do with a part. What it would make of
/// one is no part of anything: the hundred bytes asked for come back as
/// the gzip of those hundred bytes, under a `Content-Range` that still
/// counts in the bytes of the original.
pub fn is_partial_content(resp: &pingora::http::ResponseHeader) -> bool {
    resp.status == http::StatusCode::PARTIAL_CONTENT
        || resp.headers.contains_key(http::header::CONTENT_RANGE)
}

/// Takes back what a response can no longer say of itself once its body
/// is going to be another: that ranges of it can be asked for, and that
/// its `ETag` names these bytes.
///
/// The upstream's `Accept-Ranges` and strong `ETag` are about the body it
/// sent. Left on the rewritten one, a client resumed a download with a
/// range of the original, or took two different bodies for the same bytes.
pub fn body_will_change(resp: &mut pingora::http::ResponseHeader) {
    resp.remove_header(&http::header::ACCEPT_RANGES);
    weaken_etag(resp);
}

/// Makes a strong `ETag` a weak one, `true` when it changed the header.
///
/// The validator is weakened rather than removed, as nginx and pingora's
/// own compression do it: it still tells whether the resource changed.
/// One that is not a quoted string is no validator, and is removed.
pub fn weaken_etag(resp: &mut pingora::http::ResponseHeader) -> bool {
    let Some(etag) = resp.headers.get(http::header::ETAG) else {
        return false;
    };
    let value = etag.as_bytes();
    if value.starts_with(b"W/") {
        return false;
    }
    let weak = value
        .starts_with(b"\"")
        .then(|| [b"W/", value].concat())
        .and_then(|weak| http::HeaderValue::from_bytes(&weak).ok());
    match weak {
        Some(weak) => {
            let _ = resp.insert_header(http::header::ETAG, weak);
        },
        None => {
            resp.remove_header(&http::header::ETAG);
        },
    }
    true
}

/// Returns true if `accept_encoding` lists `coding` as an acceptable encoding.
///
/// Matches on comma/`;`-delimited token boundaries (so `x-gzip` does not match
/// `gzip`) and treats an explicit `q=0` as "not acceptable". Shared by the
/// `accept_encoding` and `compression` plugins so the two cannot disagree about
/// what the client accepts.
pub fn accepts_encoding(accept_encoding: &str, coding: &str) -> bool {
    accept_encoding.split(',').any(|part| {
        let mut segments = part.split(';');
        let name = segments.next().unwrap_or_default().trim();
        if !name.eq_ignore_ascii_case(coding) {
            return false;
        }
        // Acceptable unless the token is explicitly weighted q=0.
        !segments.any(|seg| {
            let seg = seg.trim();
            seg.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("q="))
                && seg[2..].trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
        })
    })
}

/// Generates a unique hash key for a plugin configuration to detect changes.
///
/// # Arguments
/// * `conf` - The plugin configuration to hash
///
/// # Returns
/// A string containing the CRC32 hash of the sorted configuration key-value pairs
pub fn get_hash_key(conf: &PluginConf) -> String {
    let mut items: Vec<_> = conf.iter().collect();
    // sort by key
    items.sort_unstable_by_key(|(k, _)| *k);

    // pre-allocate capacity to reduce subsequent memory reallocation.
    let mut buf = String::with_capacity(256);
    for (i, (key, value)) in items.iter().enumerate() {
        if i > 0 {
            buf.push('\n');
        }
        // use write! macro to write the formatted string directly into the buffer, avoid format! to produce temporary String.
        // because writing to String will not fail, so it can be safely.
        let _ = write!(&mut buf, "{key}:{value}");
    }

    let hash = crc32fast::hash(buf.as_bytes());
    format!("{hash:X}")
}

/// Gives a plugin module its `register`, which puts the plugin into a
/// factory under the category the configuration names it with.
/// [`register_builtin_plugins`] calls every one of them: a module it leaves
/// out has a `register` nothing calls, which is dead code, and `make lint`
/// refuses it.
macro_rules! register_plugin {
    ($category:literal, $ty:ty) => {
        pub(crate) fn register(factory: &crate::plugin::PluginFactory) {
            factory.register($category, |params| {
                Ok(::std::sync::Arc::new(<$ty>::new(params)?))
            });
        }
    };
}

mod accept_encoding;
mod bandwidth_limit;
mod basic_auth;
mod cache;
mod combined_auth;
mod compression;
mod cors;
mod csrf;
mod directory;
mod error_page;
mod forward_auth;
#[cfg(feature = "geo")]
mod geo_restriction;
mod hmac_auth;
mod ip_restriction;
mod ja4_restriction;
mod jwt;
mod key_auth;
mod limit;
mod maintenance;
mod mirror;
mod mock;
mod oidc;
mod ping;
mod redirect;
mod referer_restriction;
mod request_headers;
mod request_id;
mod response_headers;
mod sub_filter;
mod traffic_splitting;
mod ua_restriction;
mod uri_block;

mod plugin;

pub use plugin::{PluginFactory, get_plugin_factory};

/// Puts the plugins of this crate into `factory`. The factory of
/// [`get_plugin_factory`] is filled with them the first time it is asked
/// for, so they are there for whoever asks, whenever: no code has to run
/// before `main` or before the first use.
fn register_builtin_plugins(factory: &plugin::PluginFactory) {
    accept_encoding::register(factory);
    bandwidth_limit::register(factory);
    basic_auth::register(factory);
    cache::register(factory);
    combined_auth::register(factory);
    compression::register(factory);
    cors::register(factory);
    csrf::register(factory);
    directory::register(factory);
    error_page::register(factory);
    forward_auth::register(factory);
    #[cfg(feature = "geo")]
    geo_restriction::register(factory);
    hmac_auth::register(factory);
    ip_restriction::register(factory);
    ja4_restriction::register(factory);
    jwt::register(factory);
    key_auth::register(factory);
    limit::register(factory);
    maintenance::register(factory);
    mirror::register(factory);
    mock::register(factory);
    oidc::register(factory);
    ping::register(factory);
    redirect::register(factory);
    referer_restriction::register(factory);
    request_headers::register(factory);
    request_id::register(factory);
    response_headers::register(factory);
    sub_filter::register(factory);
    traffic_splitting::register(factory);
    ua_restriction::register(factory);
    uri_block::register(factory);
}

#[cfg(test)]
mod tests {
    use super::{accepts_encoding, get_plugin_factory, get_str_slice_conf};
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep, RequestPluginResult};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;

    /// Every plugin of this crate is in the factory the first time it is
    /// asked for, with nothing run before: no constructor before `main`.
    #[test]
    fn test_builtin_plugins_are_registered() {
        let mut expected = vec![
            "accept_encoding",
            "bandwidth_limit",
            "basic_auth",
            "cache",
            "combined_auth",
            "compression",
            "cors",
            "csrf",
            "directory",
            "error_page",
            "forward_auth",
            "hmac_auth",
            "ip_restriction",
            "ja4_restriction",
            "jwt",
            "key_auth",
            "limit",
            "maintenance",
            "mirror",
            "mock",
            "oidc",
            "ping",
            "redirect",
            "referer_restriction",
            "request_headers",
            "request_id",
            "response_headers",
            "sub_filter",
            "traffic_splitting",
            "ua_restriction",
            "uri_block",
        ];
        if cfg!(feature = "geo") {
            expected.push("geo_restriction");
            expected.sort();
        }
        assert_eq!(expected, get_plugin_factory().supported_plugins());
    }

    /// Regression: the address a dry run logs is the one the decision is
    /// made by. It was the first of `X-Forwarded-For`, which without
    /// trusted proxies is whatever the client wrote.
    #[tokio::test]
    async fn test_dry_run_logs_the_verified_address() {
        let input =
            b"GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 8.8.8.8\r\n\r\n";
        let mock_io = tokio_test::io::Builder::new().read(input).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some("1.1.1.1".to_string());
        assert_eq!("1.1.1.1", super::verified_address(&session, &ctx));
    }

    #[test]
    fn test_needs_ja4() {
        let needs = |conf: &str| {
            super::needs_ja4(&toml::from_str::<PluginConf>(conf).unwrap())
        };
        assert_eq!(true, needs("category = \"ja4_restriction\""));
        assert_eq!(true, needs("category = \"limit\"\ntag = \"ja4\""));
        assert_eq!(true, needs("category = \"limit\"\ntag = \"ip_ja4\""));
        assert_eq!(false, needs("category = \"limit\""));
        assert_eq!(false, needs("category = \"limit\"\ntag = \"header\""));
        assert_eq!(false, needs("category = \"ip_restriction\""));
    }

    /// Ten lines a second at most, and the next line that is logged says
    /// how many were not.
    #[test]
    fn test_lines_per_second() {
        let dry_run = super::DryRun::new(
            &toml::from_str::<PluginConf>("dry_run = true").unwrap(),
        );
        assert_eq!(true, dry_run.is_on());
        let budget = super::LineBudget::default();
        let lines =
            |now| (0..15).map(|_| budget.take_line(now)).collect::<Vec<_>>();
        let mut expected = vec![Some(0); 10];
        expected.extend([None; 5]);
        assert_eq!(expected, lines(100));
        // the next second: its first line carries the five
        expected[0] = Some(5);
        assert_eq!(expected, lines(101));
        assert_eq!(Some(5), budget.take_line(102));
        assert_eq!(Some(0), budget.take_line(102));
    }

    /// Every plugin that turns requests away has a dry run: the request
    /// it refuses without one goes on with one.
    #[tokio::test]
    async fn test_dry_run_lets_the_request_through() {
        let mut cases = vec![
            (
                "category = \"ip_restriction\"\nip_list = [\"1.1.1.1\"]\ntype = \"deny\"",
                "",
            ),
            (
                "category = \"ua_restriction\"\nua_list = [\"^curl\"]\ntype = \"deny\"",
                "User-Agent: curl/8.0\r\n",
            ),
            (
                "category = \"referer_restriction\"\nreferer_list = [\"bad.example\"]\ntype = \"deny\"",
                "Referer: https://bad.example/page\r\n",
            ),
            ("category = \"uri_block\"\npaths = [\"^/admin\"]", ""),
            ("category = \"limit\"\nmax = 0", ""),
            // an allow list, and a plain http request: no fingerprint
            ("category = \"ja4_restriction\"\nja4_list = [\"^t13\"]", ""),
        ];
        if cfg!(feature = "geo") {
            cases.push((
                "category = \"geo_restriction\"\ncountry_codes = [\"CN\"]\ntype = \"allow\"",
                "",
            ));
        }
        for (conf, headers) in cases {
            for dry_run in [false, true] {
                let conf = format!("{conf}\ndry_run = {dry_run}");
                let plugin = get_plugin_factory()
                    .create(&toml::from_str::<PluginConf>(&conf).unwrap())
                    .unwrap();
                let input = format!(
                    "GET /admin/users HTTP/1.1\r\nHost: example.com\r\n{headers}\r\n"
                );
                let mock_io = tokio_test::io::Builder::new()
                    .read(input.as_bytes())
                    .build();
                let mut session = Session::new_h1(Box::new(mock_io));
                session.read_request().await.unwrap();
                let mut ctx = Ctx::default();
                ctx.conn.remote_addr = Some("1.1.1.1".to_string());
                let result = plugin
                    .handle_request(PluginStep::Request, &mut session, &mut ctx)
                    .await
                    .unwrap();
                assert_eq!(
                    dry_run,
                    result == RequestPluginResult::Continue,
                    "{conf}"
                );
            }
        }
    }

    /// Regression: a value of the wrong type was read as the default, and
    /// the plugin ran with a limit of 0, an empty list or a flag left off.
    #[test]
    fn test_body_will_change() {
        use pingora::http::ResponseHeader;
        let changed = |etag: Option<&str>| {
            let mut resp = ResponseHeader::build(200, None).unwrap();
            resp.append_header("Accept-Ranges", "bytes").unwrap();
            if let Some(etag) = etag {
                resp.append_header("ETag", etag).unwrap();
            }
            super::body_will_change(&mut resp);
            assert_eq!(false, resp.headers.contains_key("Accept-Ranges"));
            resp.headers
                .get("ETag")
                .map(|value| value.to_str().unwrap().to_string())
        };
        assert_eq!(Some("W/\"v1\"".to_string()), changed(Some("\"v1\"")));
        assert_eq!(Some("W/\"v1\"".to_string()), changed(Some("W/\"v1\"")));
        // Not a validator to begin with.
        assert_eq!(None, changed(Some("v1")));
        assert_eq!(None, changed(None));

        let mut part = ResponseHeader::build(206, None).unwrap();
        assert_eq!(true, super::is_partial_content(&part));
        part.set_status(200).unwrap();
        assert_eq!(false, super::is_partial_content(&part));
        part.append_header("Content-Range", "bytes 0-9/100")
            .unwrap();
        assert_eq!(true, super::is_partial_content(&part));
    }

    #[test]
    fn test_wrong_typed_values_are_rejected() {
        let create = |conf: &str| {
            get_plugin_factory()
                .create(&toml::from_str::<PluginConf>(conf).unwrap())
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        let limit = "category = \"limit\"\ntag = \"ip\"\n";
        let key_auth = "category = \"key_auth\"\nheader = \"X-Key\"\n";
        for (conf, expected) in [
            (
                format!("{limit}max = \"100\""),
                "Plugin limit invalid, message: max must be an integer, got string \"100\"",
            ),
            (
                format!("{limit}max = 10\ninterval = 10"),
                "interval must be a string, got integer 10",
            ),
            // The value of what is a credential is not repeated: this
            // message goes to the log and to the webhook.
            (
                format!("{key_auth}keys = [\"a\", 123]"),
                "keys must be a list of strings, got integer",
            ),
            (
                format!("{key_auth}keys = [\"a\"]\nhide_credentials = \"true\""),
                "hide_credentials must be true or false, got string \"true\"",
            ),
            (
                "category = \"forward_auth\"\nauth_url = \"http://127.0.0.1/\"\ntimeout = \"10\"".to_string(),
                "timeout must be a duration such as \"10s\", got string \"10\"",
            ),
        ] {
            let err = create(&conf).unwrap_err();
            assert_eq!(true, err.contains(expected), "{conf}: {err}");
        }
        // The plugin's own error is the one reported when it has one.
        let err =
            create(&format!("{limit}max = -1\ninterval = 10")).unwrap_err();
        assert_eq!(true, err.contains("max must not be negative"), "{err}");

        assert_eq!(Ok(()), create(&format!("{limit}max = 100")));
        assert_eq!(Ok(()), create(&format!("{key_auth}keys = \"a\"")));
        // Nothing is left over for the plugin built next on this thread.
        assert_eq!(Ok(()), create(&format!("{limit}max = 100")));
    }

    /// Outside the factory the getters answer the default, as they did.
    #[test]
    fn test_getters_default_outside_the_factory() {
        let conf: PluginConf =
            toml::from_str("max = \"100\"\nkeys = 1\nflag = \"true\"").unwrap();
        assert_eq!(0, super::get_int_conf(&conf, "max"));
        assert_eq!(true, get_str_slice_conf(&conf, "keys").is_empty());
        assert_eq!(false, super::get_bool_conf(&conf, "flag"));
        assert_eq!("", super::get_str_conf(&conf, "keys"));
        assert_eq!(None, super::get_duration_conf(&conf, "max"));
    }

    #[test]
    fn test_get_str_slice_conf() {
        let conf: PluginConf = toml::from_str(
            r#"
list = ["a", "b"]
one = ["a"]
bare = "a"
empty = []
blank = ""
number = 1
"#,
        )
        .unwrap();
        assert_eq!(vec!["a", "b"], get_str_slice_conf(&conf, "list"));
        assert_eq!(vec!["a"], get_str_slice_conf(&conf, "one"));
        // One value written without the brackets, as KDL has it.
        assert_eq!(vec!["a"], get_str_slice_conf(&conf, "bare"));
        for key in ["empty", "blank", "number", "missing"] {
            assert_eq!(
                true,
                get_str_slice_conf(&conf, key).is_empty(),
                "{key}"
            );
        }
    }

    #[test]
    fn test_accepts_encoding() {
        assert_eq!(true, accepts_encoding("gzip, br", "br"));
        assert_eq!(true, accepts_encoding("gzip, deflate, br;q=0.9", "br"));
        assert_eq!(true, accepts_encoding("BR", "br"));
        // Substring false-matches must be rejected.
        assert_eq!(false, accepts_encoding("x-gzip", "gzip"));
        assert_eq!(false, accepts_encoding("gzipx", "gzip"));
        // Explicit q=0 means "not acceptable".
        assert_eq!(false, accepts_encoding("br;q=0", "br"));
    }
}
