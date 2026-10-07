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
use pingap_core::PluginStep;
use snafu::Snafu;
use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt::Write;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// The name one plugin instance keeps its response body handler under.
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

/// The value of a query parameter as the client meant it, with its
/// percent-encoding decoded. `+` stays a plus: that it stands for a space
/// is a rule of html forms, not of urls. A value that does not decode to
/// text is compared as it came.
pub(crate) fn decode_query_value(raw: &str) -> Cow<'_, str> {
    if !raw.contains('%') {
        return Cow::Borrowed(raw);
    }
    urlencoding::decode(raw).unwrap_or(Cow::Borrowed(raw))
}

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

/// Registers a plugin with the global plugin factory inside a pre-main
/// constructor. Collapses the identical `#[ctor(unsafe)] fn init()` block
/// that every plugin module would otherwise repeat.
macro_rules! register_plugin {
    ($category:literal, $ty:ty) => {
        #[::ctor::ctor(unsafe)]
        fn init() {
            $crate::get_plugin_factory().register($category, |params| {
                Ok(::std::sync::Arc::new(<$ty>::new(params)?))
            });
        }
    };
}

mod accept_encoding;
mod basic_auth;
mod cache;
mod combined_auth;
mod compression;
mod cors;
mod csrf;
mod directory;
mod forward_auth;
#[cfg(feature = "geo")]
mod geo_restriction;
mod ip_restriction;
mod jwt;
mod key_auth;
mod limit;
mod maintenance;
mod mock;
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

pub use plugin::get_plugin_factory;

#[cfg(test)]
mod tests {
    use super::{accepts_encoding, get_plugin_factory, get_str_slice_conf};
    use pingap_config::PluginConf;
    use pretty_assertions::assert_eq;

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
