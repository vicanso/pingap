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

//! Keeps credentials out of what is printed about a configuration.
//!
//! The difference between two configurations is written to the log and sent
//! to the webhook on every reload, and a plugin logs its settings at debug
//! level. Both used to carry the values as they are: a changed `secret` of
//! a `jwt` plugin, the `authorizations` of `basic_auth`, the key in the url
//! of a webhook, old and new.
//!
//! A value that is a credential is replaced by a checksum of itself, so
//! that a change of it still shows as a change.

use std::collections::HashSet;
use toml::{Table, Value};

fn masked(value: &str) -> String {
    format!("crc32:{:X}", crc32fast::hash(value.as_bytes()))
}

/// Whether the value under `key` is a credential by the name of the key.
pub fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    ["secret", "password", "passwd", "token"]
        .iter()
        .any(|part| key.contains(part))
        || matches!(
            key.as_str(),
            "key"
                | "keys"
                | "authorization"
                | "authorizations"
                | "readonly_authorizations"
                | "private_key"
                | "tls_key"
                | "client_key"
                | "acme_eab_hmac"
                // As long as `tls_cert`, and as little worth reading.
                | "client_cert"
                // Not a secret, but as long as one: its checksum says as
                // much about a change as the text does.
                | "tls_cert"
        )
}

/// How much of a url under `key` is taken for a credential.
#[derive(Clone, Copy, PartialEq)]
enum UrlSecret {
    /// The user and password in front of the host.
    UserInfo,
    /// The query as well: an access token, a signature.
    Query,
    /// Everything after the host: a webhook has its key in the path as
    /// often as in the query.
    Path,
}

fn url_secret(key: &str) -> UrlSecret {
    let key = key.to_ascii_lowercase();
    if matches!(key.as_str(), "webhook" | "sentry" | "pyroscope") {
        UrlSecret::Path
    } else if key.ends_with("_url")
        || matches!(key.as_str(), "otlp_exporter" | "prometheus_metrics")
    {
        UrlSecret::Query
    } else {
        UrlSecret::UserInfo
    }
}

/// `value` with the credentials of a url taken out, or `None` when it is
/// not a url or has none.
fn mask_url(value: &str, secret: UrlSecret) -> Option<String> {
    let (scheme, rest) = value.split_once("://")?;
    let is_scheme = !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    if !is_scheme {
        return None;
    }
    let (authority, tail) =
        rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let (user_info, host) = match authority.rsplit_once('@') {
        Some((user_info, host)) => (Some(user_info), host),
        None => (None, authority),
    };
    let (path, query) = match tail.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (tail, None),
    };
    let hide_path =
        secret == UrlSecret::Path && (path.len() > 1 || query.is_some());
    let hide_query = secret == UrlSecret::Query && query.is_some();
    if user_info.is_none() && !hide_path && !hide_query {
        return None;
    }
    let mut url = format!("{scheme}://");
    if let Some(user_info) = user_info {
        url.push_str(&masked(user_info));
        url.push('@');
    }
    url.push_str(host);
    if hide_path {
        url.push('/');
        url.push_str(&masked(tail));
    } else {
        url.push_str(path);
        match query {
            Some(query) if hide_query => {
                url.push('?');
                url.push_str(&masked(query));
            },
            Some(query) => {
                url.push('?');
                url.push_str(query);
            },
            None => {},
        }
    }
    Some(url)
}

/// `Name: value` with the value taken out when the header is one that
/// carries a credential.
fn mask_header(header: &str) -> String {
    let Some((name, value)) = header.split_once(':') else {
        return header.to_string();
    };
    let lower = name.trim().to_ascii_lowercase();
    let is_secret = matches!(lower.as_str(), "cookie" | "set-cookie")
        || [
            "auth",
            "token",
            "secret",
            "password",
            "key",
            "signature",
            "credential",
        ]
        .iter()
        .any(|part| lower.contains(part));
    if !is_secret {
        return header.to_string();
    }
    format!("{name}:{}", masked(value.trim()))
}

/// A value that is a credential as a whole. A table inside it is gone
/// through key by key, like any other: the entries of a `combined_auth`
/// keep their `app_id` and lose their `secret`.
fn mask_whole(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(masked(text)),
        Value::Array(items) => {
            Value::Array(items.iter().map(mask_whole).collect())
        },
        Value::Table(table) => Value::Table(mask_secrets(table)),
        other => Value::String(masked(&other.to_string())),
    }
}

fn mask_value(key: &str, value: &Value, is_limit: bool) -> Value {
    // The `key` of a `limit` plugin is the name of the header, cookie or
    // query parameter it counts by.
    let secret = is_secret_key(key) && !(is_limit && key == "key");
    match value {
        Value::Table(table) => Value::Table(mask_secrets(table)),
        _ if secret => mask_whole(value),
        // `Name: value` of a `maintenance` plugin: the value is what
        // lets a request through, whatever the header is called.
        Value::String(text) if key == "allow_header" => {
            Value::String(match text.split_once(':') {
                Some((name, value)) => {
                    format!("{name}:{}", masked(value.trim()))
                },
                None => masked(text),
            })
        },
        Value::String(text) => mask_url(text, url_secret(key))
            .map_or_else(|| value.clone(), Value::String),
        Value::Array(items) => {
            let headers = key.to_ascii_lowercase().contains("headers");
            Value::Array(
                items
                    .iter()
                    .map(|item| match item {
                        Value::String(text) if headers => {
                            Value::String(mask_header(text))
                        },
                        other => mask_value(key, other, is_limit),
                    })
                    .collect(),
            )
        },
        other => other.clone(),
    }
}

/// `table` - an entry of the configuration, the settings of a plugin - with
/// its credentials replaced by their checksums.
pub fn mask_secrets(table: &Table) -> Table {
    let is_limit =
        table.get("category").and_then(Value::as_str) == Some("limit");
    table
        .iter()
        .map(|(key, value)| (key.clone(), mask_value(key, value, is_limit)))
        .collect()
}

/// `value` with every string that is one of `referenced` replaced by its
/// checksum.
fn mask_referenced(value: &mut Value, referenced: &HashSet<String>) {
    match value {
        Value::String(text) => {
            if referenced.contains(text.as_str()) {
                *text = masked(text);
            }
        },
        Value::Array(items) => {
            for item in items.iter_mut() {
                mask_referenced(item, referenced);
            }
        },
        Value::Table(table) => {
            for (_, item) in table.iter_mut() {
                mask_referenced(item, referenced);
            }
        },
        _ => {},
    }
}

/// The entry `data` as toml, with its credentials taken out: what is one
/// by the name of its key, and what was read from the environment or from
/// a file (`referenced`, see [`crate::PingapConfig::referenced`]) whatever
/// its key is.
pub(crate) fn masked_entry<T: serde::Serialize>(
    data: &T,
    referenced: &HashSet<String>,
) -> String {
    match Value::try_from(data) {
        Ok(mut value @ Value::Table(_)) => {
            // First, on the values as they are: a url that came from a
            // reference is hidden whole, not only the part of it that a
            // url is known to keep a credential in.
            if !referenced.is_empty() {
                mask_referenced(&mut value, referenced);
            }
            let Value::Table(table) = value else {
                return String::new();
            };
            toml::to_string_pretty(&mask_secrets(&table)).unwrap_or_default()
        },
        _ => String::new(),
    }
}

/// The value of a storage entry: a fragment of configuration is gone
/// through like an entry, anything else is a secret as a whole.
pub(crate) fn masked_fragment(value: &str) -> String {
    match toml::from_str::<Table>(value) {
        Ok(table) if !table.is_empty() => {
            toml::to_string(&mask_secrets(&table)).unwrap_or_default()
        },
        _ if value.is_empty() => String::new(),
        _ => masked(value),
    }
}

/// The settings of a plugin as toml, for a log line.
pub fn masked_toml(table: &Table) -> String {
    mask_secrets(table).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn mask(data: &str) -> String {
        mask_secrets(&toml::from_str::<Table>(data).unwrap()).to_string()
    }

    #[test]
    fn test_mask_secrets_by_key() {
        let text = mask(
            r#"
category = "jwt"
secret = "abcd"
header = "Authorization"
admin_password = "p"
keys = ["k1", "k2"]
tls_key = "pem"
max = 10
"#,
        );
        for secret in ["abcd", "\"p\"", "k1", "k2", "pem"] {
            assert_eq!(false, text.contains(secret), "{secret}: {text}");
        }
        assert_eq!(true, text.contains(r#"header = "Authorization""#));
        assert_eq!(true, text.contains("max = 10"));
        // Two secrets, two checksums: a change still shows.
        assert_ne!(mask("secret = \"a\""), mask("secret = \"b\""));
        assert_eq!(mask("secret = \"a\""), mask("secret = \"a\""));

        // The header that lets a request past a maintenance notice: its
        // name stays, its value does not.
        let text = mask(
            "category = \"maintenance\"\nallow_header = \"X-Maintenance-Pass: s3cret\"",
        );
        assert_eq!(false, text.contains("s3cret"), "{text}");
        assert_eq!(true, text.contains("X-Maintenance-Pass:crc32:"), "{text}");

        // The entries of a combined_auth keep what is not a secret.
        let text = mask(
            r#"
[[authorizations]]
app_id = "pingap"
secret = "abcd"
ip_list = ["127.0.0.1"]
"#,
        );
        assert_eq!(true, text.contains("pingap"), "{text}");
        assert_eq!(true, text.contains("127.0.0.1"), "{text}");
        assert_eq!(false, text.contains("abcd"), "{text}");

        // What a limit counts by is a name.
        let text = mask("category = \"limit\"\nkey = \"X-Client\"");
        assert_eq!(true, text.contains("X-Client"), "{text}");
        let text = mask("category = \"csrf\"\nkey = \"abcd\"");
        assert_eq!(false, text.contains("abcd"), "{text}");
    }

    #[test]
    fn test_mask_urls_and_headers() {
        let url = |key: &str, value: &str| {
            let table: Table =
                [(key.to_string(), Value::String(value.to_string()))]
                    .into_iter()
                    .collect();
            mask_secrets(&table)[key].as_str().unwrap().to_string()
        };
        // User and password, wherever the url is.
        let masked = url("health_check", "http://admin:pwd@a.test/ping?b=1");
        assert_eq!(false, masked.contains("pwd"), "{masked}");
        assert_eq!(true, masked.ends_with("@a.test/ping?b=1"), "{masked}");
        assert_eq!(
            "http://a.test/ping?connection_timeout=3s",
            url("health_check", "http://a.test/ping?connection_timeout=3s")
        );
        // The query of what is called a url.
        let masked = url("auth_url", "https://a.test/check?token=abcd");
        assert_eq!(false, masked.contains("abcd"), "{masked}");
        assert_eq!(true, masked.starts_with("https://a.test/check?crc32:"));
        // A webhook has its key in the path or in the query.
        for value in [
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abcd",
            "https://hooks.slack.com/services/T0/B0/abcd",
        ] {
            let masked = url("webhook", value);
            assert_eq!(false, masked.contains("abcd"), "{masked}");
            assert_eq!(true, masked.contains(".com/crc32:"), "{masked}");
        }
        assert_eq!("https://a.test/", url("webhook", "https://a.test/"));
        // Not a url.
        assert_eq!("/api?x=1", url("auth_url", "/api?x=1"));
        assert_eq!("a@b", url("webhook", "a@b"));

        let text = mask(
            r#"proxy_set_headers = ["Authorization: Bearer abcd", "X-Api-Key:abcd", "X-Access-Key: abcd", "X-Signature: abcd", "X-Forwarded-Proto: https", "broken"]"#,
        );
        assert_eq!(false, text.contains("abcd"), "{text}");
        assert_eq!(true, text.contains("Authorization:crc32:"), "{text}");
        assert_eq!(true, text.contains("X-Forwarded-Proto: https"), "{text}");
        assert_eq!(true, text.contains("broken"), "{text}");
    }

    #[test]
    fn test_masked_fragment() {
        let text =
            masked_fragment("read_timeout = \"7s\"\nsecret = \"abcd\"\n");
        assert_eq!(true, text.contains("read_timeout = \"7s\""), "{text}");
        assert_eq!(false, text.contains("abcd"), "{text}");
        // Not a fragment: a secret as a whole.
        let text = masked_fragment("PLpKJqvfkjTcYTDpauJf+2JnEayP+bm+0Oe60Jk=");
        assert_eq!(true, text.starts_with("crc32:"), "{text}");
        assert_eq!("", masked_fragment(""));
    }
}
