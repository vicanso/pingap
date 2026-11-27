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

use crate::{Category, PingapConfig};
use std::collections::{HashMap, HashSet};
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
                // `Authorization: Bearer ...` for the receiver.
                | "webhook_headers"
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

fn mask_storage_value(raw: &str, referenced: &HashSet<String>) -> String {
    if raw.is_empty() {
        return String::new();
    }
    if !referenced.is_empty() && referenced.contains(raw) {
        return masked(raw);
    }
    match toml::from_str::<Table>(raw) {
        Ok(mut table) if !table.is_empty() => {
            if !referenced.is_empty() {
                let mut val = Value::Table(table);
                mask_referenced(&mut val, referenced);
                let Value::Table(t) = val else {
                    return String::new();
                };
                table = t;
            }
            toml::to_string(&mask_secrets(&table)).unwrap_or_default()
        },
        _ => masked(raw),
    }
}

fn mask_storage_table(table: &mut Table, referenced: &HashSet<String>) {
    if table.values().any(Value::is_table) {
        for (_, value) in table.iter_mut() {
            if let Value::Table(entry) = value {
                mask_storage_table(entry, referenced);
            }
        }
        return;
    }
    if let Some(Value::String(raw)) = table.get_mut("value") {
        *raw = mask_storage_value(raw, referenced);
    }
}

/// Returns `value` with credentials masked for read-only viewing according to
/// `category`: keys matching [`is_secret_key`], PEM keys/certs, URL
/// credentials/paths/queries, auth headers, storage secret fragments, and
/// values resolved from `$ENV:` or `$FILE:` references (`referenced`).
pub fn mask_category_toml_value(
    category: Category,
    value: &Value,
    referenced: &HashSet<String>,
) -> Value {
    let mut cloned = value.clone();
    if let Value::Table(ref mut table) = cloned {
        if category == Category::Storage {
            mask_storage_table(table, referenced);
        }
        if !referenced.is_empty() {
            mask_referenced(&mut cloned, referenced);
        }
        let Value::Table(table) = cloned else {
            return value.clone();
        };
        return Value::Table(mask_secrets(&table));
    }
    if !referenced.is_empty() {
        mask_referenced(&mut cloned, referenced);
    }
    cloned
}

fn mask_typed_entry<T>(
    category: Category,
    entry: &T,
    referenced: &HashSet<String>,
) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + Default,
{
    let Ok(value) = Value::try_from(entry) else {
        return T::default();
    };
    let masked = mask_category_toml_value(category.clone(), &value, referenced);
    if let Ok(parsed) = masked.try_into::<T>() {
        return parsed;
    }
    // Never fall back to the unmasked entry if a resolved reference value
    // happened to collide with a non-string typed field; mask by key/format
    // alone instead.
    let empty = HashSet::new();
    mask_category_toml_value(category, &value, &empty)
        .try_into::<T>()
        .unwrap_or_default()
}

fn mask_typed_map<T>(
    category: Category,
    entries: &HashMap<String, T>,
    referenced: &HashSet<String>,
) -> HashMap<String, T>
where
    T: serde::Serialize + serde::de::DeserializeOwned + Default,
{
    entries
        .iter()
        .map(|(name, entry)| {
            (
                name.clone(),
                mask_typed_entry(category.clone(), entry, referenced),
            )
        })
        .collect()
}

/// Returns a copy of `conf` with every secret, PEM key/cert, URL credential,
/// auth header, storage secret fragment, and `$ENV`/`$FILE` `referenced`
/// value replaced by its `crc32:` checksum.
pub fn mask_pingap_config(conf: &PingapConfig) -> PingapConfig {
    let referenced = &conf.referenced;
    let plugins = conf
        .plugins
        .iter()
        .map(|(name, plugin)| {
            let masked = mask_category_toml_value(
                Category::Plugin,
                &Value::Table(plugin.clone()),
                referenced,
            );
            let table = match masked {
                Value::Table(table) => table,
                _ => Table::new(),
            };
            (name.clone(), table)
        })
        .collect();

    PingapConfig {
        basic: mask_typed_entry(Category::Basic, &conf.basic, referenced),
        upstreams: mask_typed_map(
            Category::Upstream,
            &conf.upstreams,
            referenced,
        ),
        locations: mask_typed_map(
            Category::Location,
            &conf.locations,
            referenced,
        ),
        servers: mask_typed_map(Category::Server, &conf.servers, referenced),
        streams: mask_typed_map(Category::Stream, &conf.streams, referenced),
        plugins,
        certificates: mask_typed_map(
            Category::Certificate,
            &conf.certificates,
            referenced,
        ),
        storages: mask_typed_map(Category::Storage, &conf.storages, referenced),
        referenced: HashSet::new(),
    }
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

    /// What a webhook is given to authenticate with is not shown: its
    /// secret, and its headers, which are a token as often as not.
    #[test]
    fn test_mask_webhook_credentials() {
        let table: Table = toml::from_str(
            "webhook_secret = \"SECabcdef\"\nwebhook_headers = [\"Authorization: Bearer t0ken-1234\"]\nwebhook_template = \"{{title}}: {{message}}\"\nwebhook_min_level = \"warn\"",
        )
        .unwrap();
        let text = toml::to_string(&mask_secrets(&table)).unwrap();
        assert_eq!(false, text.contains("SECabcdef"), "{text}");
        assert_eq!(false, text.contains("t0ken-1234"), "{text}");
        // the rest of it is as it was written
        assert_eq!(true, text.contains("{{title}}: {{message}}"), "{text}");
        assert_eq!(true, text.contains("warn"), "{text}");
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

    #[test]
    fn test_mask_pingap_config_and_category_toml_value() {
        let mut conf = crate::convert_pingap_config(
            br#"
[basic]
name = "pingap"
webhook = "https://hook.test/send?key=hook-secret"
webhook_secret = "wh-sec-123"
webhook_headers = ["Authorization: Bearer hdr-sec-456", "X-Env: prod"]

[upstreams.api]
addrs = ["127.0.0.1:5000"]
health_check = "http://user:up-pass@127.0.0.1:5000/ping"
client_cert = "-----BEGIN CERTIFICATE-----\nCERTDATA\n-----END CERTIFICATE-----"
client_key = "-----BEGIN PRIVATE KEY-----\nKEYDATA\n-----END PRIVATE KEY-----"

[locations.app]
upstream = "api"
proxy_set_headers = ["Authorization: Bearer loc-token", "X-App: demo"]

[servers.web]
addr = "0.0.0.0:8080"
prometheus_metrics = "http://user:prom-pass@prom.test/metrics?token=q-tok"

[plugins.auth]
category = "jwt"
secret = "jwt-secret-xyz"
header = "Authorization"

[certificates.site]
domains = "example.com"
tls_cert = "-----BEGIN CERTIFICATE-----\nSITECERT\n-----END CERTIFICATE-----"
tls_key = "-----BEGIN PRIVATE KEY-----\nSITEKEY\n-----END PRIVATE KEY-----"
acme_eab_hmac = "eab-secret"

[storages.frag]
category = "config"
value = "read_timeout = \"7s\"\nsecret = \"frag-secret\"\n"
secret = "storage-aes-secret"

[storages.raw_sec]
category = "secret"
value = "raw-secret-token"
"#,
            false,
        )
        .unwrap();
        conf.referenced.insert("resolved-env-secret".to_string());
        conf.basic.error_template = Some("resolved-env-secret".to_string());

        let masked = mask_pingap_config(&conf);
        let serialized = toml::to_string_pretty(&masked).unwrap();
        for secret in [
            "hook-secret",
            "wh-sec-123",
            "hdr-sec-456",
            "up-pass",
            "CERTDATA",
            "KEYDATA",
            "loc-token",
            "prom-pass",
            "q-tok",
            "jwt-secret-xyz",
            "SITECERT",
            "SITEKEY",
            "eab-secret",
            "frag-secret",
            "storage-aes-secret",
            "raw-secret-token",
            "resolved-env-secret",
        ] {
            assert_eq!(
                false,
                serialized.contains(secret),
                "{secret}: {serialized}"
            );
        }
        assert_eq!(true, serialized.contains("crc32:"), "{serialized}");
        assert_eq!(false, serialized.contains("X-Env: prod"), "{serialized}");
        assert_eq!(true, serialized.contains("X-App: demo"), "{serialized}");
        assert_eq!(true, serialized.contains("read_timeout"), "{serialized}");
        assert_eq!(
            true,
            masked
                .basic
                .error_template
                .as_deref()
                .is_some_and(|v| v.starts_with("crc32:"))
        );
        assert_eq!(
            true,
            masked.storages["raw_sec"].value.starts_with("crc32:")
        );
        assert_eq!(
            false,
            masked.storages["frag"].value.contains("frag-secret")
        );
        assert_eq!(
            true,
            masked.storages["frag"].value.contains("read_timeout")
        );

        let referenced = HashSet::from(["custom-ref-val".to_string()]);
        let storage_entry: Value = toml::from_str(
            "category = \"config\"\nvalue = \"secret = \\\"inner\\\"\\nremark = \\\"custom-ref-val\\\"\"\nsecret = \"aes-key\"",
        )
        .unwrap();
        let masked_storage = mask_category_toml_value(
            Category::Storage,
            &storage_entry,
            &referenced,
        );
        let s = masked_storage.to_string();
        assert_eq!(false, s.contains("inner"), "{s}");
        assert_eq!(false, s.contains("custom-ref-val"), "{s}");
        assert_eq!(false, s.contains("aes-key"), "{s}");
        assert_eq!(true, s.contains("crc32:"), "{s}");

        let plugin_entry: Value = toml::from_str(
            "category = \"key_auth\"\nkeys = [\"k1\", \"custom-ref-val\"]\nheader = \"X-Key\"",
        )
        .unwrap();
        let masked_plugin = mask_category_toml_value(
            Category::Plugin,
            &plugin_entry,
            &referenced,
        );
        let p = masked_plugin.to_string();
        assert_eq!(false, p.contains("\"k1\""), "{p}");
        assert_eq!(false, p.contains("custom-ref-val"), "{p}");
        assert_eq!(true, p.contains("X-Key"), "{p}");
        assert_eq!(true, p.contains("crc32:"), "{p}");
    }
}
