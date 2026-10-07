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

use async_trait::async_trait;
use pingap_certificate::rcgen;
use snafu::Snafu;

/// Category name for ACME-related logging
pub static LOG_TARGET: &str = "pingap::acme";

/// Errors that can occur during ACME operations
#[derive(Debug, Snafu)]
pub enum Error {
    /// Error from the instant-acme library
    #[snafu(display("ACME instant error: {source}, category: {category}"))]
    Instant {
        category: String,
        source: instant_acme::Error,
    },

    /// Error from certificate generation
    #[snafu(display(
        "Certificate generation error: {source}, category: {category}"
    ))]
    Rcgen {
        category: String,
        source: rcgen::Error,
    },

    /// Challenge not found during verification
    #[snafu(display("ACME challenge not found: {message}"))]
    NotFound { message: String },

    /// General Let's Encrypt operation failure
    #[snafu(display(
        "Let's Encrypt operation failed: {message}, category: {category}"
    ))]
    Fail { category: String, message: String },
}

/// Convenience type alias for Results with our Error type
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// `$ENV:NAME` is read from the environment; anything else (including an
/// unset variable's name) is returned as it is.
fn get_value_from_env(value: &str) -> String {
    value
        .strip_prefix("$ENV:")
        .and_then(|name| std::env::var(name).ok())
        .unwrap_or_else(|| value.to_string())
}

/// The `dns_service_url` of a certificate with what it takes from the
/// environment filled in: the whole value written `$ENV:NAME`, or the value
/// of any of its query parameters (`?token=$ENV:CF_TOKEN`).
///
/// Only the whole value used to be looked at, while the documentation showed
/// the parameter form: the provider was handed the text `$ENV:CF_TOKEN` as
/// its credential.
fn dns_service_url_from_env(value: &str) -> String {
    let value = get_value_from_env(value);
    if !value.contains("$ENV:") {
        return value;
    }
    let Ok(mut url) = url::Url::parse(&value) else {
        return value;
    };
    let mut filled = false;
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| {
            let from_env = get_value_from_env(&value);
            filled |= from_env != value;
            (name.into_owned(), from_env)
        })
        .collect();
    // Written out again only when something was filled in.
    if !filled {
        return value;
    }
    url.query_pairs_mut().clear().extend_pairs(pairs);
    url.into()
}

/// Splits the name of a record into the part inside its zone and the zone:
/// `_acme-challenge.www.example.com` is `("_acme-challenge.www",
/// "example.com")`.
///
/// The zone is the registrable domain, from the public suffix list, which is
/// what the Cloudflare and Huawei tasks go by too. Cutting at the first dot
/// instead named `www.example.com` as the zone: the record of any name below
/// the registrable domain was refused by the provider, so a certificate for
/// a subdomain could not be issued.
pub(crate) fn split_record_name(name: &str) -> Result<(&str, &str)> {
    let name = name.trim_end_matches('.');
    psl::domain_str(name)
        .filter(|zone| zone.contains('.'))
        .and_then(|zone| {
            let record = name.strip_suffix(zone)?.strip_suffix('.')?;
            (!record.is_empty()).then_some((record, zone))
        })
        .ok_or_else(|| Error::Fail {
            category: "dns".to_string(),
            message: format!("invalid record name: {name}"),
        })
}

/// Acme DNS task
#[async_trait]
pub trait AcmeDnsTask: Sync + Send {
    /// Add a DNS TXT record
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()>;
    /// Task done, it will clean up the added dns txt record
    async fn done(&self) -> Result<()>;
}

mod dns_ali;
mod dns_cf;
mod dns_huawei;
mod dns_manual;
mod dns_tencent;
mod lets_encrypt;

pub use lets_encrypt::{handle_lets_encrypt, new_lets_encrypt_service};

#[cfg(test)]
mod tests {
    use super::{
        dns_service_url_from_env, get_value_from_env, split_record_name,
    };
    use pretty_assertions::assert_eq;

    /// Regression: the zone was everything after the first dot.
    #[test]
    fn test_split_record_name() {
        for (name, record, zone) in [
            (
                "_acme-challenge.example.com",
                "_acme-challenge",
                "example.com",
            ),
            (
                "_acme-challenge.www.example.com",
                "_acme-challenge.www",
                "example.com",
            ),
            (
                "_acme-challenge.a.b.example.com.",
                "_acme-challenge.a.b",
                "example.com",
            ),
            // a suffix of two labels
            (
                "_acme-challenge.example.co.uk",
                "_acme-challenge",
                "example.co.uk",
            ),
            (
                "_acme-challenge.www.example.com.cn",
                "_acme-challenge.www",
                "example.com.cn",
            ),
        ] {
            assert_eq!(
                (record, zone),
                split_record_name(name).unwrap(),
                "{name}"
            );
        }
        for name in ["example.com", "com", "_acme-challenge.com", ""] {
            assert_eq!(true, split_record_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn test_get_value_from_env() {
        assert_eq!("", get_value_from_env(""));
        assert_eq!("plain", get_value_from_env("plain"));
        assert_eq!(
            std::env::var("PATH").unwrap_or_default(),
            get_value_from_env("$ENV:PATH")
        );
        assert_eq!(
            "$ENV:PINGAP_NOT_SET_FOR_SURE",
            get_value_from_env("$ENV:PINGAP_NOT_SET_FOR_SURE")
        );
    }

    /// Regression: `?token=$ENV:CF_TOKEN`, the form the documentation shows,
    /// reached the provider as that text.
    #[test]
    fn test_dns_service_url_from_env() {
        let path = std::env::var("PATH").unwrap_or_default();
        let query = |value: &str| -> Vec<(String, String)> {
            url::Url::parse(&dns_service_url_from_env(value))
                .unwrap()
                .query_pairs()
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect()
        };
        assert_eq!(
            vec![
                ("token".to_string(), path.clone()),
                ("plain".to_string(), "a b+c".to_string()),
                (
                    "unset".to_string(),
                    "$ENV:PINGAP_NOT_SET_FOR_SURE".to_string()
                ),
            ],
            query(
                "https://api.cloudflare.com?token=$ENV:PATH&plain=a%20b%2Bc&unset=$ENV:PINGAP_NOT_SET_FOR_SURE"
            )
        );
        // The whole value, as before.
        assert_eq!(path, dns_service_url_from_env("$ENV:PATH"));
        // Nothing to fill in: the text is not touched.
        for value in [
            "",
            "https://api.cloudflare.com?token=abc%20d",
            "not a url $ENV:PATH",
            "https://api.cloudflare.com?token=$ENV:PINGAP_NOT_SET_FOR_SURE&a=b%20c",
            "https://user:$ENV:PATH@api.cloudflare.com/path",
        ] {
            assert_eq!(value, dns_service_url_from_env(value));
        }
    }
}
