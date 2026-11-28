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

use crate::{Error, Result, TLS_BACKEND};
use pingap_config::{CertificateConf, ServerConf, StreamConf};
use std::collections::HashMap;
#[cfg(feature = "tls-rustls")]
use std::sync::Once;

/// Installs the process-wide rustls crypto provider (`aws-lc-rs`).
///
/// No-op for the OpenSSL backend. Safe to call more than once; a later call
/// is ignored if another provider already won the race. Call early in `main`
/// before ACME or any other rustls user can install a different provider
/// (e.g. ring).
pub fn install_default_crypto_provider() {
    #[cfg(feature = "tls-rustls")]
    {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ =
                rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }
}

fn non_empty(value: Option<&str>) -> bool {
    value.is_some_and(|s| !s.is_empty())
}

fn collect_unsupported_tls_fields(
    tls_cipher_list: Option<&str>,
    tls_ciphersuites: Option<&str>,
    tls_min_version: Option<&str>,
    tls_max_version: Option<&str>,
) -> Vec<&'static str> {
    [
        ("tls_cipher_list", tls_cipher_list),
        ("tls_ciphersuites", tls_ciphersuites),
        ("tls_min_version", tls_min_version),
        ("tls_max_version", tls_max_version),
    ]
    .into_iter()
    .filter_map(|(field, value)| non_empty(value).then_some(field))
    .collect()
}

fn validate_tls_fields_for_backend<'a, I>(kind: &str, entries: I) -> Result<()>
where
    I: IntoIterator<
        Item = (
            &'a str,
            (
                Option<&'a str>,
                Option<&'a str>,
                Option<&'a str>,
                Option<&'a str>,
            ),
        ),
    >,
{
    if TLS_BACKEND != "rustls" {
        return Ok(());
    }

    let mut problems = Vec::new();
    for (name, (cipher_list, ciphersuites, min_ver, max_ver)) in entries {
        let set = collect_unsupported_tls_fields(
            cipher_list,
            ciphersuites,
            min_ver,
            max_ver,
        );
        if set.is_empty() {
            continue;
        }
        problems.push(format!(
            "{kind} `{name}` sets {} which the rustls backend does not support \
             (TLS is fixed to 1.2/1.3 with rustls default cipher suites); \
             remove them or build with the openssl feature",
            set.join(", ")
        ));
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(Error::Invalid {
            category: "tls".to_string(),
            message: problems.join("; "),
        })
    }
}

/// Rejects per-server TLS version / cipher settings that the active backend
/// cannot honour.
///
/// Under OpenSSL every setting is applied, so this is a no-op. Under rustls
/// pingora fixes TLS 1.2 + 1.3 with rustls' default cipher suites; leaving
/// the fields set used to only warn at listen time, which made
/// misconfiguration easy to miss. Config validation (startup, `--test`,
/// auto-restart) now fails instead.
pub fn validate_servers_tls_for_backend(
    servers: &HashMap<String, ServerConf>,
) -> Result<()> {
    validate_tls_fields_for_backend(
        "server",
        servers.iter().map(|(name, server)| {
            (
                name.as_str(),
                (
                    server.tls_cipher_list.as_deref(),
                    server.tls_ciphersuites.as_deref(),
                    server.tls_min_version.as_deref(),
                    server.tls_max_version.as_deref(),
                ),
            )
        }),
    )
}

/// Rejects per-stream TLS version / cipher settings that the active backend
/// cannot honour.
///
/// Shares the same rustls limitation as [`validate_servers_tls_for_backend`].
pub fn validate_streams_tls_for_backend(
    streams: &HashMap<String, StreamConf>,
) -> Result<()> {
    validate_tls_fields_for_backend(
        "stream",
        streams.iter().map(|(name, stream)| {
            (
                name.as_str(),
                (
                    stream.tls_cipher_list.as_deref(),
                    stream.tls_ciphersuites.as_deref(),
                    stream.tls_min_version.as_deref(),
                    stream.tls_max_version.as_deref(),
                ),
            )
        }),
    )
}

/// Rejects certificate ACME settings that the active TLS backend cannot honour.
///
/// Under OpenSSL `tls_alpn_challenge` negotiates `acme-tls/1` alongside HTTP/2
/// and HTTP/1.1 via OpenSSL's ALPN select callback. Pingora's rustls listener
/// only exposes single-protocol custom ALPN, so `tls_alpn_challenge` is
/// rejected at validation time when built with `tls-rustls`.
pub fn validate_certificates_tls_for_backend(
    certificates: &HashMap<String, CertificateConf>,
) -> Result<()> {
    if TLS_BACKEND != "rustls" {
        return Ok(());
    }

    let mut problems = Vec::new();
    for (name, cert) in certificates {
        if cert.tls_alpn_challenge.unwrap_or_default() {
            problems.push(format!(
                "certificate `{name}` sets tls_alpn_challenge which the rustls backend does not support \
                 (pingora's rustls listener does not support multi-protocol custom ALPN); \
                 use http-01/dns-01 or build with the openssl feature"
            ));
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(Error::Invalid {
            category: "tls".to_string(),
            message: problems.join("; "),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        install_default_crypto_provider, validate_servers_tls_for_backend,
        validate_streams_tls_for_backend,
    };
    use crate::TLS_BACKEND;
    use pingap_config::{ServerConf, StreamConf};
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;

    #[test]
    fn install_default_crypto_provider_is_idempotent() {
        install_default_crypto_provider();
        install_default_crypto_provider();
    }

    #[test]
    fn validate_accepts_clean_servers() {
        let mut servers = HashMap::new();
        servers.insert(
            "http".to_string(),
            ServerConf {
                addr: "127.0.0.1:80".to_string(),
                ..Default::default()
            },
        );
        assert!(validate_servers_tls_for_backend(&servers).is_ok());
    }

    #[test]
    fn validate_tls_settings_match_backend() {
        let mut servers = HashMap::new();
        servers.insert(
            "https".to_string(),
            ServerConf {
                addr: "127.0.0.1:443".to_string(),
                tls_min_version: Some("tlsv1.2".to_string()),
                tls_cipher_list: Some(
                    "ECDHE-RSA-AES128-GCM-SHA256".to_string(),
                ),
                ..Default::default()
            },
        );
        // An empty value is unset. Spaces are a value, so rustls
        // refuses them.
        servers.insert(
            "blank".to_string(),
            ServerConf {
                addr: "127.0.0.1:8443".to_string(),
                tls_min_version: Some(String::new()),
                tls_max_version: Some("  ".to_string()),
                ..Default::default()
            },
        );
        let result = validate_servers_tls_for_backend(&servers);
        if TLS_BACKEND == "rustls" {
            let err = result.expect_err("rustls must reject tls_* settings");
            let message = err.to_string();
            assert!(message.contains("tls_min_version"), "{message}");
            assert!(message.contains("tls_cipher_list"), "{message}");
            assert!(message.contains("tls_max_version"), "{message}");
            assert!(message.contains("https"), "{message}");
            assert!(message.contains("blank"), "{message}");
        } else {
            assert_eq!(true, result.is_ok());
        }
    }

    #[test]
    fn validate_certificate_tls_alpn_matches_backend() {
        use super::validate_certificates_tls_for_backend;
        use pingap_config::CertificateConf;

        let mut certs = HashMap::new();
        certs.insert(
            "site".to_string(),
            CertificateConf {
                domains: Some("example.com".to_string()),
                acme: Some("lets_encrypt".to_string()),
                tls_alpn_challenge: Some(true),
                ..Default::default()
            },
        );
        let result = validate_certificates_tls_for_backend(&certs);
        if TLS_BACKEND == "rustls" {
            let err =
                result.expect_err("rustls must reject tls_alpn_challenge");
            assert!(err.to_string().contains("tls_alpn_challenge"));
        } else {
            assert_eq!(true, result.is_ok());
        }
    }

    #[test]
    fn validate_stream_tls_settings_match_backend() {
        let mut streams = HashMap::new();
        streams.insert(
            "tls_gw".to_string(),
            StreamConf {
                addr: "127.0.0.1:9443".to_string(),
                upstream: Some("u".to_string()),
                global_certificates: Some(true),
                tls_min_version: Some("tlsv1.2".to_string()),
                tls_ciphersuites: Some("TLS_AES_128_GCM_SHA256".to_string()),
                ..Default::default()
            },
        );
        let result = validate_streams_tls_for_backend(&streams);
        if TLS_BACKEND == "rustls" {
            let err = result.expect_err("rustls must reject stream tls_*");
            let message = err.to_string();
            assert!(message.contains("stream `tls_gw`"), "{message}");
            assert!(message.contains("tls_min_version"), "{message}");
            assert!(message.contains("tls_ciphersuites"), "{message}");
        } else {
            assert_eq!(true, result.is_ok());
        }
    }
}
