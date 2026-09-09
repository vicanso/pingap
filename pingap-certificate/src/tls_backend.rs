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
use pingap_config::ServerConf;
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

fn non_empty(value: &Option<String>) -> bool {
    value.as_ref().is_some_and(|s| !s.is_empty())
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
    if TLS_BACKEND != "rustls" {
        return Ok(());
    }

    let mut problems = Vec::new();
    for (name, server) in servers {
        let mut set = Vec::new();
        if non_empty(&server.tls_cipher_list) {
            set.push("tls_cipher_list");
        }
        if non_empty(&server.tls_ciphersuites) {
            set.push("tls_ciphersuites");
        }
        if non_empty(&server.tls_min_version) {
            set.push("tls_min_version");
        }
        if non_empty(&server.tls_max_version) {
            set.push("tls_max_version");
        }
        if set.is_empty() {
            continue;
        }
        problems.push(format!(
            "server `{name}` sets {} which the rustls backend does not support \
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

#[cfg(test)]
mod tests {
    use super::{
        install_default_crypto_provider, validate_servers_tls_for_backend,
    };
    use crate::TLS_BACKEND;
    use pingap_config::ServerConf;
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
        let result = validate_servers_tls_for_backend(&servers);
        if TLS_BACKEND == "rustls" {
            let err = result.expect_err("rustls must reject tls_* settings");
            let message = err.to_string();
            assert!(message.contains("tls_min_version"), "{message}");
            assert!(message.contains("tls_cipher_list"), "{message}");
            assert!(message.contains("https"), "{message}");
        } else {
            assert_eq!(true, result.is_ok());
        }
    }
}
