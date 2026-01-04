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

use ahash::AHashMap;
use arc_swap::ArcSwap;
use pingap_certificate::{
    CertificateProvider, DEFAULT_SERVER_NAME, DynamicCertificates,
    parse_certificates,
};
use pingap_config::CertificateConf;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;

struct Provider {
    certificates: ArcSwap<DynamicCertificates>,
}

impl CertificateProvider for Provider {
    fn store(&self, data: DynamicCertificates) {
        self.certificates.store(Arc::new(data));
    }
    fn get(
        &self,
        sni: &str,
    ) -> Option<Arc<pingap_certificate::TlsCertificate>> {
        let certs = self.certificates.load();
        certs
            .get(sni)
            .or_else(|| {
                // If exact match fails, try wildcard match without new string allocation.
                sni.split_once('.')
                    .and_then(|(_, domain)| certs.get(&format!("*.{}", domain)))
            })
            .or_else(|| {
                // Fallback to the default certificate.
                certs.get(DEFAULT_SERVER_NAME)
            })
            .cloned()
    }
    fn list(&self) -> Arc<DynamicCertificates> {
        self.certificates.load().clone()
    }
}

static CERTIFICATE_PROVIDER: LazyLock<Arc<Provider>> = LazyLock::new(|| {
    Arc::new(Provider {
        certificates: ArcSwap::from_pointee(AHashMap::new()),
    })
});

pub fn new_certificate_provider() -> Arc<dyn CertificateProvider> {
    CERTIFICATE_PROVIDER.clone()
}

/// Updates the global certificate store with new configurations
///
/// # Arguments
/// * `certificate_configs` - HashMap of certificate names to their configurations
///
/// # Returns
/// * `Vec<String>` - List of domain names whose certificates were updated
/// * `String` - Semicolon-separated list of parsing errors
///
/// Updates certificates atomically using ArcSwap, detecting changes by comparing hash_keys.
/// Supports multiple domains per certificate and wildcard certificates.
pub fn try_update_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (Vec<String>, String) {
    let (new_certs, errors) = parse_certificates(certificate_configs);
    let old_certs = CERTIFICATE_PROVIDER.list();
    let updated_certificates: Vec<String> = new_certs
        .iter()
        .filter(|(name, cert)| {
            old_certs
                .get(*name)
                .is_none_or(|old_cert| old_cert.hash_key != cert.hash_key)
        })
        .map(|(name, _)| name.clone())
        .collect();

    let error_messages: Vec<String> = errors
        .into_iter()
        .map(|(name, msg)| format!("{}({})", msg, name))
        .collect();

    CERTIFICATE_PROVIDER.store(new_certs);
    (updated_certificates, error_messages.join(";"))
}
