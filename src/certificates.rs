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
    update_certificates,
};
use pingap_config::{CertificateConf, Hashable};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;

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
    // Certificates whose configuration did not change are carried over
    // as they are, not parsed and loaded again.
    let (new_certs, errors, updated_certificates) =
        update_certificates(certificate_configs, &CERTIFICATE_PROVIDER.list());

    let error_messages: Vec<String> = errors
        .into_iter()
        .map(|(name, msg)| format!("{}({})", msg, name))
        .collect();

    CERTIFICATE_PROVIDER.store(new_certs);
    (updated_certificates, error_messages.join(";"))
}

/// The hash a certificate given as files had when loading it last failed,
/// by name: a file that does not load is reported once, not on every pass.
static FAILED_FILES: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Loads again the certificates given as files whose files are not the
/// ones that are loaded, and leaves every other certificate in the store
/// exactly as it is.
///
/// It goes by what is loaded and not by what the last pass saw, so a
/// reload that another writer of the store overwrote is made again. And it
/// puts its result into the store as a change to whatever the store holds
/// at that moment (`rcu`), not as a new store built from an earlier look
/// at it: the certificates of ACME are written by their own service, and a
/// renewal stored in between must not be undone.
pub fn try_reload_certificate_files(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (Vec<String>, String) {
    let current = CERTIFICATE_PROVIDER.list();
    let mut failed = FAILED_FILES.lock().unwrap_or_else(|e| e.into_inner());
    let mut hashes = HashMap::new();
    let stale: HashMap<String, CertificateConf> = certificate_configs
        .iter()
        .filter(|(_, conf)| conf.reads_files())
        .filter(|(name, conf)| {
            let hash = conf.hash_key();
            let loaded = current.values().any(|cert| {
                cert.name.as_deref() == Some(name.as_str())
                    && cert.hash_key == hash
            });
            let reported = failed.get(*name) == Some(&hash);
            hashes.insert((*name).clone(), hash);
            !loaded && !reported
        })
        .map(|(name, conf)| (name.clone(), conf.clone()))
        .collect();
    // What is no longer a certificate from files has nothing to report.
    failed.retain(|name, _| hashes.contains_key(name));
    if stale.is_empty() {
        return (vec![], String::new());
    }
    let (rebuilt, errors, updated) = update_certificates(&stale, &current);
    for name in stale.keys() {
        failed.remove(name);
    }
    for (name, _) in errors.iter() {
        if let Some(hash) = hashes.remove(name) {
            failed.insert(name.clone(), hash);
        }
    }
    if !updated.is_empty() {
        let is_updated = |cert: &pingap_certificate::TlsCertificate| {
            cert.name
                .as_ref()
                .is_some_and(|name| updated.contains(name))
        };
        CERTIFICATE_PROVIDER.certificates.rcu(|certificates| {
            let mut merged: DynamicCertificates = certificates
                .iter()
                .filter(|(_, cert)| !is_updated(cert))
                .map(|(domain, cert)| (domain.clone(), cert.clone()))
                .collect();
            merged.extend(
                rebuilt
                    .iter()
                    .filter(|(_, cert)| is_updated(cert))
                    .map(|(domain, cert)| (domain.clone(), cert.clone())),
            );
            merged
        });
    }
    let error_messages: Vec<String> = errors
        .into_iter()
        .map(|(name, msg)| format!("{msg}({name})"))
        .collect();
    (updated, error_messages.join(";"))
}
