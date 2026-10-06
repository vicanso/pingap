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

/// Brings the certificates of `certificate_configs` up to date, and takes
/// those that are no longer in it out of the store, without touching the
/// ones `is_left(name)` names: they are built from `certificate_configs`
/// by someone else.
///
/// That someone is the ACME service. It stores a renewed certificate by
/// itself, and a store rebuilt here from the configuration as it was read
/// a moment earlier would put the certificate from before the renewal back
/// in its place. So the result goes into the store as a change to what the
/// store holds at that moment, as `try_reload_certificate_files` does it.
///
/// A domain that two entries name is served by one of them. When that one
/// goes, the domain is given to the other, a certificate that was left
/// alone included: it is not in the store under a name it lost to the
/// certificate that is now gone, and without this the domain had none.
pub fn try_update_certificates_except(
    certificate_configs: &HashMap<String, CertificateConf>,
    is_left: impl Fn(&str) -> bool,
) -> (Vec<String>, String) {
    let (theirs, ours): (HashMap<_, _>, HashMap<_, _>) = certificate_configs
        .iter()
        .map(|(name, conf)| (name.clone(), conf.clone()))
        .partition(|(name, _)| is_left(name));
    let current = CERTIFICATE_PROVIDER.list();
    let (rebuilt, errors, updated) = update_certificates(&ours, &current);
    // The domains of the certificates left alone, as their entries have
    // them. Only looked at for a domain nothing else serves.
    let (claimed, _, _) = update_certificates(&theirs, &current);
    CERTIFICATE_PROVIDER.certificates.rcu(|certificates| {
        let mut merged: DynamicCertificates = certificates
            .iter()
            .filter(|(_, cert)| cert.name.as_deref().is_none_or(&is_left))
            .map(|(domain, cert)| (domain.clone(), cert.clone()))
            .collect();
        merged.extend(
            rebuilt
                .iter()
                .map(|(domain, cert)| (domain.clone(), cert.clone())),
        );
        for (domain, cert) in claimed.iter() {
            if merged.contains_key(domain) {
                continue;
            }
            // The certificate the store has under that name now, which
            // may be newer than the entry this was built from.
            let stored = certificates.values().find(|stored| {
                stored.name.is_some() && stored.name == cert.name
            });
            merged.insert(domain.clone(), stored.unwrap_or(cert).clone());
        }
        merged
    });
    let error_messages: Vec<String> = errors
        .into_iter()
        .map(|(name, msg)| format!("{msg}({name})"))
        .collect();
    (updated, error_messages.join(";"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_certificate::rcgen;
    use pretty_assertions::assert_eq;

    fn new_conf(domain: &str) -> CertificateConf {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![domain.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        CertificateConf {
            domains: Some(domain.to_string()),
            tls_cert: Some(cert.pem()),
            tls_key: Some(key.serialize_pem()),
            ..Default::default()
        }
    }

    fn loaded(domain: &str) -> Option<String> {
        CERTIFICATE_PROVIDER
            .list()
            .get(domain)
            .map(|cert| cert.hash_key.clone())
    }

    /// Regression: with one certificate of ACME in the configuration none
    /// was reloaded at all. Now the others are, and the one of ACME is not
    /// touched: not by a change to it, and not by what the configuration
    /// said of it before its service stored a renewal.
    #[test]
    fn test_update_certificates_except_leaves_the_others() {
        // The store is the process's, shared with every other test.
        let mine = |name: &str| name.starts_with("cfg8-");
        let static_v1 = new_conf("cfg8-static.test");
        let acme_v1 = CertificateConf {
            acme: Some("lets_encrypt".to_string()),
            ..new_conf("cfg8-acme.test")
        };
        let configs = |items: &[(&str, &CertificateConf)]| {
            items
                .iter()
                .map(|(name, conf)| (name.to_string(), (*conf).clone()))
                .collect::<HashMap<_, _>>()
        };

        let (updated, errors) = try_update_certificates_except(
            &configs(&[("cfg8-static", &static_v1), ("cfg8-acme", &acme_v1)]),
            |name| !mine(name),
        );
        assert_eq!("", errors);
        assert_eq!(2, updated.len());
        assert_eq!(Some(static_v1.hash_key()), loaded("cfg8-static.test"));
        assert_eq!(Some(acme_v1.hash_key()), loaded("cfg8-acme.test"));

        // The ACME service stores a renewal.
        let acme_v2 = CertificateConf {
            acme: Some("lets_encrypt".to_string()),
            ..new_conf("cfg8-acme.test")
        };
        try_update_certificates_except(
            &configs(&[("cfg8-acme", &acme_v2)]),
            |name| name != "cfg8-acme",
        );
        assert_eq!(Some(acme_v2.hash_key()), loaded("cfg8-acme.test"));

        // A reload that changes the other certificate, with the entry of
        // ACME as the configuration had it before the renewal.
        let static_v2 = new_conf("cfg8-static.test");
        let left = |name: &str| name == "cfg8-acme" || !mine(name);
        let (updated, errors) = try_update_certificates_except(
            &configs(&[("cfg8-static", &static_v2), ("cfg8-acme", &acme_v1)]),
            left,
        );
        assert_eq!("", errors);
        assert_eq!(vec!["cfg8-static".to_string()], updated);
        assert_eq!(Some(static_v2.hash_key()), loaded("cfg8-static.test"));
        assert_eq!(Some(acme_v2.hash_key()), loaded("cfg8-acme.test"));

        // One that does not load keeps the certificate that is serving.
        let broken = CertificateConf {
            tls_key: new_conf("cfg8-static.test").tls_key,
            ..static_v2.clone()
        };
        let (updated, errors) = try_update_certificates_except(
            &configs(&[("cfg8-static", &broken), ("cfg8-acme", &acme_v1)]),
            left,
        );
        assert_eq!(true, updated.is_empty());
        assert_eq!(true, errors.contains("cfg8-static"), "{errors}");
        assert_eq!(Some(static_v2.hash_key()), loaded("cfg8-static.test"));

        // Taken out of the configuration, it is taken out of the store.
        let (updated, errors) = try_update_certificates_except(
            &configs(&[("cfg8-acme", &acme_v1)]),
            left,
        );
        assert_eq!("", errors);
        assert_eq!(true, updated.is_empty());
        assert_eq!(None, loaded("cfg8-static.test"));
        assert_eq!(Some(acme_v2.hash_key()), loaded("cfg8-acme.test"));

        try_update_certificates_except(&HashMap::new(), |name| !mine(name));
        assert_eq!(None, loaded("cfg8-acme.test"));
    }

    /// A domain named by a certificate that is reloaded and by one that is
    /// left alone is served by the first. Taken out, it left the domain
    /// with no certificate at all: the other was not in the store under a
    /// name it had lost.
    #[test]
    fn test_update_certificates_except_hands_a_domain_over() {
        let mine = |name: &str| name.starts_with("cfg8b-");
        let configs = |items: &[(&str, &CertificateConf)]| {
            items
                .iter()
                .map(|(name, conf)| (name.to_string(), (*conf).clone()))
                .collect::<HashMap<_, _>>()
        };
        let shared = CertificateConf {
            is_default: None,
            ..new_conf("cfg8b-shared.test")
        };
        let acme = CertificateConf {
            acme: Some("lets_encrypt".to_string()),
            domains: Some("cfg8b-shared.test,cfg8b-own.test".to_string()),
            ..new_conf("cfg8b-shared.test")
        };
        let left = |name: &str| name == "cfg8b-acme" || !mine(name);

        // The certificate of ACME is in the store, the one of the
        // configuration comes in over the domain they share.
        try_update_certificates_except(
            &configs(&[("cfg8b-acme", &acme)]),
            |name| !mine(name),
        );
        try_update_certificates_except(
            &configs(&[("cfg8b-static", &shared), ("cfg8b-acme", &acme)]),
            left,
        );
        assert_eq!(Some(shared.hash_key()), loaded("cfg8b-shared.test"));
        assert_eq!(Some(acme.hash_key()), loaded("cfg8b-own.test"));

        // It goes: the domain is the other one's again.
        try_update_certificates_except(
            &configs(&[("cfg8b-acme", &acme)]),
            left,
        );
        assert_eq!(Some(acme.hash_key()), loaded("cfg8b-shared.test"));
        assert_eq!(Some(acme.hash_key()), loaded("cfg8b-own.test"));

        try_update_certificates_except(&HashMap::new(), |name| !mine(name));
        assert_eq!(None, loaded("cfg8b-shared.test"));
    }
}
