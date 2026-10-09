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
    CertificatePair, CertificateProvider, DynamicCertificates,
    is_unused_certificate_key, lookup_certificates, unused_certificate_key,
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
        self.get_pair(sni).first().cloned()
    }
    // The name itself, its wildcard, then the default certificate: each
    // with the two certificates it may have.
    fn get_pair(&self, sni: &str) -> CertificatePair {
        lookup_certificates(&self.certificates.load(), sni)
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
    let (updated, errors) = update_except(certificate_configs, is_left);
    let error_messages: Vec<String> = errors
        .into_iter()
        .map(|(name, msg)| format!("{msg}({name})"))
        .collect();
    (updated, error_messages.join(";"))
}

/// [`try_update_certificates_except`], with the errors by the name of
/// their entry.
fn update_except(
    certificate_configs: &HashMap<String, CertificateConf>,
    is_left: impl Fn(&str) -> bool,
) -> (Vec<String>, Vec<(String, String)>) {
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
        // A certificate that was left alone and has lost every name to
        // the ones that were rebuilt stays in the store, under the key of
        // one that serves nothing: it is configured, and is looked after
        // like the rest. One that serves again does not need that key.
        let serving: std::collections::HashSet<String> = merged
            .iter()
            .filter(|(key, _)| !is_unused_certificate_key(key))
            .filter_map(|(_, cert)| cert.name.clone())
            .collect();
        merged.retain(|key, cert| {
            !is_unused_certificate_key(key)
                || cert
                    .name
                    .as_ref()
                    .is_none_or(|name| !serving.contains(name))
        });
        for cert in certificates.values().chain(claimed.values()) {
            if let Some(name) = &cert.name
                && theirs.contains_key(name)
                && !serving.contains(name)
            {
                merged
                    .entry(unused_certificate_key(name))
                    .or_insert_with(|| cert.clone());
            }
        }
        merged
    });
    // Said at every reload it is so, as for the entries that are rebuilt.
    let store = CERTIFICATE_PROVIDER.list();
    for (key, cert) in store.iter() {
        if is_unused_certificate_key(key)
            && let Some(name) = &cert.name
            && theirs.contains_key(name)
        {
            tracing::warn!(
                target: "pingap::certificate",
                ignored = name,
                "the certificate serves no domain: others with the same kind of key have them all"
            );
        }
    }
    (updated, errors)
}

/// The hash a certificate given as files had when loading it last failed,
/// by name: a file that does not load is reported once, not on every pass.
static FAILED_FILES: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Loads again the certificates given as files whose files are not the
/// ones that are loaded, and leaves every other certificate as it is.
///
/// It goes by what is loaded and not by what the last pass saw, so a
/// reload that another writer of the store overwrote is made again. A
/// certificate that serves no name - another one has them all - is in the
/// store as well (`unused_certificate_key`), and is loaded like any
/// other. And it puts its result into the store as a change to whatever
/// the store holds at that moment (`rcu`), not as a new store built from
/// an earlier look at it: the certificates of ACME are written by their
/// own service, and a renewal stored in between must not be undone.
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
    // The store is made from all of the configuration, not from what is
    // stale alone: a domain two entries name goes to the one that has it
    // at a reload, whichever of the two it is whose file changed. Made
    // from the stale ones alone, each of two such entries took the domain
    // from the other at its turn - every pass, with a reload reported for
    // each. What did not change is not built again, and what is not of
    // this configuration, or is ACME's, stays as the store has it.
    let (updated, errors) = update_except(certificate_configs, |name| {
        certificate_configs
            .get(name)
            .is_none_or(|conf| conf.is_acme())
    });
    // Of this pass is what was stale. An entry that fails at every reload
    // was reported when it did.
    let updated: Vec<String> = updated
        .into_iter()
        .filter(|name| stale.contains_key(name))
        .collect();
    let errors: Vec<(String, String)> = errors
        .into_iter()
        .filter(|(name, _)| stale.contains_key(name))
        .collect();
    for name in stale.keys() {
        failed.remove(name);
    }
    for (name, _) in errors.iter() {
        if let Some(hash) = hashes.remove(name) {
            failed.insert(name.clone(), hash);
        }
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

    /// The same with an RSA key.
    fn new_rsa_conf(domain: &str) -> CertificateConf {
        let key = rcgen::KeyPair::generate_rsa_for(
            &rcgen::PKCS_RSA_SHA256,
            rcgen::RsaKeySize::_2048,
        )
        .unwrap();
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

    /// A domain with a certificate for each kind of key is served with
    /// both, and keeps both through a reload that leaves one of them
    /// alone: they are two keys of the store, not one that the reloaded
    /// certificate takes from the other.
    #[test]
    fn test_two_certificates_of_a_domain_through_a_reload() {
        let mine = |name: &str| name.starts_with("feat63-");
        let configs = |items: &[(&str, &CertificateConf)]| {
            items
                .iter()
                .map(|(name, conf)| (name.to_string(), (*conf).clone()))
                .collect::<HashMap<_, _>>()
        };
        let names = |sni: &str| {
            CERTIFICATE_PROVIDER
                .get_pair(sni)
                .iter()
                .map(|cert| cert.name.clone().unwrap_or_default())
                .collect::<Vec<_>>()
        };
        let acme = CertificateConf {
            acme: Some("lets_encrypt".to_string()),
            ..new_conf("feat63.test")
        };
        let rsa = new_rsa_conf("feat63.test");
        let left = |name: &str| name == "feat63-acme" || !mine(name);

        try_update_certificates_except(
            &configs(&[("feat63-acme", &acme)]),
            |name| !mine(name),
        );
        assert_eq!(vec!["feat63-acme"], names("feat63.test"));

        // The RSA one comes in with a reload: the two of them.
        let (updated, errors) = try_update_certificates_except(
            &configs(&[("feat63-rsa", &rsa), ("feat63-acme", &acme)]),
            left,
        );
        assert_eq!("", errors);
        assert_eq!(vec!["feat63-rsa".to_string()], updated);
        assert_eq!(vec!["feat63-acme", "feat63-rsa"], names("feat63.test"));
        assert_eq!(vec!["feat63-acme", "feat63-rsa"], names("FEAT63.test"));
        // Where one is asked for, the one that is not RSA.
        assert_eq!(
            Some("feat63-acme"),
            CERTIFICATE_PROVIDER
                .get("feat63.test")
                .and_then(|cert| cert.name.clone())
                .as_deref()
        );

        // A second RSA one is one too many, and the first by name stays.
        let (_, errors) = try_update_certificates_except(
            &configs(&[
                ("feat63-rsa", &rsa),
                ("feat63-rsa2", &new_rsa_conf("feat63.test")),
                ("feat63-acme", &acme),
            ]),
            left,
        );
        assert_eq!("", errors);
        assert_eq!(vec!["feat63-acme", "feat63-rsa"], names("feat63.test"));

        // The RSA ones go: the other is still there.
        try_update_certificates_except(
            &configs(&[("feat63-acme", &acme)]),
            left,
        );
        assert_eq!(vec!["feat63-acme"], names("feat63.test"));

        // One that is not of ACME comes in with the same kind of key: it
        // has the domain, and the one of ACME, which is left alone, is
        // still in the store - under a key that serves nothing.
        let in_store = |name: &str| {
            CERTIFICATE_PROVIDER
                .list()
                .iter()
                .filter(|(_, cert)| cert.name.as_deref() == Some(name))
                .map(|(key, _)| is_unused_certificate_key(key))
                .collect::<Vec<_>>()
        };
        let ecdsa = new_conf("feat63.test");
        try_update_certificates_except(
            &configs(&[("feat63-ecdsa", &ecdsa), ("feat63-acme", &acme)]),
            left,
        );
        assert_eq!(vec!["feat63-ecdsa"], names("feat63.test"));
        assert_eq!(vec![true], in_store("feat63-acme"));
        // And through the next reload.
        try_update_certificates_except(
            &configs(&[("feat63-ecdsa", &ecdsa), ("feat63-acme", &acme)]),
            left,
        );
        assert_eq!(vec![true], in_store("feat63-acme"));
        // It has the domain again when the other goes, and that key no
        // more.
        try_update_certificates_except(
            &configs(&[("feat63-acme", &acme)]),
            left,
        );
        assert_eq!(vec!["feat63-acme"], names("feat63.test"));
        assert_eq!(vec![false], in_store("feat63-acme"));

        // Not by `names`: the store is shared, and a default certificate
        // of another test would answer for the domain.
        try_update_certificates_except(&HashMap::new(), |name| !mine(name));
        assert_eq!(
            false,
            CERTIFICATE_PROVIDER
                .list()
                .values()
                .any(|cert| cert.name.as_deref().is_some_and(mine))
        );
    }

    /// Regression: two entries that name one domain with keys of one
    /// kind, both from files. Each pass of the file reloader took the one
    /// that was not serving for a certificate it had not loaded, loaded
    /// it alone and gave it the domain: the certificate of the domain
    /// changed at every pass, with a reload reported each time.
    #[test]
    fn test_reload_certificate_files_with_two_for_a_domain() {
        let mine = |name: &str| name.starts_with("rl-");
        let dir = tempfile::tempdir().unwrap();
        // `conf` with its certificate and key in files of `dir`.
        let write = |file: &str, conf: &CertificateConf| {
            let cert = dir.path().join(format!("{file}.pem"));
            let key = dir.path().join(format!("{file}.key"));
            std::fs::write(&cert, conf.tls_cert.as_deref().unwrap()).unwrap();
            std::fs::write(&key, conf.tls_key.as_deref().unwrap()).unwrap();
            CertificateConf {
                tls_cert: Some(cert.to_string_lossy().to_string()),
                tls_key: Some(key.to_string_lossy().to_string()),
                ..conf.clone()
            }
        };
        let served = || {
            CERTIFICATE_PROVIDER
                .get_pair("rl.test")
                .iter()
                .map(|cert| cert.name.clone().unwrap_or_default())
                .collect::<Vec<_>>()
        };
        // The last one names no domain at all: it serves nothing, and is
        // loaded once like the others.
        let nothing_named = CertificateConf {
            domains: Some(",".to_string()),
            ..write("none", &new_conf("rl-none.test"))
        };
        let all = HashMap::from([
            ("rl-a".to_string(), write("a", &new_conf("rl.test"))),
            ("rl-b".to_string(), write("b", &new_conf("rl.test"))),
            ("rl-rsa".to_string(), write("rsa", &new_rsa_conf("rl.test"))),
            ("rl-none".to_string(), nothing_named),
        ]);
        let nothing = (Vec::<String>::new(), String::new());

        try_update_certificates_except(&all, |name| !mine(name));
        assert_eq!(vec!["rl-a", "rl-rsa"], served());
        // Nothing changed: nothing is loaded again, pass after pass, and
        // the domain stays with the one that has it.
        for _ in 0..3 {
            assert_eq!(nothing, try_reload_certificate_files(&all));
            assert_eq!(vec!["rl-a", "rl-rsa"], served());
        }

        // The file of the one that does not serve is replaced: it is
        // loaded, once, and the domain is still not its.
        write("b", &new_conf("rl.test"));
        let (updated, errors) = try_reload_certificate_files(&all);
        assert_eq!("", errors);
        assert_eq!(vec!["rl-b".to_string()], updated);
        assert_eq!(vec!["rl-a", "rl-rsa"], served());
        assert_eq!(nothing, try_reload_certificate_files(&all));

        // The file of the one that serves: the new certificate serves.
        let hash = |index: usize| {
            CERTIFICATE_PROVIDER
                .get_pair("rl.test")
                .iter()
                .nth(index)
                .map(|cert| cert.hash_key.clone())
        };
        let (first, rsa) = (hash(0), hash(1));
        write("a", &new_conf("rl.test"));
        let (updated, errors) = try_reload_certificate_files(&all);
        assert_eq!("", errors);
        assert_eq!(vec!["rl-a".to_string()], updated);
        assert_eq!(vec!["rl-a", "rl-rsa"], served());
        assert_eq!(true, first != hash(0));
        // The other one of the domain is the one it was.
        assert_eq!(rsa, hash(1));

        // A file that does not load is reported once, and what was
        // serving goes on.
        let first = hash(0);
        std::fs::write(dir.path().join("a.pem"), "junk").unwrap();
        let (updated, errors) = try_reload_certificate_files(&all);
        assert_eq!(true, updated.is_empty());
        assert_eq!(true, errors.contains("rl-a"), "{errors}");
        assert_eq!(nothing, try_reload_certificate_files(&all));
        assert_eq!(vec!["rl-a", "rl-rsa"], served());
        assert_eq!(first, hash(0));

        // The RSA one gets a file with an ECDSA certificate: a third of
        // that kind, and the domain has none with an RSA key any more.
        write("a", &new_conf("rl.test"));
        try_reload_certificate_files(&all);
        write("rsa", &new_conf("rl.test"));
        let (updated, errors) = try_reload_certificate_files(&all);
        assert_eq!("", errors);
        assert_eq!(vec!["rl-rsa".to_string()], updated);
        assert_eq!(vec!["rl-a"], served());
        assert_eq!(nothing, try_reload_certificate_files(&all));

        try_update_certificates_except(&HashMap::new(), |name| !mine(name));
        assert_eq!(
            false,
            CERTIFICATE_PROVIDER
                .list()
                .values()
                .any(|cert| cert.name.as_deref().is_some_and(mine))
        );
    }
}
