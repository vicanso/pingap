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

//! Builds a complete configuration out of a few command line arguments, so a
//! reverse proxy can be started without writing a config file:
//!
//! ```sh
//! pingap --domain=pingap.io --upstream=192.168.1.1:3000 --cert=/etc/ssl/pingap.io
//! ```
//!
//! The generated config is handed to the memory config storage, which means it
//! goes through exactly the same validation and bootstrap path as a config read
//! from a file or from etcd.

use pingap_config::{
    BasicConf, CertificateConf, LocationConf, PingapConfig, ServerConf,
    UpstreamConf,
};
use pingap_util::resolve_path;
use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;

/// Name shared by the generated server, location, upstream and certificate.
/// Only one of each is created, so a fixed name keeps the generated config
/// readable when it is dumped with `--to-hcl` / `--to-kdl`.
const NAME: &str = "pingap";

/// Value of `certificates.*.acme` that selects let's encrypt.
const ACME_LETS_ENCRYPT: &str = "lets_encrypt";

/// Directory the acme state is kept in, relative to the user's home. It holds
/// the private key of the issued certificate, so it is created owner-only.
const ACME_DIR: &str = "~/.pingap/acme";

/// Certificate file names looked up inside a `--cert` directory, in priority
/// order. Covers certbot/lego (`fullchain.pem`), the plain `cert.pem` layout
/// and kubernetes TLS secrets (`tls.crt`).
const CERT_FILE_NAMES: [&str; 5] = [
    "fullchain.pem",
    "cert.pem",
    "tls.crt",
    "server.crt",
    "cert.crt",
];

/// Private key file names looked up in the same directory as the certificate.
const KEY_FILE_NAMES: [&str; 5] = [
    "privkey.pem",
    "key.pem",
    "tls.key",
    "server.key",
    "cert.key",
];

/// The subset of command line arguments that describes a proxy without a
/// config file.
#[derive(Debug, Default)]
pub struct QuickStartParams {
    /// Comma separated domains. Restricts the location to those hosts and, when
    /// TLS is enabled, is used as the certificate's domain list.
    pub domains: Option<String>,
    /// Comma separated upstream addresses (`host:port`).
    pub upstreams: String,
    /// TLS certificate: either the PEM file itself or a directory holding it.
    pub cert: Option<String>,
    /// TLS private key file. Optional when it sits next to the certificate
    /// under one of the well known names.
    pub key: Option<String>,
    /// Listen address, defaults to `0.0.0.0:443` with TLS, `0.0.0.0:80`
    /// without.
    pub addr: Option<String>,
}

/// Splits a comma separated argument, dropping blanks around the separators.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// Returns the first of `names` that exists in `dir`.
fn find_file(dir: &Path, names: &[&str]) -> Option<PathBuf> {
    names
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.is_file())
}

/// Resolves `--cert` / `--key` into a `(certificate file, key file)` pair.
///
/// `--cert` may point at the certificate itself or at the directory holding it,
/// which is what certbot and kubernetes TLS secrets produce. The key comes from
/// `--key` when given, otherwise it is looked up next to the certificate.
fn resolve_tls_files(
    cert: &str,
    key: Option<&str>,
) -> Result<(String, String)> {
    let cert_path = PathBuf::from(resolve_path(cert));
    let (cert_file, dir) = if cert_path.is_dir() {
        let file =
            find_file(&cert_path, &CERT_FILE_NAMES).ok_or_else(|| {
                format!(
                    "no certificate found in {}, expected one of: {}",
                    cert_path.display(),
                    CERT_FILE_NAMES.join(", ")
                )
            })?;
        (file, cert_path)
    } else if cert_path.is_file() {
        let dir = cert_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        (cert_path, dir)
    } else {
        return Err(format!(
            "certificate {} does not exist",
            cert_path.display()
        )
        .into());
    };

    let key_file = if let Some(key) = key {
        let key_path = PathBuf::from(resolve_path(key));
        if !key_path.is_file() {
            return Err(format!(
                "private key {} does not exist",
                key_path.display()
            )
            .into());
        }
        key_path
    } else {
        find_file(&dir, &KEY_FILE_NAMES).ok_or_else(|| {
            format!(
                "no private key found in {}, expected one of: {}, use --key to set it",
                dir.display(),
                KEY_FILE_NAMES.join(", ")
            )
        })?
    };

    Ok((
        cert_file.to_string_lossy().to_string(),
        key_file.to_string_lossy().to_string(),
    ))
}

/// Builds a single server / location / upstream (plus a certificate when TLS is
/// requested) from the command line arguments.
pub fn build_config(params: &QuickStartParams) -> Result<PingapConfig> {
    let addrs = split_list(&params.upstreams);
    if addrs.is_empty() {
        return Err("--upstream should not be empty".into());
    }
    let domains = {
        let list = split_list(params.domains.as_deref().unwrap_or_default());
        if list.is_empty() {
            None
        } else {
            Some(list.join(","))
        }
    };

    let mut certificates = HashMap::new();
    if let Some(cert) = &params.cert {
        let (tls_cert, tls_key) =
            resolve_tls_files(cert, params.key.as_deref())?;
        certificates.insert(
            NAME.to_string(),
            CertificateConf {
                // When no domain is given the certificate serves the names in
                // its own SAN list, which is what the operator already meant.
                domains: domains.clone(),
                tls_cert: Some(tls_cert),
                tls_key: Some(tls_key),
                is_default: Some(true),
                ..Default::default()
            },
        );
    } else if params.key.is_some() {
        return Err("--key should be used with --cert".into());
    } else if let Some(domains) = &domains {
        // No certificate but a domain to prove ownership of: let's encrypt can
        // issue one over http-01. The challenge listener on :80 is added by the
        // caller, the same way it is for a configured acme certificate.
        certificates.insert(
            NAME.to_string(),
            CertificateConf {
                domains: Some(domains.clone()),
                acme: Some(ACME_LETS_ENCRYPT.to_string()),
                is_default: Some(true),
                ..Default::default()
            },
        );
    }
    let tls = !certificates.is_empty();

    let addr = params.addr.clone().unwrap_or_else(|| {
        if tls {
            "0.0.0.0:443".to_string()
        } else {
            "0.0.0.0:80".to_string()
        }
    });

    Ok(PingapConfig {
        basic: BasicConf {
            name: Some(NAME.to_string()),
            log_level: Some("INFO".to_string()),
            ..Default::default()
        },
        upstreams: HashMap::from([(
            NAME.to_string(),
            UpstreamConf {
                addrs,
                ..Default::default()
            },
        )]),
        locations: HashMap::from([(
            NAME.to_string(),
            LocationConf {
                path: Some("/".to_string()),
                host: domains,
                upstream: Some(NAME.to_string()),
                ..Default::default()
            },
        )]),
        servers: HashMap::from([(
            NAME.to_string(),
            ServerConf {
                addr,
                access_log: Some("combined".to_string()),
                locations: Some(vec![NAME.to_string()]),
                global_certificates: tls.then_some(true),
                // h2 is only negotiated over tls here, there is no reason to
                // accept h2c on a plain listener nobody asked for.
                enabled_h2: tls.then_some(true),
                ..Default::default()
            },
        )]),
        certificates,
        ..Default::default()
    })
}

/// Where the acme state of a generated config is persisted, `None` when the
/// config does not use acme. The file name is derived from the served domains
/// so two command line proxies never share a certificate file.
pub fn acme_state_path(config: &PingapConfig) -> Option<PathBuf> {
    let certificate = config.certificates.get(NAME)?;
    if certificate.acme.as_deref().unwrap_or_default().is_empty() {
        return None;
    }
    let name: String = certificate
        .domains
        .clone()
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Some(PathBuf::from(resolve_path(ACME_DIR)).join(format!("{name}.toml")))
}

/// Copies the certificate a previous run obtained from let's encrypt into the
/// freshly generated config.
///
/// Everything else keeps coming from the command line, so changing `--upstream`
/// or `--addr` takes effect immediately while the certificate — which is rate
/// limited and slow to replace — is reused. A missing or unreadable file just
/// means no certificate yet; the acme task requests one on the first run.
pub fn restore_acme_certificate(
    config: &mut PingapConfig,
    path: &Path,
) -> bool {
    let Ok(data) = std::fs::read_to_string(path) else {
        return false;
    };
    let saved = toml::from_str::<pingap_config::PingapTomlConfig>(&data)
        .ok()
        .and_then(|saved| saved.to_pingap_config(false).ok())
        .and_then(|saved| saved.certificates.get(NAME).cloned());
    let Some(saved) = saved else {
        return false;
    };
    let (Some(tls_cert), Some(tls_key)) = (saved.tls_cert, saved.tls_key)
    else {
        return false;
    };
    if tls_cert.is_empty() || tls_key.is_empty() {
        return false;
    }
    let Some(certificate) = config.certificates.get_mut(NAME) else {
        return false;
    };
    certificate.tls_cert = Some(tls_cert);
    certificate.tls_key = Some(tls_key);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::fs;

    #[test]
    fn test_build_config_without_tls() {
        let config = build_config(&QuickStartParams {
            upstreams: "192.168.1.1:3000, 192.168.1.2:3000".to_string(),
            ..Default::default()
        })
        .unwrap();

        let server = config.servers.get(NAME).unwrap();
        assert_eq!("0.0.0.0:80", server.addr);
        assert_eq!(None, server.global_certificates);
        assert_eq!(None, server.enabled_h2);
        assert_eq!(vec![NAME.to_string()], server.locations.clone().unwrap());

        let location = config.locations.get(NAME).unwrap();
        assert_eq!(Some("/".to_string()), location.path);
        assert_eq!(None, location.host);
        assert_eq!(Some(NAME.to_string()), location.upstream);

        assert_eq!(
            vec![
                "192.168.1.1:3000".to_string(),
                "192.168.1.2:3000".to_string()
            ],
            config.upstreams.get(NAME).unwrap().addrs
        );
        // no domain to prove ownership of, so no acme either
        assert!(config.certificates.is_empty());
        assert_eq!(None, acme_state_path(&config));

        config.validate().unwrap();
    }

    #[test]
    fn test_build_config_with_acme() {
        let config = build_config(&QuickStartParams {
            domains: Some("pingap.io, www.pingap.io".to_string()),
            upstreams: "192.168.1.1:3000".to_string(),
            ..Default::default()
        })
        .unwrap();

        // a domain and no certificate means let's encrypt over http-01
        let certificate = config.certificates.get(NAME).unwrap();
        assert_eq!(Some(ACME_LETS_ENCRYPT.to_string()), certificate.acme);
        assert_eq!(
            Some("pingap.io,www.pingap.io".to_string()),
            certificate.domains
        );
        assert_eq!(Some(true), certificate.is_default);
        assert_eq!(None, certificate.tls_cert);
        assert_eq!(None, certificate.dns_challenge);

        // and the server has to terminate tls for it to be of any use
        let server = config.servers.get(NAME).unwrap();
        assert_eq!("0.0.0.0:443", server.addr);
        assert_eq!(Some(true), server.global_certificates);

        config.validate().unwrap();

        assert!(
            acme_state_path(&config)
                .unwrap()
                .ends_with(".pingap/acme/pingap.io_www.pingap.io.toml")
        );
    }

    #[test]
    fn test_restore_acme_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pingap.io.toml");
        let mut config = build_config(&QuickStartParams {
            domains: Some("pingap.io".to_string()),
            upstreams: "192.168.1.1:3000".to_string(),
            ..Default::default()
        })
        .unwrap();

        // nothing issued yet
        assert!(!restore_acme_certificate(&mut config, &path));
        assert_eq!(None, config.certificates[NAME].tls_cert);

        // the acme task writes the whole config back through the storage
        let mut issued = config.clone();
        let certificate = issued.certificates.get_mut(NAME).unwrap();
        certificate.tls_cert = Some("--pem--".to_string());
        certificate.tls_key = Some("--key--".to_string());
        fs::write(&path, toml::to_string_pretty(&issued).unwrap()).unwrap();

        assert!(restore_acme_certificate(&mut config, &path));
        assert_eq!(
            Some("--pem--".to_string()),
            config.certificates[NAME].tls_cert
        );
        assert_eq!(
            Some("--key--".to_string()),
            config.certificates[NAME].tls_key
        );
        // the rest still comes from the command line
        assert_eq!(
            Some(ACME_LETS_ENCRYPT.to_string()),
            config.certificates[NAME].acme
        );
    }

    #[test]
    fn test_build_config_with_tls() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("fullchain.pem");
        let key = dir.path().join("privkey.pem");
        fs::write(&cert, "cert").unwrap();
        fs::write(&key, "key").unwrap();

        let config = build_config(&QuickStartParams {
            domains: Some("pingap.io, www.pingap.io".to_string()),
            upstreams: "192.168.1.1:3000".to_string(),
            cert: Some(dir.path().to_string_lossy().to_string()),
            ..Default::default()
        })
        .unwrap();

        let server = config.servers.get(NAME).unwrap();
        assert_eq!("0.0.0.0:443", server.addr);
        assert_eq!(Some(true), server.global_certificates);
        assert_eq!(Some(true), server.enabled_h2);

        assert_eq!(
            Some("pingap.io,www.pingap.io".to_string()),
            config.locations.get(NAME).unwrap().host
        );

        let certificate = config.certificates.get(NAME).unwrap();
        assert_eq!(
            Some("pingap.io,www.pingap.io".to_string()),
            certificate.domains
        );
        assert_eq!(
            Some(cert.to_string_lossy().to_string()),
            certificate.tls_cert
        );
        assert_eq!(
            Some(key.to_string_lossy().to_string()),
            certificate.tls_key
        );
        assert_eq!(Some(true), certificate.is_default);

        // The config is handed to the memory storage as toml, so it has to
        // survive the same round trip a config file goes through on load --
        // anything dropped there is silently missing at runtime.
        let loaded = toml::from_str::<pingap_config::PingapTomlConfig>(
            &toml::to_string_pretty(&config).unwrap(),
        )
        .unwrap()
        .to_pingap_config(true)
        .unwrap();
        assert_eq!(1, loaded.certificates.len());
        assert_eq!(certificate.tls_cert, loaded.certificates[NAME].tls_cert);
        assert_eq!(certificate.tls_key, loaded.certificates[NAME].tls_key);
        assert_eq!(Some(true), loaded.servers[NAME].global_certificates);
        assert_eq!(
            Some("pingap.io,www.pingap.io".to_string()),
            loaded.locations[NAME].host
        );
        assert_eq!(
            vec!["192.168.1.1:3000".to_string()],
            loaded.upstreams[NAME].addrs
        );
    }

    #[test]
    fn test_build_config_addr_and_errors() {
        let config = build_config(&QuickStartParams {
            upstreams: "192.168.1.1:3000".to_string(),
            addr: Some("127.0.0.1:8080".to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!("127.0.0.1:8080", config.servers.get(NAME).unwrap().addr);

        assert_eq!(
            "--upstream should not be empty",
            build_config(&QuickStartParams {
                upstreams: " , ".to_string(),
                ..Default::default()
            })
            .unwrap_err()
            .to_string()
        );

        assert_eq!(
            "--key should be used with --cert",
            build_config(&QuickStartParams {
                upstreams: "192.168.1.1:3000".to_string(),
                key: Some("/tmp/not-exists.key".to_string()),
                ..Default::default()
            })
            .unwrap_err()
            .to_string()
        );
    }

    #[test]
    fn test_resolve_tls_files() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("tls.crt");
        let key = dir.path().join("tls.key");
        fs::write(&cert, "cert").unwrap();
        fs::write(&key, "key").unwrap();

        // directory: both files are discovered
        assert_eq!(
            (
                cert.to_string_lossy().to_string(),
                key.to_string_lossy().to_string()
            ),
            resolve_tls_files(&dir.path().to_string_lossy(), None).unwrap()
        );

        // certificate file: the key is discovered next to it
        assert_eq!(
            (
                cert.to_string_lossy().to_string(),
                key.to_string_lossy().to_string()
            ),
            resolve_tls_files(&cert.to_string_lossy(), None).unwrap()
        );

        // explicit key wins
        let other_key = dir.path().join("other.key");
        fs::write(&other_key, "key").unwrap();
        assert_eq!(
            (
                cert.to_string_lossy().to_string(),
                other_key.to_string_lossy().to_string()
            ),
            resolve_tls_files(
                &cert.to_string_lossy(),
                Some(&other_key.to_string_lossy())
            )
            .unwrap()
        );

        let missing = dir.path().join("missing.pem");
        assert_eq!(
            format!("certificate {} does not exist", missing.display()),
            resolve_tls_files(&missing.to_string_lossy(), None)
                .unwrap_err()
                .to_string()
        );
        assert_eq!(
            format!("private key {} does not exist", missing.display()),
            resolve_tls_files(
                &cert.to_string_lossy(),
                Some(&missing.to_string_lossy())
            )
            .unwrap_err()
            .to_string()
        );

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            format!(
                "no certificate found in {}, expected one of: {}",
                empty.path().display(),
                CERT_FILE_NAMES.join(", ")
            ),
            resolve_tls_files(&empty.path().to_string_lossy(), None)
                .unwrap_err()
                .to_string()
        );

        let no_key = tempfile::tempdir().unwrap();
        fs::write(no_key.path().join("cert.pem"), "cert").unwrap();
        assert_eq!(
            format!(
                "no private key found in {}, expected one of: {}, use --key to set it",
                no_key.path().display(),
                KEY_FILE_NAMES.join(", ")
            ),
            resolve_tls_files(&no_key.path().to_string_lossy(), None)
                .unwrap_err()
                .to_string()
        );
    }
}
