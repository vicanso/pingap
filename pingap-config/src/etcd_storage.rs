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

use crate::storage::{History, Storage};
use crate::{Error, Observer};
use async_trait::async_trait;
use etcd_client::{
    Certificate, Client, ConnectOptions, GetOptions, Identity, KeyValue,
    KvClient, SortOrder, SortTarget, TlsOptions, WatchOptions,
};
use pingap_core::now_sec;
use pingap_util::path_join;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, warn};

type Result<T, E = Error> = std::result::Result<T, E>;

fn etcd_error(e: etcd_client::Error) -> Error {
    Error::Etcd {
        source: Box::new(e),
    }
}

pub struct EtcdStorage {
    // Base path for all config entries in etcd
    path: String,
    // History path for all config entries in etcd
    history_path: String,
    // List of etcd server addresses
    addrs: Vec<String>,
    // Connection options (timeout, auth, etc)
    options: ConnectOptions,
    // Enable history
    enable_history: bool,
    /// The connection, made on first use and kept. `etcd_client::Client`
    /// is a handle over a shared channel, so handing out clones is cheap;
    /// every request used to open a fresh connection, which the reload loop
    /// did every few seconds.
    client: Mutex<Option<Client>>,
    /// How many keys a page of a prefix holds: `PAGE_SIZE`, or what it
    /// was last brought down to by values too large for that many.
    page_size: AtomicI64,
}
pub const ETCD_PROTOCOL: &str = "etcd://";

/// What a request and a connection attempt get when the url says nothing.
///
/// There used to be no limit at all. A connection that had gone quiet -
/// a firewall dropping it, etcd behind a load balancer that went away -
/// held the poll that was waiting on it for good, and with it every save,
/// which waits its turn behind the same client.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// HTTP/2 pings on a connection with a call open, so that one that died
/// without a word is noticed: the watch has nothing else to tell it by.
/// No more often than etcd allows a client to ping (5s by default).
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many keys of a prefix are asked for at a time.
const PAGE_SIZE: i64 = 64;
/// How many earlier versions of one key are kept.
const HISTORY_KEEP: usize = 100;
/// How many versions of a key are read for whoever asks for its history:
/// as many as the admin shows of an entry.
const HISTORY_SHOWN: i64 = 20;
/// How many of the versions over that are removed by one save: an old
/// history is brought down over a number of saves, not by one that takes
/// a minute.
const HISTORY_REMOVE_AT_ONCE: usize = 64;

/// `path` as the prefix of the keys below it and of nothing else.
fn as_prefix(path: &str) -> String {
    format!("{}/", path.trim_end_matches('/'))
}

/// The end of the range of keys that start with `prefix`.
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return end;
        }
    }
    // Nothing but 0xff: everything from the prefix on.
    vec![0]
}

/// Whether a request failed for the size of its answer: the keys asked
/// for hold more than one message carries (4 MiB by default).
fn is_too_large(error: &Error) -> bool {
    let Error::Etcd { source } = error else {
        return false;
    };
    let etcd_client::Error::GRpcStatus(status) = source.as_ref() else {
        return false;
    };
    // gRPC's OUT_OF_RANGE, which is what the client says when it will not
    // decode an answer of that size, and RESOURCE_EXHAUSTED, which is the
    // server's word for the same. By number: the type is another crate's.
    matches!(status.code() as i32, 8 | 11)
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct EtcdStorageParams {
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    connect_timeout: Option<Duration>,
    #[serde(default)]
    enable_history: bool,
    /// Speak TLS to etcd, verifying its certificate with the roots of
    /// the system. Implied by any of the four below.
    #[serde(default)]
    tls: bool,
    /// A PEM file with the CA etcd's certificate is verified with, in
    /// place of the roots of the system.
    #[serde(default)]
    ca: String,
    /// PEM files with the certificate and the key this side shows to an
    /// etcd that asks its clients for one (`--client-cert-auth`).
    #[serde(default)]
    cert: String,
    #[serde(default)]
    key: String,
    /// The name etcd's certificate is verified for, where that is not
    /// the host of the url (an address, a name behind a balancer).
    #[serde(default)]
    server_name: String,
}

impl EtcdStorageParams {
    /// How the connection is secured, as far as the url says; `None`
    /// for a plain one. The files are read here, once: a process is
    /// started again to take a certificate that was replaced.
    fn tls_options(&self) -> Result<Option<TlsOptions>> {
        let wanted = self.tls
            || [&self.ca, &self.cert, &self.key, &self.server_name]
                .iter()
                .any(|value| !value.is_empty());
        if !wanted {
            return Ok(None);
        }
        if self.cert.is_empty() != self.key.is_empty() {
            return Err(Error::Invalid {
                message: "etcd: cert and key should be set together"
                    .to_string(),
            });
        }
        // What a file holds is said here: the client would only say so
        // with the first connection, as a handshake that failed.
        let read = |name: &str, path: &str| {
            use rustls_pki_types::pem::PemObject;
            let pem = std::fs::read(pingap_util::resolve_path(path)).map_err(
                |e| Error::Invalid {
                    message: format!(
                        "etcd: {name}({path}) can not be read: {e}"
                    ),
                },
            )?;
            let holds = if name == "key" {
                rustls_pki_types::PrivateKeyDer::from_pem_slice(&pem).is_ok()
            } else {
                rustls_pki_types::CertificateDer::pem_slice_iter(&pem)
                    .next()
                    .is_some_and(|cert| cert.is_ok())
            };
            if !holds {
                let what = if name == "key" { "key" } else { "certificate" };
                return Err(Error::Invalid {
                    message: format!("etcd: {name}({path}) holds no {what}"),
                });
            }
            Ok(pem)
        };
        // rustls wants to be told whose cryptography to use where more
        // than one is built in, and nothing else has said so by the time
        // the configuration is loaded.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ =
                rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        let mut tls = TlsOptions::new();
        tls = if self.ca.is_empty() {
            tls.with_native_roots()
        } else {
            tls.ca_certificate(Certificate::from_pem(read("ca", &self.ca)?))
        };
        if !self.cert.is_empty() {
            tls = tls.identity(Identity::from_pem(
                read("cert", &self.cert)?,
                read("key", &self.key)?,
            ));
        }
        if !self.server_name.is_empty() {
            tls = tls.domain_name(self.server_name.clone());
        }
        Ok(Some(tls))
    }
}

impl TryFrom<&str> for EtcdStorageParams {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self> {
        let params = serde_qs::from_str(value).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
        Ok(params)
    }
}

impl EtcdStorage {
    /// Create a new etcd storage for config.
    /// Connection url format: etcd://host1:port1,host2:port2/pingap?timeout=10s&connect_timeout=5s&user=**&password=**
    /// Over TLS: `&tls=true`, or `&ca=/path/ca.pem`, with
    /// `&cert=/path/client.pem&key=/path/client.key` for an etcd that asks
    /// for a client certificate and `&server_name=etcd.internal` where the
    /// certificate is not for the host of the url.
    pub fn new(value: &str) -> Result<Self> {
        let rest = value.strip_prefix(ETCD_PROTOCOL).unwrap_or(value);
        // `hosts/path?query`; a missing path is the root.
        let (hosts, path_query) = rest.split_once('/').unwrap_or((rest, ""));
        let (path, query) =
            path_query.split_once('?').unwrap_or((path_query, ""));
        if hosts.is_empty() {
            return Err(Error::Invalid {
                message: format!("etcd url {value} names no host"),
            });
        }
        let path = format!("/{path}");

        let addrs: Vec<String> =
            hosts.split(',').map(|item| item.to_string()).collect();
        let params = EtcdStorageParams::try_from(query)?;
        let mut options = ConnectOptions::default();
        if let Some(tls) = params.tls_options()? {
            options = options.with_tls(tls);
        }

        if !params.user.is_empty() && !params.password.is_empty() {
            options = options.with_user(params.user, params.password);
        };
        options = options
            .with_timeout(params.timeout.unwrap_or(DEFAULT_TIMEOUT))
            .with_connect_timeout(
                params.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT),
            )
            // Not while idle: etcd closes a connection that pings without
            // a call open on it. The watch always has one, and that is
            // the connection nothing else would tell dead from quiet; a
            // request on a dead one runs into its timeout.
            .with_keep_alive(KEEP_ALIVE_INTERVAL, KEEP_ALIVE_TIMEOUT);
        let history_path = format!("{}-history", path.trim_end_matches('/'));

        Ok(Self {
            addrs,
            options,
            path,
            history_path,
            enable_history: params.enable_history,
            client: Mutex::new(None),
            page_size: AtomicI64::new(PAGE_SIZE),
        })
    }

    /// The shared connection, opened on first use.
    async fn client(&self) -> Result<Client> {
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.as_ref() {
            return Ok(client.clone());
        }
        let client = Client::connect(&self.addrs, Some(self.options.clone()))
            .await
            .map_err(etcd_error)?;
        *slot = Some(client.clone());
        Ok(client)
    }

    /// Runs `op` on the shared connection. A request that fails is tried
    /// once more on a fresh connection, in case the old one went stale
    /// (etcd restarted, an auth token expired); every operation here is
    /// idempotent, so the retry is safe.
    async fn with_kv<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: Fn(KvClient) -> Fut,
        Fut: Future<Output = std::result::Result<T, etcd_client::Error>>,
    {
        let client = self.client().await?;
        match op(client.kv_client()).await {
            Ok(value) => Ok(value),
            Err(e) => {
                debug!(error = %e, "etcd request failed, reconnecting");
                *self.client.lock().await = None;
                let client = self.client().await?;
                op(client.kv_client()).await.map_err(etcd_error)
            },
        }
    }

    fn get_path(&self, key: &str) -> String {
        path_join(&self.path, key)
    }
    fn get_history_path(&self, key: &str) -> String {
        path_join(&self.history_path, key)
    }
    async fn fetch_latest(&self, key: &str) -> Result<Option<KeyValue>> {
        let key = self.get_path(key);
        let mut resp = self
            .with_kv(|mut kv| {
                let key = key.clone();
                async move { kv.get(key, None).await }
            })
            .await?;
        Ok(resp.take_kvs().into_iter().next())
    }

    async fn save_history(&self, key: &str) -> Result<()> {
        if !self.enable_history {
            return Ok(());
        }
        let latest = self.fetch_latest(key).await?;
        let Some(latest) = latest else {
            return Ok(());
        };

        let name = format!("{}-{}", latest.mod_revision(), now_sec());

        let history_key = path_join(&self.get_history_path(key), &name);
        let value = latest.value().to_vec();
        self.with_kv(|mut kv| {
            let history_key = history_key.clone();
            let value = value.clone();
            async move { kv.put(history_key, value, None).await }
        })
        .await?;
        // What is written is written: a history that could not be trimmed
        // is no reason to refuse the save it belongs to.
        if let Err(e) = self.trim_history(key).await {
            warn!(error = %e, key, "trim config history failed");
        }
        Ok(())
    }

    /// Removes the versions of `key` beyond the newest `HISTORY_KEEP`.
    /// Every save added one and nothing ever took one away.
    async fn trim_history(&self, key: &str) -> Result<()> {
        let prefix = as_prefix(&self.get_history_path(key));
        let opts = GetOptions::new()
            .with_prefix()
            .with_keys_only()
            .with_sort(SortTarget::Create, SortOrder::Descend)
            .with_limit((HISTORY_KEEP + HISTORY_REMOVE_AT_ONCE) as i64);
        let mut resp = self
            .with_kv(|mut kv| {
                let prefix = prefix.clone();
                let opts = opts.clone();
                async move { kv.get(prefix, Some(opts)).await }
            })
            .await?;
        for item in resp.take_kvs().into_iter().skip(HISTORY_KEEP) {
            let old = item.key().to_vec();
            self.with_kv(|mut kv| {
                let old = old.clone();
                async move { kv.delete(old, None).await }
            })
            .await?;
        }
        Ok(())
    }

    /// Every key that starts with `prefix`, with its value.
    ///
    /// Asked for a page at a time. One request for all of them is one
    /// answer with all of them in it, and an answer has a size it cannot
    /// exceed: a configuration of a few MiB - some hundred certificates -
    /// could be written key by key and then not be read. A page that is
    /// too much for one answer is asked for again at half its length.
    async fn fetch_prefix(&self, prefix: &str) -> Result<Vec<KeyValue>> {
        let end = prefix_end(prefix.as_bytes());
        let mut start = prefix.as_bytes().to_vec();
        // What the last read came down to: a configuration that does not
        // fit sixty-four keys to a page is not asked for them again on
        // every poll, to be told the same.
        let mut limit = self.page_size.load(Ordering::Relaxed).max(1);
        // Every page as of the first one's revision, or a change between
        // two pages would give a mix of two configurations.
        let mut revision = None;
        let mut kvs = vec![];
        loop {
            let mut opts =
                GetOptions::new().with_range(end.clone()).with_limit(limit);
            if let Some(revision) = revision {
                opts = opts.with_revision(revision);
            }
            let mut resp = match self.get_page(&start, &opts).await {
                Ok(resp) => resp,
                Err(e) if limit > 1 && is_too_large(&e) => {
                    limit /= 2;
                    self.page_size.store(limit, Ordering::Relaxed);
                    continue;
                },
                Err(e) => return Err(e),
            };
            if revision.is_none() {
                revision = resp.header().map(|header| header.revision());
            }
            let more = resp.more();
            let page = resp.take_kvs();
            let Some(last) = page.last() else {
                break;
            };
            // The key right after the last one of this page.
            start = last.key().to_vec();
            start.push(0);
            kvs.extend(page);
            if !more {
                break;
            }
        }
        Ok(kvs)
    }

    /// One page. An answer that is too large is not the connection's
    /// fault: it is given back as it is, where `with_kv` would open a new
    /// connection to ask for the same again.
    async fn get_page(
        &self,
        start: &[u8],
        opts: &GetOptions,
    ) -> Result<etcd_client::GetResponse> {
        let client = self.client().await?;
        let first = client
            .kv_client()
            .get(start.to_vec(), Some(opts.clone()))
            .await
            .map_err(etcd_error);
        match first {
            Err(e) if !is_too_large(&e) => {
                debug!(error = %e, "etcd request failed, reconnecting");
                *self.client.lock().await = None;
                let client = self.client().await?;
                client
                    .kv_client()
                    .get(start.to_vec(), Some(opts.clone()))
                    .await
                    .map_err(etcd_error)
            },
            other => other,
        }
    }
}

#[async_trait]
impl Storage for EtcdStorage {
    async fn fetch(&self, key: &str) -> Result<String> {
        let key = self.get_path(key);
        let kvs = if key.ends_with(".toml") {
            self.with_kv(|mut kv| {
                let key = key.clone();
                async move { kv.get(key, None).await }
            })
            .await?
            .take_kvs()
        } else {
            self.fetch_prefix(&key).await?
        };
        let mut buffer = vec![];
        for item in kvs {
            buffer.extend(item.value());
            buffer.push(0x0a);
        }
        Ok(String::from_utf8_lossy(buffer.as_slice()).to_string())
    }

    async fn save(&self, key: &str, value: &str) -> Result<()> {
        self.save_history(key).await?;
        let key = self.get_path(key);
        self.with_kv(|mut kv| {
            let key = key.clone();
            let value = value.to_string();
            async move { kv.put(key, value, None).await }
        })
        .await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let key = self.get_path(key);
        self.with_kv(|mut kv| {
            let key = key.clone();
            async move { kv.delete(key, None).await }
        })
        .await?;
        Ok(())
    }

    /// Indicates that this storage supports watching for changes
    fn support_observer(&self) -> bool {
        true
    }
    fn support_history(&self) -> bool {
        self.enable_history
    }
    async fn fetch_history(&self, key: &str) -> Result<Option<Vec<History>>> {
        // The versions of this key, not those of a key that starts with it.
        let key = as_prefix(&self.get_history_path(key));
        let opts = GetOptions::new()
            .with_prefix()
            .with_sort(SortTarget::Create, SortOrder::Descend)
            .with_limit(HISTORY_SHOWN);

        let mut resp = self
            .with_kv(|mut kv| {
                let key = key.clone();
                let opts = opts.clone();
                async move { kv.get(key, Some(opts)).await }
            })
            .await?;

        let histories = resp
            .take_kvs()
            .iter()
            .filter_map(|item| {
                let key_str = item.key_str().ok()?;
                let value_str = item.value_str().ok()?;
                let created_at = key_str
                    .split('-')
                    .next_back()
                    .and_then(|s| s.parse::<u64>().ok())?;
                Some(History {
                    data: value_str.to_string(),
                    created_at,
                })
            })
            .collect();

        Ok(Some(histories))
    }
    /// Sets up a watch on the config path to observe changes
    /// Note: May miss changes if processing takes too long between updates
    /// Should be used with periodic full fetches to ensure consistency
    async fn observe(&self) -> Result<Observer> {
        // A watch can miss a change made while an earlier one is still being
        // handled, so the caller pairs it with periodic full fetches.
        //
        // The watch gets a connection of its own. The shared one belongs to
        // the runtime it was opened on, and the config is first loaded on a
        // short-lived runtime at startup: a watch started on that connection
        // from the server's runtime failed at once, so nothing ever watched
        // and changes in etcd were not picked up.
        let client = Client::connect(&self.addrs, Some(self.options.clone()))
            .await
            .map_err(etcd_error)?;
        // The keys below the path. The path itself as the prefix took in
        // its neighbours: `/pingap` also watched `/pingap2`, another
        // installation's, and `/pingap-history`, where every save of this
        // one writes first - each of them a reload pass for nothing.
        let stream = client
            .watch_client()
            .watch(
                as_prefix(&self.path),
                Some(WatchOptions::default().with_prefix()),
            )
            .await
            .map_err(etcd_error)?;
        Ok(Observer {
            etcd_watch_stream: Some(stream),
            _etcd_client: Some(client),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_params() {
        // timeout=10s&connect_timeout=5s&user=abc&password=pwd
        let params = EtcdStorageParams::try_from(
            "timeout=10s&connect_timeout=5s&user=abc&password=pwd",
        )
        .unwrap();
        assert_eq!(params.timeout, Some(Duration::from_secs(10)));
        assert_eq!(params.connect_timeout, Some(Duration::from_secs(5)));
        assert_eq!(params.user, "abc");
        assert_eq!(params.password, "pwd");
    }

    /// What the url says of TLS: nothing is a plain connection, and what
    /// it names has to be there.
    #[test]
    fn test_tls_params() {
        let params = |query: &str| EtcdStorageParams::try_from(query).unwrap();
        let error = |query: &str| {
            params(query).tls_options().err().map(|e| e.to_string())
        };
        assert_eq!(
            true,
            params("timeout=10s").tls_options().unwrap().is_none()
        );
        assert_eq!(true, params("tls=false").tls_options().unwrap().is_none());
        // by the roots of the system
        assert_eq!(true, params("tls=true").tls_options().unwrap().is_some());
        assert_eq!(
            true,
            params("server_name=etcd.internal")
                .tls_options()
                .unwrap()
                .is_some()
        );

        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str, content: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, content).unwrap();
            path.to_string_lossy().to_string()
        };
        // spellchecker:off
        let ca = file(
            "ca.pem",
            "-----BEGIN CERTIFICATE-----\nMIIBeDCCAR+gAwIBAgIUNClp5P/VCqYvyxD/pG2zGGDTQlEwCgYIKoZIzj0EAwIw\n-----END CERTIFICATE-----\n",
        );
        let cert = ca.clone();
        let key = file(
            "c.key",
            "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n",
        );
        // spellchecker:on
        assert_eq!(None, error(&format!("ca={ca}")));
        assert_eq!(None, error(&format!("ca={ca}&cert={cert}&key={key}")));
        assert_eq!(
            Some(
                "Invalid error etcd: cert and key should be set together"
                    .to_string()
            ),
            error(&format!("ca={ca}&cert={cert}"))
        );
        let missing = error("ca=/nowhere/ca.pem").unwrap();
        assert_eq!(
            true,
            missing.starts_with(
                "Invalid error etcd: ca(/nowhere/ca.pem) can not be read"
            ),
            "{missing}"
        );
        // a file that is there and is not what it is given as
        assert_eq!(
            Some(format!(
                "Invalid error etcd: ca({key}) holds no certificate"
            )),
            error(&format!("ca={key}"))
        );
        assert_eq!(
            Some(format!("Invalid error etcd: key({cert}) holds no key")),
            error(&format!("ca={ca}&cert={cert}&key={cert}"))
        );
        // And the url as a whole: an error of the storage, not of the
        // first request.
        assert_eq!(
            true,
            EtcdStorage::new("etcd://127.0.0.1:2379/pingap?ca=/nowhere/ca.pem")
                .is_err()
        );
        assert_eq!(
            true,
            EtcdStorage::new(&format!(
                "etcd://127.0.0.1:2379/pingap?ca={ca}&server_name=etcd"
            ))
            .is_ok()
        );
    }

    #[test]
    fn test_parse_url() {
        let storage = EtcdStorage::new(
            "etcd://a:2379,b:2379/pingap/?timeout=10s&enable_history=true",
        )
        .unwrap();
        assert_eq!(
            vec!["a:2379".to_string(), "b:2379".to_string()],
            storage.addrs
        );
        assert_eq!("/pingap/", storage.path);
        assert_eq!("/pingap-history", storage.history_path);
        assert_eq!(true, storage.enable_history);
        assert_eq!("/pingap/basic.toml", storage.get_path("basic.toml"));

        // No path means the root; no host is an error rather than a
        // connection attempt to "".
        let storage = EtcdStorage::new("etcd://127.0.0.1:2379").unwrap();
        assert_eq!("/", storage.path);
        assert_eq!(true, EtcdStorage::new("etcd:///pingap").is_err());
    }

    #[test]
    fn test_prefix_end() {
        assert_eq!(b"/pingap0".to_vec(), prefix_end(b"/pingap/"));
        assert_eq!(b"b".to_vec(), prefix_end(b"a\xff"));
        assert_eq!(vec![0], prefix_end(b"\xff\xff"));
        assert_eq!("/pingap/", as_prefix("/pingap"));
        assert_eq!("/pingap/", as_prefix("/pingap/"));
        assert_eq!("/", as_prefix("/"));
    }

    /// A storage on the local etcd under a prefix of its own.
    fn local(name: &str, params: &str) -> EtcdStorage {
        EtcdStorage::new(&format!("etcd://127.0.0.1:2379/{name}?{params}"))
            .unwrap()
    }

    async fn remove_all(storage: &EtcdStorage, path: &str) {
        for item in storage.fetch_prefix(&as_prefix(path)).await.unwrap() {
            let key = item.key().to_vec();
            storage
                .with_kv(|mut kv| {
                    let key = key.clone();
                    async move { kv.delete(key, None).await }
                })
                .await
                .unwrap();
        }
    }

    /// Regression: the watch was on everything that starts with the path,
    /// which took in the history of the same installation and the keys of
    /// any other whose path starts alike. Needs the etcd of the tests on
    /// 127.0.0.1:2379.
    #[tokio::test]
    async fn test_watch_keeps_to_its_own_keys() {
        let name = format!("watch-{}", nanoid::nanoid!(12));
        // A request timeout shorter than the test: a watch outlives it.
        let storage = local(&name, "timeout=1s&enable_history=true");
        let neighbour = local(&format!("{name}2"), "");
        storage.save("basic.toml", "a = 1").await.unwrap();
        let mut observer = storage.observe().await.unwrap();
        // Whether a change is reported within `wait`. The message that
        // acknowledges the watch is none.
        let changed = async |observer: &mut Observer, wait: u64| {
            let deadline =
                tokio::time::Instant::now() + Duration::from_millis(wait);
            loop {
                let Ok(result) =
                    tokio::time::timeout_at(deadline, observer.watch()).await
                else {
                    return false;
                };
                if result.unwrap() {
                    return true;
                }
            }
        };

        neighbour.save("basic.toml", "a = 1").await.unwrap();
        assert_eq!(false, changed(&mut observer, 400).await);

        // Its own change is seen once, after a second of nothing: the
        // version this save put into the history is not another change.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        storage.save("basic.toml", "a = 2").await.unwrap();
        assert_eq!(true, changed(&mut observer, 3000).await);
        assert_eq!(false, changed(&mut observer, 400).await);

        remove_all(&storage, &storage.path).await;
        remove_all(&storage, &storage.history_path).await;
        remove_all(&neighbour, &neighbour.path).await;
    }

    /// Regression: a prefix was read with one request, and a
    /// configuration larger than one answer may be could not be read at
    /// all. Needs the etcd of the tests.
    #[tokio::test]
    async fn test_fetch_reads_a_prefix_in_pages() {
        let storage = local(&format!("pages-{}", nanoid::nanoid!(12)), "");
        // More keys than a page holds.
        for index in 0..150 {
            storage
                .save(&format!("small/{index:03}.toml"), &format!("v{index}"))
                .await
                .unwrap();
        }
        let all = storage.fetch("small").await.unwrap();
        let lines: Vec<_> = all.lines().collect();
        assert_eq!(150, lines.len());
        assert_eq!("v0", lines[0]);
        assert_eq!("v149", lines[149]);

        // More bytes than an answer holds: five values of a MiB.
        let large = "x".repeat(1024 * 1024);
        for index in 0..5 {
            storage
                .save(&format!("large/{index}.toml"), &large)
                .await
                .unwrap();
        }
        let all = storage.fetch("large").await.unwrap();
        assert_eq!(5 * (large.len() + 1), all.len());
        // What it came down to is where the next read starts.
        let page_size = storage.page_size.load(Ordering::Relaxed);
        assert_eq!(true, (1..PAGE_SIZE).contains(&page_size), "{page_size}");
        // A single key is still a single key.
        assert_eq!("v7\n", storage.fetch("small/007.toml").await.unwrap());

        remove_all(&storage, &storage.path).await;
    }

    /// Regression: every save added a version to the history and nothing
    /// took one away. Needs the etcd of the tests.
    #[tokio::test]
    async fn test_history_is_trimmed() {
        let storage = local(
            &format!("history-{}", nanoid::nanoid!(12)),
            "enable_history=true",
        );
        for index in 0..HISTORY_KEEP + 6 {
            storage
                .save("basic.toml", &format!("a = {index}"))
                .await
                .unwrap();
        }
        let versions = storage
            .fetch_prefix(&as_prefix(&storage.get_history_path("basic.toml")))
            .await
            .unwrap();
        assert_eq!(HISTORY_KEEP, versions.len());
        // The newest ones are the ones that are kept.
        let latest =
            storage.fetch_history("basic.toml").await.unwrap().unwrap();
        assert_eq!(format!("a = {}", HISTORY_KEEP + 4), latest[0].data);

        remove_all(&storage, &storage.path).await;
        remove_all(&storage, &storage.history_path).await;
    }
}
