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

//! Collects the JA4 fingerprint of each TLS client for the HTTP layer.
//!
//! pingora hands a TLS listener's raw TCP stream to a [`PreTlsProcess`]
//! before the handshake, whichever TLS backend is compiled in. The
//! collector reads the ClientHello there, puts every byte back for the
//! handshake, and files the fingerprint under the connection's socket
//! digest. That digest is one `Arc` from accept to the last request - the
//! TLS stream and the HTTP sessions, HTTP/2 streams included, hand back
//! the same one - so each request finds its connection's fingerprint, and
//! an entry lives exactly as long as the connection instead of on a timer.

use super::LOG_TARGET;
use ahash::AHashMap;
use async_trait::async_trait;
use pingap_core::Ja4Fingerprint;
use pingap_core::ja4::{
    ClientHelloStatus, MAX_CLIENT_HELLO_SIZE, read_client_hello,
};
use pingora::listeners::PreTlsProcess;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::{GetSocketDigest, SocketDigest};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant, timeout_at};
use tracing::debug;

/// How long to wait for the ClientHello. A client sends it right after
/// connecting; one that has not by now is not fingerprinted, and the
/// handshake, which has its own timeout, carries on with whatever arrived.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// A ClientHello plus its record headers, when split into many records.
const MAX_READ: usize = MAX_CLIENT_HELLO_SIZE + 2048;
const SHARDS: usize = 16;
/// A shard is swept for closed connections when it has doubled since the
/// last sweep, never below this.
const MIN_SWEEP_SIZE: usize = 256;

struct Entry {
    /// Keeps the digest's allocation reserved, so its address cannot be
    /// handed to a later connection while this entry exists.
    digest: Weak<SocketDigest>,
    fingerprint: Arc<Ja4Fingerprint>,
}

struct Shard {
    entries: AHashMap<usize, Entry>,
    sweep_at: usize,
}

/// The fingerprints of the open connections of one server.
pub struct Ja4Store {
    shards: [Mutex<Shard>; SHARDS],
}

impl Default for Ja4Store {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| {
                Mutex::new(Shard {
                    entries: AHashMap::new(),
                    sweep_at: MIN_SWEEP_SIZE,
                })
            }),
        }
    }
}

impl Ja4Store {
    fn key(digest: &Arc<SocketDigest>) -> usize {
        Arc::as_ptr(digest) as usize
    }

    fn shard(&self, key: usize) -> MutexGuard<'_, Shard> {
        // Allocations are aligned, so the low bits carry no information.
        let index = (key >> 4 ^ key >> 12) % SHARDS;
        // A poisoned lock only means another thread panicked while holding
        // it; the map itself is still consistent.
        self.shards[index]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Files `fingerprint` under the connection whose socket digest is
    /// `digest`.
    pub fn insert(
        &self,
        digest: &Arc<SocketDigest>,
        fingerprint: Arc<Ja4Fingerprint>,
    ) {
        let key = Self::key(digest);
        let mut shard = self.shard(key);
        // Entries of closed connections are dropped in batches: amortized,
        // each insert pays for one entry of a sweep.
        if shard.entries.len() >= shard.sweep_at {
            shard
                .entries
                .retain(|_, entry| entry.digest.strong_count() > 0);
            shard.sweep_at = (shard.entries.len() * 2).max(MIN_SWEEP_SIZE);
        }
        shard.entries.insert(
            key,
            Entry {
                digest: Arc::downgrade(digest),
                fingerprint,
            },
        );
    }

    /// The fingerprint of the connection whose socket digest is `digest`.
    pub fn get(
        &self,
        digest: &Arc<SocketDigest>,
    ) -> Option<Arc<Ja4Fingerprint>> {
        let key = Self::key(digest);
        let shard = self.shard(key);
        // The caller holds the digest, so it is alive, and an entry's weak
        // reference keeps any other allocation off this address: a hit is
        // this connection.
        shard
            .entries
            .get(&key)
            .map(|entry| entry.fingerprint.clone())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .entries
                    .len()
            })
            .sum()
    }
}

/// Reads from the start of a connection until the ClientHello is complete,
/// is found not to be one, the read limit is hit, or `deadline` passes.
///
/// Returns every byte read, which the caller must put back, and the
/// ClientHello body when there was one. Each read is cancel safe: a read
/// that the deadline cuts short consumes nothing, so the bytes returned
/// are exactly the bytes taken off the stream.
async fn read_client_hello_from<R: AsyncRead + Unpin>(
    reader: &mut R,
    deadline: Instant,
) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    loop {
        match read_client_hello(&buf) {
            ClientHelloStatus::Complete(body) => return (buf, Some(body)),
            ClientHelloStatus::Invalid => return (buf, None),
            ClientHelloStatus::Incomplete => {},
        }
        if buf.len() >= MAX_READ {
            return (buf, None);
        }
        match timeout_at(deadline, reader.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            // Closed, failed or too slow: leave it to the handshake.
            _ => return (buf, None),
        }
    }
}

/// The pre-handshake hook of a server with `ja4` enabled.
pub struct Ja4Collector {
    store: Arc<Ja4Store>,
    read_timeout: Duration,
}

impl Ja4Collector {
    pub fn new(store: Arc<Ja4Store>) -> Self {
        Self {
            store,
            read_timeout: READ_TIMEOUT,
        }
    }
}

#[async_trait]
impl PreTlsProcess for Ja4Collector {
    /// Never fails and never drops a connection: fingerprinting only
    /// observes, and a client it cannot fingerprint is served as usual.
    async fn process(&self, stream: &mut L4Stream) -> pingora::Result<()> {
        let deadline = Instant::now() + self.read_timeout;
        let (read, client_hello) =
            read_client_hello_from(stream, deadline).await;
        // Once, and all of it: pingora replays put-back chunks last in,
        // first out, so several calls would reorder the bytes.
        stream.rewind(&read);

        let fingerprint = client_hello
            .and_then(|body| Ja4Fingerprint::from_client_hello(&body));
        match (fingerprint, stream.get_socket_digest()) {
            (Some(fingerprint), Some(digest)) => {
                debug!(target: LOG_TARGET, ja4 = fingerprint.ja4(), "ja4 fingerprint");
                self.store.insert(&digest, Arc::new(fingerprint));
            },
            (None, _) => {
                debug!(
                    target: LOG_TARGET,
                    read = read.len(),
                    "no ja4 fingerprint for this connection"
                );
            },
            (Some(_), None) => {},
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_core::ja4::testing::{client_hello_records, spec_example_body};
    use pretty_assertions::assert_eq;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    const SPEC_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";

    fn fingerprint() -> Arc<Ja4Fingerprint> {
        Arc::new(
            Ja4Fingerprint::from_client_hello(&spec_example_body())
                .expect("spec example"),
        )
    }

    #[cfg(unix)]
    #[test]
    fn test_store_follows_the_connection() {
        let store = Ja4Store::default();
        let first = Arc::new(SocketDigest::from_raw_fd(0));
        let second = Arc::new(SocketDigest::from_raw_fd(0));
        store.insert(&first, fingerprint());
        assert_eq!(
            Some(SPEC_JA4),
            store.get(&first).as_deref().map(|f| f.ja4())
        );
        assert_eq!(None, store.get(&second));

        // Closed connections are swept once a shard has grown enough.
        drop(first);
        for _ in 0..(MIN_SWEEP_SIZE * SHARDS * 2) {
            let digest = Arc::new(SocketDigest::from_raw_fd(0));
            store.insert(&digest, fingerprint());
        }
        assert_eq!(
            true,
            store.len() < MIN_SWEEP_SIZE * SHARDS * 2,
            "{}",
            store.len()
        );
        store.insert(&second, fingerprint());
        assert_eq!(true, store.get(&second).is_some());
    }

    /// A connected pingora stream, and the client end of it.
    async fn connected_stream() -> (L4Stream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut stream = L4Stream::from(server);
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = stream.as_raw_fd();
            stream.set_socket_digest(SocketDigest::from_raw_fd(fd));
        }
        (stream, client)
    }

    /// Everything the stream yields until `len` bytes arrived.
    async fn read_back(stream: &mut L4Stream, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        stream.read_exact(&mut out).await.unwrap();
        out
    }

    /// The ClientHello is fingerprinted and every byte is replayed, in
    /// order, whether it came in one piece or trickled in across records,
    /// with the data behind it untouched.
    #[tokio::test]
    async fn test_collector_fingerprints_and_replays() {
        for record_size in [16 * 1024, 64] {
            let store = Arc::new(Ja4Store::default());
            let collector = Ja4Collector::new(store.clone());
            let (mut stream, mut client) = connected_stream().await;

            let mut sent =
                client_hello_records(&spec_example_body(), record_size);
            sent.extend_from_slice(b"\x17\x03\x03\x00\x02after");
            let writer = {
                let sent = sent.clone();
                tokio::spawn(async move {
                    for piece in sent.chunks(37) {
                        client.write_all(piece).await.unwrap();
                        client.flush().await.unwrap();
                        tokio::task::yield_now().await;
                    }
                    client
                })
            };
            collector.process(&mut stream).await.unwrap();
            let _client = writer.await.unwrap();

            assert_eq!(sent, read_back(&mut stream, sent.len()).await);
            #[cfg(unix)]
            {
                let digest = stream.get_socket_digest().unwrap();
                assert_eq!(
                    Some(SPEC_JA4),
                    store.get(&digest).as_deref().map(|f| f.ja4()),
                    "record size {record_size}"
                );
            }
        }
    }

    /// Not TLS: nothing is fingerprinted, and the bytes are replayed for
    /// the handshake to reject as it would have.
    #[tokio::test]
    async fn test_collector_leaves_other_protocols_alone() {
        let store = Arc::new(Ja4Store::default());
        let collector = Ja4Collector::new(store.clone());
        let (mut stream, mut client) = connected_stream().await;
        let sent = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        client.write_all(sent).await.unwrap();
        collector.process(&mut stream).await.unwrap();
        assert_eq!(sent.to_vec(), read_back(&mut stream, sent.len()).await);
        assert_eq!(0, store.len());
    }

    /// A client that stops halfway: the collector gives up at its deadline
    /// and replays what it took, followed by whatever arrives later.
    #[tokio::test]
    async fn test_collector_times_out_without_losing_bytes() {
        let store = Arc::new(Ja4Store::default());
        let collector = Ja4Collector {
            store: store.clone(),
            read_timeout: Duration::from_millis(100),
        };
        let (mut stream, mut client) = connected_stream().await;
        let hello = client_hello_records(&spec_example_body(), 16 * 1024);
        let (head, tail) = hello.split_at(hello.len() / 2);
        client.write_all(head).await.unwrap();
        collector.process(&mut stream).await.unwrap();
        assert_eq!(0, store.len());

        client.write_all(tail).await.unwrap();
        assert_eq!(hello, read_back(&mut stream, hello.len()).await);
    }

    /// A client that closes right away is not an error.
    #[tokio::test]
    async fn test_collector_on_closed_connection() {
        let collector = Ja4Collector::new(Arc::new(Ja4Store::default()));
        let (mut stream, client) = connected_stream().await;
        drop(client);
        assert_eq!(true, collector.process(&mut stream).await.is_ok());
    }
}
