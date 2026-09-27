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

//! JA4 TLS client fingerprints, computed from the raw ClientHello the
//! client sent.
//!
//! This follows FoxIO's specification of JA4 (the TLS client fingerprint,
//! BSD 3-Clause), including its raw and original-order forms. Only JA4 is
//! implemented; the other members of JA4+ are under a different licence.
//!
//! The input is the bytes on the wire, read before the TLS library sees
//! them, so the result does not depend on the TLS backend.

use sha2::{Digest, Sha256};
use std::fmt;

/// The largest ClientHello (handshake message body) that is fingerprinted.
/// A real one is a few KiB even with post-quantum key shares; anything
/// larger is reported as [`ClientHelloStatus::Invalid`] rather than read on.
pub const MAX_CLIENT_HELLO_SIZE: usize = 16 * 1024;

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// RFC 8446 §5.1: a plaintext record carries at most 2^14 bytes.
const MAX_RECORD_LEN: usize = 1 << 14;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// The value of a hashed section whose list is empty.
const EMPTY_HASH: &str = "000000000000";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Whether `value` is a GREASE value (RFC 8701): `0x0a0a`, `0x1a1a`, ...
/// `0xfafa`. JA4 ignores them wherever they appear.
#[inline]
pub fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0x00ff
}

/// Where reading a ClientHello from the start of a connection stands.
#[derive(Debug, PartialEq, Eq)]
pub enum ClientHelloStatus {
    /// The bytes so far are a valid beginning; more are needed.
    Incomplete,
    /// The whole ClientHello, as the handshake message body (without the
    /// handshake header), reassembled from however many records carried it.
    Complete(Vec<u8>),
    /// Not a TLS ClientHello, or larger than [`MAX_CLIENT_HELLO_SIZE`].
    Invalid,
}

/// Reads the ClientHello from the first bytes of a TLS connection.
///
/// The message may be split over several handshake records (RFC 8446 §5.1
/// allows it); the fragments are reassembled. Anything that is not a
/// handshake record carrying a ClientHello is [`ClientHelloStatus::Invalid`]
/// as soon as it can be told apart.
pub fn read_client_hello(buf: &[u8]) -> ClientHelloStatus {
    let mut message: Vec<u8> = Vec::new();
    let mut expected: Option<usize> = None;
    let mut pos = 0;
    while buf.len() - pos >= RECORD_HEADER_LEN {
        let header = &buf[pos..pos + RECORD_HEADER_LEN];
        if header[0] != CONTENT_TYPE_HANDSHAKE {
            return ClientHelloStatus::Invalid;
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len == 0 || len > MAX_RECORD_LEN {
            return ClientHelloStatus::Invalid;
        }
        let start = pos + RECORD_HEADER_LEN;
        let Some(fragment) = buf.get(start..start + len) else {
            return ClientHelloStatus::Incomplete;
        };
        message.extend_from_slice(fragment);
        pos = start + len;

        if expected.is_none() && message.len() >= HANDSHAKE_HEADER_LEN {
            if message[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
                return ClientHelloStatus::Invalid;
            }
            let body_len = usize::from(message[1]) << 16
                | usize::from(message[2]) << 8
                | usize::from(message[3]);
            if body_len > MAX_CLIENT_HELLO_SIZE {
                return ClientHelloStatus::Invalid;
            }
            expected = Some(HANDSHAKE_HEADER_LEN + body_len);
        }
        if let Some(total) = expected
            && message.len() >= total
        {
            message.truncate(total);
            message.drain(..HANDSHAKE_HEADER_LEN);
            return ClientHelloStatus::Complete(message);
        }
    }
    ClientHelloStatus::Incomplete
}

/// A cursor over TLS wire data; every read is bounds checked.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.data.len() < n {
            return None;
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    /// A vector with a one-byte length prefix.
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }
    /// A vector with a two-byte length prefix.
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

/// The `u16` values of a list, GREASE removed; `None` for an odd length.
fn u16_list(data: &[u8]) -> Option<Vec<u16>> {
    let (pairs, rest) = data.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    Some(
        pairs
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .filter(|value| !is_grease(*value))
            .collect(),
    )
}

/// The first protocol of an ALPN extension, `Some(None)` when the list is
/// empty, `None` when the extension is malformed.
fn first_alpn(data: &[u8]) -> Option<Option<&[u8]>> {
    let mut reader = Reader::new(data);
    let list = reader.vec16()?;
    if !reader.is_empty() {
        return None;
    }
    let mut list = Reader::new(list);
    if list.is_empty() {
        return Some(None);
    }
    Some(Some(list.vec8()?))
}

/// The highest version a supported_versions extension offers, GREASE
/// ignored; `Some(None)` when it offers none, `None` when malformed.
fn highest_version(data: &[u8]) -> Option<Option<u16>> {
    let mut reader = Reader::new(data);
    let versions = u16_list(reader.vec8()?)?;
    if !reader.is_empty() {
        return None;
    }
    Some(versions.into_iter().max())
}

/// The two characters JA4 uses for a TLS version.
fn version_code(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// The two characters JA4 uses for the first ALPN protocol: its first and
/// last characters when both are ASCII alphanumeric, otherwise the first
/// and last characters of its hex form; `00` when there is none.
fn alpn_code(protocol: Option<&[u8]>) -> [u8; 2] {
    match protocol {
        Some(value) if !value.is_empty() => {
            let (first, last) = (value[0], value[value.len() - 1]);
            if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
                [first, last]
            } else {
                [HEX[usize::from(first >> 4)], HEX[usize::from(last & 0x0f)]]
            }
        },
        _ => *b"00",
    }
}

/// A count as the two digits JA4 prints, capped at 99.
fn push_count(out: &mut String, count: usize) {
    let count = count.min(99);
    out.push(char::from(b'0' + (count / 10) as u8));
    out.push(char::from(b'0' + (count % 10) as u8));
}

/// `values` as comma separated four-digit lowercase hex.
fn join_hex(values: &[u16]) -> String {
    let mut out = String::with_capacity(values.len() * 5);
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        for shift in [12, 8, 4, 0] {
            out.push(char::from(HEX[usize::from((value >> shift) & 0x0f)]));
        }
    }
    out
}

/// The first 12 lowercase hex characters of the SHA-256 of `input`.
fn hash12(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(12);
    for byte in &digest[..6] {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// The part of a fingerprint built from the extensions: the list, then,
/// when there are any, `_` and the signature algorithms in their original
/// order.
fn extension_part(extensions: &[u16], signature_algorithms: &[u16]) -> String {
    let mut out = join_hex(extensions);
    if !signature_algorithms.is_empty() {
        out.push('_');
        out.push_str(&join_hex(signature_algorithms));
    }
    out
}

fn hashed(raw: &str, list_is_empty: bool) -> String {
    if list_is_empty {
        EMPTY_HASH.to_string()
    } else {
        hash12(raw)
    }
}

/// The JA4 fingerprint of one ClientHello.
///
/// [`Ja4Fingerprint::ja4`] is computed up front, since it is the form that
/// is normally logged; the raw and original-order forms are built when
/// asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Fingerprint {
    /// The first section, e.g. `t13d1516h2`.
    prefix: String,
    /// Cipher suites in the order the client sent them, GREASE removed.
    ciphers: Box<[u16]>,
    /// Extensions in the order the client sent them, GREASE removed.
    extensions: Box<[u16]>,
    /// Signature algorithms in the order the client sent them, GREASE
    /// removed.
    signature_algorithms: Box<[u16]>,
    ja4: Box<str>,
}

impl Ja4Fingerprint {
    /// Fingerprints a ClientHello message body, as returned by
    /// [`read_client_hello`]. `None` when it is malformed: a fingerprint of
    /// a broken hello would not match what any other tool computes.
    pub fn from_client_hello(body: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(body);
        let legacy_version = reader.u16()?;
        // random
        reader.take(32)?;
        let session_id = reader.vec8()?;
        if session_id.len() > 32 {
            return None;
        }
        let ciphers = u16_list(reader.vec16()?)?;
        // compression methods
        reader.vec8()?;

        let mut extensions = Vec::new();
        let mut signature_algorithms = Vec::new();
        let mut has_sni = false;
        let mut alpn = None;
        let mut supported_version = None;
        if !reader.is_empty() {
            let mut list = Reader::new(reader.vec16()?);
            if !reader.is_empty() {
                return None;
            }
            while !list.is_empty() {
                let ext_type = list.u16()?;
                let data = list.vec16()?;
                if is_grease(ext_type) {
                    continue;
                }
                extensions.push(ext_type);
                match ext_type {
                    EXT_SERVER_NAME => has_sni = true,
                    EXT_ALPN => alpn = first_alpn(data)?,
                    EXT_SUPPORTED_VERSIONS => {
                        supported_version = highest_version(data)?
                    },
                    EXT_SIGNATURE_ALGORITHMS => {
                        let mut reader = Reader::new(data);
                        signature_algorithms = u16_list(reader.vec16()?)?;
                        if !reader.is_empty() {
                            return None;
                        }
                    },
                    _ => {},
                }
            }
        }

        let mut prefix = String::with_capacity(10);
        prefix.push('t');
        prefix.push_str(version_code(
            supported_version.unwrap_or(legacy_version),
        ));
        prefix.push(if has_sni { 'd' } else { 'i' });
        push_count(&mut prefix, ciphers.len());
        push_count(&mut prefix, extensions.len());
        let [first, last] = alpn_code(alpn);
        prefix.push(char::from(first));
        prefix.push(char::from(last));

        let mut fingerprint = Self {
            prefix,
            ciphers: ciphers.into(),
            extensions: extensions.into(),
            signature_algorithms: signature_algorithms.into(),
            ja4: Box::default(),
        };
        let (ciphers, extensions) = fingerprint.sorted_parts();
        fingerprint.ja4 = format!(
            "{}_{}_{}",
            fingerprint.prefix,
            hashed(&ciphers, fingerprint.ciphers.is_empty()),
            hashed(&extensions, extensions.is_empty())
        )
        .into();
        Some(fingerprint)
    }

    /// The raw ciphers and extensions of the sorted forms: both sorted,
    /// SNI and ALPN left out of the extensions (the prefix covers them).
    fn sorted_parts(&self) -> (String, String) {
        let mut ciphers = self.ciphers.to_vec();
        ciphers.sort_unstable();
        let mut extensions: Vec<u16> = self
            .extensions
            .iter()
            .copied()
            .filter(|ext| *ext != EXT_SERVER_NAME && *ext != EXT_ALPN)
            .collect();
        extensions.sort_unstable();
        let extensions = if extensions.is_empty() {
            String::new()
        } else {
            extension_part(&extensions, &self.signature_algorithms)
        };
        (join_hex(&ciphers), extensions)
    }

    /// The raw ciphers and extensions of the original-order forms: as sent,
    /// SNI and ALPN included.
    fn original_parts(&self) -> (String, String) {
        let extensions = if self.extensions.is_empty() {
            String::new()
        } else {
            extension_part(&self.extensions, &self.signature_algorithms)
        };
        (join_hex(&self.ciphers), extensions)
    }

    /// `JA4`, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    pub fn ja4(&self) -> &str {
        &self.ja4
    }

    /// `JA4_r`: the sorted lists themselves instead of their hashes.
    pub fn ja4_r(&self) -> String {
        let (ciphers, extensions) = self.sorted_parts();
        format!("{}_{ciphers}_{extensions}", self.prefix)
    }

    /// `JA4_o`: hashed like `JA4`, but over the lists in the order the
    /// client sent them, SNI and ALPN included.
    pub fn ja4_o(&self) -> String {
        let (ciphers, extensions) = self.original_parts();
        format!(
            "{}_{}_{}",
            self.prefix,
            hashed(&ciphers, self.ciphers.is_empty()),
            hashed(&extensions, self.extensions.is_empty())
        )
    }

    /// `JA4_ro`: the lists in the order the client sent them, unhashed.
    pub fn ja4_ro(&self) -> String {
        let (ciphers, extensions) = self.original_parts();
        format!("{}_{ciphers}_{extensions}", self.prefix)
    }
}

impl fmt::Display for Ja4Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.ja4)
    }
}

/// Builders for ClientHello bytes, for tests and benchmarks in this and
/// other crates. Not part of the API.
#[doc(hidden)]
pub mod testing {
    /// An SNI extension payload for `host`.
    pub fn sni(host: &str) -> Vec<u8> {
        let name = host.as_bytes();
        let mut entry = vec![0u8];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name);
        let mut out = (entry.len() as u16).to_be_bytes().to_vec();
        out.extend(entry);
        out
    }

    /// An ALPN extension payload offering `protocols` in order.
    pub fn alpn(protocols: &[&[u8]]) -> Vec<u8> {
        let mut list = Vec::new();
        for protocol in protocols {
            list.push(protocol.len() as u8);
            list.extend_from_slice(protocol);
        }
        let mut out = (list.len() as u16).to_be_bytes().to_vec();
        out.extend(list);
        out
    }

    /// A supported_versions extension payload (client form).
    pub fn supported_versions(versions: &[u16]) -> Vec<u8> {
        let mut out = vec![(versions.len() * 2) as u8];
        for version in versions {
            out.extend_from_slice(&version.to_be_bytes());
        }
        out
    }

    /// A signature_algorithms extension payload.
    pub fn signature_algorithms(algorithms: &[u16]) -> Vec<u8> {
        let mut out = ((algorithms.len() * 2) as u16).to_be_bytes().to_vec();
        for algorithm in algorithms {
            out.extend_from_slice(&algorithm.to_be_bytes());
        }
        out
    }

    /// A ClientHello message body. `extensions` of `None` leaves the
    /// extensions block out, as an old client would.
    pub fn client_hello_body(
        legacy_version: u16,
        ciphers: &[u16],
        extensions: Option<&[(u16, Vec<u8>)]>,
    ) -> Vec<u8> {
        let mut body = legacy_version.to_be_bytes().to_vec();
        body.extend_from_slice(&[0x11; 32]);
        body.push(32);
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for cipher in ciphers {
            body.extend_from_slice(&cipher.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);
        if let Some(extensions) = extensions {
            let mut block = Vec::new();
            for (ext_type, data) in extensions {
                block.extend_from_slice(&ext_type.to_be_bytes());
                block.extend_from_slice(&(data.len() as u16).to_be_bytes());
                block.extend_from_slice(data);
            }
            body.extend_from_slice(&(block.len() as u16).to_be_bytes());
            body.extend(block);
        }
        body
    }

    /// `body` as a handshake message split into records of at most
    /// `record_size` payload bytes each.
    pub fn client_hello_records(body: &[u8], record_size: usize) -> Vec<u8> {
        let mut message = vec![0x01];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(body);
        let mut out = Vec::new();
        for chunk in message.chunks(record_size.max(1)) {
            out.extend_from_slice(&[0x16, 0x03, 0x01]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    /// The ClientHello behind the examples of the JA4 specification: the
    /// cipher, extension and signature algorithm lists of its `JA4_ro`
    /// example, in that order, with GREASE values mixed in the way
    /// browsers send them. Its fingerprints are the specification's.
    pub fn spec_example_body() -> Vec<u8> {
        let ciphers = [
            0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let sig_algs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let extensions: Vec<(u16, Vec<u8>)> = vec![
            (0x0a0a, vec![]),
            (0x001b, vec![2, 0, 2]),
            (0x0000, sni("example.com")),
            (0x0033, vec![0, 0]),
            (0x0010, alpn(&[b"h2", b"http/1.1"])),
            (0x4469, vec![0, 3, 2, b'h', b'2']),
            (0x0017, vec![]),
            (0x002d, vec![1, 1]),
            (0x000d, signature_algorithms(&sig_algs)),
            (0x0005, vec![1, 0, 0, 0, 0]),
            (0x0023, vec![]),
            (0x0012, vec![]),
            (0x002b, supported_versions(&[0x3a3a, 0x0304, 0x0303])),
            (0xff01, vec![0]),
            (0x000b, vec![1, 0]),
            (0x000a, vec![0, 4, 0x3a, 0x3a, 0, 0x1d]),
            (0x0015, vec![0; 16]),
            (0x1a1a, vec![0]),
        ];
        client_hello_body(0x0303, &ciphers, Some(&extensions))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use pretty_assertions::assert_eq;

    fn fingerprint(body: &[u8]) -> Ja4Fingerprint {
        Ja4Fingerprint::from_client_hello(body).expect("valid client hello")
    }

    #[test]
    fn test_is_grease() {
        for value in [0x0a0a, 0x1a1a, 0x2a2a, 0xaaaa, 0xeaea, 0xfafa] {
            assert_eq!(true, is_grease(value), "{value:04x}");
        }
        for value in [0x0a1a, 0x0000, 0x1301, 0xabab, 0x0a0b] {
            assert_eq!(false, is_grease(value), "{value:04x}");
        }
    }

    /// The hash inputs and outputs the specification prints.
    #[test]
    fn test_spec_hashes() {
        assert_eq!(
            "8daaf6152771",
            hash12(
                "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
            )
        );
        assert_eq!(
            "e5627efa2ab1",
            hash12(
                "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
            )
        );
        // Without signature algorithms the string ends without `_`.
        assert_eq!(
            "6d807ffa2a79",
            hash12(
                "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"
            )
        );
    }

    /// Every form the specification gives for its example ClientHello.
    #[test]
    fn test_spec_example() {
        let fp = fingerprint(&spec_example_body());
        assert_eq!("t13d1516h2_8daaf6152771_e5627efa2ab1", fp.ja4());
        assert_eq!("t13d1516h2_8daaf6152771_e5627efa2ab1", fp.to_string());
        assert_eq!(
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601",
            fp.ja4_r()
        );
        assert_eq!("t13d1516h2_acb858a92679_18f69afefd3d", fp.ja4_o());
        assert_eq!(
            "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601",
            fp.ja4_ro()
        );
    }

    /// A TLS 1.2 client with no extensions at all: the legacy version
    /// counts, no SNI is `i`, no ALPN is `00`, and the extension hash is
    /// the empty value.
    #[test]
    fn test_no_extensions() {
        let fp =
            fingerprint(&client_hello_body(0x0303, &[0xc02f, 0x009c], None));
        assert_eq!(
            format!("t12i020000_{}_000000000000", hash12("009c,c02f")),
            fp.ja4()
        );
        assert_eq!("t12i020000_009c,c02f_", fp.ja4_r());
    }

    #[test]
    fn test_prefix_rules() {
        let prefix = |extensions: &[(u16, Vec<u8>)]| {
            fingerprint(&client_hello_body(0x0301, &[0x1301], Some(extensions)))
                .ja4()[..10]
                .to_string()
        };
        // supported_versions wins over the legacy version, GREASE aside.
        assert_eq!(
            "t13i0101",
            &prefix(&[(0x002b, supported_versions(&[0x0303, 0x0304, 0xfafa]))])
                [..8]
        );
        // Only GREASE in it: the legacy version stands.
        assert_eq!(
            "t10i0101",
            &prefix(&[(0x002b, supported_versions(&[0x2a2a]))])[..8]
        );
        // An unknown version, no ciphers, an empty extensions block.
        let fp = fingerprint(&client_hello_body(0x9999, &[], Some(&[])));
        assert_eq!("t00i000000_000000000000_000000000000", fp.ja4());
        // ALPN: first protocol only, first and last character.
        assert_eq!(
            "t10i0101h1",
            prefix(&[(0x0010, alpn(&[b"http/1.1", b"h2"]))])
        );
        assert_eq!("t10i0101hh", prefix(&[(0x0010, alpn(&[b"h"]))]));
        // Not alphanumeric at either end: the hex form's ends.
        assert_eq!("t10i0101ab", prefix(&[(0x0010, alpn(&[&[0xab]]))]));
        assert_eq!("t10i010120", prefix(&[(0x0010, alpn(&[b" "]))]));
        assert_eq!("t10i0101ad", prefix(&[(0x0010, alpn(&[&[0xab, 0xcd]]))]));
        assert_eq!("t10i010100", prefix(&[(0x0010, alpn(&[b""]))]));
        assert_eq!("t10i010100", prefix(&[(0x0010, alpn(&[]))]));
        // SNI counts as an extension and turns `i` into `d`.
        assert_eq!("t10d0101", &prefix(&[(0x0000, sni("a.b"))])[..8]);
    }

    /// Counts stop at 99, GREASE never counts.
    #[test]
    fn test_counts() {
        let ciphers: Vec<u16> = (0..120)
            .map(|i| 0x0100 + i)
            .chain([0x0a0a, 0x1a1a])
            .collect();
        let fp = fingerprint(&client_hello_body(0x0303, &ciphers, None));
        assert_eq!("t12i9900", &fp.ja4()[..8]);
    }

    /// The extension hash leaves SNI and ALPN out; the original-order
    /// hash keeps them.
    #[test]
    fn test_sni_and_alpn_in_hashes() {
        let body = client_hello_body(
            0x0303,
            &[0x1301],
            Some(&[
                (0x0000, sni("example.com")),
                (0x0010, alpn(&[b"h2"])),
                (0x0017, vec![]),
            ]),
        );
        let fp = fingerprint(&body);
        assert_eq!(
            format!("t12d0103h2_{}_{}", hash12("1301"), hash12("0017")),
            fp.ja4()
        );
        assert_eq!(
            format!(
                "t12d0103h2_{}_{}",
                hash12("1301"),
                hash12("0000,0010,0017")
            ),
            fp.ja4_o()
        );
    }

    #[test]
    fn test_malformed_client_hello() {
        let body = spec_example_body();
        for len in [0, 1, 34, 40, body.len() - 1] {
            assert_eq!(
                None,
                Ja4Fingerprint::from_client_hello(&body[..len]),
                "{len}"
            );
        }
        let mut trailing = body.clone();
        trailing.push(0);
        assert_eq!(None, Ja4Fingerprint::from_client_hello(&trailing));
        // An odd-length cipher list.
        // The cipher list length sits right after the 32-byte session id.
        let mut odd = client_hello_body(0x0303, &[0x1301], None);
        odd[68] = 3;
        assert_eq!(None, Ja4Fingerprint::from_client_hello(&odd));
    }

    #[test]
    fn test_read_client_hello() {
        let body = spec_example_body();
        let records = client_hello_records(&body, 16 * 1024);
        assert_eq!(
            ClientHelloStatus::Complete(body.clone()),
            read_client_hello(&records)
        );
        // Split over many records, and followed by more data.
        let mut split = client_hello_records(&body, 100);
        assert_eq!(true, split.len() > records.len());
        split.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xff]);
        assert_eq!(
            ClientHelloStatus::Complete(body.clone()),
            read_client_hello(&split)
        );
        // Every prefix is incomplete, never invalid.
        for len in 0..records.len() {
            assert_eq!(
                ClientHelloStatus::Incomplete,
                read_client_hello(&records[..len]),
                "{len}"
            );
        }
        // Not TLS, not a ClientHello, too large.
        assert_eq!(
            ClientHelloStatus::Invalid,
            read_client_hello(b"GET / HTTP/1.1\r\n")
        );
        let mut server_hello = records.clone();
        server_hello[5] = 0x02;
        assert_eq!(
            ClientHelloStatus::Invalid,
            read_client_hello(&server_hello)
        );
        let huge = [0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00];
        assert_eq!(ClientHelloStatus::Invalid, read_client_hello(&huge));
        assert_eq!(
            ClientHelloStatus::Invalid,
            read_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x00])
        );
    }
}
