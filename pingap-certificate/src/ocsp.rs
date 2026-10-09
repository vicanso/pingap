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

//! OCSP stapling: what the responder of the CA is asked about a
//! certificate, and what of its answer is taken.
//!
//! A handshake carries the answer along with the certificate, so the client
//! does not have to ask the CA itself. An answer is only ever one that says
//! the certificate is good, is the CA's own word (its signature, or that of
//! a responder it delegates to), and is still current: anything else is not
//! stapled, and the handshake goes without, as it does with stapling off.

use super::{CertificateProvider, LOG_TARGET};
use ahash::AHashSet;
use async_trait::async_trait;
use pingap_core::BackgroundTask;
use pingap_core::Error as ServiceError;
use sha1::{Digest, Sha1};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::time::Duration;
use tracing::{error, info, warn};
use x509_parser::asn1_rs::BitString;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::x509::AlgorithmIdentifier;

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_ENUMERATED: u8 = 0x0a;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
/// `[0]` and `[1]` with something inside.
const TAG_CONTEXT_0: u8 = 0xa0;
const TAG_CONTEXT_1: u8 = 0xa1;
/// `[0]` with nothing inside: the status of a certificate that is good.
const TAG_STATUS_GOOD: u8 = 0x80;

/// 1.3.14.3.2.26
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
/// 1.3.6.1.5.5.7.48.1.1, id-pkix-ocsp-basic
const OID_OCSP_BASIC: &[u8] =
    &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

/// How far ahead of this clock the time of an answer may be.
const CLOCK_SKEW: i64 = 5 * 60;

/// What the responder says of a certificate its CA has revoked.
const REVOKED: &str = "the responder says the certificate is revoked";

/// How long a responder is given to answer.
const ASK_TIMEOUT: Duration = Duration::from_secs(10);
/// No answer is this long: one for a single certificate, with the
/// certificate of its signer, is a few thousand bytes.
const MAX_ANSWER_SIZE: usize = 64 * 1024;
/// The most that is stapled. A client reads the status of a certificate
/// up to 16 KiB and ends the handshake over a longer one.
const MAX_STAPLE_SIZE: usize = 12 * 1024;
/// The longest a responder is left alone, in seconds: after an answer,
/// and after the last of several failures.
const MAX_WAIT: i64 = 3600;
/// How many responders are asked at a time.
const ASK_AT_A_TIME: usize = 8;

/// One element of DER: its tag, what is in it, and all of its bytes.
struct Element<'a> {
    tag: u8,
    content: &'a [u8],
    raw: &'a [u8],
}

/// The elements of DER one after another.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }
    fn next(&mut self) -> Option<Element<'a>> {
        let input = self.0;
        let (&tag, rest) = input.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 || rest.len() < count {
                return None;
            }
            let (bytes, rest) = rest.split_at(count);
            let len = bytes
                .iter()
                .fold(0usize, |len, byte| (len << 8) | *byte as usize);
            (len, rest)
        };
        if rest.len() < len {
            return None;
        }
        let header = input.len() - rest.len();
        let (content, rest) = rest.split_at(len);
        self.0 = rest;
        Some(Element {
            tag,
            content,
            raw: &input[..header + len],
        })
    }
    /// The next element, which has to be a `tag`.
    fn expect(&mut self, tag: u8, what: &str) -> Result<Element<'a>, String> {
        self.next()
            .filter(|element| element.tag == tag)
            .ok_or_else(|| {
                format!("the answer is not an OCSP response: {what}")
            })
    }
    /// The next element when it is a `tag`.
    fn optional(&mut self, tag: u8) -> Option<Element<'a>> {
        if self.peek() == Some(tag) {
            self.next()
        } else {
            None
        }
    }
}

/// `content` as an element of DER.
fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = Vec::with_capacity(len + 6);
    out.push(tag);
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|byte| **byte == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// Unix seconds of a `GeneralizedTime` as OCSP has it: `YYYYMMDDHHMMSSZ`,
/// with or without a fraction of a second.
fn generalized_time(content: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(content).ok()?;
    let text = text.strip_suffix('Z')?;
    let digits = text.split('.').next()?;
    if digits.len() != 14 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number = |range: std::ops::Range<usize>| digits[range].parse::<u32>();
    let month = time::Month::try_from(number(4..6).ok()? as u8).ok()?;
    let date = time::Date::from_calendar_date(
        number(0..4).ok()? as i32,
        month,
        number(6..8).ok()? as u8,
    )
    .ok()?;
    let time = date
        .with_hms(
            number(8..10).ok()? as u8,
            number(10..12).ok()? as u8,
            number(12..14).ok()? as u8,
        )
        .ok()?;
    Some(time.assume_utc().unix_timestamp())
}

/// What the responder of a CA is asked about one certificate, and where.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Query {
    /// The responder, as the certificate names it.
    pub url: String,
    /// The request, to be sent as `application/ocsp-request`.
    pub request: Vec<u8>,
    name_hash: [u8; 20],
    key_hash: [u8; 20],
    serial: Vec<u8>,
}

/// The responder a certificate names: the first `http` address of its
/// authority information access.
fn responder_url(certificate: &X509Certificate<'_>) -> Option<String> {
    certificate.extensions().iter().find_map(|extension| {
        let ParsedExtension::AuthorityInfoAccess(access) =
            extension.parsed_extension()
        else {
            return None;
        };
        access.iter().find_map(|description| {
            if description.access_method != OID_PKIX_ACCESS_DESCRIPTOR_OCSP {
                return None;
            }
            match &description.access_location {
                GeneralName::URI(url) if url.starts_with("http") => {
                    Some(url.to_string())
                },
                _ => None,
            }
        })
    })
}

/// The question about the certificate `leaf_pem`, for the CA whose
/// certificate is `issuer_pem`. An error says why there is none to ask: the
/// certificate names no responder, or the one given as its issuer is not.
pub(crate) fn new_query(
    leaf_pem: &[u8],
    issuer_pem: &[u8],
) -> Result<Query, String> {
    let invalid =
        |e: &dyn std::fmt::Display| format!("invalid certificate: {e}");
    let (_, leaf_block) = parse_x509_pem(leaf_pem).map_err(|e| invalid(&e))?;
    let leaf = leaf_block.parse_x509().map_err(|e| invalid(&e))?;
    let (_, issuer_block) =
        parse_x509_pem(issuer_pem).map_err(|e| invalid(&e))?;
    let issuer = issuer_block.parse_x509().map_err(|e| invalid(&e))?;
    if leaf.issuer().as_raw() != issuer.subject().as_raw() {
        return Err(
            "the certificate after it in the chain is not the one of its issuer"
                .to_string(),
        );
    }
    let url = responder_url(&leaf)
        .ok_or_else(|| "the certificate names no OCSP responder".to_string())?;
    // The names and hashes of RFC 6960: the issuer's name as the
    // certificate has it, and the issuer's key without what is around it.
    let name_hash: [u8; 20] = Sha1::digest(leaf.issuer().as_raw()).into();
    let key_hash: [u8; 20] =
        Sha1::digest(&issuer.public_key().subject_public_key.data).into();
    let serial = leaf.raw_serial().to_vec();
    let algorithm = encode(
        TAG_SEQUENCE,
        &[encode(TAG_OID, OID_SHA1), encode(TAG_NULL, &[])].concat(),
    );
    let cert_id = encode(
        TAG_SEQUENCE,
        &[
            algorithm,
            encode(TAG_OCTET_STRING, &name_hash),
            encode(TAG_OCTET_STRING, &key_hash),
            encode(TAG_INTEGER, &serial),
        ]
        .concat(),
    );
    // OCSPRequest { TBSRequest { requestList { Request { CertID } } } }
    let request = (0..4).fold(cert_id, |inner, _| encode(TAG_SEQUENCE, &inner));
    Ok(Query {
        url,
        request,
        name_hash,
        key_hash,
        serial,
    })
}

/// What is kept of an answer that was taken.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Answer {
    /// When the responder made the statement, in unix seconds.
    pub this_update: i64,
    /// Until when it stands for it.
    pub next_update: i64,
    /// The answer to staple: what the CA signed, its signature, and the
    /// certificate of the responder when it is not the CA itself - put
    /// together anew, with nothing else of what the responder sent. The
    /// signature covers the statement and not what is around it, and
    /// whoever sits between here and the responder could add to that:
    /// bytes at the end, certificates by the dozen, something more in
    /// the name of the algorithm. A client that reads strictly, or reads
    /// no more than 16 KiB, would end its handshakes over an answer that
    /// passed every check made here.
    pub staple: Vec<u8>,
}

/// Whether `id`, the `CertID` of an answer, is the certificate of `query`:
/// the serial, and the two hashes of the issuer as they were asked with,
/// SHA-1. A responder answers with the id it was asked with. An id made
/// with another hash would be one that a client looking for the usual one
/// does not find.
fn is_asked_for(id: &[u8], query: &Query) -> bool {
    let mut id = Reader(id);
    let (Some(algorithm), Some(name_hash), Some(key_hash), Some(serial)) =
        (id.next(), id.next(), id.next(), id.next())
    else {
        return false;
    };
    let sha1 = Reader(algorithm.content)
        .next()
        .is_some_and(|oid| oid.tag == TAG_OID && oid.content == OID_SHA1);
    sha1 && id.next().is_none()
        && serial.tag == TAG_INTEGER
        && serial.content == query.serial
        && name_hash.content == query.name_hash
        && key_hash.content == query.key_hash
}

/// Whose signature an answer has, when it is the CA's word: `Some(None)`
/// for one made with the key of `issuer`, `Some(Some(certificate))` for
/// one made with the key of a certificate sent along which the CA signed
/// for the purpose (`OCSPSigning`) and which is current. `None` for
/// anybody else's.
fn signer<'a>(
    issuer: &X509Certificate<'_>,
    data: &[u8],
    algorithm: &[u8],
    signature: &[u8],
    certificates: Option<&'a [u8]>,
    now: i64,
) -> Option<Option<&'a [u8]>> {
    let (_, algorithm) = AlgorithmIdentifier::from_der(algorithm).ok()?;
    let (_, signature) = BitString::from_der(signature).ok()?;
    let verifies = |certificate: &X509Certificate<'_>| {
        x509_parser::verify::verify_signature(
            certificate.public_key(),
            &algorithm,
            &signature,
            data,
        )
        .is_ok()
    };
    if verifies(issuer) {
        return Some(None);
    }
    let mut certificates = Reader(certificates?);
    while let Some(element) = certificates.next() {
        let Ok((_, responder)) = X509Certificate::from_der(element.raw) else {
            continue;
        };
        let delegated = responder
            .extended_key_usage()
            .ok()
            .flatten()
            .is_some_and(|usage| usage.value.ocsp_signing);
        let validity = responder.validity();
        let current = validity.not_before.timestamp() <= now + CLOCK_SKEW
            && now <= validity.not_after.timestamp();
        if delegated
            && current
            && responder
                .verify_signature(Some(issuer.public_key()))
                .is_ok()
            && verifies(&responder)
        {
            return Some(Some(element.raw));
        }
    }
    None
}

/// A signature algorithm as it is handed on: its name, and parameters
/// that are none or `NULL` - which is what the algorithms verified here
/// have. No signature covers this part of an answer or of a certificate,
/// and what verifies a signature does not look at all of it: anything
/// else in it could be put there on the way, for a client that reads
/// strictly to end its handshake over.
fn canonical_algorithm(algorithm: &Element<'_>) -> Option<Vec<u8>> {
    let mut parts = Reader(algorithm.content);
    let name = parts.next().filter(|part| part.tag == TAG_OID)?;
    let mut content = encode(TAG_OID, name.content);
    match parts.next() {
        None => {},
        Some(part) if part.tag == TAG_NULL && part.content.is_empty() => {
            content.extend(encode(TAG_NULL, &[]));
        },
        Some(_) => return None,
    }
    if parts.next().is_some() {
        return None;
    }
    Some(encode(TAG_SEQUENCE, &content))
}

/// A signature as it is handed on: whole bytes, as every signature is.
fn canonical_signature(signature: &Element<'_>) -> Option<Vec<u8>> {
    (signature.content.first() == Some(&0))
        .then(|| encode(TAG_BIT_STRING, signature.content))
}

/// The certificate of a responder as it is handed on: what its issuer
/// signed as it is, the algorithm and the signature written anew, and
/// nothing after them.
fn canonical_certificate(raw: &[u8]) -> Option<Vec<u8>> {
    let certificate =
        Reader(raw).next().filter(|part| part.tag == TAG_SEQUENCE)?;
    let mut parts = Reader(certificate.content);
    let signed = parts.next().filter(|part| part.tag == TAG_SEQUENCE)?;
    let algorithm = parts.next().filter(|part| part.tag == TAG_SEQUENCE)?;
    let signature = parts.next().filter(|part| part.tag == TAG_BIT_STRING)?;
    if parts.next().is_some() {
        return None;
    }
    Some(encode(
        TAG_SEQUENCE,
        &[
            signed.raw.to_vec(),
            canonical_algorithm(&algorithm)?,
            canonical_signature(&signature)?,
        ]
        .concat(),
    ))
}

/// Takes the answer of a responder to `query`, or says why not.
///
/// It is taken when it says the certificate is good, is signed by the CA
/// whose certificate is `issuer_pem` (or by a responder that CA delegates
/// to), was made no later than `now` and is to be relied on beyond it.
pub(crate) fn check_response(
    response: &[u8],
    query: &Query,
    issuer_pem: &[u8],
    now: i64,
) -> Result<Answer, String> {
    let (_, issuer_block) = parse_x509_pem(issuer_pem)
        .map_err(|e| format!("invalid certificate: {e}"))?;
    let issuer = issuer_block
        .parse_x509()
        .map_err(|e| format!("invalid certificate: {e}"))?;

    // OCSPResponse { responseStatus, [0] { responseType, response } }
    let mut outer = Reader(
        Reader(response)
            .expect(TAG_SEQUENCE, "no sequence")?
            .content,
    );
    let status = outer.expect(TAG_ENUMERATED, "no status")?.content;
    if status != [0] {
        let name = match status {
            [1] => "malformedRequest",
            [2] => "internalError",
            [3] => "tryLater",
            [5] => "sigRequired",
            [6] => "unauthorized",
            _ => "an unknown status",
        };
        return Err(format!("the responder answers {name}"));
    }
    let mut bytes = Reader(
        Reader(outer.expect(TAG_CONTEXT_0, "no response")?.content)
            .expect(TAG_SEQUENCE, "no response")?
            .content,
    );
    if bytes.expect(TAG_OID, "no type")?.content != OID_OCSP_BASIC {
        return Err("the answer is not a basic OCSP response".to_string());
    }
    let basic = bytes.expect(TAG_OCTET_STRING, "no response")?.content;

    // BasicOCSPResponse { tbsResponseData, algorithm, signature, [0] certs }
    let mut basic = Reader(
        Reader(basic)
            .expect(TAG_SEQUENCE, "no basic response")?
            .content,
    );
    let data = basic.expect(TAG_SEQUENCE, "no response data")?;
    let algorithm = basic.expect(TAG_SEQUENCE, "no algorithm")?;
    let signature = basic.expect(TAG_BIT_STRING, "no signature")?;
    let certificates = basic
        .optional(TAG_CONTEXT_0)
        .and_then(|element| Reader(element.content).next())
        .filter(|element| element.tag == TAG_SEQUENCE)
        .map(|element| element.content);
    let Some(responder) = signer(
        &issuer,
        data.raw,
        algorithm.raw,
        signature.raw,
        certificates,
        now,
    ) else {
        return Err(
            "the answer is not signed by the issuer of the certificate"
                .to_string(),
        );
    };
    // The answer as it is handed on, see `Answer::staple`. What is
    // signed goes as it is: one byte of it changed, and the signature
    // would not have verified. The rest is written anew.
    let malformed = || "the answer is not well formed".to_string();
    let mut basic = [
        data.raw.to_vec(),
        canonical_algorithm(&algorithm).ok_or_else(malformed)?,
        canonical_signature(&signature).ok_or_else(malformed)?,
    ]
    .concat();
    if let Some(responder) = responder {
        let certificate =
            canonical_certificate(responder).ok_or_else(malformed)?;
        basic
            .extend(encode(TAG_CONTEXT_0, &encode(TAG_SEQUENCE, &certificate)));
    }
    let bytes = [
        encode(TAG_OID, OID_OCSP_BASIC),
        encode(TAG_OCTET_STRING, &encode(TAG_SEQUENCE, &basic)),
    ]
    .concat();
    let staple = encode(
        TAG_SEQUENCE,
        &[
            encode(TAG_ENUMERATED, &[0]),
            encode(TAG_CONTEXT_0, &encode(TAG_SEQUENCE, &bytes)),
        ]
        .concat(),
    );
    if staple.len() > MAX_STAPLE_SIZE {
        return Err("the answer is too long to staple".to_string());
    }

    // ResponseData { [0] version, responderID, producedAt, responses, .. }
    let mut data = Reader(data.content);
    data.optional(TAG_CONTEXT_0);
    // The responder, by name or by key: who it is was settled above.
    data.next();
    data.expect(TAG_GENERALIZED_TIME, "no time")?;
    let mut responses =
        Reader(data.expect(TAG_SEQUENCE, "no responses")?.content);
    while let Some(single) = responses.next() {
        // SingleResponse { certID, certStatus, thisUpdate, [0] nextUpdate }
        let mut single = Reader(single.content);
        let id = single.expect(TAG_SEQUENCE, "no certificate id")?;
        if !is_asked_for(id.content, query) {
            continue;
        }
        let status = single.next().map(|element| element.tag);
        match status {
            Some(TAG_STATUS_GOOD) => {},
            Some(TAG_CONTEXT_1) => {
                return Err(REVOKED.to_string());
            },
            _ => {
                return Err(
                    "the responder does not know the certificate".to_string()
                );
            },
        }
        let time = |element: Element<'_>| {
            generalized_time(element.content)
                .ok_or_else(|| "the answer has an invalid time".to_string())
        };
        let this_update =
            time(single.expect(TAG_GENERALIZED_TIME, "no time")?)?;
        // Without it the responder stands for the answer at no later
        // moment than the one it gave it at: nothing to hand on.
        let Some(next_update) = single.optional(TAG_CONTEXT_0) else {
            return Err(
                "the answer does not say until when it holds".to_string()
            );
        };
        let next_update = time(
            Reader(next_update.content)
                .expect(TAG_GENERALIZED_TIME, "no time")?,
        )?;
        if this_update > now + CLOCK_SKEW {
            return Err("the answer is from the future".to_string());
        }
        if next_update <= now {
            return Err("the answer is out of date".to_string());
        }
        return Ok(Answer {
            this_update,
            next_update,
            staple,
        });
    }
    Err("the answer is about another certificate".to_string())
}

/// What is kept for a certificate whose handshakes carry the answer of
/// its responder: what to ask, and when.
#[derive(Debug)]
pub struct Stapling {
    query: Query,
    issuer_pem: Vec<u8>,
    /// Unix seconds before which the responder is not asked.
    ask_at: AtomicI64,
    /// How many times in a row there was no answer to take.
    failures: AtomicU32,
}

impl Stapling {
    /// For the certificate `leaf_pem`, whose issuer's certificate is the
    /// first of `chain`. An error says why this certificate can not have
    /// an answer stapled.
    pub(crate) fn new(
        leaf_pem: &[u8],
        chain: &[Vec<u8>],
    ) -> Result<Self, String> {
        let issuer_pem = chain.first().ok_or_else(|| {
            "the certificate of its issuer is not in the chain".to_string()
        })?;
        Ok(Self {
            query: new_query(leaf_pem, issuer_pem)?,
            issuer_pem: issuer_pem.clone(),
            ask_at: AtomicI64::new(0),
            failures: AtomicU32::new(0),
        })
    }
}

/// When to ask again after an answer that holds until `next_update`: an
/// hour on, as a CA that makes its answers ahead of time hands out the one
/// it has for most of the time it holds; five minutes before it runs out
/// when that is sooner; and never within the minute.
fn refresh_at(now: i64, next_update: i64) -> i64 {
    (next_update - 300).min(now + MAX_WAIT).max(now + 60)
}

/// When to ask again after `failures` tries without an answer: a minute
/// on, then twice as long each time, up to an hour.
fn retry_at(now: i64, failures: u32) -> i64 {
    now + (60i64 << failures.saturating_sub(1).min(6)).min(MAX_WAIT)
}

/// An error with what caused it: the one of an HTTP client says
/// "error sending request" and leaves the reason to its source.
fn error_text(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// What the responder answers to `query`.
async fn ask(
    client: &reqwest::Client,
    query: &Query,
) -> Result<Vec<u8>, String> {
    let mut response = client
        .post(&query.url)
        .header("Content-Type", "application/ocsp-request")
        .body(query.request.clone())
        .send()
        .await
        .map_err(|e| error_text(&e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("the responder answers {status}"));
    }
    let mut answer = vec![];
    while let Some(chunk) =
        response.chunk().await.map_err(|e| error_text(&e))?
    {
        if answer.len() + chunk.len() > MAX_ANSWER_SIZE {
            return Err("the answer of the responder is too long".to_string());
        }
        answer.extend_from_slice(&chunk);
    }
    Ok(answer)
}

struct OcspStaplingTask {
    provider: Arc<dyn CertificateProvider>,
    client: reqwest::Client,
}

impl OcspStaplingTask {
    /// Asks the responders of the certificates that are due at `now`: the
    /// ones with no answer yet, and the ones whose answer is to be
    /// renewed. Whether any was asked.
    ///
    /// Several at a time: one after the other, a few responders that do
    /// not answer held up every certificate after them for ten seconds
    /// each.
    async fn refresh(&self, now: i64) -> bool {
        use futures::StreamExt;
        let started = std::time::Instant::now();
        // The store has a certificate once for every domain.
        let mut seen = AHashSet::new();
        let due: Vec<_> = self
            .provider
            .list()
            .values()
            .filter_map(|cert| {
                let (stapling, certificate) =
                    (cert.ocsp.as_ref()?, cert.certificate.as_ref()?);
                if !seen.insert(Arc::as_ptr(stapling) as usize) {
                    return None;
                }
                // A time that is further off than any wait that is ever
                // set, twice over, was set by a clock that has been put
                // back since: the wait is over.
                let ask_at = stapling.ask_at.load(Ordering::Relaxed);
                if now < ask_at && ask_at - now <= 2 * MAX_WAIT {
                    return None;
                }
                Some((
                    cert.name.clone().unwrap_or_default(),
                    stapling.clone(),
                    certificate.clone(),
                ))
            })
            .collect();
        let asked = !due.is_empty();
        futures::stream::iter(due)
            .for_each_concurrent(
                ASK_AT_A_TIME,
                |(name, stapling, certificate)| async move {
                    // The time this one is asked at, which is later than
                    // the time the pass began at when others were slow.
                    let now = now + started.elapsed().as_secs() as i64;
                    self.refresh_one(&name, &stapling, &certificate, now).await;
                },
            )
            .await;
        asked
    }

    /// Asks the responder of one certificate and takes its answer, or
    /// puts the next try off.
    async fn refresh_one(
        &self,
        name: &str,
        stapling: &Stapling,
        certificate: &crate::LoadedCertificate,
        now: i64,
    ) {
        let url = stapling.query.url.as_str();
        let result = match ask(&self.client, &stapling.query).await {
            Ok(response) => check_response(
                &response,
                &stapling.query,
                &stapling.issuer_pem,
                now,
            ),
            Err(e) => Err(e),
        };
        match result {
            Ok(answer) => {
                let failures = stapling.failures.swap(0, Ordering::Relaxed);
                // Said for the first answer and for one that comes after
                // there was none, not every hour.
                if failures > 0 || !certificate.has_staple(now) {
                    info!(
                        target: LOG_TARGET,
                        name,
                        url,
                        until = answer.next_update,
                        "ocsp answer is stapled"
                    );
                }
                stapling.ask_at.store(
                    refresh_at(now, answer.next_update),
                    Ordering::Relaxed,
                );
                certificate
                    .set_staple(Some((answer.staple, answer.next_update)));
            },
            Err(error) => {
                let failures =
                    stapling.failures.fetch_add(1, Ordering::Relaxed) + 1;
                stapling
                    .ask_at
                    .store(retry_at(now, failures), Ordering::Relaxed);
                if error == REVOKED {
                    // The answer it had says the opposite, and is good
                    // for days yet.
                    certificate.set_staple(None);
                    error!(
                        target: LOG_TARGET,
                        name,
                        url,
                        "the certificate is revoked, nothing is stapled"
                    );
                } else if failures.is_power_of_two() {
                    // The answer it has is stapled until it runs out;
                    // after that the handshakes go without.
                    warn!(
                        target: LOG_TARGET,
                        name,
                        url,
                        failures,
                        error,
                        "no ocsp answer to staple"
                    );
                }
            },
        }
    }
}

#[async_trait]
impl BackgroundTask for OcspStaplingTask {
    async fn execute(&self, _count: u32) -> Result<bool, ServiceError> {
        Ok(self.refresh(pingap_core::now_sec() as i64).await)
    }
}

/// The task that keeps the OCSP answers of the certificates with
/// `ocsp_stapling` up to date. It is run once a minute and asks a
/// responder when its certificate is due.
pub fn new_ocsp_stapling_service(
    provider: Arc<dyn CertificateProvider>,
) -> Box<dyn BackgroundTask> {
    let client = reqwest::Client::builder()
        .timeout(ASK_TIMEOUT)
        // The answer is the responder's, at the address the certificate
        // names: not that of wherever something on the way points to.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();
    Box::new(OcspStaplingTask { provider, client })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::sync::Mutex;

    // A CA with certificates that name `http://127.0.0.1:9499` as their
    // responder (one of them without any), and what `openssl ocsp` asked
    // and was answered about them: by the CA itself, and by a responder
    // with a certificate of the CA for signing such answers. The answers
    // are from 2026-10-09 09:41:36 UTC and hold for a day; the certificates
    // are good for ten years, and two of their keys are here for the
    // handshakes that are tested with them.
    // spellchecker:off
    pub(crate) const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgIUJ5paLsKWWyIKM7hPfmX4ig3XGO4wCgYIKoZIzj0EAwIw\nFzEVMBMGA1UEAwwMb2NzcCB0ZXN0IGNhMB4XDTI2MTAwOTA5NDEzNloXDTM2MTAw\nNjA5NDEzNlowFzEVMBMGA1UEAwwMb2NzcCB0ZXN0IGNhMFkwEwYHKoZIzj0CAQYI\nKoZIzj0DAQcDQgAEIu9Ykz0YB2tAhBkjai+5N/sOzcJS3kVjFkwE7OS7fFiW5SuC\ntwEvctXmfr1u5mYZNcOKJ5MBDxXrTbug+PA1IKNTMFEwHQYDVR0OBBYEFBA4ZQ/V\ncYPsTck5sm/lB5F1E6WwMB8GA1UdIwQYMBaAFBA4ZQ/VcYPsTck5sm/lB5F1E6Ww\nMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhALqHJOSv5BHhJpSH\nry1GUGpHlnnMgiwd5UNFPlyUmev3AiAI/gFUvR/bKEOsA6m58lbwqicLHocsfSY7\n2ewiwehEvQ==\n-----END CERTIFICATE-----";
    pub(crate) const LEAF: &str = "-----BEGIN CERTIFICATE-----\nMIIB3jCCAYSgAwIBAgICEAAwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMb2NzcCB0\nZXN0IGNhMB4XDTI2MTAwOTA5NDEzNloXDTM2MTAwNjA5NDEzNlowEDEOMAwGA1UE\nAwwFZWNkc2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATHn2Sk4GNLhzFJ+Lp6\nwpF/tNKdEk7G5bjL22LfCCZyfPYoq0O9W07awb9ihWIjkpkIX8xwKYO1D/gTS6t3\nGLSgo4HGMIHDMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsG\nAQUFBwMBMCEGA1UdEQQaMBiCCW9jc3AudGVzdIILKi5vY3NwLnRlc3QwMQYIKwYB\nBQUHAQEEJTAjMCEGCCsGAQUFBzABhhVodHRwOi8vMTI3LjAuMC4xOjk0OTkwHQYD\nVR0OBBYEFG/YTNnz4EnLhNoLTC1WdJaZp78HMB8GA1UdIwQYMBaAFBA4ZQ/VcYPs\nTck5sm/lB5F1E6WwMAoGCCqGSM49BAMCA0gAMEUCIC6zNOV28/N3dvjHfOWua7ZR\niJYgZemClqdmRJy19ZYtAiEArPz913h8N0TVc2Ti7Tc+Z92KfXGcCHlT/c4ih10W\ne9U=\n-----END CERTIFICATE-----";
    pub(crate) const LEAF_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVSB4MNK/GdHINiIU\n5J3HZEeS0Oe3edWcip8YnH6xKryhRANCAATHn2Sk4GNLhzFJ+Lp6wpF/tNKdEk7G\n5bjL22LfCCZyfPYoq0O9W07awb9ihWIjkpkIX8xwKYO1D/gTS6t3GLSg\n-----END PRIVATE KEY-----";
    pub(crate) const RSA_LEAF: &str = "-----BEGIN CERTIFICATE-----\nMIICqDCCAk2gAwIBAgICEAEwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMb2NzcCB0\nZXN0IGNhMB4XDTI2MTAwOTA5NDEzNloXDTM2MTAwNjA5NDEzNlowDjEMMAoGA1UE\nAwwDcnNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlso6cPTeM4ek\n5rSlvNVolTrbK6FqQ03sU8CAz9GbUx5mB59yMk8d2zjnCWmRnwVXpa+bhssR4Bn5\noB4KOVGrlPmcjCSUnZhTA+wi7bgUUADmdwBP0gG7iGn6Np2Vtj/rKJVEObO6pclV\n6CqBGDatr5hzVcmXnLUaQa9mWpoGqxIHFGHukBQkaofMM9x6skXFFCjl/bqJD4Yi\nf9XX3HqkgPZh5ym0kX6AoX7r8yqhK65rRCG4RIqsP158XzXi/0wp41x3g8s4BpdX\nb+zCTrgGE1EryYzh0WnTTmPtkSbdCTUjHIBFhSb8m9d77a2v8wQrXG9cWSk3+uuA\n/0Qu6TxduQIDAQABo4HGMIHDMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeAMBMGA1Ud\nJQQMMAoGCCsGAQUFBwMBMCEGA1UdEQQaMBiCCW9jc3AudGVzdIILKi5vY3NwLnRl\nc3QwMQYIKwYBBQUHAQEEJTAjMCEGCCsGAQUFBzABhhVodHRwOi8vMTI3LjAuMC4x\nOjk0OTkwHQYDVR0OBBYEFJmdhJkYqufEAGgCutv5BSqbCAvIMB8GA1UdIwQYMBaA\nFBA4ZQ/VcYPsTck5sm/lB5F1E6WwMAoGCCqGSM49BAMCA0kAMEYCIQC91o5PwUIV\nc9rRe+Gwa8Snqsy31JtVatdjzhNhWTsv/wIhAMSLjdphaHBuWNIe4wqzMTGZpmld\nQDKmI3vdHjJBt9P0\n-----END CERTIFICATE-----";
    pub(crate) const RSA_LEAF_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWyjpw9N4zh6Tm\ntKW81WiVOtsroWpDTexTwIDP0ZtTHmYHn3IyTx3bOOcJaZGfBVelr5uGyxHgGfmg\nHgo5UauU+ZyMJJSdmFMD7CLtuBRQAOZ3AE/SAbuIafo2nZW2P+solUQ5s7qlyVXo\nKoEYNq2vmHNVyZectRpBr2ZamgarEgcUYe6QFCRqh8wz3HqyRcUUKOX9uokPhiJ/\n1dfceqSA9mHnKbSRfoChfuvzKqErrmtEIbhEiqw/XnxfNeL/TCnjXHeDyzgGl1dv\n7MJOuAYTUSvJjOHRadNOY+2RJt0JNSMcgEWFJvyb13vtra/zBCtcb1xZKTf664D/\nRC7pPF25AgMBAAECggEAAyO1wMlQYQlHdSg4tSxKT6UYkBl9wWX7cCj3ZZxLHBlr\nbWgz8/kyuXA/WzJP/lwZnZEA73cF6cEQsfU+KEBbjq/9wus2DuvveortlT56acoD\nAmJGxywTD/2I4J86UT+WcVNeRsdHsRD2kW1lH7BvwFKvwA8A8ZnRsKFqw6MmVWR0\nAexYcsFFRne6rW0+raeVOhxC9e5ShKk4X8i2IzKVEa4OAAn/vlbZX3L7gWBoqPnC\n0MdRxByJMAcpelS7s/hgg7IH1gxsDPwp5TFu3paWv9WbetaYHanaghI8S+s/yfA6\n9w/pjsjCQcAuxo8avOIeTWI3yKZThi9ZsD3US51RYwKBgQDNC7IWw0hlmFM0hxJS\n7psLpm51+DgCKxN+JZd8gSxMpvEJn6cKiYDqkjqyDYvhUNRnizmBAbkjUys5Agoo\nk3qI9Z3HrJ6JogcvM+ckW3R1/LFYKincmRIMBu5j3JTv/HbUrunJ4r6aehDsCwWD\nbepouKXUCLpdLnGJpdq6q2dI8wKBgQC8QvgBPnL/gN+rcGRy1DjFTk4Trdc+kfJO\nnKSfGkGhEN/5zD9x9v58BOGMqVFyBDxFGTjJtQTilyUw4p5yttmC5ZM/idQzzd5S\nMXQ0ObiSKqHU2jCnjVaG2QCVxwqd72DMcz0/76VBrD8ZdIy5+8s1daFZ/4zvJx4n\nFHXUZ44powKBgQCXmekfSV1SuE/0i1Vx+baq42/SSybl+4FbCGI7jKn7NocKbX8s\nnEOzq1A4aymb+o5AzEBE8Mg4pPpVGPv3yiqT7r2sbyV8b07OiJqCWBgAUEey/uGa\nl5YvTESfkuyPj2Mwlu6F9N6mClBOpUt7RB5HNRZucdGQqZEKi5Tv5WDlHwKBgHh6\nEuQY5tcDzh+UaXPixAHgPq7xTRHJrFsKe38l+mHsvqjJQMDZ47nSFdVCddCVTUya\n+3B524p2V2KVY/jdcw0FhdnfhmEwmdnXtBnH5ooDplTk3MYc+QaK0IkJO44epr+v\n775+yi7g3/CWWYibzkuD36IMnFBfpDg2K8GmE6ApAoGAJDPwxEVec2re4mxDIXK0\ndCVHEDqUalOzkav/57+TRKNOQ8DrDWHk8XwcA/u6bT9Ay47qbAkM3qPeA+1WPUH/\nMDpR6cFd0zODvx57zjqi+wiTkoNu6sE05ciW+z4uJ14GwUclETdajhYPs2R/10nj\n+xpsqC1p1pjyTmaZwoC2azY=\n-----END PRIVATE KEY-----";
    pub(crate) const REVOKED_LEAF: &str = "-----BEGIN CERTIFICATE-----\nMIIB4TCCAYagAwIBAgICEAMwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMb2NzcCB0\nZXN0IGNhMB4XDTI2MTAwOTA5NDEzNloXDTM2MTAwNjA5NDEzNlowEjEQMA4GA1UE\nAwwHcmV2b2tlZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKnufRpyEy5zF35Z\ntc3E6hmSyWIUg3eVOcxf/qontCUrpn0DO2dKLLS2qmzdfxRuHV0vcYPQE3RHpf9M\nWAvUPu2jgcYwgcMwCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYI\nKwYBBQUHAwEwIQYDVR0RBBowGIIJb2NzcC50ZXN0ggsqLm9jc3AudGVzdDAxBggr\nBgEFBQcBAQQlMCMwIQYIKwYBBQUHMAGGFWh0dHA6Ly8xMjcuMC4wLjE6OTQ5OTAd\nBgNVHQ4EFgQUB5G96zx+r4hJUzhLq2Mk06kLor8wHwYDVR0jBBgwFoAUEDhlD9Vx\ng+xNyTmyb+UHkXUTpbAwCgYIKoZIzj0EAwIDSQAwRgIhAMtOAMU7offA6FvZqELj\na8YsdG0m41w6bq8bZCfGxYwVAiEA32+GY7B+v1h8yZzYMQaqsnWIVgcc4dHd2ME7\nvnKbBiI=\n-----END CERTIFICATE-----";
    pub(crate) const PLAIN_LEAF: &str = "-----BEGIN CERTIFICATE-----\nMIIBfDCCASGgAwIBAgICEAIwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMb2NzcCB0\nZXN0IGNhMB4XDTI2MTAwOTA5NDEzNloXDTM2MTAwNjA5NDEzNlowEDEOMAwGA1UE\nAwwFcGxhaW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATuBzx2nHieSucBhXM5\n9sZfSND8u/p5bT1Oa2Oonxi18lIDZruTBi18ZOjBPI9vbVtkWNAmhNSyBUwQAmoK\nxHK8o2QwYjAJBgNVHRMEAjAAMBUGA1UdEQQOMAyCCnBsYWluLnRlc3QwHQYDVR0O\nBBYEFHk+HgHTN30Vz2Z3maXQZI6WmHDIMB8GA1UdIwQYMBaAFBA4ZQ/VcYPsTck5\nsm/lB5F1E6WwMAoGCCqGSM49BAMCA0kAMEYCIQCusff6k0FSFI47ufkGltyUzCpn\nA67cBtevFVFRs6afvQIhAJ2+CMEzQb56/MW2T/itnGu6FLdRSEi+cvTkWR1tIzU0\n-----END CERTIFICATE-----";
    pub(crate) const REQUEST: &str = "MEMwQTA/MD0wOzAJBgUrDgMCGgUABBTEXYCcof4Cuk5ilWJEJYVTBFqulgQUEDhlD9Vxg+xNyTmyb+UHkXUTpbACAhAA";
    pub(crate) const GOOD: &str = "MIICmQoBAKCCApIwggKOBgkrBgEFBQcwAQEEggJ/MIICezCBk6EZMBcxFTATBgNVBAMMDG9jc3AgdGVzdCBjYRgPMjAyNjEwMDkwOTQxMzZaMGUwYzA7MAkGBSsOAwIaBQAEFMRdgJyh/gK6TmKVYkQlhVMEWq6WBBQQOGUP1XGD7E3JObJv5QeRdROlsAICEACAABgPMjAyNjEwMDkwOTQxMzZaoBEYDzIwMjYxMDEwMDk0MTM2WjAKBggqhkjOPQQDAgNIADBFAiEAqFpitWpg38TuHRE4adJl8JTC+UXnjLw+sQABHK8RvWUCIHbZ9/D2bqkmv+y08+4ZOhbRf0Nn5Ver4yrmxluFHKUqoIIBizCCAYcwggGDMIIBKaADAgECAhQnmlouwpZbIgozuE9+ZfiKDdcY7jAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxvY3NwIHRlc3QgY2EwHhcNMjYxMDA5MDk0MTM2WhcNMzYxMDA2MDk0MTM2WjAXMRUwEwYDVQQDDAxvY3NwIHRlc3QgY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQi71iTPRgHa0CEGSNqL7k3+w7NwlLeRWMWTATs5Lt8WJblK4K3AS9y1eZ+vW7mZhk1w4onkwEPFetNu6D48DUgo1MwUTAdBgNVHQ4EFgQUEDhlD9Vxg+xNyTmyb+UHkXUTpbAwHwYDVR0jBBgwFoAUEDhlD9Vxg+xNyTmyb+UHkXUTpbAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAuock5K/kEeEmlIevLUZQakeWecyCLB3lQ0U+XJSZ6/cCIAj+AVS9H9soQ6wDqbnyVvCqJwsehyx9JjvZ7CLB6ES9";
    pub(crate) const GOOD_RSA: &str = "MIICmQoBAKCCApIwggKOBgkrBgEFBQcwAQEEggJ/MIICezCBk6EZMBcxFTATBgNVBAMMDG9jc3AgdGVzdCBjYRgPMjAyNjEwMDkwOTQxMzZaMGUwYzA7MAkGBSsOAwIaBQAEFMRdgJyh/gK6TmKVYkQlhVMEWq6WBBQQOGUP1XGD7E3JObJv5QeRdROlsAICEAGAABgPMjAyNjEwMDkwOTQxMzZaoBEYDzIwMjYxMDEwMDk0MTM2WjAKBggqhkjOPQQDAgNIADBFAiEAo2tsGuWhNwEDYOU0T7YUA7UzsotTujirkTmtt3nBNJUCIF1JNw1XBwJx2CyWmZElbx5DWz1KO+SbZAKhGLD9j/J9oIIBizCCAYcwggGDMIIBKaADAgECAhQnmlouwpZbIgozuE9+ZfiKDdcY7jAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxvY3NwIHRlc3QgY2EwHhcNMjYxMDA5MDk0MTM2WhcNMzYxMDA2MDk0MTM2WjAXMRUwEwYDVQQDDAxvY3NwIHRlc3QgY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQi71iTPRgHa0CEGSNqL7k3+w7NwlLeRWMWTATs5Lt8WJblK4K3AS9y1eZ+vW7mZhk1w4onkwEPFetNu6D48DUgo1MwUTAdBgNVHQ4EFgQUEDhlD9Vxg+xNyTmyb+UHkXUTpbAwHwYDVR0jBBgwFoAUEDhlD9Vxg+xNyTmyb+UHkXUTpbAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAuock5K/kEeEmlIevLUZQakeWecyCLB3lQ0U+XJSZ6/cCIAj+AVS9H9soQ6wDqbnyVvCqJwsehyx9JjvZ7CLB6ES9";
    pub(crate) const REVOKED: &str = "MIICqgoBAKCCAqMwggKfBgkrBgEFBQcwAQEEggKQMIICjDCBpKEZMBcxFTATBgNVBAMMDG9jc3AgdGVzdCBjYRgPMjAyNjEwMDkwOTQxMzZaMHYwdDA7MAkGBSsOAwIaBQAEFMRdgJyh/gK6TmKVYkQlhVMEWq6WBBQQOGUP1XGD7E3JObJv5QeRdROlsAICEAOhERgPMjAyNjEwMDkwOTQxMzZaGA8yMDI2MTAwOTA5NDEzNlqgERgPMjAyNjEwMTAwOTQxMzZaMAoGCCqGSM49BAMCA0gAMEUCIDNictz24mVieOSmhm+KUJutRFyDSA42ZWIYKMX1FCK7AiEAjy9Uzekp1WENAmXdfLV4UfJgRzPPuIl8wQBswbYzqo6gggGLMIIBhzCCAYMwggEpoAMCAQICFCeaWi7CllsiCjO4T35l+IoN1xjuMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDG9jc3AgdGVzdCBjYTAeFw0yNjEwMDkwOTQxMzZaFw0zNjEwMDYwOTQxMzZaMBcxFTATBgNVBAMMDG9jc3AgdGVzdCBjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCLvWJM9GAdrQIQZI2ovuTf7Ds3CUt5FYxZMBOzku3xYluUrgrcBL3LV5n69buZmGTXDiieTAQ8V6027oPjwNSCjUzBRMB0GA1UdDgQWBBQQOGUP1XGD7E3JObJv5QeRdROlsDAfBgNVHSMEGDAWgBQQOGUP1XGD7E3JObJv5QeRdROlsDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQC6hyTkr+QR4SaUh68tRlBqR5Z5zIIsHeVDRT5clJnr9wIgCP4BVL0f2yhDrAOpufJW8KonCx6HLH0mO9nsIsHoRL0=";
    pub(crate) const DELEGATED: &str = "MIIEIQoBAKCCBBowggQWBgkrBgEFBQcwAQEEggQHMIIEAzCBjaETMBExDzANBgNVBAMMBnNpZ25lchgPMjAyNjEwMDkwOTQxMzZaMGUwYzA7MAkGBSsOAwIaBQAEFMRdgJyh/gK6TmKVYkQlhVMEWq6WBBQQOGUP1XGD7E3JObJv5QeRdROlsAICEACAABgPMjAyNjEwMDkwOTQxMzZaoBEYDzIwMjYxMDEwMDk0MTM2WjANBgkqhkiG9w0BAQsFAAOCAQEAwoJMbL2Q/NN5PPQqZsTsFPhrpUpYmcOAw311tru7pk9n4tQZwaA5bJz569E+DAxMPLjj9x1RfY2xs0Zw0xrfnaJQoE6LOOPhzQ9nD3i0Dx24cgwK5kNu0FZg1rpjUNDi9f3sDwwWAye8ICjXVkvSNJywer4tx/XZ3i+ycv2DtxTgih0zLpREVPZsXsBTAXsSvuYgP0iQB3/aAij5QdIKGbfdNqk/sf2TVplgX1In9tA8o384OCJCF/oT+1e0RT6TkBB4lHLy5D+eun89WMdW08O8yCLqJCAEKio0N/YwVFCnyvbAvSgALHTN/rXXl4FnNPb66gF8XyBQCYbXgoC/waCCAlswggJXMIICUzCCAfigAwIBAgICEAQwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMb2NzcCB0ZXN0IGNhMB4XDTI2MTAwOTA5NDEzNloXDTM2MTAwNjA5NDEzNlowETEPMA0GA1UEAwwGc2lnbmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw2aa0/6tlsZxMeufXtfixZ+5Bku7hY/J5J/qGb5qeLVrmeJ8ESmMv/OxdJJ50mMku2rEudLtG6DceB9sme/z7k7hPyj3DcQJQCHgUEYkRbfZcCGUdbf3ShOprvs5Q6gw1MUinkw2hNVfDAvOQaeO5DqdM0vqN5o2uPTgq4+V29xxP4ukjJiHfzQV6T+S7CfPLcWLAJiN+CoLZYR61ml+t/5ZbBza6bv3ueWAJsVmfleOoGKCHzliw7iahvJr1390GbE8sHqHs59LFoSDViKbJ4fxhzyfOZSCixIhBrRFFCjcpDIZS/0vnQekuJdwQm9GsyD8mnB7VUgD6atLoSxnqQIDAQABo28wbTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDCTAdBgNVHQ4EFgQUQ1ldj2nqMZAoHOCKQYdswNoKv7swHwYDVR0jBBgwFoAUEDhlD9Vxg+xNyTmyb+UHkXUTpbAwCgYIKoZIzj0EAwIDSQAwRgIhAMbPDKca56WIF/Gs/FipktjaYq7FH3sC/fq+55Uz/0jiAiEAi1ZXaT9fm0DyGWc0OBL/7f1bGqFtG+/CTaAAqzWzeTU=";
    // Answers about the first certificate that are not the CA's word,
    // made forty minutes later: signed by a certificate of the CA that
    // is not for signing answers, by one that was and ran out in 2020,
    // by one that is for it and is nobody's. And one that is the CA's
    // word, with the certificate named by SHA-256 hashes.
    const BY_LEAF: &str = "MIIEcwoBAKCCBGwwggRoBgkrBgEFBQcwAQEEggRZMIIEVTCBiqEQMA4xDDAKBgNVBAMMA3JzYRgPMjAyNjEwMDkxMDIxMjNaMGUwYzA7MAkGBSsOAwIaBQAEFMRdgJyh/gK6TmKVYkQlhVMEWq6WBBQQOGUP1XGD7E3JObJv5QeRdROlsAICEACAABgPMjAyNjEwMDkxMDIxMjNaoBEYDzIwMjYxMDEwMTAyMTIzWjANBgkqhkiG9w0BAQsFAAOCAQEADyrxjnJEet2yAkCBDfb0ak4FQqLPe1TVm/0fZudIRavcpDsgj4VBYNOq+B4WOF2G3PkVWFsRxmDEMb2zrhQ/mE3Gv5AbOmd+zG8axThtsFnVs7T1eGfEztohQAPE5ATJRhS75vFf5vUaZOIXCcwmNkBeXRfoSikw2SItfTk5D9s4KnRhFuH5hmh4rP0XC8sLjHgPJpKomRnL0jgsiO02lkCZly8M9NC3qw1l8JLikn/064jO8T5p0WRUV/ivy7XEInQMytkDcwjzPLxuEZnezQXAA6BHdaUnV4bs1LV1CJ3j0eXBU8Y5ja3XyAyReLPA5CpcVC8wesFxe0cIIngB26CCArAwggKsMIICqDCCAk2gAwIBAgICEAEwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMb2NzcCB0ZXN0IGNhMB4XDTI2MTAwOTA5NDEzNloXDTM2MTAwNjA5NDEzNlowDjEMMAoGA1UEAwwDcnNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlso6cPTeM4ek5rSlvNVolTrbK6FqQ03sU8CAz9GbUx5mB59yMk8d2zjnCWmRnwVXpa+bhssR4Bn5oB4KOVGrlPmcjCSUnZhTA+wi7bgUUADmdwBP0gG7iGn6Np2Vtj/rKJVEObO6pclV6CqBGDatr5hzVcmXnLUaQa9mWpoGqxIHFGHukBQkaofMM9x6skXFFCjl/bqJD4Yif9XX3HqkgPZh5ym0kX6AoX7r8yqhK65rRCG4RIqsP158XzXi/0wp41x3g8s4BpdXb+zCTrgGE1EryYzh0WnTTmPtkSbdCTUjHIBFhSb8m9d77a2v8wQrXG9cWSk3+uuA/0Qu6TxduQIDAQABo4HGMIHDMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMCEGA1UdEQQaMBiCCW9jc3AudGVzdIILKi5vY3NwLnRlc3QwMQYIKwYBBQUHAQEEJTAjMCEGCCsGAQUFBzABhhVodHRwOi8vMTI3LjAuMC4xOjk0OTkwHQYDVR0OBBYEFJmdhJkYqufEAGgCutv5BSqbCAvIMB8GA1UdIwQYMBaAFBA4ZQ/VcYPsTck5sm/lB5F1E6WwMAoGCCqGSM49BAMCA0kAMEYCIQC91o5PwUIVc9rRe+Gwa8Snqsy31JtVatdjzhNhWTsv/wIhAMSLjdphaHBuWNIe4wqzMTGZpmldQDKmI3vdHjJBt9P0";
    const BY_OLD: &str = "MIIEJwoBAKCCBCAwggQcBgkrBgEFBQcwAQEEggQNMIIECTCBkaEXMBUxEzARBgNVBAMMCm9sZCBzaWduZXIYDzIwMjYxMDA5MTAyMTIzWjBlMGMwOzAJBgUrDgMCGgUABBTEXYCcof4Cuk5ilWJEJYVTBFqulgQUEDhlD9Vxg+xNyTmyb+UHkXUTpbACAhAAgAAYDzIwMjYxMDA5MTAyMTIzWqARGA8yMDI2MTAxMDEwMjEyM1owDQYJKoZIhvcNAQELBQADggEBAGEz7Yd7Mhh4N0FqM5st57iPc6wS1E7QyWGx5ZDeQWTHRqzJVyzL5hyeHzOzvX84Trj6SaNA2YMlN3TyV21YB/o/BoJMUfTuRmUsRU3hkVcrlPW15AWWZIpHE2c7Vt2wDjW8MZYmkEJdVtAf2Ak5UJBkDFPUG7T6iyAONht3/jd26VSBH8uNF3+Z8fxdfK795N9Psh1MvJpsesBI0wPcX+OAaxhmWvvq2uZ5wedEiOg5yZKYVrJst1dhxWfd5wcHawYQAAWI3FPKSUOWkdcbJILjFQKucYsfpxCRVqBjLhNA+IskrM2Zd/vKaOqGvQyAPrCZW0gJCIIrocCNCas+62agggJdMIICWTCCAlUwggH8oAMCAQICAhAFMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDG9jc3AgdGVzdCBjYTAeFw0yMDAxMDEwMDAwMDBaFw0yMDAyMDEwMDAwMDBaMBUxEzARBgNVBAMMCm9sZCBzaWduZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnmIbwCBikC+0shmF1fBMk9fU9UufQiAIfPvKj2DDn9iYJsWeev/w1CBpy6mzilAVrLP085NZUMWS9iGRB4UdikLhtEcT6r7ZEfi2hg1Oavp9R1/eGEH5t9yU8m2AS7ziUX37IZzILtBkI4u3OdNg3s7FzLbaX7SGvbwqZedg9KH9HaugBgXbs8BxUzcHzZDBl29P83w5Mdfeyhf4yoO8QYVoTV1gmYzt5a1Y2/+KbVAdm59soSo7kUqb4kO14IBGFGv60ui9oAMax/O8M0ONHWEw4bSohDhT/ftfdPT6j/Jcw+XMFVWPS5arp6BRV4YxF121hgDz6GV1dWb71eKTRAgMBAAGjbzBtMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMJMB0GA1UdDgQWBBQhtXioRDchmcxlJz5e9Hy8saDPEDAfBgNVHSMEGDAWgBQQOGUP1XGD7E3JObJv5QeRdROlsDAKBggqhkjOPQQDAgNHADBEAiB1ykAUDjT7361arxO0Ha+LxJUkgJOw3z/qTqqB+EAfvQIgYsPNpM1ttKm/Yaa2n00BX7LvIspWMQsRCHJWYnHbTpI=";
    const BY_SELF: &str = "MIIE9QoBAKCCBO4wggTqBgkrBgEFBQcwAQEEggTbMIIE1zCBkqEYMBYxFDASBgNVBAMMC3NlbGYgc2lnbmVyGA8yMDI2MTAwOTEwMjEyM1owZTBjMDswCQYFKw4DAhoFAAQUxF2AnKH+ArpOYpViRCWFUwRarpYEFBA4ZQ/VcYPsTck5sm/lB5F1E6WwAgIQAIAAGA8yMDI2MTAwOTEwMjEyM1qgERgPMjAyNjEwMTAxMDIxMjNaMA0GCSqGSIb3DQEBCwUAA4IBAQCjQ76CKNSz4XB/ZBNtuDPxoKasug8OToBpq7p3o3LjpPCyB/hFCQR/ZWw3MPqG/0+GU7GfDKIUjs1CK65Ues/mDfN5sorUjc8UkWGzLrSotK5rvCwNECcOz1V7KDr3cWYjSxN7IM/xJG1EPf1eHrO47Jn6zGhxtat5o4CtxhJJ8VA7n8qsVyRBxsoo6aPkfsZBhYzRahB0fompgYuMzfXe5d7/6Slb9PObGf/T/rr0Mdr4q7tIYEFzR1CewZi5e8INEOpdDSvyUgrHeiIFkBv6pq7lm5W/YiNi9YtgmVgY+Z9hGrt9iWiV8qq1d4kJPP6q4L80/Bl4yhs3bdn0RJ41oIIDKjCCAyYwggMiMIICCqADAgECAhQ+4PdSlsx1oRmaEGeW4MMTQFuNizANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAtzZWxmIHNpZ25lcjAeFw0yNjEwMDkxMDIxMjNaFw0zNjEwMDYxMDIxMjNaMBYxFDASBgNVBAMMC3NlbGYgc2lnbmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2CALu6qAVctGhQ7koeJrNYh1mpUtcx5a4NeKqLoXM6KTdpjE39y9hD6UxPXICLBgSXFPsAP2OCM/5ykgItPs74lHidwXLTsrFGoa04ZUpd2QCDLfERV7rkV+78DH/OLtLStiQsSI/Vgzf2O4cDBUHkvu18nCDD6Czu2iJZylMdDjKPn1h7JOkm3wfmZ2Uhh/ZOIGE/lCqemV4OH8MzQbLsBXhNpno34Mm1ZamU/1ED6VUZ5y8/jd94BQpIK5q17TaeXrue3Xrt+wywIRoF5uLQrTzyez6Yd6zZ8O7duIqNl1PCgo7SmlLS2WqfjHdgLiTzsy8L5Q7SmVODr9oZr2cwIDAQABo2gwZjAdBgNVHQ4EFgQUGAvLmQ7ThwbMqY68QfoOxSoYvf4wHwYDVR0jBBgwFoAUGAvLmQ7ThwbMqY68QfoOxSoYvf4wDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDCTANBgkqhkiG9w0BAQsFAAOCAQEArGnmzOExWffFCtR6RmoRhEPY3OKYf6U0+p2EIX/mhNOkhiUoS9J7Jesm3ry5KkzGLOi15Psva95VMuBBHuHP27L9ju+Qx5zqizxB2bFrqBNJWfG5+R7qtI9XAlmKKIxwS8gc6hFtH48Uo2a/7arvMQe9njdnyag5dV4BFNTJ+lxkGFhFm85ybsn9ROoTqWeffhrYSAj73DfPu51JX8BJ0GqZvX4GLMfKghIg0c1JW24apfcwzLu4TPvl3e/5wvsRE+c2ShfbRGDF9e1lKKjyXLDdvokxdEo1H+LfFS+xIkNQPVc8rEN/c68xtfBcG+rswwaZfIHiUnZlu4JjPMwhtg==";
    const SHA256_ID: &str = "MIICtgoBAKCCAq8wggKrBgkrBgEFBQcwAQEEggKcMIICmDCBsKEZMBcxFTATBgNVBAMMDG9jc3AgdGVzdCBjYRgPMjAyNjEwMDkxMDIzMDZaMIGBMH8wVzANBglghkgBZQMEAgEFAAQgitrR+kRxsQZgU8wjtTF+aAjyJJZWa4pSgOmR7GZqsJMEIGl4loq5liFz9qVEvwq+A8HNz2aMqAytqC6jCOED2VVlAgIQAIAAGA8yMDI2MTAwOTEwMjMwNlqgERgPMjAyNjEwMTAxMDIzMDZaMAoGCCqGSM49BAMCA0gAMEUCIFxubQ2S/cDOmmrQkBRdkgQiWV10fAuBGcar9rMeE5/nAiEAkflq4Qom5gEVrtPB0s96MqMaVAxL52hLZgllC9DrXCGgggGLMIIBhzCCAYMwggEpoAMCAQICFCeaWi7CllsiCjO4T35l+IoN1xjuMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDG9jc3AgdGVzdCBjYTAeFw0yNjEwMDkwOTQxMzZaFw0zNjEwMDYwOTQxMzZaMBcxFTATBgNVBAMMDG9jc3AgdGVzdCBjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCLvWJM9GAdrQIQZI2ovuTf7Ds3CUt5FYxZMBOzku3xYluUrgrcBL3LV5n69buZmGTXDiieTAQ8V6027oPjwNSCjUzBRMB0GA1UdDgQWBBQQOGUP1XGD7E3JObJv5QeRdROlsDAfBgNVHSMEGDAWgBQQOGUP1XGD7E3JObJv5QeRdROlsDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQC6hyTkr+QR4SaUh68tRlBqR5Z5zIIsHeVDRT5clJnr9wIgCP4BVL0f2yhDrAOpufJW8KonCx6HLH0mO9nsIsHoRL0=";
    // spellchecker:on
    pub(crate) const MADE_AT: i64 = 1791538896;
    const DAY: i64 = 24 * 3600;

    fn decode(value: &str) -> Vec<u8> {
        pingap_util::base64_decode(value).unwrap()
    }

    #[test]
    fn test_der() {
        assert_eq!(vec![0x04, 0x02, 1, 2], encode(TAG_OCTET_STRING, &[1, 2]));
        let long = encode(TAG_OCTET_STRING, &[7; 300]);
        assert_eq!([0x04, 0x82, 0x01, 0x2c], long[..4]);
        let mut reader = Reader(&long);
        let element = reader.next().unwrap();
        assert_eq!(TAG_OCTET_STRING, element.tag);
        assert_eq!(300, element.content.len());
        assert_eq!(long.len(), element.raw.len());
        assert_eq!(true, reader.next().is_none());
        // Cut short, or with a length that is not one.
        assert_eq!(true, Reader(&long[..100]).next().is_none());
        assert_eq!(true, Reader(&[0x04, 0x80]).next().is_none());
        assert_eq!(true, Reader(&[0x04]).next().is_none());

        assert_eq!(Some(MADE_AT), generalized_time(b"20261009094136Z"));
        assert_eq!(Some(MADE_AT), generalized_time(b"20261009094136.123Z"));
        assert_eq!(Some(0), generalized_time(b"19700101000000Z"));
        for invalid in
            ["20261009094136", "202610090925Z", "20261309094136Z", ""]
        {
            assert_eq!(None, generalized_time(invalid.as_bytes()), "{invalid}");
        }
    }

    /// The request is the one `openssl ocsp` makes for the certificate.
    #[test]
    fn test_new_query() {
        let query = new_query(LEAF.as_bytes(), CA.as_bytes()).unwrap();
        assert_eq!("http://127.0.0.1:9499", query.url);
        assert_eq!(decode(REQUEST), query.request);

        assert_eq!(
            "the certificate names no OCSP responder",
            new_query(PLAIN_LEAF.as_bytes(), CA.as_bytes()).unwrap_err()
        );
        // A chain that starts with something else than the issuer.
        assert_eq!(
            "the certificate after it in the chain is not the one of its issuer",
            new_query(LEAF.as_bytes(), RSA_LEAF.as_bytes()).unwrap_err()
        );
        assert_eq!(
            true,
            new_query(b"junk", CA.as_bytes())
                .unwrap_err()
                .starts_with("invalid certificate")
        );
    }

    #[test]
    fn test_check_response() {
        let query = new_query(LEAF.as_bytes(), CA.as_bytes()).unwrap();
        let check = |response: &str, query: &Query, now: i64| {
            check_response(&decode(response), query, CA.as_bytes(), now)
        };
        let times = |answer: std::result::Result<Answer, String>| {
            answer.map(|answer| (answer.this_update, answer.next_update))
        };
        let day = Ok((MADE_AT, MADE_AT + DAY));
        assert_eq!(day, times(check(GOOD, &query, MADE_AT + 3600)));
        // The clock of the responder a little ahead of this one.
        assert_eq!(day, times(check(GOOD, &query, MADE_AT - 60)));
        // Signed by a responder the CA has given a certificate for it.
        assert_eq!(day, times(check(DELEGATED, &query, MADE_AT + 3600)));
        // With an RSA key, signed by the same CA.
        let rsa = new_query(RSA_LEAF.as_bytes(), CA.as_bytes()).unwrap();
        assert_eq!(day, times(check(GOOD_RSA, &rsa, MADE_AT + 3600)));
        // The certificate named with other hashes than the ones it was
        // asked with: not what a client looks for.
        assert_eq!(
            "the answer is about another certificate",
            check(SHA256_ID, &query, MADE_AT + 3600).unwrap_err()
        );

        assert_eq!(
            "the answer is out of date",
            check(GOOD, &query, MADE_AT + DAY).unwrap_err()
        );
        assert_eq!(
            "the answer is from the future",
            check(GOOD, &query, MADE_AT - 3600).unwrap_err()
        );
        // An answer about another certificate of the CA.
        assert_eq!(
            "the answer is about another certificate",
            check(GOOD_RSA, &query, MADE_AT + 3600).unwrap_err()
        );
        let revoked =
            new_query(REVOKED_LEAF.as_bytes(), CA.as_bytes()).unwrap();
        assert_eq!(
            super::REVOKED,
            check(REVOKED, &revoked, MADE_AT + 3600).unwrap_err()
        );
    }

    /// What is stapled is put together from what was checked, and has
    /// nothing in it that the signature does not cover or that a client
    /// does not need.
    #[test]
    fn test_staple_is_made_anew() {
        let query = new_query(LEAF.as_bytes(), CA.as_bytes()).unwrap();
        let now = MADE_AT + 3600;
        let check = |response: &[u8]| {
            check_response(response, &query, CA.as_bytes(), now)
        };
        let good = decode(GOOD);
        let staple = check(&good).unwrap().staple;
        // Signed by the CA, whose certificate the client has: the copy
        // the responder sent along is left out.
        assert_eq!(true, staple.len() < good.len() - 300);
        // It is an answer like the one it was made of, and made of
        // itself it is itself.
        let again = check(&staple).unwrap();
        assert_eq!(
            (MADE_AT, MADE_AT + DAY),
            (again.this_update, again.next_update)
        );
        assert_eq!(staple, again.staple);

        // Signed by a responder of the CA: its certificate goes along,
        // and none besides.
        let delegated = check(&decode(DELEGATED)).unwrap().staple;
        assert_eq!(true, delegated.len() > staple.len() + 300);
        assert_eq!(delegated, check(&delegated).unwrap().staple);

        // What somebody on the way to the responder can add without
        // touching what is signed is not handed on: bytes at the end,
        // and certificates that have nothing to do with it.
        let mut padded = good.clone();
        padded.extend_from_slice(&[0u8; 3000]);
        assert_eq!(staple, check(&padded).unwrap().staple);
        // The certificates of the answer, twenty times over.
        let mut outer = Reader(&good);
        let mut response = Reader(outer.next().unwrap().content);
        let status = response.next().unwrap();
        let mut bytes = Reader(
            Reader(response.next().unwrap().content)
                .next()
                .unwrap()
                .content,
        );
        let oid = bytes.next().unwrap();
        let mut basic = Reader(
            Reader(bytes.next().unwrap().content)
                .next()
                .unwrap()
                .content,
        );
        let (data, algorithm, signature) = (
            basic.next().unwrap(),
            basic.next().unwrap(),
            basic.next().unwrap(),
        );
        let certificate = Reader(basic.next().unwrap().content)
            .next()
            .unwrap()
            .content;
        let stuffed = [
            data.raw,
            algorithm.raw,
            signature.raw,
            &encode(
                TAG_CONTEXT_0,
                &encode(TAG_SEQUENCE, &certificate.repeat(20)),
            ),
        ]
        .concat();
        let stuffed = encode(
            TAG_SEQUENCE,
            &[
                status.raw,
                &encode(
                    TAG_CONTEXT_0,
                    &encode(
                        TAG_SEQUENCE,
                        &[
                            oid.raw,
                            &encode(
                                TAG_OCTET_STRING,
                                &encode(TAG_SEQUENCE, &stuffed),
                            ),
                        ]
                        .concat(),
                    ),
                ),
            ]
            .concat(),
        );
        assert_eq!(true, stuffed.len() > 8000);
        assert_eq!(staple, check(&stuffed).unwrap().staple);

        // The same goes for the parts beside what is signed that are
        // kept: the name of the algorithm and the signature. An answer
        // with these parts, and no certificates.
        let assemble = |algorithm: &[u8], signature: &[u8]| {
            let basic = [data.raw, algorithm, signature].concat();
            encode(
                TAG_SEQUENCE,
                &[
                    status.raw,
                    &encode(
                        TAG_CONTEXT_0,
                        &encode(
                            TAG_SEQUENCE,
                            &[
                                oid.raw,
                                &encode(
                                    TAG_OCTET_STRING,
                                    &encode(TAG_SEQUENCE, &basic),
                                ),
                            ]
                            .concat(),
                        ),
                    ),
                ]
                .concat(),
            )
        };
        assert_eq!(
            staple,
            check(&assemble(algorithm.raw, signature.raw))
                .unwrap()
                .staple
        );
        // A length written the long way, which is the same to a reader
        // that is not strict: written the short way in what is stapled.
        let long_way = |element: &Element<'_>| {
            let mut bytes =
                vec![element.tag, 0x81, element.content.len() as u8];
            bytes.extend_from_slice(element.content);
            bytes
        };
        assert_eq!(
            staple,
            check(&assemble(&long_way(&algorithm), &long_way(&signature)))
                .unwrap()
                .staple
        );
        // Something more in the name of the algorithm, which nothing
        // that verifies the signature looks at.
        let more = encode(
            TAG_SEQUENCE,
            &[algorithm.content, &encode(TAG_OCTET_STRING, &[0u8; 64])]
                .concat(),
        );
        assert_eq!(
            "the answer is not well formed",
            check(&assemble(&more, signature.raw)).unwrap_err()
        );
        // A signature that is said not to be whole bytes.
        let mut bits = signature.content.to_vec();
        bits[0] = 1;
        assert_eq!(
            true,
            check(&assemble(algorithm.raw, &encode(TAG_BIT_STRING, &bits)))
                .is_err()
        );
    }

    /// An answer that is not the CA's word is not taken: one that was
    /// changed on the way, or made by somebody else.
    #[test]
    fn test_check_response_signature() {
        let query = new_query(LEAF.as_bytes(), CA.as_bytes()).unwrap();
        let now = MADE_AT + 3600;
        let good = decode(GOOD);
        assert_eq!(
            true,
            check_response(&good, &query, CA.as_bytes(), now).is_ok()
        );

        // "Revoked" turned into "good" by whoever sits on the way: the
        // status of the answer about the revoked certificate, with the
        // rest left as it was.
        let revoked =
            new_query(REVOKED_LEAF.as_bytes(), CA.as_bytes()).unwrap();
        let answer = decode(REVOKED);
        let position = answer
            .windows(2)
            .position(|bytes| bytes == [TAG_CONTEXT_1, 0x11])
            .unwrap();
        let mut forged = answer.clone();
        // Not a well formed answer any more, and it does not have to be:
        // the signature is looked at before anything in it.
        forged[position] = TAG_STATUS_GOOD;
        assert_eq!(
            "the answer is not signed by the issuer of the certificate",
            check_response(&forged, &revoked, CA.as_bytes(), now).unwrap_err()
        );

        // The day it holds until, made a later one.
        let mut longer = good.clone();
        let position = longer
            .windows(8)
            .position(|bytes| bytes == b"20261010")
            .unwrap();
        longer[position + 7] = b'9';
        assert_eq!(
            "the answer is not signed by the issuer of the certificate",
            check_response(&longer, &query, CA.as_bytes(), now).unwrap_err()
        );

        // Checked with the key of a certificate that did not sign it.
        assert_eq!(
            "the answer is not signed by the issuer of the certificate",
            check_response(&good, &query, RSA_LEAF.as_bytes(), now)
                .unwrap_err()
        );
        // Signed by who is not entitled to: a certificate of the CA that
        // is not for signing answers, one that was and has run out, and
        // one that says it is and that the CA never signed.
        for answer in [BY_LEAF, BY_OLD, BY_SELF] {
            assert_eq!(
                "the answer is not signed by the issuer of the certificate",
                check_response(&decode(answer), &query, CA.as_bytes(), now)
                    .unwrap_err()
            );
        }

        for junk in [&b""[..], b"junk", &[0x30, 0x03, 0x0a, 0x01, 0x00]] {
            assert_eq!(
                true,
                check_response(junk, &query, CA.as_bytes(), now)
                    .unwrap_err()
                    .starts_with("the answer is not an OCSP response"),
            );
        }
        // What a responder says when it will not answer.
        assert_eq!(
            "the responder answers unauthorized",
            check_response(
                &[0x30, 0x03, 0x0a, 0x01, 0x06],
                &query,
                CA.as_bytes(),
                now
            )
            .unwrap_err()
        );
    }

    struct Store(crate::DynamicCertificates);

    impl CertificateProvider for Store {
        fn get(&self, sni: &str) -> Option<Arc<crate::TlsCertificate>> {
            self.0.get(sni).cloned()
        }
        fn list(&self) -> Arc<crate::DynamicCertificates> {
            Arc::new(self.0.clone())
        }
        fn store(&self, _data: crate::DynamicCertificates) {}
    }

    /// What the responder of a test answers with, and what it was asked.
    #[derive(Default)]
    struct Responder {
        status: Mutex<u16>,
        answer: Mutex<Vec<u8>>,
        requests: Mutex<Vec<(String, Vec<u8>)>>,
    }

    /// A responder on a port of its own: every request gets what
    /// `responder` holds at that moment.
    async fn serve(responder: Arc<Responder>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut request = vec![];
                let mut buf = [0u8; 4096];
                // The head, then as much of a body as it says.
                let (head, body) = loop {
                    let Ok(count) = stream.read(&mut buf).await else {
                        return;
                    };
                    request.extend_from_slice(&buf[..count]);
                    let end = request
                        .windows(4)
                        .position(|bytes| bytes == b"\r\n\r\n");
                    if let Some(end) = end {
                        let head = String::from_utf8_lossy(&request[..end])
                            .to_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("content-length:")
                            })
                            .and_then(|value| {
                                value.trim().parse::<usize>().ok()
                            })
                            .unwrap_or_default();
                        if request.len() >= end + 4 + length {
                            break (head, request[end + 4..].to_vec());
                        }
                    }
                    if count == 0 {
                        return;
                    }
                };
                responder.requests.lock().unwrap().push((head, body));
                let status = *responder.status.lock().unwrap();
                let answer = responder.answer.lock().unwrap().clone();
                let head = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    answer.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&answer).await;
            }
        });
        format!("http://{addr}")
    }

    /// The task from the first answer to the one that does not come: an
    /// answer is stapled and not asked for again until it is due, one
    /// that can not be taken leaves the one there is, and a certificate
    /// the CA has revoked loses its answer.
    #[tokio::test]
    async fn test_stapling_task() {
        use pingap_config::CertificateConf;

        let responder = Arc::new(Responder::default());
        *responder.status.lock().unwrap() = 200;
        *responder.answer.lock().unwrap() = decode(GOOD);
        let url = serve(responder.clone()).await;
        let requests = || responder.requests.lock().unwrap().len();

        // The certificate the answers are about, and a second entry of
        // the store for the same one: asked about once.
        let conf = CertificateConf {
            tls_cert: Some(format!("{LEAF}\n{CA}")),
            tls_key: Some(LEAF_KEY.to_string()),
            ..Default::default()
        };
        let mut cert = crate::TlsCertificate::try_from(&conf).unwrap();
        // Not asked for: nothing to do with a responder.
        assert_eq!(true, cert.ocsp.is_none());
        let mut stapling =
            Stapling::new(LEAF.as_bytes(), &[CA.as_bytes().to_vec()]).unwrap();
        // The certificate names a port nothing listens on.
        stapling.query.url = url.clone();
        let stapling = Arc::new(stapling);
        cert.name = Some("site".to_string());
        cert.ocsp = Some(stapling.clone());
        let cert = Arc::new(cert);
        let certificate = cert.certificate.clone().unwrap();
        let store = crate::DynamicCertificates::from_iter([
            ("ocsp.test".to_string(), cert.clone()),
            ("*.ocsp.test".to_string(), cert.clone()),
        ]);
        let task = OcspStaplingTask {
            provider: Arc::new(Store(store)),
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
        };

        let now = MADE_AT + 600;
        assert_eq!(false, certificate.has_staple(now));
        assert_eq!(true, task.refresh(now).await);
        assert_eq!(1, requests());
        assert_eq!(true, certificate.has_staple(now));
        // Until the answer runs out, and no longer.
        assert_eq!(true, certificate.has_staple(MADE_AT + DAY - 1));
        assert_eq!(false, certificate.has_staple(MADE_AT + DAY));
        // What was asked is the request of the certificate, as OCSP has
        // it sent.
        {
            let asked = responder.requests.lock().unwrap();
            assert_eq!(decode(REQUEST), asked[0].1);
            assert_eq!(true, asked[0].0.starts_with("post / http/1.1"));
            assert_eq!(
                true,
                asked[0]
                    .0
                    .contains("content-type: application/ocsp-request")
            );
        }

        // Not again within the hour.
        assert_eq!(false, task.refresh(now + 3599).await);
        assert_eq!(1, requests());
        // A wait that is longer than any that is set here was set by a
        // clock that has been put back since: it is over.
        stapling.ask_at.store(now + 3 * 3600, Ordering::Relaxed);
        assert_eq!(true, task.refresh(now).await);
        assert_eq!(2, requests());
        responder.requests.lock().unwrap().pop();
        assert_eq!(false, task.refresh(now + 3599).await);
        assert_eq!(true, task.refresh(now + 3600).await);
        assert_eq!(2, requests());

        // A responder that fails: the answer there is stays, and it is
        // asked again after a minute, then after two more.
        *responder.status.lock().unwrap() = 500;
        let now = now + 2 * 3600;
        assert_eq!(true, task.refresh(now).await);
        assert_eq!(3, requests());
        assert_eq!(true, certificate.has_staple(now));
        assert_eq!(false, task.refresh(now + 59).await);
        assert_eq!(true, task.refresh(now + 60).await);
        assert_eq!(false, task.refresh(now + 60 + 119).await);
        assert_eq!(4, requests());
        assert_eq!(2, stapling.failures.load(Ordering::Relaxed));
        // An answer about another certificate is no better.
        *responder.status.lock().unwrap() = 200;
        *responder.answer.lock().unwrap() = decode(GOOD_RSA);
        assert_eq!(true, task.refresh(now + 3600).await);
        assert_eq!(true, certificate.has_staple(now));
        assert_eq!(3, stapling.failures.load(Ordering::Relaxed));
        // It works again: the failures are forgotten.
        *responder.answer.lock().unwrap() = decode(GOOD);
        assert_eq!(true, task.refresh(now + 3 * 3600).await);
        assert_eq!(0, stapling.failures.load(Ordering::Relaxed));

        // The CA revokes a certificate: what was stapled says the
        // opposite, and goes.
        let mut revoked =
            Stapling::new(REVOKED_LEAF.as_bytes(), &[CA.as_bytes().to_vec()])
                .unwrap();
        revoked.query.url = url;
        let cert = Arc::new(crate::TlsCertificate {
            name: Some("revoked".to_string()),
            ocsp: Some(Arc::new(revoked)),
            ..cert.as_ref().clone()
        });
        let task = OcspStaplingTask {
            provider: Arc::new(Store(crate::DynamicCertificates::from_iter([
                ("ocsp.test".to_string(), cert),
            ]))),
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
        };
        *responder.answer.lock().unwrap() = decode(REVOKED);
        assert_eq!(true, certificate.has_staple(now));
        assert_eq!(true, task.refresh(now).await);
        assert_eq!(false, certificate.has_staple(now));
    }

    #[test]
    fn test_when_to_ask_again() {
        let now = 1_000_000;
        // An hour on while the answer holds for longer.
        assert_eq!(now + 3600, refresh_at(now, now + 7 * DAY));
        // Five minutes before it runs out when that is sooner.
        assert_eq!(now + 1500, refresh_at(now, now + 1800));
        // Never within the minute.
        assert_eq!(now + 60, refresh_at(now, now + 120));
        assert_eq!(now + 60, refresh_at(now, now - 10));

        assert_eq!(now + 60, retry_at(now, 1));
        assert_eq!(now + 120, retry_at(now, 2));
        assert_eq!(now + 1920, retry_at(now, 6));
        assert_eq!(now + 3600, retry_at(now, 7));
        assert_eq!(now + 3600, retry_at(now, 100));
        assert_eq!(now + 60, retry_at(now, 0));

        // What can not have an answer stapled, and why.
        let chain = [CA.as_bytes().to_vec()];
        assert_eq!(true, Stapling::new(LEAF.as_bytes(), &chain).is_ok());
        assert_eq!(
            "the certificate of its issuer is not in the chain",
            Stapling::new(LEAF.as_bytes(), &[]).unwrap_err()
        );
        assert_eq!(
            "the certificate names no OCSP responder",
            Stapling::new(PLAIN_LEAF.as_bytes(), &chain).unwrap_err()
        );
    }
}
