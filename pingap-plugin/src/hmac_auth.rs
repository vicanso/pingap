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

use super::{
    Error, get_bool_conf, get_duration_conf, get_hash_key, get_str_slice_conf,
};
use ahash::AHashMap;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CONTENT_LENGTH, DATE, HOST, TRANSFER_ENCODING,
    WWW_AUTHENTICATE,
};
use http::{HeaderName, HeaderValue, StatusCode};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HandleRequestBody, HttpResponse, Plugin, PluginStep,
    RequestPluginResult, constant_time_eq, new_internal_error, now_sec,
};
use pingora::proxy::Session;
use sha2::{Digest, Sha256, Sha512};
use std::borrow::Cow;
use std::time::Duration;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "hmac_auth";
/// What stands for the method and the target of the request in the list
/// of what is signed.
const REQUEST_TARGET: &str = "(request-target)";
const X_DATE: &str = "x-date";
const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Requests signed with a shared secret, as HTTP Signatures
/// (draft-cavage-http-signatures) has it:
///
/// ```text
/// Authorization: Signature keyId="app1",algorithm="hmac-sha256",
///     headers="(request-target) host date",signature="<base64>"
/// ```
///
/// What is signed is one line for each name in `headers`, in that order,
/// joined by a line feed: `(request-target): get /path?query` for the
/// method (in lower case) and the target, `name: value` for a header.
///
/// The signature of `combined_auth` covers the secret and a time, and is
/// good for any request while that time holds. This one covers the
/// method, the path and the query of the request it was made for, the
/// headers the configuration asks for, and with `validate_body` the body.
pub struct HmacAuth {
    /// The secret of each key id.
    keys: AHashMap<String, Vec<u8>>,
    /// The headers a signature has to cover, in lower case. `date` is
    /// covered by `x-date` as well: a browser cannot set `Date`.
    signed_headers: Vec<String>,
    /// How far the time of a request may be from the time here.
    clock_skew: Duration,
    /// The body is held to the digest the request was signed with.
    validate_body: bool,
    /// `Authorization` is not passed on to the upstream.
    hide_credentials: bool,
    challenge: HeaderValue,
    hash_value: String,
}

impl TryFrom<&PluginConf> for HmacAuth {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let mut keys = AHashMap::new();
        for item in get_str_slice_conf(value, "keys") {
            let entry = item
                .split_once(':')
                .map(|(id, secret)| (id.trim(), secret))
                .filter(|(id, secret)| {
                    !id.is_empty() && !secret.is_empty() && !id.contains('"')
                });
            // The entry itself is not put into the message: it is a
            // secret, or most of one.
            let Some((id, secret)) = entry else {
                return Err(invalid(
                    "keys: each entry should be key_id:secret".to_string(),
                ));
            };
            if keys
                .insert(id.to_string(), secret.as_bytes().to_vec())
                .is_some()
            {
                return Err(invalid(format!("keys: there are two for {id}")));
            }
        }
        if keys.is_empty() {
            return Err(invalid(
                "keys is required, as key_id:secret".to_string(),
            ));
        }

        let mut signed_headers = vec![];
        let mut listed = get_str_slice_conf(value, "signed_headers");
        if listed.is_empty() {
            listed = vec!["host".to_string(), "date".to_string()];
        }
        for name in listed {
            let name = name.trim().to_ascii_lowercase();
            // The target is signed whatever is listed here.
            if name == REQUEST_TARGET {
                continue;
            }
            if HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(invalid(format!(
                    "signed_headers: {name:?} is not a header name"
                )));
            }
            if !signed_headers.contains(&name) {
                signed_headers.push(name);
            }
        }
        let clock_skew = get_duration_conf(value, "clock_skew")
            .unwrap_or(DEFAULT_CLOCK_SKEW);
        // In whole seconds, which is what a date has: less than one is
        // none, and no two clocks agree to the second.
        if clock_skew < Duration::from_secs(1) {
            return Err(invalid(
                "clock_skew should be at least 1s: no two clocks agree to the second"
                    .to_string(),
            ));
        }
        // What a client is told to sign, on a `401`.
        let mut required = vec![REQUEST_TARGET.to_string()];
        required.extend(signed_headers.iter().cloned());
        let challenge = HeaderValue::from_str(&format!(
            "Signature realm=\"pingap\",headers=\"{}\"",
            required.join(" ")
        ))
        .map_err(|e| invalid(e.to_string()))?;

        Ok(Self {
            keys,
            signed_headers,
            clock_skew,
            validate_body: get_bool_conf(value, "validate_body"),
            hide_credentials: get_bool_conf(value, "hide_credentials"),
            challenge,
            hash_value,
        })
    }
}

/// The parameters of `Authorization: Signature ...`.
#[derive(Debug, Default, PartialEq)]
struct SignatureParams<'a> {
    key_id: &'a str,
    algorithm: &'a str,
    headers: Vec<String>,
    signature: &'a str,
}

/// `Signature keyId="a",algorithm="hmac-sha256",headers="x y",signature="s"`
/// as its parts. `None` for another scheme, or for parameters that are
/// not `name="value"`.
fn parse_authorization(value: &str) -> Option<SignatureParams<'_>> {
    let (scheme, mut rest) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("signature") {
        return None;
    }
    let mut params = SignatureParams::default();
    let mut headers = None;
    loop {
        rest = rest.trim_start_matches([' ', ',']);
        if rest.is_empty() {
            break;
        }
        let (name, after) = rest.split_once('=')?;
        // A value is quoted, and has no quote in it: none of the four is
        // a text that needs one.
        let after = after.strip_prefix('"')?;
        let (value, after) = after.split_once('"')?;
        match name.trim() {
            "keyId" => params.key_id = value,
            "algorithm" => params.algorithm = value,
            "headers" => headers = Some(value),
            "signature" => params.signature = value,
            // `created`, `expires` and whatever else there may be: not
            // gone by here.
            _ => {},
        }
        rest = after;
    }
    // Left out, it is the date alone that is signed, as the draft says.
    params.headers = headers
        .unwrap_or("date")
        .split_ascii_whitespace()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    if params.key_id.is_empty() || params.signature.is_empty() {
        return None;
    }
    Some(params)
}

/// Seconds since the epoch of a `Date` (or an `X-Date`, which may also
/// be that number itself).
fn parse_time(value: &str) -> Option<i64> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<i64>() {
        return Some(seconds);
    }
    chrono::DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|time| time.timestamp())
}

/// The digest a request names for its body.
#[derive(Debug, Clone, PartialEq)]
enum BodyDigest {
    Sha256(Vec<u8>),
    Sha512(Vec<u8>),
}

/// The digest in a `Content-Digest` (RFC 9530: `sha-256=:<base64>:`) or a
/// `Digest` (RFC 3230: `SHA-256=<base64>`) header: the first of the
/// algorithms known here.
fn parse_digest(value: &str) -> Option<BodyDigest> {
    for item in value.split(',') {
        let Some((algorithm, digest)) = item.trim().split_once('=') else {
            continue;
        };
        let digest = digest.trim().trim_matches(':');
        let Ok(digest) = STANDARD.decode(digest) else {
            continue;
        };
        match algorithm.trim().to_ascii_lowercase().as_str() {
            "sha-256" if digest.len() == 32 => {
                return Some(BodyDigest::Sha256(digest));
            },
            "sha-512" if digest.len() == 64 => {
                return Some(BodyDigest::Sha512(digest));
            },
            _ => {},
        }
    }
    None
}

enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

/// Holds the body of a request to the digest it was signed with, as the
/// body goes by.
///
/// By the length the request declares, and not by being told that the
/// body has ended. To an upstream a body with a `Content-Length` is
/// complete with its last byte, while the end of the stream may be said
/// later - a client over HTTP/2 can hold it back for as long as it
/// likes - or, for a body that turns out empty, not be said at all. The
/// chunk that completes the length is where the digest is compared,
/// before that chunk is passed on.
struct DigestCheck {
    expected: BodyDigest,
    hasher: Hasher,
    /// What the request says its body is long.
    length: u64,
    seen: u64,
    done: bool,
}

impl DigestCheck {
    fn new(expected: BodyDigest, length: u64) -> Self {
        let hasher = Self::hasher_for(&expected);
        Self {
            expected,
            hasher,
            length,
            seen: 0,
            done: false,
        }
    }

    fn hasher_for(expected: &BodyDigest) -> Hasher {
        match expected {
            BodyDigest::Sha256(_) => Hasher::Sha256(Sha256::new()),
            BodyDigest::Sha512(_) => Hasher::Sha512(Sha512::new()),
        }
    }

    fn refuse() -> pingora::BError {
        new_internal_error(
            401,
            "the body of the request is not the one that was signed",
        )
    }
}

impl HandleRequestBody for DigestCheck {
    fn handle(
        &mut self,
        body: Option<&Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        let len = body.map(|body| body.len() as u64).unwrap_or_default();
        if self.done {
            // Nothing follows a body that is complete.
            return if len == 0 {
                Ok(())
            } else {
                Err(Self::refuse())
            };
        }
        self.seen = self.seen.saturating_add(len);
        if self.seen > self.length {
            return Err(Self::refuse());
        }
        if let Some(body) = body {
            match &mut self.hasher {
                Hasher::Sha256(hasher) => hasher.update(body),
                Hasher::Sha512(hasher) => hasher.update(body),
            }
        }
        if self.seen < self.length {
            // The end of a body that is shorter than it said.
            return if end_of_stream {
                Err(Self::refuse())
            } else {
                Ok(())
            };
        }
        self.done = true;
        let same = match (&mut self.hasher, &self.expected) {
            (Hasher::Sha256(hasher), BodyDigest::Sha256(expected)) => {
                constant_time_eq(&hasher.finalize_reset(), expected)
            },
            (Hasher::Sha512(hasher), BodyDigest::Sha512(expected)) => {
                constant_time_eq(&hasher.finalize_reset(), expected)
            },
            _ => false,
        };
        if same { Ok(()) } else { Err(Self::refuse()) }
    }

    fn restart(&mut self) {
        self.done = false;
        self.seen = 0;
        self.hasher = Self::hasher_for(&self.expected);
    }
}

/// Why a request is refused. What it says goes to the client, so it
/// tells what is wrong with the request and nothing of the keys.
type Refusal = &'static str;

const INVALID: Refusal = "Signature invalid";

impl HmacAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new hmac auth plugin"
        );
        Self::try_from(params)
    }

    fn refuse(&self, message: Refusal) -> RequestPluginResult {
        RequestPluginResult::Respond(HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            headers: Some(vec![(WWW_AUTHENTICATE, self.challenge.clone())]),
            body: Bytes::from_static(message.as_bytes()),
            ..Default::default()
        })
    }

    /// The value of the header `name` as it is signed: its values joined
    /// by a comma and a space, without the blanks around them. `None`
    /// for a header that is not there, and for one with a value that is
    /// no text: left out of what is signed, such a value went to the
    /// upstream under a signature that said nothing of it.
    fn header_value(session: &Session, name: &str) -> Option<String> {
        let header = session.req_header();
        let mut values = vec![];
        for value in header.headers.get_all(name).iter() {
            values.push(value.to_str().ok()?.trim());
        }
        if !values.is_empty() {
            return Some(values.join(", "));
        }
        // HTTP/2 has the host in the target of the request.
        if name == HOST.as_str() {
            return header
                .uri
                .authority()
                .map(|authority| authority.to_string());
        }
        None
    }

    /// The request is one this plugin lets through: signed by a key that
    /// is known, over what has to be signed, at a time close to now.
    /// What it names as the digest of its body comes back with it.
    fn verify(
        &self,
        session: &Session,
        ctx: &Ctx,
        now: i64,
    ) -> Result<Option<BodyDigest>, Refusal> {
        let authorization = session
            .req_header()
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or("Signature missing")?;
        let params =
            parse_authorization(authorization).ok_or("Signature missing")?;
        let signed = |name: &str| params.headers.iter().any(|h| h == name);
        if !signed(REQUEST_TARGET) {
            return Err("Signature should cover (request-target)");
        }
        for name in self.signed_headers.iter() {
            let covered =
                signed(name) || (name == DATE.as_str() && signed(X_DATE));
            if !covered {
                return Err("Signature does not cover a required header");
            }
        }

        // The request as the client sent it: a rewrite of the location is
        // not what was signed.
        let header = session.req_header();
        let uri = ctx
            .features
            .as_ref()
            .and_then(|features| features.original_uri.as_ref())
            .unwrap_or(&header.uri);
        let target = uri
            .path_and_query()
            .map(|target| target.as_str())
            .unwrap_or("/");
        let mut lines = Vec::with_capacity(params.headers.len());
        let mut time = None;
        let mut digest = None;
        for name in params.headers.iter() {
            if name == REQUEST_TARGET {
                lines.push(format!(
                    "{REQUEST_TARGET}: {} {target}",
                    header.method.as_str().to_ascii_lowercase()
                ));
                continue;
            }
            let value = Self::header_value(session, name).ok_or(
                "A signed header is not in the request, or is not text",
            )?;
            match name.as_str() {
                // Of the two, the one that is the client's own to set.
                X_DATE => time = Some(parse_time(&value)),
                "date" if time.is_none() => time = Some(parse_time(&value)),
                "content-digest" => digest = parse_digest(&value),
                "digest" if digest.is_none() => digest = parse_digest(&value),
                _ => {},
            }
            lines.push(format!("{name}: {value}"));
        }
        if let Some(time) = time {
            let time = time.ok_or("The date of the request is not a date")?;
            if now.abs_diff(time) > self.clock_skew.as_secs() {
                return Err("The date of the request is too far from now");
            }
        }

        let secret = self.keys.get(params.key_id).ok_or(INVALID)?;
        let signature =
            STANDARD.decode(params.signature).map_err(|_| INVALID)?;
        let message = lines.join("\n");
        let same = match params.algorithm.to_ascii_lowercase().as_str() {
            "" | "hmac-sha256" => constant_time_eq(
                &hmac_sha256::HMAC::mac(message.as_bytes(), secret),
                &signature,
            ),
            "hmac-sha512" => constant_time_eq(
                &hmac_sha512::HMAC::mac(message.as_bytes(), secret),
                &signature,
            ),
            _ => return Err("Signature algorithm is not supported"),
        };
        if !same {
            return Err(INVALID);
        }
        Ok(digest)
    }
}

#[async_trait]
impl Plugin for HmacAuth {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // At the request step alone, as the other plugins that say who
        // may ask: later, a response from the cache has gone out to
        // whoever asked.
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }
        let digest = match self.verify(session, ctx, now_sec() as i64) {
            Ok(digest) => digest,
            Err(message) => return Ok(self.refuse(message)),
        };
        if self.validate_body {
            // How long the body is, by what the request says of it. One
            // that does not say - a chunked upload, an HTTP/2 stream
            // without a length - can not be held to a digest in time:
            // there is no telling which of its chunks is the last before
            // the upstream has it.
            let header = session.req_header();
            let declared = header
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok());
            let length = if header.headers.contains_key(TRANSFER_ENCODING) {
                None
            } else if declared.is_some() {
                declared
            } else if session.is_body_empty() {
                // Neither a length nor a coding is no body at all, and so
                // is a stream that ended with its header.
                Some(0)
            } else {
                None
            };
            match (length, digest) {
                (None, _) => {
                    return Ok(RequestPluginResult::Respond(HttpResponse {
                        status: StatusCode::LENGTH_REQUIRED,
                        body: Bytes::from_static(
                            b"A signed body needs a Content-Length",
                        ),
                        ..Default::default()
                    }));
                },
                // Nothing to sign for, and nothing signed.
                (Some(0), None) => {},
                // A body nobody has signed for is not let through.
                (Some(_), None) => {
                    return Ok(self.refuse(
                        "Signature should cover the digest of the body",
                    ));
                },
                (Some(length), Some(digest)) => {
                    let mut check = DigestCheck::new(digest, length);
                    if length == 0 {
                        // No body is a body too, and known by now.
                        if check.handle(None, true).is_err() {
                            return Ok(self.refuse(INVALID));
                        }
                    } else {
                        ctx.add_request_body_handler(Box::new(check));
                    }
                },
            }
        }
        if self.hide_credentials {
            session.req_header_mut().remove_header(&AUTHORIZATION);
        }
        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("hmac_auth", HmacAuth);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    const DATE_TEXT: &str = "Fri, 09 Oct 2026 08:00:00 GMT";
    const DATE_SEC: i64 = 1791532800;

    fn new_plugin(conf: &str) -> Result<HmacAuth> {
        HmacAuth::new(&toml::from_str::<PluginConf>(conf).unwrap())
    }

    fn sign(secret: &str, message: &str) -> String {
        STANDARD.encode(hmac_sha256::HMAC::mac(message, secret))
    }

    async fn new_session(request: &str) -> Session {
        let mock_io = Builder::new().read(request.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    /// A request for `GET /api/users?page=2` signed over the target, the
    /// host and the date.
    fn signed_request(target: &str, signature: &str) -> String {
        format!(
            "GET {target} HTTP/1.1\r\nHost: api.test\r\nDate: {DATE_TEXT}\r\nAuthorization: Signature keyId=\"app1\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date\",signature=\"{signature}\"\r\n\r\n"
        )
    }

    #[test]
    fn test_hmac_auth_params() {
        let plugin =
            new_plugin("keys = [\"app1:s3cret\", \"app2:a:b\"]").unwrap();
        assert_eq!(vec!["host", "date"], plugin.signed_headers);
        assert_eq!(DEFAULT_CLOCK_SKEW, plugin.clock_skew);
        // a secret may have a colon in it
        assert_eq!(b"a:b".to_vec(), plugin.keys["app2"]);
        assert_eq!(
            "Signature realm=\"pingap\",headers=\"(request-target) host date\"",
            plugin.challenge
        );
        let plugin = new_plugin(
            "keys = [\"a:b\"]\nsigned_headers = [\"Host\", \"(request-target)\", \"X-Tenant\", \"host\"]\nclock_skew = \"30s\"",
        )
        .unwrap();
        assert_eq!(vec!["host", "x-tenant"], plugin.signed_headers);
        assert_eq!(Duration::from_secs(30), plugin.clock_skew);

        for (conf, message) in [
            ("", "keys is required"),
            ("keys = [\"nocolon\"]", "each entry should be key_id:secret"),
            ("keys = [\":secret\"]", "each entry should be key_id:secret"),
            ("keys = [\"id:\"]", "each entry should be key_id:secret"),
            ("keys = [\"a:1\", \"a:2\"]", "there are two for a"),
            (
                "keys = [\"a:1\"]\nsigned_headers = [\"x y\"]",
                "is not a header name",
            ),
            (
                "keys = [\"a:1\"]\nclock_skew = \"0s\"",
                "clock_skew should be at least 1s",
            ),
            // less than a second is none, to a date in seconds
            (
                "keys = [\"a:1\"]\nclock_skew = \"500ms\"",
                "clock_skew should be at least 1s",
            ),
        ] {
            let error = new_plugin(conf).err().unwrap().to_string();
            assert_eq!(true, error.contains(message), "{conf}: {error}");
            // the secret is not in what is reported
            assert_eq!(false, error.contains("nocolon"), "{error}");
        }
    }

    #[test]
    fn test_parse_authorization() {
        let params = parse_authorization(
            "Signature keyId=\"app1\", algorithm=\"hmac-sha256\",headers=\"(request-target) Host date\",signature=\"abc=\"",
        )
        .unwrap();
        assert_eq!("app1", params.key_id);
        assert_eq!("hmac-sha256", params.algorithm);
        assert_eq!(vec!["(request-target)", "host", "date"], params.headers);
        assert_eq!("abc=", params.signature);
        // No list of headers is the date alone.
        let params =
            parse_authorization("signature keyId=\"a\",signature=\"s\"")
                .unwrap();
        assert_eq!(vec!["date"], params.headers);
        for value in [
            "Basic dXNlcjpwYXNz", // spellchecker:disable-line
            "Signature",
            "Signature keyId=app1,signature=\"s\"",
            "Signature keyId=\"app1\"",
            "Signature signature=\"s\"",
            "Signature keyId=\"app1\",signature=\"s",
        ] {
            assert_eq!(None, parse_authorization(value), "{value}");
        }
    }

    #[test]
    fn test_parse_time_and_digest() {
        assert_eq!(Some(DATE_SEC), parse_time(DATE_TEXT));
        assert_eq!(Some(DATE_SEC), parse_time(" 1791532800 "));
        assert_eq!(None, parse_time("yesterday"));

        let empty = STANDARD.encode(Sha256::digest(b""));
        assert_eq!(
            Some(BodyDigest::Sha256(Sha256::digest(b"").to_vec())),
            parse_digest(&format!("sha-256=:{empty}:"))
        );
        assert_eq!(
            Some(BodyDigest::Sha256(Sha256::digest(b"").to_vec())),
            parse_digest(&format!("md5=abc, SHA-256={empty}"))
        );
        let long = STANDARD.encode(Sha512::digest(b"a"));
        assert_eq!(
            Some(BodyDigest::Sha512(Sha512::digest(b"a").to_vec())),
            parse_digest(&format!("sha-512=:{long}:"))
        );
        // not a digest of that length, not base64, not a known algorithm
        assert_eq!(None, parse_digest("sha-256=:YWJj:")); // spellchecker:disable-line
        assert_eq!(None, parse_digest("sha-256=:***:"));
        assert_eq!(None, parse_digest(&format!("md5={empty}")));
    }

    /// The signature is of one request: its method, its path, its query
    /// and the headers that have to be covered.
    #[tokio::test]
    async fn test_hmac_auth_verify() {
        let plugin = new_plugin("keys = [\"app1:s3cret\"]").unwrap();
        let message = format!(
            "(request-target): get /api/users?page=2\nhost: api.test\ndate: {DATE_TEXT}"
        );
        let signature = sign("s3cret", &message);
        let verify = async |plugin: &HmacAuth, request: &str, now: i64| {
            let session = new_session(request).await;
            plugin.verify(&session, &Ctx::default(), now)
        };
        let good = signed_request("/api/users?page=2", &signature);
        assert_eq!(Ok(None), verify(&plugin, &good, DATE_SEC + 10).await);

        // The same signature for another path, another query, another
        // method or another host: it was not made for those.
        for request in [
            signed_request("/api/admin?page=2", &signature),
            signed_request("/api/users?page=3", &signature),
            signed_request("/api/users", &signature),
            good.replacen("GET ", "DELETE ", 1),
            good.replace("api.test", "other.test"),
        ] {
            assert_eq!(
                Err(INVALID),
                verify(&plugin, &request, DATE_SEC).await,
                "{request}"
            );
        }
        // Nor for another time.
        assert_eq!(
            Err("The date of the request is too far from now"),
            verify(&plugin, &good, DATE_SEC + 301).await
        );
        assert_eq!(
            Err("The date of the request is too far from now"),
            verify(&plugin, &good, DATE_SEC - 301).await
        );
        assert_eq!(Ok(None), verify(&plugin, &good, DATE_SEC - 300).await);
        // A key that is not known, a secret that is not the key's.
        assert_eq!(
            Err(INVALID),
            verify(&plugin, &good.replace("app1", "app9"), DATE_SEC).await
        );
        let forged =
            signed_request("/api/users?page=2", &sign("guess", &message));
        assert_eq!(Err(INVALID), verify(&plugin, &forged, DATE_SEC).await);

        // No signature at all, or one of another kind.
        assert_eq!(
            Err("Signature missing"),
            verify(&plugin, "GET / HTTP/1.1\r\nHost: api.test\r\n\r\n", 0)
                .await
        );
        assert_eq!(
            Err("Signature missing"),
            verify(
                &plugin,
                "GET / HTTP/1.1\r\nAuthorization: Bearer abc\r\n\r\n",
                0
            )
            .await
        );
        // What has to be covered is: the target always, and the headers
        // of the configuration.
        let narrow =
            |headers: &str| good.replace("(request-target) host date", headers);
        assert_eq!(
            Err("Signature should cover (request-target)"),
            verify(&plugin, &narrow("host date"), DATE_SEC).await
        );
        assert_eq!(
            Err("Signature does not cover a required header"),
            verify(&plugin, &narrow("(request-target) date"), DATE_SEC).await
        );
        assert_eq!(
            Err("Signature does not cover a required header"),
            verify(&plugin, &narrow("(request-target) host"), DATE_SEC).await
        );
        // A header that is signed and not there.
        let missing = "A signed header is not in the request, or is not text";
        assert_eq!(
            Err(missing),
            verify(
                &plugin,
                &narrow("(request-target) host date x-tenant"),
                DATE_SEC
            )
            .await
        );
        assert_eq!(
            Err("Signature algorithm is not supported"),
            verify(
                &plugin,
                &good.replace("hmac-sha256", "rsa-sha256"),
                DATE_SEC
            )
            .await
        );
    }

    /// `X-Date` stands in for `Date`, sha-512 for sha-256, and the target
    /// that is signed is the one the client asked for.
    #[tokio::test]
    async fn test_hmac_auth_variants() {
        let plugin = new_plugin("keys = [\"app1:s3cret\"]").unwrap();
        let message = format!(
            "(request-target): post /orders\nhost: api.test\nx-date: {DATE_SEC}"
        );
        let signature = STANDARD
            .encode(hmac_sha512::HMAC::mac(message.as_bytes(), b"s3cret"));
        let request = format!(
            "POST /orders HTTP/1.1\r\nHost: api.test\r\nX-Date: {DATE_SEC}\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\nAuthorization: Signature keyId=\"app1\",algorithm=\"hmac-sha512\",headers=\"(request-target) host x-date\",signature=\"{signature}\"\r\n\r\n"
        );
        let session = new_session(&request).await;
        assert_eq!(
            Ok(None),
            plugin.verify(&session, &Ctx::default(), DATE_SEC + 60)
        );
        // It is the date that was signed that counts, not the other one.
        assert_eq!(
            Err("The date of the request is too far from now"),
            plugin.verify(&session, &Ctx::default(), DATE_SEC + 3600)
        );

        // A location that rewrites the path: what was signed is what the
        // client sent.
        let message = format!(
            "(request-target): get /v1/users\nhost: api.test\ndate: {DATE_TEXT}"
        );
        let request = signed_request("/users", &sign("s3cret", &message));
        let session = new_session(&request).await;
        let mut ctx = Ctx::default();
        assert_eq!(Err(INVALID), plugin.verify(&session, &ctx, DATE_SEC));
        ctx.features.get_or_insert_default().original_uri =
            Some("/v1/users".parse().unwrap());
        assert_eq!(Ok(None), plugin.verify(&session, &ctx, DATE_SEC));
    }

    /// `validate_body`: the body is the one whose digest was signed.
    #[tokio::test]
    async fn test_hmac_auth_body() {
        let plugin = new_plugin(
            "keys = [\"app1:s3cret\"]\nvalidate_body = true\nhide_credentials = true",
        )
        .unwrap();
        let now = now_sec() as i64;
        let request = |body: &str, digest_of: &str, signed: &str| {
            let digest = format!(
                "sha-256=:{}:",
                STANDARD.encode(Sha256::digest(digest_of.as_bytes()))
            );
            let mut message = format!(
                "(request-target): post /orders\nhost: api.test\nx-date: {now}"
            );
            if signed.contains("content-digest") {
                message.push_str(&format!("\ncontent-digest: {digest}"));
            }
            let signature = sign("s3cret", &message);
            format!(
                "POST /orders HTTP/1.1\r\nHost: api.test\r\nX-Date: {now}\r\nContent-Digest: {digest}\r\nContent-Length: {}\r\nAuthorization: Signature keyId=\"app1\",headers=\"{signed}\",signature=\"{signature}\"\r\n\r\n{body}",
                body.len()
            )
        };
        let all = "(request-target) host x-date content-digest";
        let run = async |request: String| {
            let mut session = new_session(&request).await;
            let mut ctx = Ctx::default();
            let result = plugin
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();
            let refused = match result {
                RequestPluginResult::Respond(resp) => {
                    Some(String::from_utf8_lossy(&resp.body).to_string())
                },
                _ => None,
            };
            let handlers = ctx
                .features
                .and_then(|features| features.request_body_handlers);
            (
                refused,
                handlers,
                session.req_header().headers.contains_key(AUTHORIZATION),
            )
        };

        // Signed with its digest: let through, the body still to check,
        // and the signature not passed on.
        let (refused, handlers, has_authorization) =
            run(request("{\"id\":1}", "{\"id\":1}", all)).await;
        assert_eq!(None, refused);
        assert_eq!(false, has_authorization);
        let mut handlers = handlers.unwrap();
        assert_eq!(1, handlers.len());
        let check = &mut handlers[0];
        // in two chunks, and once more for a retry
        for _ in 0..2 {
            let chunk = Bytes::from_static(b"{\"id\"");
            assert_eq!(true, check.handle(Some(&chunk), false).is_ok());
            let chunk = Bytes::from_static(b":1}");
            assert_eq!(true, check.handle(Some(&chunk), true).is_ok());
            check.restart();
        }
        // Another body than the one that was signed: refused with the
        // chunk that completes its length, whether or not the end of the
        // stream is said with it. A client over HTTP/2 that held the end
        // back had the upstream answer a request that was never checked.
        for end_of_stream in [true, false] {
            let chunk = Bytes::from_static(b"{\"id\":2}");
            let error = check.handle(Some(&chunk), end_of_stream).unwrap_err();
            assert_eq!(&pingora::ErrorType::HTTPStatus(401), error.etype());
            check.restart();
        }
        // The right body, and the end of the stream said later: checked
        // when it is complete, and nothing may follow it.
        let chunk = Bytes::from_static(b"{\"id\":1}");
        assert_eq!(true, check.handle(Some(&chunk), false).is_ok());
        assert_eq!(true, check.handle(None, true).is_ok());
        assert_eq!(
            true,
            check.handle(Some(&Bytes::from_static(b"x")), true).is_err()
        );
        check.restart();
        // Shorter than it said, and longer.
        let chunk = Bytes::from_static(b"{\"id\"");
        assert_eq!(true, check.handle(Some(&chunk), false).is_ok());
        assert_eq!(true, check.handle(None, true).is_err());
        check.restart();
        let chunk = Bytes::from_static(b"{\"id\":1} ");
        assert_eq!(true, check.handle(Some(&chunk), false).is_err());

        // The digest is there and not signed: anybody could have set it.
        let (refused, handlers, _) = run(request(
            "{\"id\":1}",
            "{\"id\":1}",
            "(request-target) host x-date",
        ))
        .await;
        assert_eq!(
            Some("Signature should cover the digest of the body".to_string()),
            refused
        );
        assert_eq!(true, handlers.is_none());

        // No body: a digest that is signed is checked at once.
        let (refused, handlers, _) = run(request("", "", all)).await;
        assert_eq!(None, refused);
        assert_eq!(true, handlers.is_none());
        let (refused, _, _) = run(request("", "not empty", all)).await;
        assert_eq!(Some(INVALID.to_string()), refused);

        // A body that does not say how long it is can not be checked in
        // time, and is not taken.
        let chunked = request("{\"id\":1}", "{\"id\":1}", all)
            .replace("Content-Length: 8\r\n", "Transfer-Encoding: chunked\r\n");
        assert_eq!(true, chunked.contains("Transfer-Encoding"));
        let (refused, handlers, _) = run(chunked).await;
        assert_eq!(
            Some("A signed body needs a Content-Length".to_string()),
            refused
        );
        assert_eq!(true, handlers.is_none());
    }

    /// A value of a signed header that is no text is not left out of
    /// what is signed: the request is refused. Passed over, a second
    /// line of the header went to the upstream under a signature that
    /// was made without it.
    #[tokio::test]
    async fn test_hmac_auth_header_that_is_not_text() {
        let plugin = new_plugin(
            "keys = [\"app1:s3cret\"]\nsigned_headers = [\"host\", \"date\", \"x-account\"]",
        )
        .unwrap();
        let message = format!(
            "(request-target): get /a\nhost: api.test\ndate: {DATE_TEXT}\nx-account: 42"
        );
        let signature = sign("s3cret", &message);
        let request = |extra: &[u8]| {
            let mut bytes = format!(
                "GET /a HTTP/1.1\r\nHost: api.test\r\nDate: {DATE_TEXT}\r\nX-Account: 42\r\n"
            )
            .into_bytes();
            bytes.extend_from_slice(extra);
            bytes.extend_from_slice(
                format!(
                    "Authorization: Signature keyId=\"app1\",headers=\"(request-target) host date x-account\",signature=\"{signature}\"\r\n\r\n"
                )
                .as_bytes(),
            );
            bytes
        };
        let verify = async |bytes: Vec<u8>| {
            let mock_io = Builder::new().read(&bytes).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            plugin.verify(&session, &Ctx::default(), DATE_SEC)
        };
        assert_eq!(Ok(None), verify(request(b"")).await);
        // a second value, as text: part of what is signed, so no match
        assert_eq!(Err(INVALID), verify(request(b"X-Account: 7\r\n")).await);
        // and one that is no text
        assert_eq!(
            Err("A signed header is not in the request, or is not text"),
            verify(request(b"X-Account: 7\xa0\r\n")).await
        );
    }

    #[tokio::test]
    async fn test_hmac_auth_steps_and_challenge() {
        let plugin = new_plugin("keys = [\"app1:s3cret\"]").unwrap();
        let mut session =
            new_session("GET / HTTP/1.1\r\nHost: api.test\r\n\r\n").await;
        let mut ctx = Ctx::default();
        let result = plugin
            .handle_request(PluginStep::ProxyUpstream, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(true, matches!(result, RequestPluginResult::Skipped));
        let result = plugin
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("the request should be refused");
        };
        assert_eq!(StatusCode::UNAUTHORIZED, resp.status);
        assert_eq!("Signature missing", resp.body);
        let headers = resp.headers.unwrap();
        assert_eq!(WWW_AUTHENTICATE, headers[0].0);
        assert_eq!(
            "Signature realm=\"pingap\",headers=\"(request-target) host date\"",
            headers[0].1
        );
    }
}
