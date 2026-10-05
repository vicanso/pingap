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

use bytes::{BufMut, BytesMut};
use chrono::{DateTime, Datelike, Local, Offset, TimeZone, Timelike, Utc};
use pingap_core::{
    Ctx, CtxLogField, HOST_NAME_TAG, format_duration, get_hostname,
};
use pingap_util::format_byte_size;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

// Enum representing different types of log tags that can be used in the logging format
#[derive(Debug, Clone, PartialEq)]
pub enum TagCategory {
    Fill,     // Static text
    Host,     // Server hostname
    Method,   // HTTP method (GET, POST, etc.)
    Path,     // Request path
    Proto,    // Protocol version
    Query,    // Query parameters
    Remote,   // Remote address
    ClientIp, // Client IP address
    Scheme,
    Uri,
    Referrer,
    UserAgent,
    When,
    WhenUtcIso,
    WhenUnix,
    Size,
    SizeHuman,
    Status,
    Latency,
    LatencyHuman,
    Cookie,
    RequestHeader,
    ResponseHeader,
    Context(CtxLogField),
    PayloadSize,
    PayloadSizeHuman,
    RequestId,
}

/// Where a tag sits in a JSON format.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum JsonSlot {
    /// Text of the format itself.
    #[default]
    Literal,
    /// A placeholder inside a JSON string: its value is escaped into it.
    InString,
    /// A placeholder outside any string, standing for a whole JSON value:
    /// a number, a boolean, a quoted string, or `null` when missing.
    Value,
}

// Represents a single tag in the log format
#[derive(Debug, Clone)]
pub struct Tag {
    pub category: TagCategory,
    pub data: Option<String>, // Optional data associated with the tag
    /// Only read when the format is JSON.
    pub json: JsonSlot,
}

impl Tag {
    fn new(category: TagCategory, data: Option<String>) -> Self {
        Self {
            category,
            data,
            json: JsonSlot::Literal,
        }
    }
    fn simple(category: TagCategory) -> Self {
        Self::new(category, None)
    }
    fn fill(text: &str) -> Self {
        Self::new(TagCategory::Fill, Some(text.to_string()))
    }
}

#[derive(Debug, Default, Clone)]
pub struct Parser {
    pub needs_timestamp: bool,
    pub capacity: usize,
    pub tags: Vec<Tag>,
    /// The format is a JSON object: values are escaped, and a missing one
    /// is empty or `null` instead of `-`.
    pub json: bool,
}

// Parses special tags with prefixes like ~, >, <, :, $
fn format_extra_tag(key: &str) -> Option<Tag> {
    let key = key.strip_prefix('{')?.strip_suffix('}')?;
    let (prefix, value) = key.split_at_checked(1)?;
    match prefix {
        // Cookie values
        "~" => Some(Tag::new(TagCategory::Cookie, Some(value.to_string()))),
        // Request headers
        ">" => Some(Tag::new(
            TagCategory::RequestHeader,
            Some(value.to_string()),
        )),
        // Response headers
        "<" => Some(Tag::new(
            TagCategory::ResponseHeader,
            Some(value.to_string()),
        )),
        // Resolved here, once; an unknown name printed nothing before and
        // still does.
        ":" => value
            .parse::<CtxLogField>()
            .ok()
            .map(|field| Tag::simple(TagCategory::Context(field))),
        "$" => {
            if key.as_bytes() == HOST_NAME_TAG {
                Some(Tag::fill(get_hostname()))
            } else {
                Some(Tag::fill(&std::env::var(value).unwrap_or_default()))
            }
        },
        _ => None,
    }
}

/// The tag for one `{...}` placeholder, braces included; `None` for a name
/// that is not a tag.
fn parse_tag(key: &str) -> Option<Tag> {
    let category = match key {
        "{host}" => TagCategory::Host,
        "{method}" => TagCategory::Method,
        "{path}" => TagCategory::Path,
        "{proto}" => TagCategory::Proto,
        "{query}" => TagCategory::Query,
        "{remote}" => TagCategory::Remote,
        "{client_ip}" => TagCategory::ClientIp,
        "{scheme}" => TagCategory::Scheme,
        "{uri}" => TagCategory::Uri,
        "{referer}" => TagCategory::Referrer,
        "{user_agent}" => TagCategory::UserAgent,
        "{when}" => TagCategory::When,
        "{when_utc_iso}" => TagCategory::WhenUtcIso,
        "{when_unix}" => TagCategory::WhenUnix,
        "{size}" => TagCategory::Size,
        "{size_human}" => TagCategory::SizeHuman,
        "{status}" => TagCategory::Status,
        "{latency}" => TagCategory::Latency,
        "{latency_human}" => TagCategory::LatencyHuman,
        "{payload_size}" => TagCategory::PayloadSize,
        "{payload_size_human}" => TagCategory::PayloadSizeHuman,
        "{request_id}" => TagCategory::RequestId,
        _ => return format_extra_tag(key),
    };
    Some(Tag::simple(category))
}

/// Characters a placeholder name is made of: letters, digits and the
/// prefixes and separators of header, cookie, context and env tags.
#[inline]
fn is_tag_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(b, b'_' | b'-' | b'<' | b'>' | b'~' | b':' | b'$')
}

/// Follows JSON string boundaries through literal format text, so each
/// placeholder knows whether it sits inside a string.
#[derive(Default)]
struct JsonStringState {
    in_string: bool,
    escaped: bool,
}

impl JsonStringState {
    fn scan(&mut self, text: &str) {
        for b in text.bytes() {
            if self.escaped {
                self.escaped = false;
            } else if b == b'\\' && self.in_string {
                self.escaped = true;
            } else if b == b'"' {
                self.in_string = !self.in_string;
            }
        }
    }
    fn slot(&self) -> JsonSlot {
        if self.in_string {
            JsonSlot::InString
        } else {
            JsonSlot::Value
        }
    }
}

/// Splits a format string into literal text and `{tag}` placeholders. A
/// placeholder is `{`, one or more tag characters and `}`; a `{` that is
/// not followed by that is literal text, as is everything outside
/// placeholders. A well-formed placeholder that names no tag is dropped.
fn parse_tags(value: &str) -> Vec<Tag> {
    let mut tags = vec![];
    let bytes = value.as_bytes();
    let mut fill_start = 0;
    let mut pos = 0;
    let mut json = JsonStringState::default();
    while let Some(offset) = value[pos..].find('{') {
        let start = pos + offset;
        let name_len = bytes[start + 1..]
            .iter()
            .take_while(|b| is_tag_byte(**b))
            .count();
        let end = start + 1 + name_len + 1;
        if name_len == 0 || bytes.get(end - 1) != Some(&b'}') {
            pos = start + 1;
            continue;
        }
        if fill_start < start {
            let text = &value[fill_start..start];
            json.scan(text);
            tags.push(Tag::fill(text));
        }
        if let Some(mut tag) = parse_tag(&value[start..end]) {
            tag.json = json.slot();
            tags.push(tag);
        }
        fill_start = end;
        pos = end;
    }
    if fill_start < value.len() {
        tags.push(Tag::fill(&value[fill_start..]));
    }
    tags
}

/// Whether `value` is a JSON object format: `{` and then a `"`, spaces
/// allowed between them. A text format never starts that way, since `{"`
/// opens no placeholder.
fn is_json_format(value: &str) -> bool {
    value
        .trim_start()
        .strip_prefix('{')
        .is_some_and(|rest| rest.trim_start().starts_with('"'))
}

// Predefined log formats
static COMBINED: &str = r###"{remote} "{method} {uri} {proto}" {status} {size_human} "{referer}" "{user_agent}""###;
static COMMON: &str =
    r###"{remote} "{method} {uri} {proto}" {status} {size_human}""###;
static SHORT: &str = r###"{remote} {method} {uri} {proto} {status} {size_human} - {latency}ms"###;
static TINY: &str = r###"{method} {uri} {status} {size_human} - {latency}ms"###;
static JSON: &str = r###"{"when":{when},"remote":{remote},"client_ip":{client_ip},"host":{host},"method":{method},"uri":{uri},"proto":{proto},"status":{status},"size":{size},"latency":{latency},"referer":{referer},"user_agent":{user_agent},"request_id":{request_id}}"###;

/// The names `access_log` accepts in place of a format. Kept in
/// `pingap-core`, where the config validation can reach them as well.
pub use pingap_core::ACCESS_LOG_PRESETS;

impl From<&str> for Parser {
    fn from(value: &str) -> Self {
        let value = match value {
            "combined" => COMBINED,
            "common" => COMMON,
            "short" => SHORT,
            "tiny" => TINY,
            "json" => JSON,
            _ => value,
        };
        let json = is_json_format(value);
        let mut tags = parse_tags(value);
        if json {
            // `{$name}` placeholders were resolved to text while parsing,
            // so they are escaped here, once, rather than on every line.
            for tag in tags.iter_mut().filter(|tag| {
                tag.category == TagCategory::Fill
                    && tag.json != JsonSlot::Literal
            }) {
                let text = tag.data.take().unwrap_or_default();
                let mut buf = BytesMut::with_capacity(text.len() + 2);
                put_json_text(&mut buf, tag.json, text.as_bytes());
                tag.data = Some(String::from_utf8_lossy(&buf).into_owned());
            }
        }
        let needs_timestamp = tags.iter().any(|t| {
            matches!(
                t.category,
                TagCategory::When
                    | TagCategory::WhenUtcIso
                    | TagCategory::WhenUnix
                    | TagCategory::Latency
                    | TagCategory::LatencyHuman
            )
        });
        let capacity = if *LOG_CAPACITY > 0 {
            *LOG_CAPACITY
        } else {
            Parser::estimate_capacity(&tags)
        };
        Parser {
            capacity,
            tags,
            needs_timestamp,
            json,
        }
    }
}

fn get_resp_header_value<'a>(
    resp_header: &'a ResponseHeader,
    key: &str,
) -> Option<&'a [u8]> {
    resp_header.headers.get(key).map(|v| v.as_bytes())
}

static LOG_CAPACITY: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("PINGAP_ACCESS_LOG_CAPACITY")
        .unwrap_or_default()
        .parse::<usize>()
        .unwrap_or_default()
});

const EMPTY_FIELD: &[u8] = b"-";

/// Appends `value` as exactly `width` decimal digits (zero padded).
#[inline]
fn put_digits(buf: &mut BytesMut, mut value: u32, width: usize) {
    let mut digits = [b'0'; 10];
    let mut i = digits.len();
    while i > digits.len() - width {
        i -= 1;
        digits[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    buf.put_slice(&digits[digits.len() - width..]);
}

/// RFC 3339 with millisecond precision - `2024-01-02T03:04:05.006+08:00`,
/// or `Z` for an offset of zero when `use_z` - appended without an
/// intermediate `String`. Matches chrono's
/// `to_rfc3339_opts(SecondsFormat::Millis, use_z)`.
fn put_rfc3339_millis<Tz: TimeZone>(
    buf: &mut BytesMut,
    time: &DateTime<Tz>,
    use_z: bool,
) {
    let local = time.naive_local();
    let year = local.year();
    if (0..=9999).contains(&year) {
        put_digits(buf, year as u32, 4);
    } else {
        buf.put_slice(itoa::Buffer::new().format(year).as_bytes());
    }
    buf.put_u8(b'-');
    put_digits(buf, local.month(), 2);
    buf.put_u8(b'-');
    put_digits(buf, local.day(), 2);
    buf.put_u8(b'T');
    put_digits(buf, local.hour(), 2);
    buf.put_u8(b':');
    put_digits(buf, local.minute(), 2);
    buf.put_u8(b':');
    put_digits(buf, local.second(), 2);
    buf.put_u8(b'.');
    put_digits(buf, local.nanosecond() / 1_000_000, 3);
    let offset = time.offset().fix().local_minus_utc();
    if offset == 0 && use_z {
        buf.put_u8(b'Z');
        return;
    }
    buf.put_u8(if offset < 0 { b'-' } else { b'+' });
    let offset = offset.unsigned_abs();
    put_digits(buf, offset / 3600, 2);
    buf.put_u8(b':');
    put_digits(buf, (offset % 3600) / 60, 2);
}

/// Appends `value` and returns true, or returns false when it is empty.
#[inline]
fn put_value(buf: &mut BytesMut, value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    buf.put_slice(value);
    true
}

/// The JSON type a tag's value takes outside a string.
#[derive(Clone, Copy, PartialEq)]
enum JsonKind {
    String,
    Number,
    Bool,
}

fn json_kind(category: &TagCategory) -> JsonKind {
    match category {
        TagCategory::Status
        | TagCategory::Size
        | TagCategory::PayloadSize
        | TagCategory::Latency
        | TagCategory::WhenUnix => JsonKind::Number,
        TagCategory::Context(field) => context_json_kind(*field),
        _ => JsonKind::String,
    }
}

/// By field rather than by what a value looks like, so a field keeps one
/// type across lines - a location named `404` is still a string.
fn context_json_kind(field: CtxLogField) -> JsonKind {
    match field {
        CtxLogField::UpstreamReused | CtxLogField::ConnectionReused => {
            JsonKind::Bool
        },
        CtxLogField::ConnectionId
        | CtxLogField::Processing
        | CtxLogField::UpstreamStatus
        | CtxLogField::UpstreamConnected
        | CtxLogField::UpstreamConnectTime
        | CtxLogField::UpstreamProcessingTime
        | CtxLogField::UpstreamResponseTime
        | CtxLogField::UpstreamTcpConnectTime
        | CtxLogField::UpstreamTlsHandshakeTime
        | CtxLogField::UpstreamConnectOffloadWaitTime
        | CtxLogField::UpstreamConnectionTime
        | CtxLogField::ConnectionTime
        | CtxLogField::TlsHandshakeTime
        | CtxLogField::CompressionTime
        | CtxLogField::CompressionRatio
        | CtxLogField::CacheLookupTime
        | CtxLogField::CacheLockTime
        | CtxLogField::ServiceTime => JsonKind::Number,
        _ => JsonKind::String,
    }
}

/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?`, the shape the numeric tags print.
/// Anything else, such as the `-` of a missing upstream status, is not a
/// number and becomes `null`.
fn is_json_number(value: &[u8]) -> bool {
    let digits = value.strip_prefix(b"-").unwrap_or(value);
    let (int, frac) = match digits.iter().position(|b| *b == b'.') {
        Some(dot) => (&digits[..dot], Some(&digits[dot + 1..])),
        None => (digits, None),
    };
    let all_digits =
        |part: &[u8]| !part.is_empty() && part.iter().all(u8::is_ascii_digit);
    all_digits(int)
        && (int.len() == 1 || int[0] != b'0')
        && frac.is_none_or(all_digits)
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The bytes that must be escaped: control characters, quote, backslash.
const fn needs_escape(b: u8) -> bool {
    b < 0x20 || b == b'"' || b == b'\\'
}

/// Escapes `buf[start..]` for use inside a JSON string. Valid UTF-8 with
/// no quote, backslash or control character - nearly every value - is
/// left alone without copying; otherwise the value is rewritten, with
/// invalid UTF-8 replaced by U+FFFD, since a header can carry any byte.
fn escape_json(buf: &mut BytesMut, start: usize) {
    let value = &buf[start..];
    // One pass for plain ASCII, the common case; UTF-8 is only validated
    // when there is a byte above it.
    let Some(first) =
        value.iter().position(|b| needs_escape(*b) || !b.is_ascii())
    else {
        return;
    };
    let rest = &value[first..];
    if !rest.iter().any(|b| needs_escape(*b))
        && std::str::from_utf8(rest).is_ok()
    {
        return;
    }
    let raw = value.to_vec();
    buf.truncate(start);
    for chunk in raw.utf8_chunks() {
        let text = chunk.valid().as_bytes();
        let mut done = 0;
        for (i, b) in text.iter().enumerate() {
            let escaped: &[u8] = match b {
                b'"' => b"\\\"",
                b'\\' => b"\\\\",
                b'\n' => b"\\n",
                b'\r' => b"\\r",
                b'\t' => b"\\t",
                0..=0x1f => b"",
                _ => continue,
            };
            buf.put_slice(&text[done..i]);
            if escaped.is_empty() {
                buf.put_slice(b"\\u00");
                buf.put_u8(HEX_DIGITS[(b >> 4) as usize]);
                buf.put_u8(HEX_DIGITS[(b & 0x0f) as usize]);
            } else {
                buf.put_slice(escaped);
            }
            done = i + 1;
        }
        buf.put_slice(&text[done..]);
        if !chunk.invalid().is_empty() {
            buf.put_slice(b"\\ufffd");
        }
    }
}

/// Whether a tag's value is text from outside: the request line, a header
/// of either side, the client address a header can give. The rest is
/// numbers, times and names from the configuration.
const fn is_outside_text(category: &TagCategory) -> bool {
    matches!(
        category,
        TagCategory::Host
            | TagCategory::Path
            | TagCategory::Query
            | TagCategory::Uri
            | TagCategory::ClientIp
            | TagCategory::Referrer
            | TagCategory::UserAgent
            | TagCategory::Cookie
            | TagCategory::RequestHeader
            | TagCategory::ResponseHeader
            | TagCategory::RequestId
    )
}

/// The bytes a line of text cannot carry as they are. Without a branch, so
/// that the scan over a value can be done several bytes at a time.
const fn needs_text_escape(b: u8) -> bool {
    (b < 0x20) | (b == b'"') | (b == b'\\') | (b == 0x7f)
}

/// Escapes `buf[start..]` for a text format: `\"`, `\\`, and `\xXX` for a
/// control character.
///
/// A header value can hold a quote, and a format quotes its fields
/// (`"{referer}" "{user_agent}"`): a user agent of `" 200 "-` wrote fields
/// of its own choosing into its line. Nearly every value has nothing to
/// escape and costs the one scan.
#[inline(always)]
fn escape_text(buf: &mut BytesMut, start: usize) {
    // Every byte is looked at, with no early exit: there is nearly never
    // anything to find, and the loop without one is the faster.
    let found = buf[start..]
        .iter()
        .fold(false, |found, b| found | needs_text_escape(*b));
    if found {
        escape_text_bytes(buf, start);
    }
}

#[cold]
fn escape_text_bytes(buf: &mut BytesMut, start: usize) {
    let raw = buf.split_off(start);
    for b in raw.iter().copied() {
        match b {
            b'"' => buf.put_slice(b"\\\""),
            b'\\' => buf.put_slice(b"\\\\"),
            b if needs_text_escape(b) => {
                buf.put_slice(b"\\x");
                buf.put_u8(HEX_DIGITS[(b >> 4) as usize]);
                buf.put_u8(HEX_DIGITS[(b & 0x0f) as usize]);
            },
            b => buf.put_u8(b),
        }
    }
}

/// Appends `text` for its place in a JSON format: escaped inside a string,
/// a quoted string (or `null` when empty) as a value of its own.
fn put_json_text(buf: &mut BytesMut, slot: JsonSlot, text: &[u8]) {
    match slot {
        JsonSlot::Literal => buf.put_slice(text),
        JsonSlot::InString => {
            let start = buf.len();
            buf.put_slice(text);
            escape_json(buf, start);
        },
        JsonSlot::Value if text.is_empty() => buf.put_slice(b"null"),
        JsonSlot::Value => {
            buf.put_u8(b'"');
            let start = buf.len();
            buf.put_slice(text);
            escape_json(buf, start);
            buf.put_u8(b'"');
        },
    }
}

/// What one line's values are read from.
struct LineSource<'a> {
    session: &'a Session,
    req_header: &'a RequestHeader,
    ctx: &'a Ctx,
    now: Option<DateTime<Utc>>,
    latency: Option<Duration>,
}

impl LineSource<'_> {
    /// Appends the value of `tag` and returns true, or appends nothing and
    /// returns false when there is no value. Inlined into `format`: as a
    /// call it cost the text format bench about 3%.
    #[inline(always)]
    fn put(&self, buf: &mut BytesMut, tag: &Tag) -> bool {
        let session = self.session;
        let ctx = self.ctx;
        let req_header = self.req_header;
        match &tag.category {
            TagCategory::Fill => put_value(
                buf,
                tag.data.as_deref().unwrap_or_default().as_bytes(),
            ),
            TagCategory::Host => {
                let host = pingap_core::get_host(req_header);
                put_value(buf, host.unwrap_or_default().as_bytes())
            },
            TagCategory::Method => {
                put_value(buf, req_header.method.as_str().as_bytes())
            },
            TagCategory::Path => {
                put_value(buf, req_header.uri.path().as_bytes())
            },
            TagCategory::Proto => {
                if session.is_http2() {
                    buf.put_slice(b"HTTP/2.0");
                } else {
                    buf.put_slice(b"HTTP/1.1");
                }
                true
            },
            TagCategory::Query => {
                let query = req_header.uri.query().unwrap_or_default();
                put_value(buf, query.as_bytes())
            },
            TagCategory::Remote => {
                let addr = ctx.conn.remote_addr.as_deref().unwrap_or_default();
                put_value(buf, addr.as_bytes())
            },
            TagCategory::ClientIp => match &ctx.conn.client_ip {
                Some(client_ip) => put_value(buf, client_ip.as_bytes()),
                None => {
                    let client_ip = pingap_core::get_client_ip(session);
                    put_value(buf, client_ip.as_bytes())
                },
            },
            TagCategory::Scheme => {
                if ctx.conn.tls_version.is_some() {
                    buf.put_slice(b"https");
                } else {
                    buf.put_slice(b"http");
                }
                true
            },
            TagCategory::Uri => {
                let uri = req_header
                    .uri
                    .path_and_query()
                    .map(|value| value.as_str())
                    .unwrap_or_default();
                put_value(buf, uri.as_bytes())
            },
            TagCategory::Referrer => {
                put_value(buf, session.get_header_bytes("referer"))
            },
            TagCategory::UserAgent => {
                put_value(buf, session.get_header_bytes("user-agent"))
            },
            TagCategory::When => self.now.is_some_and(|now| {
                put_rfc3339_millis(buf, &now.with_timezone(&Local), false);
                true
            }),
            TagCategory::WhenUtcIso => self.now.is_some_and(|now| {
                put_rfc3339_millis(buf, &now, true);
                true
            }),
            TagCategory::WhenUnix => self.now.is_some_and(|now| {
                buf.put_slice(
                    itoa::Buffer::new()
                        .format(now.timestamp_millis())
                        .as_bytes(),
                );
                true
            }),
            TagCategory::Size => {
                buf.put_slice(
                    itoa::Buffer::new()
                        .format(session.body_bytes_sent())
                        .as_bytes(),
                );
                true
            },
            TagCategory::SizeHuman => {
                format_byte_size(buf, session.body_bytes_sent());
                true
            },
            TagCategory::Status => ctx.state.status.is_some_and(|status| {
                buf.put_slice(status.as_str().as_bytes());
                true
            }),
            TagCategory::Latency => self.latency.is_some_and(|latency| {
                buf.put_slice(
                    itoa::Buffer::new().format(latency.as_millis()).as_bytes(),
                );
                true
            }),
            TagCategory::LatencyHuman => self.latency.is_some_and(|latency| {
                format_duration(buf, latency.as_millis() as u64);
                true
            }),
            TagCategory::Cookie => {
                let value = tag.data.as_deref().and_then(|cookie| {
                    pingap_core::get_cookie_value(req_header, cookie)
                });
                put_value(buf, value.unwrap_or_default().as_bytes())
            },
            TagCategory::RequestHeader => {
                let value = tag
                    .data
                    .as_deref()
                    .and_then(|key| req_header.headers.get(key))
                    .map(|value| value.as_bytes())
                    .unwrap_or_default();
                put_value(buf, value)
            },
            TagCategory::ResponseHeader => {
                let value = session
                    .response_written()
                    .zip(tag.data.as_deref())
                    .and_then(|(resp_header, key)| {
                        get_resp_header_value(resp_header, key)
                    })
                    .unwrap_or_default();
                put_value(buf, value)
            },
            TagCategory::PayloadSize => {
                buf.put_slice(
                    itoa::Buffer::new()
                        .format(ctx.state.payload_size)
                        .as_bytes(),
                );
                true
            },
            TagCategory::PayloadSizeHuman => {
                format_byte_size(buf, ctx.state.payload_size);
                true
            },
            TagCategory::RequestId => {
                let id = ctx.state.request_id.as_deref().unwrap_or_default();
                put_value(buf, id.as_bytes())
            },
            TagCategory::Context(field) => {
                let start = buf.len();
                ctx.append_log_field(buf, *field);
                buf.len() > start
            },
        }
    }

    /// Appends the value of `tag` for its place in a JSON format. Inside a
    /// string a missing value is empty; as a value of its own it is `null`,
    /// as is a numeric tag that printed something other than a number.
    fn put_json(&self, buf: &mut BytesMut, tag: &Tag) {
        let start = buf.len();
        if tag.json != JsonSlot::Value {
            if self.put(buf, tag) {
                escape_json(buf, start);
            }
            return;
        }
        match json_kind(&tag.category) {
            JsonKind::String => {
                buf.put_u8(b'"');
                if self.put(buf, tag) {
                    escape_json(buf, start + 1);
                    buf.put_u8(b'"');
                } else {
                    buf.truncate(start);
                    buf.put_slice(b"null");
                }
            },
            kind => {
                let valid = self.put(buf, tag)
                    && match kind {
                        JsonKind::Bool => {
                            matches!(&buf[start..], b"true" | b"false")
                        },
                        _ => is_json_number(&buf[start..]),
                    };
                if !valid {
                    buf.truncate(start);
                    buf.put_slice(b"null");
                }
            },
        }
    }
}

impl Parser {
    // Add a method to estimate capacity based on tag types
    fn estimate_capacity(tags: &[Tag]) -> usize {
        // Base size plus estimation for each tag type
        let mut size = 128; // Base size
        for tag in tags {
            size += match tag.category {
                TagCategory::Fill => tag.data.as_ref().map_or(0, |s| s.len()),
                TagCategory::Uri | TagCategory::Path => 64, // URIs can be long
                TagCategory::UserAgent => 100, // User agents are often long
                // Add more specific estimates for other tag types
                _ => 16, // Default estimate for other tags
            };
        }
        size
    }
    /// Formats one access log line. In a text format a missing value is
    /// `-` (a context field writes nothing), and a quote, a backslash or a
    /// control character in a value from the request is escaped; in a JSON
    /// format values are escaped and a missing one is empty or `null`.
    pub fn format(&self, session: &Session, ctx: &Ctx) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.capacity);
        // Only read the clocks when a tag needs them.
        let (now, latency) = if self.needs_timestamp {
            (
                Some(Utc::now()),
                Some(
                    Instant::now()
                        .saturating_duration_since(ctx.timing.created_at),
                ),
            )
        } else {
            (None, None)
        };
        let source = LineSource {
            session,
            req_header: session.req_header(),
            ctx,
            now,
            latency,
        };
        for tag in self.tags.iter() {
            if let TagCategory::Fill = tag.category {
                if let Some(data) = &tag.data {
                    buf.put_slice(data.as_bytes());
                }
            } else if self.json {
                source.put_json(&mut buf, tag);
            } else {
                let start = buf.len();
                if source.put(&mut buf, tag) {
                    if is_outside_text(&tag.category) {
                        escape_text(&mut buf, start);
                    }
                } else if !matches!(tag.category, TagCategory::Context(_)) {
                    buf.put_slice(EMPTY_FIELD);
                }
            }
        }
        buf
    }
}

/// Parse the access log directive
///
/// # Arguments
///
/// * `access_log` - The access log directive
///
/// # Returns
///
/// * `(access_log, path)` - The access log directive and the path
///
/// # Examples
///
/// ```
/// use pingap_logger::parse_access_log_directive;
/// let (access_log, path) = parse_access_log_directive(Some(
///     &"{when} {host} {method} {path}".to_string(),
/// ));
/// assert_eq!(Some("{when} {host} {method} {path}".to_string()), access_log);
/// assert_eq!(None, path);
/// ```
///
/// ```
/// use pingap_logger::parse_access_log_directive;
/// let (access_log, path) = parse_access_log_directive(Some(
///     &"/var/log/pingap.log {when} {host} {method} {path}".to_string(),
/// ));
/// assert_eq!(Some("{when} {host} {method} {path}".to_string()), access_log);
/// assert_eq!(Some("/var/log/pingap.log".to_string()), path);
/// ```
pub fn parse_access_log_directive(
    access_log: Option<&String>,
) -> (Option<String>, Option<String>) {
    let default_value = (access_log.cloned(), None);
    let Some(access_log) = access_log else {
        return default_value;
    };
    if access_log.starts_with('{') {
        return default_value;
    }
    let Some((path, access)) = access_log.split_once(' ') else {
        return default_value;
    };

    if !ACCESS_LOG_PRESETS.contains(&access) && !access.starts_with('{') {
        return default_value;
    }

    (Some(access.to_string()), Some(path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        Parser, TagCategory, format_extra_tag, get_resp_header_value,
        parse_access_log_directive, parse_tags, put_rfc3339_millis,
    };
    use bytes::BytesMut;
    use chrono::{FixedOffset, SecondsFormat, TimeZone, Utc};
    use http::Method;
    use pingap_core::{
        ConnectionInfo, Ctx, RequestState, Timing, UpstreamInfo,
    };
    use pingora::{http::ResponseHeader, proxy::Session};
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_parse_access_log_directive() {
        let (access, path) = parse_access_log_directive(Some(
            &"{when} {host} {method} {path}".to_string(),
        ));
        assert_eq!(Some("{when} {host} {method} {path}".to_string()), access);
        assert_eq!(None, path);

        let (access, path) = parse_access_log_directive(Some(
            &"/var/log/pingap.log {when} {host} {method} {path}".to_string(),
        ));
        assert_eq!(Some("{when} {host} {method} {path}".to_string()), access);
        assert_eq!(Some("/var/log/pingap.log".to_string()), path);
    }

    #[test]
    fn test_format_extra_tag() {
        assert_eq!(true, format_extra_tag(":").is_none());

        let cookie = format_extra_tag("{~deviceId}").unwrap();
        assert_eq!(TagCategory::Cookie, cookie.category);
        assert_eq!("deviceId", cookie.data.unwrap());

        let req_header = format_extra_tag("{>X-User}").unwrap();
        assert_eq!(TagCategory::RequestHeader, req_header.category);
        assert_eq!("X-User", req_header.data.unwrap());

        let resp_header = format_extra_tag("{<X-Response-Id}").unwrap();
        assert_eq!(TagCategory::ResponseHeader, resp_header.category);
        assert_eq!("X-Response-Id", resp_header.data.unwrap());

        let hostname = format_extra_tag("{$hostname}").unwrap();
        assert_eq!(TagCategory::Fill, hostname.category);
        assert_eq!(false, hostname.data.unwrap().is_empty());

        let env = format_extra_tag("{$HOME}").unwrap();
        assert_eq!(TagCategory::Fill, env.category);
        assert_eq!(false, env.data.unwrap().is_empty());
    }
    #[test]
    fn test_parse_format() {
        let tests = [
            ("{host}", TagCategory::Host),
            ("{method}", TagCategory::Method),
            ("{path}", TagCategory::Path),
            ("{proto}", TagCategory::Proto),
            ("{query}", TagCategory::Query),
            ("{remote}", TagCategory::Remote),
            ("{client_ip}", TagCategory::ClientIp),
            ("{scheme}", TagCategory::Scheme),
            ("{uri}", TagCategory::Uri),
            ("{referer}", TagCategory::Referrer),
            ("{user_agent}", TagCategory::UserAgent),
            ("{when}", TagCategory::When),
            ("{when_utc_iso}", TagCategory::WhenUtcIso),
            ("{when_unix}", TagCategory::WhenUnix),
            ("{size}", TagCategory::Size),
            ("{size_human}", TagCategory::SizeHuman),
            ("{status}", TagCategory::Status),
            ("{latency}", TagCategory::Latency),
            ("{latency_human}", TagCategory::LatencyHuman),
            ("{payload_size}", TagCategory::PayloadSize),
            ("{payload_size_human}", TagCategory::PayloadSizeHuman),
            ("{request_id}", TagCategory::RequestId),
        ];

        for (value, category) in tests {
            let p = Parser::from(value);
            assert_eq!(category, p.tags[0].category);
        }
    }

    /// Regression: a text format wrote a value from the request as it
    /// came. A quote in it ended the field the format had quoted, and the
    /// rest of the value read as fields of the line.
    #[tokio::test]
    async fn test_text_format_escapes_request_values() {
        let p: Parser =
            r#"{method} "{uri}" {status} "{referer}" "{user_agent}" "{>x-tab}" {~id}"#
                .into();
        let headers = [
            r#"User-Agent: evil" 200 "-" "curl"#,
            r"Referer: https://a.test/back\slash",
            "X-Tab: a\tb",
            "Cookie: id=plain",
        ]
        .join("\r\n");
        let input_header = format!("GET /a?b=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let ctx = Ctx {
            state: RequestState {
                status: Some(http::StatusCode::NOT_FOUND),
                ..Default::default()
            },
            ..Default::default()
        };
        let log = p.format(&session, &ctx);
        assert_eq!(
            r#"GET "/a?b=1" 404 "https://a.test/back\\slash" "evil\" 200 \"-\" \"curl" "a\x09b" plain"#,
            std::string::String::from_utf8_lossy(&log)
        );
    }

    #[tokio::test]
    async fn test_logger() {
        let p: Parser =
            "{host} {method} {path} {proto} {query} {remote} {client_ip} \
{scheme} {uri} {referer} {user_agent} {size} \
{size_human} {status} {payload_size} {payload_size_human} \
{~deviceId} {>accept} {:upstream_reused} {:upstream_addr} \
{:processing} {:upstream_connect_time_human} {:location} \
{:connection_time_human} {:tls_version} {request_id}"
                .into();
        let headers = [
            "Host: github.com",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
        ]
        .join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();

        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(Method::GET, session.req_header().method);

        let ctx = Ctx {
            conn: ConnectionInfo {
                remote_addr: Some("10.1.1.1".to_string()),
                client_ip: Some("1.1.1.1".to_string()),
                tls_version: Some("1.2".into()),
                ..Default::default()
            },
            upstream: UpstreamInfo {
                reused: true,
                address: "192.186.1.1:6188".to_string(),
                location: "test".to_string().into(),
                ..Default::default()
            },
            timing: Timing {
                connection_duration: 300,
                upstream_connect: Some(100),
                ..Default::default()
            },
            state: RequestState {
                request_id: Some("nanoid".to_string()),
                processing_count: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let log = p.format(&session, &ctx);
        assert_eq!(
            "github.com GET /vicanso/pingap HTTP/1.1 size=1 10.1.1.1 1.1.1.1 https /vicanso/pingap?size=1 - pingap/0.1.1 0 0B - 0 0B abc application/json true 192.186.1.1:6188 1 100ms test 300ms 1.2 nanoid",
            log
        );

        // a missing cookie, header or response header is `-`
        let p: Parser = "{~nope} {>x-nope} {<x-nope}".into();
        assert_eq!("- - -", p.format(&session, &ctx));

        let p: Parser = "{when_utc_iso}".into();
        let log = p.format(&session, &ctx);
        assert_eq!(true, log.len() > 20);

        let p: Parser = "{when}".into();
        let log = p.format(&session, &ctx);
        assert_eq!(true, log.len() > 20);

        let p: Parser = "{when_unix}".into();
        let log = p.format(&session, &ctx);
        assert_eq!(true, log.len() == 13);
    }

    async fn json_session(extra_headers: &[&str]) -> Session {
        let mut headers =
            vec!["Host: github.com", r#"User-Agent: say "hi" \ bye"#];
        headers.extend_from_slice(extra_headers);
        let input_header =
            format!("GET /a?b=1 HTTP/1.1\r\n{}\r\n\r\n", headers.join("\r\n"));
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    /// Placeholders inside a string are escaped into it; outside one they
    /// become typed values, and a missing value is `""` or `null`.
    #[tokio::test]
    async fn test_json_format() {
        let session = json_session(&[]).await;
        let ctx = Ctx {
            conn: ConnectionInfo {
                client_ip: Some("1.1.1.1".to_string()),
                ..Default::default()
            },
            upstream: UpstreamInfo {
                reused: true,
                location: "404".to_string().into(),
                ..Default::default()
            },
            state: RequestState {
                status: Some(http::StatusCode::OK),
                ..Default::default()
            },
            ..Default::default()
        };
        let p: Parser =
            r#"{ "ua": "agent: {user_agent}", "ua_value": {user_agent},
"ip": {client_ip}, "status": {status}, "size": {size},
"referer": "{referer}", "referer_value": {referer},
"reused": {:upstream_reused}, "upstream_status": {:upstream_status},
"connect": {:upstream_connect_time}, "location": {:location},
"request": "{method} {uri}", "quote\"{status}": 1 }"#
                .into();
        assert_eq!(true, p.json);
        let log = p.format(&session, &ctx);
        let value: serde_json::Value = serde_json::from_slice(&log)
            .unwrap_or_else(|e| {
                panic!("{e}: {}", String::from_utf8_lossy(&log))
            });
        assert_eq!(
            serde_json::json!({
                "ua": r#"agent: say "hi" \ bye"#,
                "ua_value": r#"say "hi" \ bye"#,
                "ip": "1.1.1.1",
                "status": 200,
                "size": 0,
                "referer": "",
                "referer_value": null,
                "reused": true,
                // printed as `-` when there was no upstream response
                "upstream_status": null,
                "connect": null,
                // a string field stays a string even when it looks numeric
                "location": "404",
                "request": "GET /a?b=1",
                "quote\"200": 1,
            }),
            value
        );

        // a missing status as a value is null, not `-`
        let ctx = Ctx::default();
        let p: Parser = r#"{"status":{status}}"#.into();
        assert_eq!(r#"{"status":null}"#, p.format(&session, &ctx));
    }

    /// The `json` preset is one valid object per line, and works as the
    /// format of a destination.
    #[tokio::test]
    async fn test_json_preset() {
        let session = json_session(&["Referer: https://a.com/\u{e9}"]).await;
        let ctx = Ctx::default();
        let p: Parser = "json".into();
        let log = p.format(&session, &ctx);
        let value: serde_json::Value = serde_json::from_slice(&log).unwrap();
        assert_eq!("GET", value["method"]);
        assert_eq!("/a?b=1", value["uri"]);
        assert_eq!("https://a.com/\u{e9}", value["referer"]);
        assert_eq!(serde_json::Value::Null, value["request_id"]);
        assert_eq!(true, value["latency"].is_u64());
        assert_eq!(true, value["when"].is_string());

        let (access, path) =
            parse_access_log_directive(Some(&"stdout json".to_string()));
        assert_eq!(Some("json".to_string()), access);
        assert_eq!(Some("stdout".to_string()), path);
    }

    #[test]
    fn test_escape_json() {
        // Only the bytes from `start` on are escaped.
        let escape = |value: &[u8]| {
            let mut buf = BytesMut::from(&b"x"[..]);
            buf.extend_from_slice(value);
            super::escape_json(&mut buf, 1);
            String::from_utf8(buf.to_vec()).unwrap()
        };
        assert_eq!("xplain é", escape("plain é".as_bytes()));
        assert_eq!(r#"xa\"b\\c\n\t\u0001"#, escape(b"a\"b\\c\n\t\x01"));
        // Invalid UTF-8 cannot go into JSON as it is: one U+FFFD per bad
        // sequence, as `String::from_utf8_lossy` does.
        assert_eq!("xa\\ufffd\\ufffdb", escape(b"a\xff\xfeb"));
        // valid text after a bad byte is kept
        assert_eq!("x\\ufffdé", escape(b"\xff\xc3\xa9"));
    }

    #[test]
    fn test_is_json_format() {
        assert_eq!(true, super::is_json_format(r#"{"a":{status}}"#));
        assert_eq!(true, super::is_json_format(r#"  { "a": 1 }"#));
        assert_eq!(false, super::is_json_format("{status} {method}"));
        assert_eq!(false, super::is_json_format("combined"));
        assert_eq!(false, Parser::from("tiny").json);
        assert_eq!(true, Parser::from("json").json);
    }

    /// The tokenizer: digits in names, literal braces, nested and
    /// unterminated braces, unknown tags dropped.
    #[test]
    fn test_parse_tags() {
        let render = |value: &str| {
            parse_tags(value)
                .iter()
                .map(|tag| match &tag.category {
                    TagCategory::Fill => {
                        format!("fill({})", tag.data.as_deref().unwrap_or(""))
                    },
                    TagCategory::RequestHeader => {
                        format!("header({})", tag.data.as_deref().unwrap_or(""))
                    },
                    category => format!("{category:?}"),
                })
                .collect::<Vec<String>>()
                .join(" ")
        };
        assert_eq!(
            "Remote fill( \") Method fill( ) Uri fill(\")",
            render(r#"{remote} "{method} {uri}""#)
        );
        // digits are part of a name: a header such as X-B3-TraceId
        assert_eq!("header(X-B3-TraceId)", render("{>X-B3-TraceId}"));
        // a brace that opens no placeholder is text
        assert_eq!("fill({ ) Status fill( })", render("{ {status} }"));
        assert_eq!("fill({) Status", render("{{status}"));
        assert_eq!("fill({status)", render("{status"));
        assert_eq!("fill({a b}) Host", render("{a b}{host}"));
        // a placeholder that names no tag is dropped
        assert_eq!("Host fill( ) Method", render("{host} {nope}{method}"));
        assert_eq!("", render(""));
    }

    /// The allocation-free timestamp matches chrono's rfc3339 output.
    #[test]
    fn test_put_rfc3339_millis() {
        let utc = Utc.with_ymd_and_hms(2024, 1, 2, 3, 4, 5).unwrap()
            + chrono::Duration::milliseconds(6);
        let east = utc.with_timezone(&FixedOffset::east_opt(8 * 3600).unwrap());
        let west =
            utc.with_timezone(&FixedOffset::west_opt(5 * 3600 + 1800).unwrap());
        for (time, use_z) in [(utc, true), (utc, false)] {
            let mut buf = BytesMut::new();
            put_rfc3339_millis(&mut buf, &time, use_z);
            assert_eq!(
                time.to_rfc3339_opts(SecondsFormat::Millis, use_z),
                std::str::from_utf8(&buf).unwrap()
            );
        }
        for time in [east, west] {
            let mut buf = BytesMut::new();
            put_rfc3339_millis(&mut buf, &time, false);
            assert_eq!(
                time.to_rfc3339_opts(SecondsFormat::Millis, false),
                std::str::from_utf8(&buf).unwrap()
            );
        }
        let mut buf = BytesMut::new();
        put_rfc3339_millis(&mut buf, &east, false);
        assert_eq!(
            "2024-01-02T11:04:05.006+08:00",
            std::str::from_utf8(&buf).unwrap()
        );
    }

    #[test]
    fn test_get_resp_header_value() {
        let mut header =
            ResponseHeader::build_no_case(200, Some(1024)).unwrap();
        header
            .append_header("Content-Type", "application/json")
            .unwrap();
        let value = get_resp_header_value(&header, "content-type");
        assert_eq!(
            "application/json",
            std::str::from_utf8(value.unwrap()).unwrap()
        );

        let value = get_resp_header_value(&header, "content-type-not-exists");
        assert_eq!(None, value);
    }
}
