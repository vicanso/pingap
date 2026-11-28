// Copyright 2024-2026 Tree xie.
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

//! Configurable Layer 4 stream access log formatter and filter.

use super::{AccessLogFilter, Error, check_access_log_target};
use bytes::{BufMut, BytesMut};
use pingap_core::{
    HOST_NAME_TAG, ProxyProtocolTlvs, TlsClientCert, format_duration,
    get_hostname, get_identity,
};
use std::cell::Cell;
use std::time::Duration;
use time::{OffsetDateTime, UtcOffset};

type Result<T> = std::result::Result<T, Error>;

const COMBINED: &str = r#"{client_ip} [{when}] {stream} "{sni}" -> {upstream} ({backend}) {result} rx={bytes_rx} tx={bytes_tx} {latency}"#;
const COMMON: &str = r#"{client_ip} [{when}] {stream} {upstream} {result} {bytes_rx} {bytes_tx} {duration_ms}"#;
const SHORT: &str = r#"{client_ip} {stream} {upstream} {result} {bytes_rx}/{bytes_tx} {duration_ms}ms"#;
const TINY: &str = r#"{stream} {upstream} {result} {duration_ms}ms"#;

const EMPTY_FIELD: &[u8] = b"-";
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const RFC3339_CACHE_CAP: usize = 40;

/// Per-connection metadata passed to [`StreamLogParser`] and [`StreamLogger`].
#[derive(Debug, Clone, Copy, Default)]
pub struct StreamLogContext<'a> {
    pub stream: &'a str,
    pub client_addr: &'a str,
    pub client_ip: &'a str,
    pub sni: Option<&'a str>,
    pub upstream: &'a str,
    pub backend: Option<&'a str>,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub duration: Duration,
    pub connect_time_ms: Option<u64>,
    pub result: &'a str,
    pub tls_version: Option<&'a str>,
    pub tls_cipher: Option<&'a str>,
    pub tls_client_cert: Option<&'a TlsClientCert>,
    pub proxy_protocol_tlvs: Option<&'a ProxyProtocolTlvs>,
}

#[derive(Debug, Clone, PartialEq)]
enum StreamTagCategory {
    Fill,
    Stream,
    ClientAddr,
    ClientIp,
    Sni,
    Upstream,
    Backend,
    BytesRx,
    BytesTx,
    Size,
    DurationMs,
    Latency,
    ConnectTime,
    Result,
    TlsVersion,
    TlsCipher,
    TlsClientSubject,
    TlsClientFingerprint,
    TlsClientSerial,
    TlsClientVerified,
    PpAlpn,
    PpAuthority,
    PpUniqueId,
    PpNetns,
    PpTlsVersion,
    PpTlsCn,
    PpTlsCipher,
    PpAwsVpceId,
    When,
    WhenUtcIso,
    WhenUnix,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
enum JsonSlot {
    #[default]
    Literal,
    InString,
    Value,
}

#[derive(Debug, Clone)]
struct StreamTag {
    category: StreamTagCategory,
    data: Option<String>,
    json: JsonSlot,
}

impl StreamTag {
    fn simple(category: StreamTagCategory) -> Self {
        Self {
            category,
            data: None,
            json: JsonSlot::Literal,
        }
    }

    fn fill(text: &str) -> Self {
        Self {
            category: StreamTagCategory::Fill,
            data: Some(text.to_string()),
            json: JsonSlot::Literal,
        }
    }
}

#[derive(Clone, Copy)]
enum JsonKind {
    String,
    Number,
    Bool,
}

/// Formatter for Layer 4 stream access logs supporting presets (`combined`,
/// `common`, `short`, `tiny`, `json`), custom `{...}` templates, and JSON.
#[derive(Debug, Default, Clone)]
pub struct StreamLogParser {
    needs_timestamp: bool,
    capacity: usize,
    tags: Vec<StreamTag>,
    json: bool,
    preset_json: bool,
}

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

#[inline]
fn is_tag_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(b, b'_' | b'-' | b'<' | b'>' | b'~' | b':' | b'$')
}

fn format_extra_tag(key: &str) -> Option<StreamTag> {
    let key = key.strip_prefix('{')?.strip_suffix('}')?;
    let (prefix, value) = key.split_at_checked(1)?;
    if prefix != "$" {
        return None;
    }
    if key.as_bytes() == HOST_NAME_TAG {
        Some(StreamTag::fill(get_hostname()))
    } else if value == "name" {
        Some(StreamTag::fill(&get_identity().name))
    } else if let Some(label) = value.strip_prefix("label:") {
        Some(StreamTag::fill(
            get_identity().label(label).unwrap_or_default(),
        ))
    } else {
        Some(StreamTag::fill(&std::env::var(value).unwrap_or_default()))
    }
}

fn parse_tag(key: &str) -> Option<StreamTag> {
    let category = match key {
        "{stream}" => StreamTagCategory::Stream,
        "{client_addr}" | "{remote_addr}" => StreamTagCategory::ClientAddr,
        "{client_ip}" => StreamTagCategory::ClientIp,
        "{sni}" => StreamTagCategory::Sni,
        "{upstream}" => StreamTagCategory::Upstream,
        "{backend}" | "{upstream_addr}" => StreamTagCategory::Backend,
        "{bytes_rx}" => StreamTagCategory::BytesRx,
        "{bytes_tx}" => StreamTagCategory::BytesTx,
        "{size}" => StreamTagCategory::Size,
        "{duration_ms}" => StreamTagCategory::DurationMs,
        "{latency}" => StreamTagCategory::Latency,
        "{connect_time}" => StreamTagCategory::ConnectTime,
        "{result}" | "{status}" => StreamTagCategory::Result,
        "{tls_version}" => StreamTagCategory::TlsVersion,
        "{tls_cipher}" => StreamTagCategory::TlsCipher,
        "{tls_client_subject}" => StreamTagCategory::TlsClientSubject,
        "{tls_client_fingerprint}" => StreamTagCategory::TlsClientFingerprint,
        "{tls_client_serial}" => StreamTagCategory::TlsClientSerial,
        "{tls_client_verified}" => StreamTagCategory::TlsClientVerified,
        "{pp_alpn}" => StreamTagCategory::PpAlpn,
        "{pp_authority}" => StreamTagCategory::PpAuthority,
        "{pp_unique_id}" => StreamTagCategory::PpUniqueId,
        "{pp_netns}" => StreamTagCategory::PpNetns,
        "{pp_tls_version}" => StreamTagCategory::PpTlsVersion,
        "{pp_tls_cn}" => StreamTagCategory::PpTlsCn,
        "{pp_tls_cipher}" => StreamTagCategory::PpTlsCipher,
        "{pp_aws_vpce_id}" => StreamTagCategory::PpAwsVpceId,
        "{when}" => StreamTagCategory::When,
        "{when_utc_iso}" => StreamTagCategory::WhenUtcIso,
        "{when_unix}" => StreamTagCategory::WhenUnix,
        _ => return format_extra_tag(key),
    };
    Some(StreamTag::simple(category))
}

fn parse_tags(value: &str) -> Vec<StreamTag> {
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
            tags.push(StreamTag::fill(text));
        }
        if let Some(mut tag) = parse_tag(&value[start..end]) {
            tag.json = json.slot();
            tags.push(tag);
        }
        fill_start = end;
        pos = end;
    }
    if fill_start < value.len() {
        tags.push(StreamTag::fill(&value[fill_start..]));
    }
    tags
}

fn is_json_format(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed
        .strip_prefix('{')
        .is_some_and(|rest| rest.trim_start().starts_with('"'))
        && trimmed.ends_with('}')
}

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

fn put_rfc3339_millis_pos(
    buf: &mut BytesMut,
    time: &OffsetDateTime,
    use_z: bool,
) -> usize {
    let year = time.year();
    if (0..=9999).contains(&year) {
        put_digits(buf, year as u32, 4);
    } else {
        buf.put_slice(itoa::Buffer::new().format(year).as_bytes());
    }
    buf.put_u8(b'-');
    put_digits(buf, u32::from(u8::from(time.month())), 2);
    buf.put_u8(b'-');
    put_digits(buf, u32::from(time.day()), 2);
    buf.put_u8(b'T');
    put_digits(buf, u32::from(time.hour()), 2);
    buf.put_u8(b':');
    put_digits(buf, u32::from(time.minute()), 2);
    buf.put_u8(b':');
    put_digits(buf, u32::from(time.second()), 2);
    buf.put_u8(b'.');
    let ms_pos = buf.len();
    put_digits(buf, u32::from(time.millisecond()), 3);
    let offset = time.offset().whole_seconds();
    if offset == 0 && use_z {
        buf.put_u8(b'Z');
        return ms_pos;
    }
    buf.put_u8(if offset < 0 { b'-' } else { b'+' });
    let offset = offset.unsigned_abs();
    put_digits(buf, offset / 3600, 2);
    buf.put_u8(b':');
    put_digits(buf, (offset % 3600) / 60, 2);
    ms_pos
}

#[derive(Clone, Copy)]
struct CachedRfc3339 {
    sec: i64,
    millis: i64,
    len: u8,
    ms_pos: u8,
    bytes: [u8; RFC3339_CACHE_CAP],
}

impl CachedRfc3339 {
    const EMPTY: Self = Self {
        sec: i64::MIN,
        millis: i64::MIN,
        len: 0,
        ms_pos: 0,
        bytes: [0; RFC3339_CACHE_CAP],
    };
}

thread_local! {
    static STREAM_LOCAL_RFC3339_CACHE: Cell<CachedRfc3339> =
        const { Cell::new(CachedRfc3339::EMPTY) };
    static STREAM_UTC_RFC3339_CACHE: Cell<CachedRfc3339> =
        const { Cell::new(CachedRfc3339::EMPTY) };
}

#[inline]
fn put_cached_rfc3339(
    buf: &mut BytesMut,
    now_ms: i64,
    utc_mode: bool,
    slot: &Cell<CachedRfc3339>,
) -> bool {
    let mut cached = slot.get();
    if cached.len > 0 && cached.millis == now_ms {
        buf.put_slice(&cached.bytes[..usize::from(cached.len)]);
        return true;
    }
    let sec = now_ms.div_euclid(1_000);
    if cached.len > 0 && cached.sec == sec {
        let subsec_ms = now_ms.rem_euclid(1_000) as u32;
        let pos = usize::from(cached.ms_pos);
        cached.bytes[pos] = b'0' + (subsec_ms / 100) as u8;
        cached.bytes[pos + 1] = b'0' + ((subsec_ms / 10) % 10) as u8;
        cached.bytes[pos + 2] = b'0' + (subsec_ms % 10) as u8;
        cached.millis = now_ms;
        slot.set(cached);
        buf.put_slice(&cached.bytes[..usize::from(cached.len)]);
        return true;
    }
    let Ok(utc) = OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(now_ms) * 1_000_000,
    ) else {
        return false;
    };
    let start = buf.len();
    let ms_pos_abs = if utc_mode {
        put_rfc3339_millis_pos(buf, &utc, true)
    } else {
        let offset = UtcOffset::local_offset_at(utc).unwrap_or(UtcOffset::UTC);
        put_rfc3339_millis_pos(buf, &utc.to_offset(offset), false)
    };
    let formatted = &buf[start..];
    if formatted.len() <= RFC3339_CACHE_CAP {
        let mut next = CachedRfc3339::EMPTY;
        next.sec = sec;
        next.millis = now_ms;
        next.len = formatted.len() as u8;
        next.ms_pos = (ms_pos_abs - start) as u8;
        next.bytes[..formatted.len()].copy_from_slice(formatted);
        slot.set(next);
    }
    true
}

const fn needs_escape(b: u8) -> bool {
    b < 0x20 || b == b'"' || b == b'\\'
}

fn escape_json(buf: &mut BytesMut, start: usize) {
    let value = &buf[start..];
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

const fn needs_text_escape(b: u8) -> bool {
    (b < 0x20) | (b == b'"') | (b == b'\\') | (b == 0x7f)
}

#[inline(always)]
fn escape_text(buf: &mut BytesMut, start: usize) {
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

fn json_kind(category: &StreamTagCategory) -> JsonKind {
    match category {
        StreamTagCategory::BytesRx
        | StreamTagCategory::BytesTx
        | StreamTagCategory::Size
        | StreamTagCategory::DurationMs
        | StreamTagCategory::ConnectTime
        | StreamTagCategory::WhenUnix => JsonKind::Number,
        StreamTagCategory::TlsClientVerified => JsonKind::Bool,
        _ => JsonKind::String,
    }
}

const fn is_outside_text(category: &StreamTagCategory) -> bool {
    matches!(
        category,
        StreamTagCategory::ClientIp
            | StreamTagCategory::Sni
            | StreamTagCategory::TlsClientSubject
            | StreamTagCategory::PpAlpn
            | StreamTagCategory::PpAuthority
            | StreamTagCategory::PpUniqueId
            | StreamTagCategory::PpNetns
            | StreamTagCategory::PpTlsVersion
            | StreamTagCategory::PpTlsCn
            | StreamTagCategory::PpTlsCipher
            | StreamTagCategory::PpAwsVpceId
    )
}

#[inline]
fn put_value(buf: &mut BytesMut, value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    buf.put_slice(value);
    true
}

#[inline]
fn put_opt_str(buf: &mut BytesMut, value: Option<&str>) -> bool {
    put_value(buf, value.unwrap_or_default().as_bytes())
}

#[inline]
fn put_u64(buf: &mut BytesMut, value: u64) -> bool {
    buf.put_slice(itoa::Buffer::new().format(value).as_bytes());
    true
}

fn put_pp_field(
    buf: &mut BytesMut,
    tlvs: Option<&ProxyProtocolTlvs>,
    category: &StreamTagCategory,
) -> bool {
    let val = tlvs.and_then(|t| match category {
        StreamTagCategory::PpAlpn => t.alpn.as_deref(),
        StreamTagCategory::PpAuthority => t.authority.as_deref(),
        StreamTagCategory::PpUniqueId => t.unique_id.as_deref(),
        StreamTagCategory::PpNetns => t.netns.as_deref(),
        StreamTagCategory::PpTlsVersion => t.tls_version.as_deref(),
        StreamTagCategory::PpTlsCn => t.tls_cn.as_deref(),
        StreamTagCategory::PpTlsCipher => t.tls_cipher.as_deref(),
        StreamTagCategory::PpAwsVpceId => t.aws_vpce_id.as_deref(),
        _ => None,
    });
    put_opt_str(buf, val)
}

fn put_tls_field(
    buf: &mut BytesMut,
    ctx: &StreamLogContext<'_>,
    category: &StreamTagCategory,
) -> bool {
    match category {
        StreamTagCategory::TlsVersion => put_opt_str(buf, ctx.tls_version),
        StreamTagCategory::TlsCipher => put_opt_str(buf, ctx.tls_cipher),
        StreamTagCategory::TlsClientSubject => {
            put_opt_str(buf, ctx.tls_client_cert.map(|c| c.subject.as_str()))
        },
        StreamTagCategory::TlsClientFingerprint => put_opt_str(
            buf,
            ctx.tls_client_cert.map(|c| c.fingerprint.as_str()),
        ),
        StreamTagCategory::TlsClientSerial => {
            put_opt_str(buf, ctx.tls_client_cert.map(|c| c.serial.as_str()))
        },
        StreamTagCategory::TlsClientVerified => {
            buf.put_slice(if ctx.tls_client_cert.is_some() {
                b"true"
            } else {
                b"false"
            });
            true
        },
        _ => false,
    }
}

fn put_tag(
    buf: &mut BytesMut,
    tag: &StreamTag,
    ctx: &StreamLogContext<'_>,
    now_ms: Option<i64>,
) -> bool {
    match &tag.category {
        StreamTagCategory::Fill => put_opt_str(buf, tag.data.as_deref()),
        StreamTagCategory::Stream => put_value(buf, ctx.stream.as_bytes()),
        StreamTagCategory::ClientAddr => {
            put_value(buf, ctx.client_addr.as_bytes())
        },
        StreamTagCategory::ClientIp => put_value(buf, ctx.client_ip.as_bytes()),
        StreamTagCategory::Sni => put_opt_str(buf, ctx.sni),
        StreamTagCategory::Upstream => put_value(buf, ctx.upstream.as_bytes()),
        StreamTagCategory::Backend => put_opt_str(buf, ctx.backend),
        StreamTagCategory::BytesRx => put_u64(buf, ctx.bytes_rx),
        StreamTagCategory::BytesTx => put_u64(buf, ctx.bytes_tx),
        StreamTagCategory::Size => {
            put_u64(buf, ctx.bytes_rx.saturating_add(ctx.bytes_tx))
        },
        StreamTagCategory::DurationMs => {
            let ms =
                u64::try_from(ctx.duration.as_millis()).unwrap_or(u64::MAX);
            put_u64(buf, ms)
        },
        StreamTagCategory::Latency => {
            let ms =
                u64::try_from(ctx.duration.as_millis()).unwrap_or(u64::MAX);
            format_duration(buf, ms);
            true
        },
        StreamTagCategory::ConnectTime => {
            ctx.connect_time_ms.is_some_and(|ms| put_u64(buf, ms))
        },
        StreamTagCategory::Result => put_value(buf, ctx.result.as_bytes()),
        StreamTagCategory::TlsVersion
        | StreamTagCategory::TlsCipher
        | StreamTagCategory::TlsClientSubject
        | StreamTagCategory::TlsClientFingerprint
        | StreamTagCategory::TlsClientSerial
        | StreamTagCategory::TlsClientVerified => {
            put_tls_field(buf, ctx, &tag.category)
        },
        StreamTagCategory::PpAlpn
        | StreamTagCategory::PpAuthority
        | StreamTagCategory::PpUniqueId
        | StreamTagCategory::PpNetns
        | StreamTagCategory::PpTlsVersion
        | StreamTagCategory::PpTlsCn
        | StreamTagCategory::PpTlsCipher
        | StreamTagCategory::PpAwsVpceId => {
            put_pp_field(buf, ctx.proxy_protocol_tlvs, &tag.category)
        },
        StreamTagCategory::When => now_ms.is_some_and(|ms| {
            STREAM_LOCAL_RFC3339_CACHE
                .with(|slot| put_cached_rfc3339(buf, ms, false, slot))
        }),
        StreamTagCategory::WhenUtcIso => now_ms.is_some_and(|ms| {
            STREAM_UTC_RFC3339_CACHE
                .with(|slot| put_cached_rfc3339(buf, ms, true, slot))
        }),
        StreamTagCategory::WhenUnix => now_ms.is_some_and(|ms| {
            buf.put_slice(itoa::Buffer::new().format(ms).as_bytes());
            true
        }),
    }
}

fn put_json_tag(
    buf: &mut BytesMut,
    tag: &StreamTag,
    ctx: &StreamLogContext<'_>,
    now_ms: Option<i64>,
) {
    let start = buf.len();
    if tag.json != JsonSlot::Value {
        if put_tag(buf, tag, ctx, now_ms) {
            escape_json(buf, start);
        }
        return;
    }
    match json_kind(&tag.category) {
        JsonKind::String => {
            buf.put_u8(b'"');
            if put_tag(buf, tag, ctx, now_ms) {
                escape_json(buf, start + 1);
                buf.put_u8(b'"');
            } else {
                buf.truncate(start);
                buf.put_slice(b"null");
            }
        },
        kind => {
            let valid = put_tag(buf, tag, ctx, now_ms)
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

fn push_json_str_literal(buf: &mut BytesMut, value: &str) {
    buf.put_u8(b'"');
    let start = buf.len();
    buf.put_slice(value.as_bytes());
    escape_json(buf, start);
    buf.put_u8(b'"');
}

fn push_json_kv_str(buf: &mut BytesMut, key: &str, value: &str) {
    buf.put_u8(b',');
    push_json_str_literal(buf, key);
    buf.put_u8(b':');
    push_json_str_literal(buf, value);
}

fn push_json_kv_opt_str(buf: &mut BytesMut, key: &str, value: Option<&str>) {
    buf.put_u8(b',');
    push_json_str_literal(buf, key);
    buf.put_u8(b':');
    match value.filter(|v| !v.is_empty()) {
        Some(val) => push_json_str_literal(buf, val),
        None => buf.put_slice(b"null"),
    }
}

fn push_json_kv_u64(buf: &mut BytesMut, key: &str, value: u64) {
    buf.put_u8(b',');
    push_json_str_literal(buf, key);
    buf.put_u8(b':');
    buf.put_slice(itoa::Buffer::new().format(value).as_bytes());
}

fn push_json_opt_str_field(buf: &mut BytesMut, key: &str, value: Option<&str>) {
    if let Some(val) = value.filter(|v| !v.is_empty()) {
        push_json_kv_str(buf, key, val);
    }
}

fn push_json_identity(buf: &mut BytesMut) {
    let identity = get_identity();
    if !identity.name.is_empty() {
        push_json_kv_str(buf, "name", &identity.name);
    }
    if !identity.labels.is_empty() {
        buf.put_slice(b",\"labels\":{");
        for (idx, (k, v)) in identity.labels.iter().enumerate() {
            if idx > 0 {
                buf.put_u8(b',');
            }
            push_json_str_literal(buf, k);
            buf.put_u8(b':');
            push_json_str_literal(buf, v);
        }
        buf.put_u8(b'}');
    }
}

fn format_json_preset(ctx: &StreamLogContext<'_>, now_ms: i64) -> BytesMut {
    let mut buf = BytesMut::with_capacity(384);
    buf.put_slice(b"{\"when\":\"");
    STREAM_LOCAL_RFC3339_CACHE
        .with(|slot| put_cached_rfc3339(&mut buf, now_ms, false, slot));
    buf.put_u8(b'"');

    push_json_kv_str(&mut buf, "stream", ctx.stream);
    push_json_kv_str(&mut buf, "client_ip", ctx.client_ip);
    push_json_kv_str(&mut buf, "client_addr", ctx.client_addr);
    push_json_kv_opt_str(&mut buf, "sni", ctx.sni);
    push_json_kv_str(&mut buf, "upstream", ctx.upstream);
    push_json_kv_opt_str(&mut buf, "backend", ctx.backend);
    push_json_kv_str(&mut buf, "result", ctx.result);
    push_json_kv_u64(&mut buf, "bytes_rx", ctx.bytes_rx);
    push_json_kv_u64(&mut buf, "bytes_tx", ctx.bytes_tx);
    let duration_ms =
        u64::try_from(ctx.duration.as_millis()).unwrap_or(u64::MAX);
    push_json_kv_u64(&mut buf, "duration_ms", duration_ms);

    if let Some(connect_ms) = ctx.connect_time_ms {
        push_json_kv_u64(&mut buf, "connect_time_ms", connect_ms);
    }
    push_json_opt_str_field(&mut buf, "tls_version", ctx.tls_version);
    push_json_opt_str_field(&mut buf, "tls_cipher", ctx.tls_cipher);
    if let Some(cert) = ctx.tls_client_cert {
        push_json_opt_str_field(
            &mut buf,
            "tls_client_subject",
            Some(cert.subject.as_str()),
        );
        push_json_opt_str_field(
            &mut buf,
            "tls_client_serial",
            Some(cert.serial.as_str()),
        );
    }
    if let Some(pp) = ctx.proxy_protocol_tlvs {
        push_json_opt_str_field(&mut buf, "pp_alpn", pp.alpn.as_deref());
        push_json_opt_str_field(
            &mut buf,
            "pp_authority",
            pp.authority.as_deref(),
        );
        push_json_opt_str_field(
            &mut buf,
            "pp_unique_id",
            pp.unique_id.as_deref(),
        );
        push_json_opt_str_field(&mut buf, "pp_netns", pp.netns.as_deref());
        push_json_opt_str_field(
            &mut buf,
            "pp_aws_vpce_id",
            pp.aws_vpce_id.as_deref(),
        );
    }
    push_json_identity(&mut buf);
    buf.put_u8(b'}');
    buf
}

fn current_now_ms() -> i64 {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

impl From<&str> for StreamLogParser {
    fn from(value: &str) -> Self {
        if value == "json" {
            return Self {
                needs_timestamp: true,
                capacity: 384,
                tags: Vec::new(),
                json: true,
                preset_json: true,
            };
        }
        let value = match value {
            "combined" => COMBINED,
            "common" => COMMON,
            "short" => SHORT,
            "tiny" => TINY,
            _ => value,
        };
        let json = is_json_format(value);
        let mut tags = parse_tags(value);
        if json {
            for tag in tags.iter_mut().filter(|tag| {
                tag.category == StreamTagCategory::Fill
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
                StreamTagCategory::When
                    | StreamTagCategory::WhenUtcIso
                    | StreamTagCategory::WhenUnix
            )
        });
        let capacity = 128
            + tags
                .iter()
                .map(|t| match t.category {
                    StreamTagCategory::Fill => {
                        t.data.as_ref().map_or(0, String::len)
                    },
                    _ => 16,
                })
                .sum::<usize>();
        Self {
            needs_timestamp,
            capacity,
            tags,
            json,
            preset_json: false,
        }
    }
}

impl StreamLogParser {
    /// Creates a stream log parser from a preset name or template string.
    pub fn new(format: &str) -> Self {
        Self::from(format)
    }

    /// Formats a stream connection log line without a trailing newline.
    pub fn format(&self, ctx: &StreamLogContext<'_>) -> BytesMut {
        let now_ms = self.needs_timestamp.then(current_now_ms);
        if self.preset_json {
            return format_json_preset(
                ctx,
                now_ms.unwrap_or_else(current_now_ms),
            );
        }
        let mut buf = BytesMut::with_capacity(self.capacity);
        for tag in &self.tags {
            if let StreamTagCategory::Fill = tag.category {
                if let Some(data) = &tag.data {
                    buf.put_slice(data.as_bytes());
                }
            } else if self.json {
                put_json_tag(&mut buf, tag, ctx, now_ms);
            } else {
                let start = buf.len();
                if put_tag(&mut buf, tag, ctx, now_ms) {
                    if is_outside_text(&tag.category) {
                        escape_text(&mut buf, start);
                    }
                } else {
                    buf.put_slice(EMPTY_FIELD);
                }
            }
        }
        buf
    }
}

fn result_status_code(result: &str) -> u16 {
    if result == "ok" {
        return 200;
    }
    if result.contains("denied")
        || result.contains("acl")
        || result.contains("reject")
        || result == "forbidden"
    {
        return 403;
    }
    500
}

/// Configurable Layer 4 stream access logger combining [`StreamLogParser`]
/// and an optional [`AccessLogFilter`].
#[derive(Debug)]
pub struct StreamLogger {
    parser: StreamLogParser,
    filter: Option<AccessLogFilter>,
}

impl StreamLogger {
    /// Parses `format` (preset or `{...}` template) and optional target query
    /// filter (`skip`, `min_status`, `min_latency`, `sample`).
    pub fn try_new(format: &str, target: Option<&str>) -> Result<Self> {
        let filter = match target {
            Some(target) => {
                check_access_log_target(target).map_err(|e| {
                    Error::Invalid {
                        message: e.to_string(),
                    }
                })?;
                AccessLogFilter::new(target)?
            },
            None => None,
        };
        Ok(Self {
            parser: StreamLogParser::from(format),
            filter,
        })
    }

    /// Returns the underlying [`StreamLogParser`].
    pub fn parser(&self) -> &StreamLogParser {
        &self.parser
    }

    /// Returns the optional [`AccessLogFilter`].
    pub fn filter(&self) -> Option<&AccessLogFilter> {
        self.filter.as_ref()
    }

    /// Checks the filter (if any) and formats a log line without a trailing
    /// newline (`AsyncLoggerTask` appends `\n` automatically).
    pub fn format_line(&self, ctx: &StreamLogContext<'_>) -> Option<BytesMut> {
        if let Some(filter) = &self.filter {
            let target =
                ctx.sni.filter(|s| !s.is_empty()).unwrap_or(ctx.stream);
            let status = result_status_code(ctx.result);
            if !filter.allows(target, status, ctx.duration) {
                return None;
            }
        }
        Some(self.parser.format(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn sample_cert() -> TlsClientCert {
        TlsClientCert {
            subject: "O=Example, CN=client-1".to_string(),
            fingerprint: "deadbeef01".to_string(),
            serial: "7a09".to_string(),
        }
    }

    fn sample_tlvs() -> ProxyProtocolTlvs {
        ProxyProtocolTlvs {
            alpn: Some("h2".to_string()),
            authority: Some("app.example.com".to_string()),
            unique_id: Some("pp-id-1".to_string()),
            netns: Some("edge-ns".to_string()),
            tls_version: Some("TLSv1.3".to_string()),
            tls_cn: Some("pp-client".to_string()),
            tls_cipher: Some("TLS_AES_128_GCM_SHA256".to_string()),
            aws_vpce_id: Some("vpce-12345".to_string()),
            custom: vec![],
        }
    }

    fn full_ctx<'a>(
        cert: &'a TlsClientCert,
        tlvs: &'a ProxyProtocolTlvs,
    ) -> StreamLogContext<'a> {
        StreamLogContext {
            stream: "tls_mux",
            client_addr: "203.0.113.10:51234",
            client_ip: "203.0.113.10",
            sni: Some("api.example.com"),
            upstream: "backend_a",
            backend: Some("10.0.0.5:8443"),
            bytes_rx: 512,
            bytes_tx: 1024,
            duration: Duration::from_millis(45),
            connect_time_ms: Some(7),
            result: "ok",
            tls_version: Some("TLSv1.3"),
            tls_cipher: Some("TLS_AES_256_GCM_SHA384"),
            tls_client_cert: Some(cert),
            proxy_protocol_tlvs: Some(tlvs),
        }
    }

    #[test]
    fn test_stream_log_text_presets() {
        let cert = sample_cert();
        let tlvs = sample_tlvs();
        let ctx = full_ctx(&cert, &tlvs);

        let tiny = StreamLogParser::from("tiny").format(&ctx);
        assert_eq!("tls_mux backend_a ok 45ms", tiny);

        let short = StreamLogParser::from("short").format(&ctx);
        assert_eq!("203.0.113.10 tls_mux backend_a ok 512/1024 45ms", short);

        let common = String::from_utf8(
            StreamLogParser::from("common").format(&ctx).to_vec(),
        )
        .unwrap();
        assert_eq!(true, common.starts_with("203.0.113.10 ["), "{common}");
        assert_eq!(
            true,
            common.ends_with("] tls_mux backend_a ok 512 1024 45"),
            "{common}"
        );

        let combined = String::from_utf8(
            StreamLogParser::from("combined").format(&ctx).to_vec(),
        )
        .unwrap();
        assert_eq!(
            true,
            combined.ends_with(
                "] tls_mux \"api.example.com\" -> backend_a (10.0.0.5:8443) ok rx=512 tx=1024 45ms"
            ),
            "{combined}"
        );

        // Missing optional fields render `-` in text presets.
        let minimal = StreamLogContext {
            stream: "tcp_plain",
            client_addr: "127.0.0.1:4000",
            client_ip: "127.0.0.1",
            sni: None,
            upstream: "",
            backend: None,
            bytes_rx: 0,
            bytes_tx: 0,
            duration: Duration::from_millis(1200),
            connect_time_ms: None,
            result: "ip_denied",
            tls_version: None,
            tls_cipher: None,
            tls_client_cert: None,
            proxy_protocol_tlvs: None,
        };
        let combined_min = String::from_utf8(
            StreamLogParser::from("combined").format(&minimal).to_vec(),
        )
        .unwrap();
        assert_eq!(
            true,
            combined_min.ends_with(
                "] tcp_plain \"-\" -> - (-) ip_denied rx=0 tx=0 1.2s"
            ),
            "{combined_min}"
        );
    }

    #[test]
    fn test_stream_log_json_preset_full_and_minimal() {
        let cert = sample_cert();
        let tlvs = sample_tlvs();
        let ctx = full_ctx(&cert, &tlvs);

        let parser = StreamLogParser::from("json");
        let raw = parser.format(&ctx);
        assert_eq!(false, raw.ends_with(b"\n"));
        let val: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(true, val["when"].is_string());
        assert_eq!("tls_mux", val["stream"]);
        assert_eq!("203.0.113.10", val["client_ip"]);
        assert_eq!("203.0.113.10:51234", val["client_addr"]);
        assert_eq!("api.example.com", val["sni"]);
        assert_eq!("backend_a", val["upstream"]);
        assert_eq!("10.0.0.5:8443", val["backend"]);
        assert_eq!("ok", val["result"]);
        assert_eq!(512, val["bytes_rx"]);
        assert_eq!(1024, val["bytes_tx"]);
        assert_eq!(45, val["duration_ms"]);
        assert_eq!(7, val["connect_time_ms"]);
        assert_eq!("TLSv1.3", val["tls_version"]);
        assert_eq!("TLS_AES_256_GCM_SHA384", val["tls_cipher"]);
        assert_eq!("O=Example, CN=client-1", val["tls_client_subject"]);
        assert_eq!("7a09", val["tls_client_serial"]);
        assert_eq!("h2", val["pp_alpn"]);
        assert_eq!("app.example.com", val["pp_authority"]);
        assert_eq!("pp-id-1", val["pp_unique_id"]);
        assert_eq!("edge-ns", val["pp_netns"]);
        assert_eq!("vpce-12345", val["pp_aws_vpce_id"]);
        assert_eq!(get_identity().name, val["name"]);
        if !get_identity().labels.is_empty() {
            assert_eq!(true, val["labels"].is_object());
        }

        // Minimal context omits optional TLS/PP/connect_time_ms fields.
        let minimal = StreamLogContext {
            stream: "tcp_plain",
            client_addr: "127.0.0.1:4000",
            client_ip: "127.0.0.1",
            upstream: "echo",
            result: "ok",
            ..Default::default()
        };
        let raw_min = parser.format(&minimal);
        let min_val: serde_json::Value =
            serde_json::from_slice(&raw_min).unwrap();
        let obj = min_val.as_object().unwrap();
        assert_eq!(serde_json::Value::Null, obj["sni"]);
        assert_eq!(serde_json::Value::Null, obj["backend"]);
        for omitted in [
            "connect_time_ms",
            "tls_version",
            "tls_cipher",
            "tls_client_subject",
            "tls_client_serial",
            "pp_alpn",
            "pp_authority",
            "pp_unique_id",
            "pp_netns",
            "pp_aws_vpce_id",
        ] {
            assert_eq!(false, obj.contains_key(omitted), "{omitted}");
        }
    }

    #[test]
    fn test_stream_log_custom_tags_and_escaping() {
        let cert = TlsClientCert {
            subject: r#"CN="evil" \ user"#.to_string(),
            fingerprint: "abcd".to_string(),
            serial: "01".to_string(),
        };
        let tlvs = sample_tlvs();
        let ctx = StreamLogContext {
            stream: "s1",
            client_addr: "1.2.3.4:1000",
            client_ip: "1.2.3.4",
            sni: Some("a\tb.example"),
            upstream: "u1",
            backend: Some("10.0.0.1:80"),
            bytes_rx: 10,
            bytes_tx: 20,
            duration: Duration::from_millis(5),
            connect_time_ms: Some(2),
            result: "ok",
            tls_version: Some("TLSv1.2"),
            tls_cipher: Some("AES"),
            tls_client_cert: Some(&cert),
            proxy_protocol_tlvs: Some(&tlvs),
        };

        // Template starting and ending with `{...}` must NOT be treated as JSON.
        let text_parser = StreamLogParser::from(
            r#"{stream} {remote_addr} "{sni}" {upstream_addr} {size} {connect_time} {status} "{tls_client_subject}" {tls_client_fingerprint} {tls_client_serial} {tls_client_verified} {pp_alpn} {pp_authority} {pp_unique_id} {pp_netns} {pp_tls_version} {pp_tls_cn} {pp_tls_cipher} {pp_aws_vpce_id} {$name}"#,
        );
        assert_eq!(false, text_parser.json);
        let rendered =
            String::from_utf8(text_parser.format(&ctx).to_vec()).unwrap();
        let expected = format!(
            r#"s1 1.2.3.4:1000 "a\x09b.example" 10.0.0.1:80 30 2 ok "CN=\"evil\" \\ user" abcd 01 true h2 app.example.com pp-id-1 edge-ns TLSv1.3 pp-client TLS_AES_128_GCM_SHA256 vpce-12345 {}"#,
            get_identity().name
        );
        assert_eq!(expected, rendered);

        // Custom JSON template with typed fields and string escaping.
        let json_parser = StreamLogParser::from(
            r#"{"stream":{stream},"sni":"{sni}","subject":{tls_client_subject},"size":{size},"connect":{connect_time},"verified":{tls_client_verified},"unix":{when_unix},"utc":"{when_utc_iso}","host":{$hostname}}"#,
        );
        assert_eq!(true, json_parser.json);
        let json_raw = json_parser.format(&ctx);
        let json_val: serde_json::Value =
            serde_json::from_slice(&json_raw).unwrap();
        assert_eq!("s1", json_val["stream"]);
        assert_eq!("a\tb.example", json_val["sni"]);
        assert_eq!(r#"CN="evil" \ user"#, json_val["subject"]);
        assert_eq!(30, json_val["size"]);
        assert_eq!(2, json_val["connect"]);
        assert_eq!(true, json_val["verified"]);
        assert_eq!(true, json_val["unix"].is_i64());
        assert_eq!(true, json_val["utc"].as_str().unwrap().ends_with('Z'));
        assert_eq!(get_hostname(), json_val["host"]);

        // Missing optional fields in custom JSON template become `null` / `""`.
        let empty = StreamLogContext {
            stream: "s2",
            ..Default::default()
        };
        let json_empty: serde_json::Value =
            serde_json::from_slice(&json_parser.format(&empty)).unwrap();
        assert_eq!("", json_empty["sni"]);
        assert_eq!(serde_json::Value::Null, json_empty["subject"]);
        assert_eq!(serde_json::Value::Null, json_empty["connect"]);
        assert_eq!(false, json_empty["verified"]);
    }

    #[test]
    fn test_stream_logger_filtering() {
        let base = StreamLogContext {
            stream: "tcp_echo",
            client_addr: "127.0.0.1:9000",
            client_ip: "127.0.0.1",
            upstream: "echo",
            duration: Duration::from_millis(10),
            result: "ok",
            ..Default::default()
        };

        // No target -> logs all lines without trailing `\n`.
        let logger = StreamLogger::try_new("tiny", None).unwrap();
        assert_eq!(true, logger.filter().is_none());
        let line = logger.format_line(&base).unwrap();
        assert_eq!("tcp_echo echo ok 10ms", line);
        assert_eq!(false, line.ends_with(b"\n"));

        // `skip` matches SNI when present, otherwise stream name.
        let skip_logger = StreamLogger::try_new(
            "tiny",
            Some("stdout?skip=^(health|probe\\.local)$"),
        )
        .unwrap();
        assert_eq!(
            None,
            skip_logger.format_line(&StreamLogContext {
                stream: "health",
                ..base
            })
        );
        assert_eq!(
            None,
            skip_logger.format_line(&StreamLogContext {
                sni: Some("probe.local"),
                ..base
            })
        );
        assert_eq!(true, skip_logger.format_line(&base).is_some());

        // `min_status`: ok=200, denied/acl/rejected=403, errors=500.
        let min_400 =
            StreamLogger::try_new("tiny", Some("/tmp/s.log?min_status=400"))
                .unwrap();
        assert_eq!(None, min_400.format_line(&base));
        assert_eq!(
            true,
            min_400
                .format_line(&StreamLogContext {
                    result: "ip_denied",
                    ..base
                })
                .is_some()
        );
        assert_eq!(
            true,
            min_400
                .format_line(&StreamLogContext {
                    result: "connect_failed",
                    ..base
                })
                .is_some()
        );

        let min_500 =
            StreamLogger::try_new("tiny", Some("/tmp/s.log?min_status=500"))
                .unwrap();
        assert_eq!(
            None,
            min_500.format_line(&StreamLogContext {
                result: "ip_denied",
                ..base
            })
        );
        assert_eq!(
            true,
            min_500
                .format_line(&StreamLogContext {
                    result: "connect_failed",
                    ..base
                })
                .is_some()
        );

        // `min_latency`
        let slow =
            StreamLogger::try_new("tiny", Some("stdout?min_latency=100ms"))
                .unwrap();
        assert_eq!(None, slow.format_line(&base));
        assert_eq!(
            true,
            slow.format_line(&StreamLogContext {
                duration: Duration::from_millis(120),
                ..base
            })
            .is_some()
        );

        // `sample`
        let sampled =
            StreamLogger::try_new("tiny", Some("stdout?sample=0.5")).unwrap();
        let count = (0..10)
            .filter(|_| sampled.format_line(&base).is_some())
            .count();
        assert_eq!(5, count);

        // Invalid filter / target params return Err.
        assert_eq!(
            true,
            StreamLogger::try_new("tiny", Some("stdout?sample=2")).is_err()
        );
        assert_eq!(
            true,
            StreamLogger::try_new("tiny", Some("/tmp/s.log?rolling=bad"))
                .is_err()
        );
    }
}
