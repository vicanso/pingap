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
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::sync::LazyLock;
use std::time::Instant;

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

// Represents a single tag in the log format
#[derive(Debug, Clone)]
pub struct Tag {
    pub category: TagCategory,
    pub data: Option<String>, // Optional data associated with the tag
}

impl Tag {
    fn simple(category: TagCategory) -> Self {
        Self {
            category,
            data: None,
        }
    }
    fn fill(text: &str) -> Self {
        Self {
            category: TagCategory::Fill,
            data: Some(text.to_string()),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Parser {
    pub needs_timestamp: bool,
    pub capacity: usize,
    pub tags: Vec<Tag>,
}

// Parses special tags with prefixes like ~, >, <, :, $
fn format_extra_tag(key: &str) -> Option<Tag> {
    let key = key.strip_prefix('{')?.strip_suffix('}')?;
    let (prefix, value) = key.split_at_checked(1)?;
    match prefix {
        "~" => Some(Tag {
            // Cookie values
            category: TagCategory::Cookie,
            data: Some(value.to_string()),
        }),
        ">" => Some(Tag {
            // Request headers
            category: TagCategory::RequestHeader,
            data: Some(value.to_string()),
        }),
        "<" => Some(Tag {
            // Response headers
            category: TagCategory::ResponseHeader,
            data: Some(value.to_string()),
        }),
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

/// Splits a format string into literal text and `{tag}` placeholders. A
/// placeholder is `{`, one or more tag characters and `}`; a `{` that is
/// not followed by that is literal text, as is everything outside
/// placeholders. A well-formed placeholder that names no tag is dropped.
fn parse_tags(value: &str) -> Vec<Tag> {
    let mut tags = vec![];
    let bytes = value.as_bytes();
    let mut fill_start = 0;
    let mut pos = 0;
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
            tags.push(Tag::fill(&value[fill_start..start]));
        }
        if let Some(tag) = parse_tag(&value[start..end]) {
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

// Predefined log formats
static COMBINED: &str = r###"{remote} "{method} {uri} {proto}" {status} {size_human} "{referer}" "{user_agent}""###;
static COMMON: &str =
    r###"{remote} "{method} {uri} {proto}" {status} {size_human}""###;
static SHORT: &str = r###"{remote} {method} {uri} {proto} {status} {size_human} - {latency}ms"###;
static TINY: &str = r###"{method} {uri} {status} {size_human} - {latency}ms"###;

impl From<&str> for Parser {
    fn from(value: &str) -> Self {
        let value = match value {
            "combined" => COMBINED,
            "common" => COMMON,
            "short" => SHORT,
            "tiny" => TINY,
            _ => value,
        };
        let tags = parse_tags(value);
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

/// Appends `value`, or `-` when it is empty.
#[inline]
fn put_or_empty(buf: &mut BytesMut, value: &[u8]) {
    if value.is_empty() {
        buf.put_slice(EMPTY_FIELD);
    } else {
        buf.put_slice(value);
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
    // Formats a log entry based on the session and context
    pub fn format(&self, session: &Session, ctx: &Ctx) -> BytesMut {
        // Better capacity estimation based on tag types and count
        let mut buf = BytesMut::with_capacity(self.capacity);
        let req_header = session.req_header();

        // Then only calculate if needed
        let (now, instant) = if self.needs_timestamp {
            (Some(Utc::now()), Some(Instant::now()))
        } else {
            (None, None)
        };
        let latency_ms = || {
            instant.map(|instant| {
                instant.saturating_duration_since(ctx.timing.created_at)
            })
        };

        // Process each tag in the format string
        for tag in self.tags.iter() {
            match &tag.category {
                TagCategory::Fill => {
                    // Static text, just append it
                    if let Some(data) = &tag.data {
                        buf.put_slice(data.as_bytes());
                    }
                },
                TagCategory::Host => {
                    // Add the host from request headers
                    let host = pingap_core::get_host(req_header);
                    put_or_empty(&mut buf, host.unwrap_or_default().as_bytes());
                },
                TagCategory::Method => {
                    put_or_empty(
                        &mut buf,
                        req_header.method.as_str().as_bytes(),
                    );
                },
                TagCategory::Path => {
                    put_or_empty(&mut buf, req_header.uri.path().as_bytes());
                },
                TagCategory::Proto => {
                    if session.is_http2() {
                        buf.put_slice(b"HTTP/2.0");
                    } else {
                        buf.put_slice(b"HTTP/1.1");
                    }
                },
                TagCategory::Query => {
                    let query = req_header.uri.query().unwrap_or_default();
                    put_or_empty(&mut buf, query.as_bytes());
                },
                TagCategory::Remote => {
                    let addr =
                        ctx.conn.remote_addr.as_deref().unwrap_or_default();
                    put_or_empty(&mut buf, addr.as_bytes());
                },
                TagCategory::ClientIp => match &ctx.conn.client_ip {
                    Some(client_ip) => {
                        put_or_empty(&mut buf, client_ip.as_bytes());
                    },
                    None => {
                        let client_ip = pingap_core::get_client_ip(session);
                        put_or_empty(&mut buf, client_ip.as_bytes());
                    },
                },
                TagCategory::Scheme => {
                    if ctx.conn.tls_version.is_some() {
                        buf.put_slice(b"https");
                    } else {
                        buf.put_slice(b"http");
                    }
                },
                TagCategory::Uri => {
                    let uri = req_header
                        .uri
                        .path_and_query()
                        .map(|value| value.as_str())
                        .unwrap_or_default();
                    put_or_empty(&mut buf, uri.as_bytes());
                },
                TagCategory::Referrer => {
                    put_or_empty(&mut buf, session.get_header_bytes("referer"));
                },
                TagCategory::UserAgent => {
                    put_or_empty(
                        &mut buf,
                        session.get_header_bytes("user-agent"),
                    );
                },
                TagCategory::When => match &now {
                    Some(now) => put_rfc3339_millis(
                        &mut buf,
                        &now.with_timezone(&Local),
                        false,
                    ),
                    None => buf.put_slice(EMPTY_FIELD),
                },
                TagCategory::WhenUtcIso => match &now {
                    Some(now) => put_rfc3339_millis(&mut buf, now, true),
                    None => buf.put_slice(EMPTY_FIELD),
                },
                TagCategory::WhenUnix => match &now {
                    Some(now) => buf.put_slice(
                        itoa::Buffer::new()
                            .format(now.timestamp_millis())
                            .as_bytes(),
                    ),
                    None => buf.put_slice(EMPTY_FIELD),
                },
                TagCategory::Size => {
                    buf.put_slice(
                        itoa::Buffer::new()
                            .format(session.body_bytes_sent())
                            .as_bytes(),
                    );
                },
                TagCategory::SizeHuman => {
                    format_byte_size(&mut buf, session.body_bytes_sent());
                },
                TagCategory::Status => match &ctx.state.status {
                    Some(status) => buf.put_slice(status.as_str().as_bytes()),
                    None => buf.put_slice(EMPTY_FIELD),
                },
                TagCategory::Latency => match latency_ms() {
                    Some(latency) => buf.put_slice(
                        itoa::Buffer::new()
                            .format(latency.as_millis())
                            .as_bytes(),
                    ),
                    None => buf.put_slice(EMPTY_FIELD),
                },
                TagCategory::LatencyHuman => match latency_ms() {
                    Some(latency) => {
                        format_duration(&mut buf, latency.as_millis() as u64)
                    },
                    None => buf.put_slice(EMPTY_FIELD),
                },
                // A missing cookie is `-` like every other missing value;
                // it used to leave the field empty.
                TagCategory::Cookie => {
                    let value = tag.data.as_deref().and_then(|cookie| {
                        pingap_core::get_cookie_value(req_header, cookie)
                    });
                    put_or_empty(
                        &mut buf,
                        value.unwrap_or_default().as_bytes(),
                    );
                },
                TagCategory::RequestHeader => {
                    let value = tag
                        .data
                        .as_deref()
                        .and_then(|key| req_header.headers.get(key))
                        .map(|value| value.as_bytes())
                        .unwrap_or_default();
                    put_or_empty(&mut buf, value);
                },
                TagCategory::ResponseHeader => {
                    let value = session
                        .response_written()
                        .zip(tag.data.as_deref())
                        .and_then(|(resp_header, key)| {
                            get_resp_header_value(resp_header, key)
                        })
                        .unwrap_or_default();
                    put_or_empty(&mut buf, value);
                },
                TagCategory::PayloadSize => {
                    buf.put_slice(
                        itoa::Buffer::new()
                            .format(ctx.state.payload_size)
                            .as_bytes(),
                    );
                },
                TagCategory::PayloadSizeHuman => {
                    format_byte_size(&mut buf, ctx.state.payload_size);
                },
                TagCategory::RequestId => {
                    let id =
                        ctx.state.request_id.as_deref().unwrap_or_default();
                    put_or_empty(&mut buf, id.as_bytes());
                },
                TagCategory::Context(field) => {
                    ctx.append_log_field(&mut buf, *field);
                },
            };
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

    if !["combined", "common", "short", "tiny"].contains(&access)
        && !access.starts_with('{')
    {
        return default_value;
    }

    (Some(access.to_string()), Some(path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        Parser, Tag, TagCategory, format_extra_tag, get_resp_header_value,
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
            (
                "{host}",
                Tag {
                    category: TagCategory::Host,
                    data: None,
                },
            ),
            (
                "{method}",
                Tag {
                    category: TagCategory::Method,
                    data: None,
                },
            ),
            (
                "{path}",
                Tag {
                    category: TagCategory::Path,
                    data: None,
                },
            ),
            (
                "{proto}",
                Tag {
                    category: TagCategory::Proto,
                    data: None,
                },
            ),
            (
                "{query}",
                Tag {
                    category: TagCategory::Query,
                    data: None,
                },
            ),
            (
                "{remote}",
                Tag {
                    category: TagCategory::Remote,
                    data: None,
                },
            ),
            (
                "{client_ip}",
                Tag {
                    category: TagCategory::ClientIp,
                    data: None,
                },
            ),
            (
                "{scheme}",
                Tag {
                    category: TagCategory::Scheme,
                    data: None,
                },
            ),
            (
                "{uri}",
                Tag {
                    category: TagCategory::Uri,
                    data: None,
                },
            ),
            (
                "{referer}",
                Tag {
                    category: TagCategory::Referrer,
                    data: None,
                },
            ),
            (
                "{user_agent}",
                Tag {
                    category: TagCategory::UserAgent,
                    data: None,
                },
            ),
            (
                "{when}",
                Tag {
                    category: TagCategory::When,
                    data: None,
                },
            ),
            (
                "{when_utc_iso}",
                Tag {
                    category: TagCategory::WhenUtcIso,
                    data: None,
                },
            ),
            (
                "{when_unix}",
                Tag {
                    category: TagCategory::WhenUnix,
                    data: None,
                },
            ),
            (
                "{size}",
                Tag {
                    category: TagCategory::Size,
                    data: None,
                },
            ),
            (
                "{size_human}",
                Tag {
                    category: TagCategory::SizeHuman,
                    data: None,
                },
            ),
            (
                "{status}",
                Tag {
                    category: TagCategory::Status,
                    data: None,
                },
            ),
            (
                "{latency}",
                Tag {
                    category: TagCategory::Latency,
                    data: None,
                },
            ),
            (
                "{latency_human}",
                Tag {
                    category: TagCategory::LatencyHuman,
                    data: None,
                },
            ),
            (
                "{payload_size}",
                Tag {
                    category: TagCategory::PayloadSize,
                    data: None,
                },
            ),
            (
                "{payload_size_human}",
                Tag {
                    category: TagCategory::PayloadSizeHuman,
                    data: None,
                },
            ),
            (
                "{request_id}",
                Tag {
                    category: TagCategory::RequestId,
                    data: None,
                },
            ),
        ];

        for (value, tag) in tests {
            let p = Parser::from(value);
            assert_eq!(tag.category, p.tags[0].category);
        }
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
