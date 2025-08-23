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

use bytes::BytesMut;
use chrono::{Local, Utc};
use pingap_core::{get_hostname, Ctx, HOST_NAME_TAG};
use pingap_util::{format_byte_size, format_duration};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use regex::Regex;
use std::time::Instant;
use substring::Substring;

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
    Context,
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

#[derive(Debug, Default, Clone)]
pub struct Parser {
    pub needs_timestamp: bool,
    pub capacity: usize,
    pub tags: Vec<Tag>,
}

// Parses special tags with prefixes like ~, >, <, :, $
fn format_extra_tag(key: &str) -> Option<Tag> {
    // Requires at least 2 chars (prefix + content)
    if key.len() < 2 {
        return None;
    }
    let key = key.substring(1, key.len() - 1);
    let ch = key.substring(0, 1);
    let value = key.substring(1, key.len());
    match ch {
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
        ":" => Some(Tag {
            category: TagCategory::Context,
            data: Some(value.to_string()),
        }),
        "$" => {
            if key.as_bytes() == HOST_NAME_TAG {
                Some(Tag {
                    category: TagCategory::Fill,
                    data: Some(get_hostname().to_string()),
                })
            } else {
                Some(Tag {
                    category: TagCategory::Fill,
                    data: Some(std::env::var(value).unwrap_or_default()),
                })
            }
        },
        _ => None,
    }
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
        let reg = Regex::new(r"(\{[a-zA-Z_<>\-~:$]+*\})").unwrap();
        let mut current = 0;
        let mut end = 0;
        let mut tags = vec![];

        while let Some(result) = reg.find_at(value, current) {
            if end < result.start() {
                tags.push(Tag {
                    category: TagCategory::Fill,
                    data: Some(
                        value.substring(end, result.start()).to_string(),
                    ),
                });
            }
            let key = result.as_str();

            match key {
                "{host}" => tags.push(Tag {
                    category: TagCategory::Host,
                    data: None,
                }),
                "{method}" => tags.push(Tag {
                    category: TagCategory::Method,
                    data: None,
                }),
                "{path}" => tags.push(Tag {
                    category: TagCategory::Path,
                    data: None,
                }),
                "{proto}" => tags.push(Tag {
                    category: TagCategory::Proto,
                    data: None,
                }),
                "{query}" => tags.push(Tag {
                    category: TagCategory::Query,
                    data: None,
                }),
                "{remote}" => tags.push(Tag {
                    category: TagCategory::Remote,
                    data: None,
                }),
                "{client_ip}" => tags.push(Tag {
                    category: TagCategory::ClientIp,
                    data: None,
                }),
                "{scheme}" => tags.push(Tag {
                    category: TagCategory::Scheme,
                    data: None,
                }),
                "{uri}" => tags.push(Tag {
                    category: TagCategory::Uri,
                    data: None,
                }),
                "{referer}" => tags.push(Tag {
                    category: TagCategory::Referrer,
                    data: None,
                }),
                "{user_agent}" => tags.push(Tag {
                    category: TagCategory::UserAgent,
                    data: None,
                }),
                "{when}" => tags.push(Tag {
                    category: TagCategory::When,
                    data: None,
                }),
                "{when_utc_iso}" => tags.push(Tag {
                    category: TagCategory::WhenUtcIso,
                    data: None,
                }),
                "{when_unix}" => tags.push(Tag {
                    category: TagCategory::WhenUnix,
                    data: None,
                }),
                "{size}" => tags.push(Tag {
                    category: TagCategory::Size,
                    data: None,
                }),
                "{size_human}" => tags.push(Tag {
                    category: TagCategory::SizeHuman,
                    data: None,
                }),
                "{status}" => tags.push(Tag {
                    category: TagCategory::Status,
                    data: None,
                }),
                "{latency}" => tags.push(Tag {
                    category: TagCategory::Latency,
                    data: None,
                }),
                "{latency_human}" => tags.push(Tag {
                    category: TagCategory::LatencyHuman,
                    data: None,
                }),
                "{payload_size}" => tags.push(Tag {
                    category: TagCategory::PayloadSize,
                    data: None,
                }),
                "{payload_size_human}" => tags.push(Tag {
                    category: TagCategory::PayloadSizeHuman,
                    data: None,
                }),
                "{request_id}" => tags.push(Tag {
                    category: TagCategory::RequestId,
                    data: None,
                }),
                _ => {
                    if let Some(tag) = format_extra_tag(key) {
                        tags.push(tag);
                    }
                },
            }

            end = result.end();
            current = result.start() + 1;
        }
        if end < value.len() {
            tags.push(Tag {
                category: TagCategory::Fill,
                data: Some(value.substring(end, value.len()).to_string()),
            });
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
        let capacity = Parser::estimate_capacity(&tags);
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
    pub fn format(&self, session: &Session, ctx: &Ctx) -> String {
        // Better capacity estimation based on tag types and count
        let mut buf = BytesMut::with_capacity(self.capacity);
        let req_header = session.req_header();

        // Then only calculate if needed
        let (now, instant) = if self.needs_timestamp {
            let n = Utc::now();
            (Some(n), Some(Instant::now()))
        } else {
            (None, None)
        };

        // Process each tag in the format string
        for tag in self.tags.iter() {
            match tag.category {
                TagCategory::Fill => {
                    // Static text, just append it
                    if let Some(data) = &tag.data {
                        buf.extend_from_slice(data.as_bytes());
                    }
                },
                TagCategory::Host => {
                    // Add the host from request headers
                    if let Some(host) = pingap_core::get_host(req_header) {
                        buf.extend_from_slice(host.as_bytes());
                    }
                },
                TagCategory::Method => {
                    buf.extend_from_slice(
                        req_header.method.as_str().as_bytes(),
                    );
                },
                TagCategory::Path => {
                    buf.extend_from_slice(req_header.uri.path().as_bytes());
                },
                TagCategory::Proto => {
                    if session.is_http2() {
                        buf.extend_from_slice(b"HTTP/2.0");
                    } else {
                        buf.extend_from_slice(b"HTTP/1.1");
                    }
                },
                TagCategory::Query => {
                    if let Some(query) = req_header.uri.query() {
                        buf.extend_from_slice(query.as_bytes());
                    }
                },
                TagCategory::Remote => {
                    if let Some(addr) = &ctx.conn.remote_addr {
                        buf.extend_from_slice(addr.as_bytes());
                    }
                },
                TagCategory::ClientIp => {
                    if let Some(client_ip) = &ctx.conn.client_ip {
                        buf.extend_from_slice(client_ip.as_bytes());
                    } else {
                        buf.extend_from_slice(
                            pingap_core::get_client_ip(session).as_bytes(),
                        );
                    }
                },
                TagCategory::Scheme => {
                    if ctx.conn.tls_version.is_some() {
                        buf.extend_from_slice(b"https");
                    } else {
                        buf.extend_from_slice(b"http");
                    }
                },
                TagCategory::Uri => {
                    if let Some(value) = req_header.uri.path_and_query() {
                        buf.extend_from_slice(value.as_str().as_bytes());
                    }
                },
                TagCategory::Referrer => {
                    let value = session.get_header_bytes("Referer");
                    buf.extend_from_slice(value);
                },
                TagCategory::UserAgent => {
                    let value = session.get_header_bytes("User-Agent");
                    buf.extend_from_slice(value);
                },
                TagCategory::When => {
                    if let Some(now) = &now {
                        buf.extend_from_slice(
                            now.with_timezone(&Local).to_rfc3339().as_bytes(),
                        );
                    }
                },
                TagCategory::WhenUtcIso => {
                    if let Some(now) = &now {
                        buf.extend_from_slice(now.to_rfc3339().as_bytes());
                    }
                },
                TagCategory::WhenUnix => {
                    if let Some(now) = &now {
                        buf.extend_from_slice(
                            itoa::Buffer::new()
                                .format(now.timestamp_millis())
                                .as_bytes(),
                        );
                    }
                },
                TagCategory::Size => {
                    buf.extend_from_slice(
                        itoa::Buffer::new()
                            .format(session.body_bytes_sent())
                            .as_bytes(),
                    );
                },
                TagCategory::SizeHuman => {
                    format_byte_size(&mut buf, session.body_bytes_sent());
                },
                TagCategory::Status => {
                    if let Some(status) = &ctx.state.status {
                        buf.extend_from_slice(status.as_str().as_bytes());
                    } else {
                        buf.extend_from_slice(b"0");
                    }
                },
                TagCategory::Latency => {
                    if let Some(instant) = instant {
                        let ms = (instant - ctx.timing.created_at).as_millis();
                        buf.extend_from_slice(
                            itoa::Buffer::new().format(ms).as_bytes(),
                        );
                    }
                },
                TagCategory::LatencyHuman => {
                    if let Some(instant) = instant {
                        let ms = (instant - ctx.timing.created_at).as_millis();
                        format_duration(&mut buf, ms as u64);
                    }
                },
                TagCategory::Cookie => {
                    if let Some(cookie) = &tag.data {
                        if let Some(value) =
                            pingap_core::get_cookie_value(req_header, cookie)
                        {
                            buf.extend_from_slice(value.as_bytes());
                        }
                    }
                },
                TagCategory::RequestHeader => {
                    if let Some(key) = &tag.data {
                        if let Some(value) = req_header.headers.get(key) {
                            buf.extend_from_slice(value.as_bytes());
                        }
                    }
                },
                TagCategory::ResponseHeader => {
                    if let Some(resp_header) = session.response_written() {
                        if let Some(key) = &tag.data {
                            if let Some(value) =
                                get_resp_header_value(resp_header, key)
                            {
                                buf.extend_from_slice(value);
                            }
                        }
                    }
                },
                TagCategory::PayloadSize => {
                    buf.extend_from_slice(
                        itoa::Buffer::new()
                            .format(ctx.state.payload_size)
                            .as_bytes(),
                    );
                },
                TagCategory::PayloadSizeHuman => {
                    format_byte_size(&mut buf, ctx.state.payload_size);
                },
                TagCategory::RequestId => {
                    if let Some(key) = &ctx.state.request_id {
                        buf.extend_from_slice(key.as_bytes());
                    }
                },
                TagCategory::Context => {
                    if let Some(key) = &tag.data {
                        buf = ctx.append_log_value(buf, key.as_str());
                    }
                },
            };
        }

        std::string::String::from_utf8(buf.into()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{format_extra_tag, Parser, Tag, TagCategory};
    use http::Method;
    use pingap_core::{
        ConnectionInfo, Ctx, RequestState, Timing, UpstreamInfo,
    };
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

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
            "Referer: https://github.com/",
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
                tls_version: Some("1.2".to_string()),
                ..Default::default()
            },
            upstream: UpstreamInfo {
                reused: true,
                address: "192.186.1.1:6188".to_string(),
                location: "test".to_string(),
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
            "github.com GET /vicanso/pingap HTTP/1.1 size=1 10.1.1.1 1.1.1.1 https /vicanso/pingap?size=1 https://github.com/ pingap/0.1.1 0 0B 0 0 0B abc application/json true 192.186.1.1:6188 1 100ms test 300ms 1.2 nanoid",
            log
        );

        let p: Parser = "{when_utc_iso}".into();
        let log = p.format(&session, &ctx);
        assert_eq!(true, log.len() > 25);

        let p: Parser = "{when}".into();
        let log = p.format(&session, &ctx);
        assert_eq!(true, log.len() > 25);

        let p: Parser = "{when_unix}".into();
        let log = p.format(&session, &ctx);
        assert_eq!(true, log.len() == 13);
    }
}
