// Copyright 2024 Tree xie.
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

use crate::http_extra::HOST_NAME_TAG;
use crate::state::{get_hostname, State};
use crate::util;
use bytes::BytesMut;
use bytesize::ByteSize;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use regex::Regex;
use std::time::{Duration, Instant};
use substring::Substring;

#[derive(Debug, Clone, PartialEq)]
pub enum TagCategory {
    Fill,
    Host,
    Method,
    Path,
    Proto,
    Query,
    Remote,
    ClientIp,
    Scheme,
    Uri,
    Referer,
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

#[derive(Debug, Clone)]
pub struct Tag {
    pub category: TagCategory,
    pub data: Option<String>,
}
#[derive(Debug, Default, Clone)]

pub struct Parser {
    pub tags: Vec<Tag>,
}

fn format_extra_tag(key: &str) -> Option<Tag> {
    if key.len() < 2 {
        return None;
    }
    let key = key.substring(1, key.len() - 1);
    let ch = key.substring(0, 1);
    let value = key.substring(1, key.len());
    match ch {
        "~" => Some(Tag {
            category: TagCategory::Cookie,
            data: Some(value.to_string()),
        }),
        ">" => Some(Tag {
            category: TagCategory::RequestHeader,
            data: Some(value.to_string()),
        }),
        "<" => Some(Tag {
            category: TagCategory::ResponseHeader,
            data: Some(value.to_string()),
        }),
        ":" => Some(Tag {
            category: TagCategory::Context,
            data: Some(value.to_string()),
        }),
        "$" => {
            if key == HOST_NAME_TAG {
                Some(Tag {
                    category: TagCategory::Fill,
                    data: Some(get_hostname()),
                })
            } else {
                Some(Tag {
                    category: TagCategory::Fill,
                    data: Some(std::env::var(value).unwrap_or_default()),
                })
            }
        }
        _ => None,
    }
}

static COMBINED: &str =
    r###"{remote} "{method} {uri} {proto}" {status} {size_human} "{referer}" "{user_agent}""###;
static COMMON: &str = r###"{remote} "{method} {uri} {proto}" {status} {size_human}""###;
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
                    data: Some(value.substring(end, result.start()).to_string()),
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
                    category: TagCategory::Referer,
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
                }
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
        Parser { tags }
    }
}

fn get_resp_header_value<'a>(resp_header: &'a ResponseHeader, key: &str) -> Option<&'a [u8]> {
    if let Some(value) = resp_header.headers.get(key) {
        return Some(value.as_bytes());
    }
    None
}

impl Parser {
    pub fn format(&self, session: &Session, ctx: &State) -> String {
        let mut buf = BytesMut::with_capacity(1024);
        let req_header = session.req_header();
        for tag in self.tags.iter() {
            match tag.category {
                TagCategory::Fill => {
                    if let Some(data) = &tag.data {
                        buf.extend(data.as_bytes());
                    }
                }
                TagCategory::Host => {
                    if let Some(host) = util::get_host(req_header) {
                        buf.extend(host.as_bytes());
                    }
                }
                TagCategory::Method => {
                    buf.extend(req_header.method.as_str().as_bytes());
                }
                TagCategory::Path => {
                    buf.extend(req_header.uri.path().as_bytes());
                }
                TagCategory::Proto => {
                    if session.is_http2() {
                        buf.extend(b"HTTP/2.0");
                    } else {
                        buf.extend(b"HTTP/1.1");
                    }
                }
                TagCategory::Query => {
                    if let Some(query) = req_header.uri.query() {
                        buf.extend(query.as_bytes());
                    }
                }
                TagCategory::Remote => {
                    if let Some(addr) = &ctx.remote_addr {
                        buf.extend(addr.as_bytes());
                    }
                }
                TagCategory::ClientIp => {
                    if let Some(client_ip) = &ctx.client_ip {
                        buf.extend(client_ip.as_bytes());
                    } else {
                        buf.extend(util::get_client_ip(session).as_bytes());
                    }
                }
                TagCategory::Scheme => {
                    if ctx.tls_version.is_some() {
                        buf.extend(b"https");
                    } else {
                        buf.extend(b"http");
                    }
                }
                TagCategory::Uri => {
                    if let Some(value) = req_header.uri.path_and_query() {
                        buf.extend(value.as_str().as_bytes());
                    }
                }
                TagCategory::Referer => {
                    let value = session.get_header_bytes("Referer");
                    buf.extend(value);
                }
                TagCategory::UserAgent => {
                    let value = session.get_header_bytes("User-Agent");
                    buf.extend(value);
                }
                TagCategory::When => {
                    buf.extend(chrono::Local::now().to_rfc3339().as_bytes());
                }
                TagCategory::WhenUtcIso => {
                    buf.extend(chrono::Utc::now().to_rfc3339().as_bytes());
                }
                TagCategory::WhenUnix => {
                    buf.extend(chrono::Utc::now().timestamp_millis().to_string().as_bytes());
                }
                TagCategory::Size => {
                    buf.extend(ctx.response_body_size.to_string().as_bytes());
                }
                TagCategory::SizeHuman => {
                    buf.extend(
                        ByteSize(ctx.response_body_size as u64)
                            .to_string()
                            .replace(' ', "")
                            .as_bytes(),
                    );
                }
                TagCategory::Status => {
                    if let Some(status) = ctx.status {
                        buf.extend(status.as_str().as_bytes());
                    } else {
                        buf.extend(b"0");
                    }
                }
                TagCategory::Latency => {
                    let d = Instant::now().duration_since(ctx.created_at);
                    buf.extend(d.as_millis().to_string().as_bytes())
                }
                TagCategory::LatencyHuman => {
                    let ms = Instant::now().duration_since(ctx.created_at).as_millis();
                    buf.extend(format!("{:?}", Duration::from_millis(ms as u64)).as_bytes());
                }
                TagCategory::Cookie => {
                    if let Some(value) =
                        util::get_cookie_value(req_header, &tag.data.clone().unwrap_or_default())
                    {
                        buf.extend(value.as_bytes());
                    }
                }
                TagCategory::RequestHeader => {
                    if let Some(key) = &tag.data {
                        let value = session.get_header_bytes(key);
                        buf.extend(value);
                    }
                }
                TagCategory::ResponseHeader => {
                    if let Some(resp_header) = session.response_written() {
                        if let Some(key) = &tag.data {
                            if let Some(value) = get_resp_header_value(resp_header, key) {
                                buf.extend(value);
                            }
                        }
                    }
                }
                TagCategory::PayloadSize => {
                    buf.extend(ctx.payload_size.to_string().as_bytes());
                }
                TagCategory::PayloadSizeHuman => {
                    buf.extend(
                        ByteSize(ctx.payload_size as u64)
                            .to_string()
                            .replace(' ', "")
                            .as_bytes(),
                    );
                }
                TagCategory::Context => {
                    if let Some(key) = &tag.data {
                        match key.as_str() {
                            "reused" => buf.extend(ctx.reused.to_string().as_bytes()),
                            "upstream_address" => buf.extend(ctx.upstream_address.as_bytes()),
                            "processing" => buf.extend(ctx.processing.to_string().as_bytes()),
                            "upstream_connect_time" => {
                                if let Some(value) = ctx.get_upstream_connect_time() {
                                    buf.extend(
                                        format!("{:?}", Duration::from_millis(value as u64))
                                            .as_bytes(),
                                    );
                                }
                            }
                            "upstream_connected" => {
                                if let Some(value) = &ctx.upstream_connected {
                                    buf.extend(value.to_string().as_bytes());
                                }
                            }
                            "upstream_processing_time" => {
                                if let Some(value) = ctx.get_upstream_processing_time() {
                                    buf.extend(
                                        format!("{:?}", Duration::from_millis(value as u64))
                                            .as_bytes(),
                                    );
                                }
                            }
                            "location" => buf.extend(ctx.location.as_bytes()),
                            "established" => buf.extend(ctx.established.to_string().as_bytes()),
                            "tls_version" => {
                                if let Some(value) = &ctx.tls_version {
                                    buf.extend(value.as_bytes());
                                }
                            }
                            "compression_time" => {
                                if let Some(value) = &ctx.compression_stat {
                                    buf.extend(format!("{:?}", value.duration).as_bytes());
                                }
                            }
                            "compression_ratio" => {
                                if let Some(value) = &ctx.compression_stat {
                                    buf.extend(format!("{:.1}", value.ratio()).as_bytes());
                                }
                            }
                            "cache_lookup_time" => {
                                if let Some(d) = ctx.cache_lookup_duration {
                                    buf.extend(format!("{:?}", d).as_bytes());
                                }
                            }
                            "cache_lock_time" => {
                                if let Some(d) = ctx.cache_lock_duration {
                                    buf.extend(format!("{:?}", d).as_bytes());
                                }
                            }
                            _ => {}
                        }
                    }
                }
                TagCategory::RequestId => {
                    if let Some(key) = &ctx.request_id {
                        buf.extend(key.as_bytes());
                    }
                }
            };
        }

        std::string::String::from_utf8_lossy(&buf).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{format_extra_tag, Parser, Tag, TagCategory};
    use crate::state::State;
    use http::Method;
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
                    category: TagCategory::Referer,
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
        let p: Parser = "{host} {method} {path} {proto} {query} {remote} {client_ip} \
{scheme} {uri} {referer} {user_agent} {size} \
{size_human} {status} {payload_size} {payload_size_human} \
{~deviceId} {>accept} {:reused} {:upstream_address} \
{:processing} {:upstream_connect_time} {:location} \
{:established} {:tls_version} {request_id}"
            .into();
        let headers = [
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
        ]
        .join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();

        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(Method::GET, session.req_header().method);

        let ctx = State {
            response_body_size: 1024,
            reused: true,
            upstream_address: "192.186.1.1:6188".to_string(),
            processing: 1,
            upstream_connect_time: Some(100),
            location: "test".to_string(),
            established: 1651852800,
            tls_version: Some("1.2".to_string()),
            request_id: Some("nanoid".to_string()),
            ..Default::default()
        };
        let log = p.format(&session, &ctx);
        assert_eq!(
            "github.com GET /vicanso/pingap HTTP/1.1 size=1   https /vicanso/pingap?size=1 https://github.com/ pingap/0.1.1 1024 1.0KB 0 0 0B abc application/json true 192.186.1.1:6188 1 100ms test 1651852800 1.2 nanoid",
            log
        );
    }
}
