use crate::state::State;
use crate::utils;
use bytesize::ByteSize;
use pingora::http::RequestHeader;
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
}

#[derive(Debug, Clone)]
pub struct Tag {
    pub category: TagCategory,
    pub data: Option<String>,
}
#[derive(Debug, Default, Clone)]

pub struct Parser {
    pub tags: Vec<Tag>,
    pub response_headers: Vec<String>,
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
        "$" => Some(Tag {
            category: TagCategory::Fill,
            data: Some(std::env::var(value).unwrap_or_default()),
        }),
        _ => None,
    }
}

static COMBINED: &str =
    r###"{remote} "{method} {uri} {proto}" {status} {size-human} "{referer}" "{userAgent}""###;
static COMMON: &str = r###"{remote} "{method} {uri} {proto}" {status} {size-human}""###;
static SHORT: &str = r###"{remote} {method} {uri} {proto} {status} {size-human} - {latency}ms"###;
static TINY: &str = r###"{method} {uri} {status} {size-human} - {latency}ms"###;

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
        let mut response_headers = vec![];

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
                "{client-ip}" => tags.push(Tag {
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
                "{user-agent}" => tags.push(Tag {
                    category: TagCategory::UserAgent,
                    data: None,
                }),
                "{when}" => tags.push(Tag {
                    category: TagCategory::When,
                    data: None,
                }),
                "{when-utc-iso}" => tags.push(Tag {
                    category: TagCategory::WhenUtcIso,
                    data: None,
                }),
                "{when-unix}" => tags.push(Tag {
                    category: TagCategory::WhenUnix,
                    data: None,
                }),
                "{size}" => tags.push(Tag {
                    category: TagCategory::Size,
                    data: None,
                }),
                "{size-human}" => tags.push(Tag {
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
                "{latency-human}" => tags.push(Tag {
                    category: TagCategory::LatencyHuman,
                    data: None,
                }),
                "{payload-size}" => tags.push(Tag {
                    category: TagCategory::PayloadSize,
                    data: None,
                }),
                "{payload-size-human}" => tags.push(Tag {
                    category: TagCategory::PayloadSizeHuman,
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
        for tag in tags.iter() {
            if tag.category == TagCategory::ResponseHeader {
                let value = tag.data.clone().unwrap_or_default();
                if !response_headers.contains(&value) {
                    response_headers.push(value);
                }
            }
        }
        Parser {
            tags,
            response_headers,
        }
    }
}

fn get_header_value<'a>(req_header: &'a RequestHeader, key: &str) -> Option<&'a str> {
    if let Some(value) = req_header.headers.get(key) {
        if let Ok(value) = value.to_str() {
            return Some(value);
        }
    }
    None
}

impl Parser {
    pub fn format(&self, req_header: &RequestHeader, ctx: &State) -> String {
        let mut buf = String::with_capacity(1024);
        for tag in self.tags.iter() {
            match tag.category {
                TagCategory::Fill => {
                    if let Some(data) = &tag.data {
                        buf.push_str(data);
                    }
                }
                TagCategory::Host => {
                    if let Some(host) = get_header_value(req_header, "Host") {
                        buf.push_str(host);
                    }
                }
                TagCategory::Method => {
                    buf.push_str(req_header.method.as_str());
                }
                TagCategory::Path => {
                    buf.push_str(req_header.uri.path());
                }
                TagCategory::Proto => {
                    if ctx.http_version == 2 {
                        buf.push_str("HTTP/2.0");
                    } else {
                        buf.push_str("HTTP/1.1");
                    }
                }
                TagCategory::Query => {
                    if let Some(query) = req_header.uri.query() {
                        buf.push_str(query);
                    }
                }
                TagCategory::Remote => {
                    // TODO
                }
                TagCategory::ClientIp => {
                    if let Some(value) = get_header_value(req_header, "X-Forwarded-For") {
                        let arr: Vec<&str> = value.split(',').collect();
                        if !arr.is_empty() {
                            buf.push_str(arr[0].trim());
                        }
                    } else if let Some(value) = get_header_value(req_header, "X-Real-Ip") {
                        buf.push_str(value);
                    }
                }
                TagCategory::Scheme => {
                    // TODO
                }
                TagCategory::Uri => {
                    buf.push_str(&req_header.uri.to_string());
                }
                TagCategory::Referer => {
                    if let Some(value) = get_header_value(req_header, "Referer") {
                        buf.push_str(value);
                    }
                }
                TagCategory::UserAgent => {
                    if let Some(value) = get_header_value(req_header, "User-Agent") {
                        buf.push_str(value);
                    }
                }
                TagCategory::When => {
                    buf.push_str(&chrono::Local::now().to_rfc3339());
                }
                TagCategory::WhenUtcIso => {
                    buf.push_str(&chrono::Utc::now().to_rfc3339());
                }
                TagCategory::WhenUnix => {
                    buf.push_str(&chrono::Utc::now().timestamp_millis().to_string());
                }
                TagCategory::Size => {
                    buf.push_str(&ctx.response_body_size.to_string());
                }
                TagCategory::SizeHuman => {
                    buf.push_str(
                        &ByteSize(ctx.response_body_size as u64)
                            .to_string()
                            .replace(' ', ""),
                    );
                }
                TagCategory::Status => {
                    if let Some(status) = ctx.status {
                        buf.push_str(status.as_str());
                    } else {
                        buf.push('0');
                    }
                }
                TagCategory::Latency => {
                    let d = Instant::now().duration_since(ctx.created_at);
                    buf.push_str(&d.as_millis().to_string())
                }
                TagCategory::LatencyHuman => {
                    let ms = Instant::now().duration_since(ctx.created_at).as_millis();
                    buf.push_str(&format!("{:?}", Duration::from_millis(ms as u64)));
                }
                TagCategory::Cookie => {
                    let cookie_name = tag.data.clone().unwrap_or_default();
                    let cookie_value = get_header_value(req_header, "Cookie").unwrap_or_default();
                    for item in cookie_value.split(';') {
                        if let Some([k, v]) = utils::split_to_two_trim(item, "=") {
                            if k == cookie_name {
                                buf.push_str(&v);
                            }
                        }
                    }
                }
                TagCategory::RequestHeader => {
                    if let Some(key) = &tag.data {
                        if let Some(value) = get_header_value(req_header, key) {
                            buf.push_str(value);
                        }
                    }
                }
                TagCategory::ResponseHeader => {
                    if let Some(m) = &ctx.response_headers {
                        if let Some(key) = &tag.data {
                            if let Some(value) = m.get(key) {
                                buf.push_str(value);
                            }
                        }
                    }
                }
                TagCategory::PayloadSize => {
                    // TODO
                }
                TagCategory::PayloadSizeHuman => {
                    // TODO
                }
                TagCategory::Context => {
                    if let Some(key) = &tag.data {
                        match key.as_str() {
                            "reused" => buf.push_str(&ctx.reused.to_string()),
                            "upstream-address" => buf.push_str(&ctx.upstream_address),
                            "processing" => buf.push_str(&ctx.processing.to_string()),
                            _ => {}
                        }
                    }
                }
            };
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::Parser;
    use crate::state::State;
    use pingora::http::RequestHeader;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;

    #[test]
    fn test_logger() {
        let p: Parser = "{host} {method} {path} {proto} {query} {remote} {client-ip} \
{scheme} {uri} {referer} {user-agent} {size} \
{size-human} {status} {latency} {latency-human} {payload-size} {payload-size-human} \
{~deviceId} {>accept} {<content-type} {:reused}"
            .into();
        let mut req_header =
            RequestHeader::build_no_case("GET", b"/vicanso/pingap?size=1", Some(4)).unwrap();
        req_header.insert_header("Host", "github.com").unwrap();
        req_header
            .insert_header("Referer", "https://github.com/")
            .unwrap();
        req_header
            .insert_header("User-Agent", "pingap/0.1.1")
            .unwrap();
        req_header.insert_header("Cookie", "deviceId=abc").unwrap();
        req_header
            .insert_header("Accept", "application/json")
            .unwrap();
        let mut m = HashMap::new();
        m.insert("content-type".to_string(), "json".to_string());
        let ctx = State {
            response_body_size: 1024,
            reused: true,
            response_headers: Some(m),
            ..Default::default()
        };
        let log = p.format(&req_header, &ctx);
        assert_eq!(
            "github.com GET /vicanso/pingap HTTP/1.1 size=1    /vicanso/pingap?size=1 \
https://github.com/ pingap/0.1.1 1024 1.0KB 0 0 0ns   abc application/json json true",
            log
        );
    }
}
