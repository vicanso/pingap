use super::state::State;
use bytesize::ByteSize;
use pingora::proxy::Session;
use regex::Regex;
use std::time::Instant;
use substring::Substring;

#[derive(Debug, Clone)]
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
}

impl From<&str> for Parser {
    fn from(value: &str) -> Self {
        let reg = Regex::new(r"(\{[a-zA-Z_<>\-~]+*\})").unwrap();
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
                // 	cookie           = "cookie"
                _ => {
                    let key = key.substring(1, key.len() - 1);
                    let ch = key.substring(0, 1);
                    let value = key.substring(1, key.len());
                    match ch {
                        "~" => tags.push(Tag {
                            category: TagCategory::Cookie,
                            data: Some(value.to_string()),
                        }),
                        ">" => tags.push(Tag {
                            category: TagCategory::RequestHeader,
                            data: Some(value.to_string()),
                        }),
                        "<" => tags.push(Tag {
                            category: TagCategory::ResponseHeader,
                            data: Some(value.to_string()),
                        }),
                        _ => {}
                    }
                }
            }

            end = result.end();
            current = result.start() + 1;
        }
        Parser { tags }
    }
}

fn get_header_value<'a>(session: &'a Session, key: &str) -> Option<&'a str> {
    if let Some(value) = session.get_header(key) {
        if let Ok(value) = value.to_str() {
            return Some(value);
        }
    }
    None
}

impl Parser {
    pub fn format(&self, session: &Session, ctx: &State) -> String {
        let mut buf = String::with_capacity(1024);
        for tag in self.tags.iter() {
            match tag.category {
                TagCategory::Fill => {
                    if let Some(data) = &tag.data {
                        buf.push_str(data);
                    }
                }
                TagCategory::Host => {
                    if let Some(host) = session.req_header().uri.host() {
                        buf.push_str(host);
                    }
                }
                TagCategory::Method => {
                    buf.push_str(session.req_header().method.as_str());
                }
                TagCategory::Path => {
                    buf.push_str(session.req_header().uri.path());
                }
                TagCategory::Proto => {
                    if session.is_http2() {
                        buf.push_str("HTTP/2.0");
                    } else {
                        buf.push_str("HTTP/1.1");
                    }
                }
                TagCategory::Query => {
                    if let Some(query) = session.req_header().uri.query() {
                        buf.push_str(query);
                    }
                }
                TagCategory::Remote => {
                    // TODO
                }
                TagCategory::ClientIp => {
                    if let Some(value) = get_header_value(session, "X-Forwarded-For") {
                        let arr: Vec<&str> = value.split(',').collect();
                        if !arr.is_empty() {
                            buf.push_str(arr[0].trim());
                        }
                    } else if let Some(value) = get_header_value(session, "X-Real-Ip") {
                        buf.push_str(value);
                    }
                }
                TagCategory::Scheme => {
                    // TODO
                }
                TagCategory::Uri => {
                    buf.push_str(&session.req_header().uri.to_string());
                }
                TagCategory::Referer => {
                    if let Some(value) = get_header_value(session, "Referer") {
                        buf.push_str(value);
                    }
                }
                TagCategory::UserAgent => {
                    if let Some(value) = get_header_value(session, "User-Agent") {
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
                    }
                }
                TagCategory::Latency => {
                    let d = Instant::now().duration_since(ctx.created_at);
                    buf.push_str(&d.as_millis().to_string())
                }
                TagCategory::LatencyHuman => {
                    let d = Instant::now().duration_since(ctx.created_at);
                    buf.push_str(&format!("{d:?}"));
                }
                TagCategory::Cookie => {
                    let cookie_name = tag.data.clone().unwrap_or_default();
                    let cookie_value = get_header_value(session, "Cookie").unwrap_or_default();
                    for item in cookie_value.split(';') {
                        let arr: Vec<&str> = item.split('=').collect();
                        if arr.len() != 2 {
                            continue;
                        }
                        if arr[0] == cookie_name {
                            buf.push_str(arr[1]);
                        }
                    }
                }
                TagCategory::RequestHeader => {
                    if let Some(key) = &tag.data {
                        if let Some(value) = get_header_value(session, key) {
                            buf.push_str(value);
                        }
                    }
                }
                TagCategory::ResponseHeader => {
                    // TODO
                }
                TagCategory::PayloadSize => {
                    // TODO
                }
                TagCategory::PayloadSizeHuman => {
                    // TODO
                }
            };
        }

        buf
    }
}
