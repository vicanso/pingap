use super::state::State;
use bytes::{BufMut, BytesMut};
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
    RealIp,
    ClientIp,
    Scheme,
    Uri,
    Referer,
    UserAgent,
    When,
    WhenIso,
    WhenIsoMs,
    WhenUtcIso,
    WhenUnix,
    WhenUtcIsoMs,
    Size,
    SizeHuman,
    Status,
    Latency,
    LatencyHuman,
    Cookie,
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
        let reg = Regex::new(r"(\{[a-zA-Z_-]+*\})").unwrap();
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
                "{real-ip}" => tags.push(Tag {
                    category: TagCategory::RealIp,
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
                "{when-iso}" => tags.push(Tag {
                    category: TagCategory::WhenIso,
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
                "{when-iso-ms}" => tags.push(Tag {
                    category: TagCategory::WhenIsoMs,
                    data: None,
                }),
                "{when-utc-iso-ms}" => tags.push(Tag {
                    category: TagCategory::WhenUtcIsoMs,
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
                    let ch = key.substring(0, 1);
                    let value = key.substring(1, key.len());
                    match ch {
                        "~" => tags.push(Tag {
                            category: TagCategory::Cookie,
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

impl Parser {
    pub fn format(&self, session: &Session, state: &State) -> String {
        let mut buf = BytesMut::with_capacity(1024);
        for tag in self.tags.iter() {
            match tag.category {
                TagCategory::Fill => {
                    if let Some(data) = &tag.data {
                        buf.put(data.as_bytes());
                    }
                }
                TagCategory::Host => {
                    if let Some(host) = session.req_header().uri.host() {
                        buf.put(host.as_bytes());
                    }
                }
                TagCategory::Method => {
                    buf.put(session.req_header().method.as_str().as_bytes());
                }
                TagCategory::Path => {
                    buf.put(session.req_header().uri.path().as_bytes());
                }
                TagCategory::Proto => {
                    if session.is_http2() {
                        buf.put(&b"HTTP/2.0"[..]);
                    } else {
                        buf.put(&b"HTTP/1.1"[..]);
                    }
                }
                TagCategory::Query => {
                    if let Some(query) = session.req_header().uri.query() {
                        buf.put(query.as_bytes());
                    }
                }
                TagCategory::Uri => {
                    buf.put(session.req_header().raw_path());
                }
                TagCategory::WhenIso => {
                    buf.put(chrono::Utc::now().to_rfc3339().as_bytes());
                }
                TagCategory::Latency => {
                    let d = Instant::now().duration_since(state.created_at);
                    buf.put(d.as_millis().to_string().as_bytes())
                }
                TagCategory::LatencyHuman => {
                    let d = Instant::now().duration_since(state.created_at);
                    // d.to_string();
                    buf.put(format!("{d:?}").as_bytes());
                }
                _ => {}
            };
        }

        std::string::String::from_utf8_lossy(&buf).to_string()
    }
}
