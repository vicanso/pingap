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

use pingora::proxy::Session;
use std::borrow::Cow;

/// A pre-parsed, efficient representation of the hash strategy.
#[derive(PartialEq)]
pub enum HashStrategy {
    Url,
    Ip,
    Header(String),
    Cookie(String),
    Query(String),
    Path, // Default
}

impl HashStrategy {
    /// Gets the value to use for consistent hashing.
    /// This is optimized to avoid allocations where possible.
    pub fn get_value<'a>(
        &self,
        session: &'a Session,
        client_ip: &'a Option<String>,
    ) -> Cow<'a, str> {
        match self {
            HashStrategy::Url => {
                Cow::Owned(session.req_header().uri.to_string())
            },
            HashStrategy::Ip => {
                if let Some(ip) = client_ip {
                    Cow::Borrowed(ip)
                } else {
                    Cow::Owned(pingap_core::get_client_ip(session))
                }
            },
            HashStrategy::Header(key) => {
                pingap_core::get_req_header_value(session.req_header(), key)
                    .map(Cow::Borrowed)
                    .unwrap_or(Cow::Borrowed(""))
            },
            HashStrategy::Cookie(key) => {
                pingap_core::get_cookie_value(session.req_header(), key)
                    .map(Cow::Borrowed)
                    .unwrap_or(Cow::Borrowed(""))
            },
            HashStrategy::Query(key) => {
                pingap_core::get_query_value(session.req_header(), key)
                    .map(Cow::Borrowed)
                    .unwrap_or(Cow::Borrowed(""))
            },
            HashStrategy::Path => {
                Cow::Borrowed(session.req_header().uri.path())
            },
        }
    }
}

impl From<(&str, &str)> for HashStrategy {
    fn from(tuple: (&str, &str)) -> Self {
        match tuple.0 {
            "url" => HashStrategy::Url,
            "ip" => HashStrategy::Ip,
            "header" => HashStrategy::Header(tuple.1.to_string()),
            "cookie" => HashStrategy::Cookie(tuple.1.to_string()),
            "query" => HashStrategy::Query(tuple.1.to_string()),
            _ => HashStrategy::Path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HashStrategy;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_new_hash_strategy() {
        assert!(HashStrategy::Url == HashStrategy::from(("url", "")));
        assert!(HashStrategy::Ip == HashStrategy::from(("ip", "")));
        assert!(
            HashStrategy::Header("User-Agent".to_string())
                == HashStrategy::from(("header", "User-Agent"))
        );
        assert!(
            HashStrategy::Cookie("deviceId".to_string())
                == HashStrategy::from(("cookie", "deviceId"))
        );
        assert!(
            HashStrategy::Query("id".to_string())
                == HashStrategy::from(("query", "id"))
        );
        assert!(HashStrategy::Path == HashStrategy::from(("", "")));
    }

    #[tokio::test]
    async fn test_get_hash_key_value() {
        let headers = [
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
            "X-Forwarded-For: 1.1.1.1",
        ]
        .join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?id=1234 HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();

        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        assert_eq!(
            "/vicanso/pingap?id=1234",
            HashStrategy::Url.get_value(&session, &None)
        );

        assert_eq!("1.1.1.1", HashStrategy::Ip.get_value(&session, &None));
        assert_eq!(
            "2.2.2.2",
            HashStrategy::Ip.get_value(&session, &Some("2.2.2.2".to_string()))
        );

        assert_eq!(
            "pingap/0.1.1",
            HashStrategy::Header("User-Agent".to_string())
                .get_value(&session, &None)
        );

        assert_eq!(
            "abc",
            HashStrategy::Cookie("deviceId".to_string())
                .get_value(&session, &None)
        );
        assert_eq!(
            "1234",
            HashStrategy::Query("id".to_string()).get_value(&session, &None)
        );
        assert_eq!(
            "/vicanso/pingap",
            HashStrategy::Path.get_value(&session, &None)
        );
    }
}
