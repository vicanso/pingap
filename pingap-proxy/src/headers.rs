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

use pingap_core::{Ctx, convert_header_value};
use pingora::http::RequestHeader;
use pingora::proxy::Session;

/// Returns true when the header value may contain a `$…` / `:…` substitution.
#[inline]
fn is_dynamic_header_value(value: &http::HeaderValue) -> bool {
    let buf = value.as_bytes();
    !buf.is_empty() && (buf[0] == b'$' || buf[0] == b':')
}

/// Sets or appends proxy-related headers before forwarding request
/// Handles both default reverse proxy headers and custom configured headers
#[inline]
pub fn set_append_proxy_headers(
    session: &Session,
    ctx: &Ctx,
    header: &mut RequestHeader,
) {
    if let Some(location) = &ctx.upstream.location_instance
        && let Some(headers) = location.headers()
    {
        for (k, v, append) in headers {
            // Static values skip convert_header_value entirely (common for
            // proxy_set_headers / proxy_add_headers without `$` substitutions).
            let value = if is_dynamic_header_value(v) {
                convert_header_value(v, session, ctx)
                    .unwrap_or_else(|| v.clone())
            } else {
                v.clone()
            };
            if *append {
                let _ = header.append_header(k, value);
            } else {
                let _ = header.insert_header(k, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::set_append_proxy_headers;
    use pingap_config::LocationConf;
    use pingap_core::Ctx;
    use pingap_location::Location;
    use pingora::{http::RequestHeader, proxy::Session};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use tokio_test::io::Builder;

    async fn new_session() -> Session {
        let headers = [
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
            "X-Uuid: 138q71",
            "X-Forwarded-For: 1.1.1.1, 192.168.1.2",
        ]
        .join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?key=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    #[tokio::test]
    async fn test_set_append_proxy_headers() {
        let session = new_session().await;
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some("192.168.1.3".into());
        ctx.conn.server_port = Some(8080);
        let mut header = RequestHeader::build("GET", b"/", None).unwrap();
        let location = Arc::new(
            Location::new(
                "test",
                &LocationConf {
                    enable_reverse_proxy_headers: Some(true),
                    proxy_add_headers: Some(vec![
                        "x-server:123".to_string(),
                        "x-server:456".to_string(),
                    ]),
                    proxy_set_headers: Some(vec!["x-trace-id:ab".to_string()]),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        ctx.upstream.location_instance = Some(location);
        set_append_proxy_headers(&session, &ctx, &mut header);

        assert_eq!(
            "192.168.1.3",
            header.headers.get("x-real-ip").unwrap().to_str().unwrap()
        );
        assert_eq!(
            "1.1.1.1, 192.168.1.2, 192.168.1.3",
            header
                .headers
                .get("x-forwarded-for")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "http",
            header
                .headers
                .get("x-forwarded-proto")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "github.com",
            header
                .headers
                .get("x-forwarded-host")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "8080",
            header
                .headers
                .get("x-forwarded-port")
                .unwrap()
                .to_str()
                .unwrap()
        );

        assert_eq!(
            "123,456",
            header
                .headers
                .get_all("x-server")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            "ab",
            header.headers.get("x-trace-id").unwrap().to_str().unwrap()
        );
    }

    #[tokio::test]
    async fn test_set_append_proxy_protocol_tlv_headers() {
        let session = new_session().await;
        let mut ctx = Ctx::default();
        ctx.conn.proxy_protocol_tlvs =
            Some(Arc::new(pingap_core::ProxyProtocolTlvs {
                alpn: Some("h2".to_string()),
                authority: Some("app.example.com".to_string()),
                unique_id: Some("conn-123".to_string()),
                netns: Some("ns-prod".to_string()),
                tls_version: Some("TLSv1.3".to_string()),
                tls_cn: Some("client.example".to_string()),
                tls_cipher: Some("TLS_AES_128_GCM_SHA256".to_string()),
                aws_vpce_id: Some("vpce-12345".to_string()),
                custom: vec![(0xE1, b"custom-tag".to_vec())],
            }));
        let mut header = RequestHeader::build("GET", b"/", None).unwrap();
        let location = Arc::new(
            Location::new(
                "test-pp-tlvs",
                &LocationConf {
                    proxy_set_headers: Some(vec![
                        "x-pp-alpn:$proxy_protocol_alpn".to_string(),
                        "x-pp-authority:$proxy_protocol_authority".to_string(),
                        "x-pp-unique-id:$proxy_protocol_unique_id".to_string(),
                        "x-pp-netns:$proxy_protocol_netns".to_string(),
                        "x-pp-tls-ver:$proxy_protocol_tls_version".to_string(),
                        "x-pp-tls-cn:$proxy_protocol_tls_cn".to_string(),
                        "x-pp-tls-cipher:$proxy_protocol_tls_cipher"
                            .to_string(),
                        "x-pp-vpce:$proxy_protocol_aws_vpce_id".to_string(),
                        "x-pp-custom:$proxy_protocol_tlv_0xe1".to_string(),
                    ]),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        ctx.upstream.location_instance = Some(location);
        set_append_proxy_headers(&session, &ctx, &mut header);

        assert_eq!(
            "h2",
            header.headers.get("x-pp-alpn").unwrap().to_str().unwrap()
        );
        assert_eq!(
            "app.example.com",
            header
                .headers
                .get("x-pp-authority")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "conn-123",
            header
                .headers
                .get("x-pp-unique-id")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "ns-prod",
            header.headers.get("x-pp-netns").unwrap().to_str().unwrap()
        );
        assert_eq!(
            "TLSv1.3",
            header
                .headers
                .get("x-pp-tls-ver")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "client.example",
            header.headers.get("x-pp-tls-cn").unwrap().to_str().unwrap()
        );
        assert_eq!(
            "TLS_AES_128_GCM_SHA256",
            header
                .headers
                .get("x-pp-tls-cipher")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "vpce-12345",
            header.headers.get("x-pp-vpce").unwrap().to_str().unwrap()
        );
        assert_eq!(
            "custom-tag",
            header.headers.get("x-pp-custom").unwrap().to_str().unwrap()
        );
    }
}
