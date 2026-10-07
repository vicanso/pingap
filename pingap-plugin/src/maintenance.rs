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

use super::{
    Error, get_bool_conf, get_hash_key, get_int_conf, get_str_conf,
    get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::header::RETRY_AFTER;
use http::{HeaderName, HeaderValue, StatusCode};
use humantime::parse_duration;
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HTTP_HEADER_CONTENT_HTML, HTTP_HEADER_CONTENT_TEXT, HttpHeader,
    HttpResponse, Plugin, PluginStep, RequestPluginResult, constant_time_eq,
    convert_header, ensure_verified_client_ip,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "maintenance";

/// Answers every request of a location with the notice that the site is
/// down for maintenance, except for those that are let through: the
/// addresses on a list, and whoever sends a header the others do not know.
///
/// A `mock` plugin could answer `503` for everyone, the people doing the
/// maintenance included, who then had no way to look at the site they
/// were working on.
pub struct Maintenance {
    /// Off, the plugin lets everything through. It is there so that the
    /// page and the list can be kept in the configuration between two
    /// maintenances and switched with one setting.
    enabled: bool,
    status: StatusCode,
    /// `Retry-After`, in seconds.
    retry_after: Option<HeaderValue>,
    /// The body and the type it is sent as.
    body: Bytes,
    content_type: HttpHeader,
    /// The client addresses that are let through.
    allow_ip_rules: Option<pingap_util::IpRules>,
    /// A request with this header and this value is let through.
    allow_header: Option<HttpHeader>,
    hash_value: String,
}

impl TryFrom<&PluginConf> for Maintenance {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        // A status that is not an error would have a client, and a cache
        // in front of it, take the notice for the page.
        let status = if value.contains_key("status") {
            u16::try_from(get_int_conf(value, "status"))
                .ok()
                .filter(|status| (400..600).contains(status))
                .and_then(|status| StatusCode::from_u16(status).ok())
                .ok_or_else(|| {
                    invalid("status must be between 400 and 599".to_string())
                })?
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        let retry_after = get_str_conf(value, "retry_after");
        let retry_after = if retry_after.is_empty() {
            None
        } else {
            let seconds = parse_duration(&retry_after)
                .map_err(|e| invalid(format!("invalid retry_after: {e}")))?
                .as_secs()
                .max(1);
            Some(HeaderValue::from(seconds))
        };
        let html = get_str_conf(value, "html");
        let message = get_str_conf(value, "message");
        if !html.is_empty() && !message.is_empty() {
            return Err(invalid(
                "message and html are two forms of one body, set one of them"
                    .to_string(),
            ));
        }
        let (body, content_type) = if !html.is_empty() {
            (Bytes::from(html), HTTP_HEADER_CONTENT_HTML.clone())
        } else if !message.is_empty() {
            (Bytes::from(message), HTTP_HEADER_CONTENT_TEXT.clone())
        } else {
            (
                Bytes::from_static(b"Service is under maintenance"),
                HTTP_HEADER_CONTENT_TEXT.clone(),
            )
        };
        let allow_ip_list = get_str_slice_conf(value, "allow_ip_list");
        let allow_ip_rules = if allow_ip_list.is_empty() {
            None
        } else {
            Some(
                pingap_util::IpRules::try_new(&allow_ip_list)
                    .map_err(|e| invalid(format!("allow_ip_list: {e}")))?,
            )
        };
        // `Name: value`, and the value is what lets a request through: a
        // name alone would be one anybody can send.
        let allow_header = get_str_conf(value, "allow_header");
        let allow_header = if allow_header.is_empty() {
            None
        } else {
            let header = convert_header(&allow_header)
                .map_err(|e| invalid(format!("allow_header: {e}")))?
                .filter(|(_, value)| !value.is_empty())
                .ok_or_else(|| {
                    invalid(format!(
                        "allow_header: {allow_header:?} should be name:value"
                    ))
                })?;
            Some(header)
        };

        Ok(Self {
            hash_value,
            // On unless it says otherwise: a plugin that is listed on a
            // location is one that is meant to act.
            enabled: !value.contains_key("enabled")
                || get_bool_conf(value, "enabled"),
            status,
            retry_after,
            body,
            content_type,
            allow_ip_rules,
            allow_header,
        })
    }
}

impl Maintenance {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new maintenance plugin"
        );
        Self::try_from(params)
    }

    /// Whether the request carries the header that lets it through. Every
    /// value of the header is looked at, each in constant time.
    fn has_allow_header(&self, session: &Session) -> bool {
        let Some((name, expected)) = &self.allow_header else {
            return false;
        };
        let name: &HeaderName = name;
        session
            .req_header()
            .headers
            .get_all(name)
            .iter()
            .any(|value| {
                constant_time_eq(value.as_bytes(), expected.as_bytes())
            })
    }
}

#[async_trait]
impl Plugin for Maintenance {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }
        if !self.enabled {
            return Ok(RequestPluginResult::Skipped);
        }
        if self.has_allow_header(session) {
            return Ok(RequestPluginResult::Continue);
        }
        // By an address the client cannot choose: its own behind trusted
        // proxies, the peer's without them.
        if let Some(rules) = &self.allow_ip_rules
            && rules
                .is_match(ensure_verified_client_ip(session, ctx))
                .unwrap_or(false)
        {
            return Ok(RequestPluginResult::Continue);
        }
        let mut builder = HttpResponse::builder(self.status)
            .header(self.content_type.clone())
            .body(self.body.clone())
            // Not for a cache to keep: it would go on answering with the
            // notice after the maintenance is over.
            .no_store();
        if let Some(retry_after) = &self.retry_after {
            builder = builder.header((RETRY_AFTER, retry_after.clone()));
        }
        Ok(RequestPluginResult::Respond(builder.finish()))
    }
}

register_plugin!("maintenance", Maintenance);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    fn new_plugin(conf: &str) -> Result<Maintenance> {
        Maintenance::new(&toml::from_str::<PluginConf>(conf).unwrap())
    }

    /// What a request from `peer` with `headers` gets: `None` when it is
    /// let through.
    async fn respond(
        plugin: &Maintenance,
        peer: &str,
        headers: &str,
    ) -> Option<HttpResponse> {
        let input = format!("GET /x HTTP/1.1\r\nHost: a\r\n{headers}\r\n");
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some(peer.to_string());
        match plugin
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap()
        {
            RequestPluginResult::Respond(resp) => Some(resp),
            _ => None,
        }
    }

    fn header_of(resp: &HttpResponse, name: &str) -> Option<String> {
        resp.headers.iter().flatten().find_map(|(key, value)| {
            (key.as_str() == name).then(|| value.to_str().unwrap().to_string())
        })
    }

    #[tokio::test]
    async fn test_maintenance() {
        // As it is with nothing set.
        let plugin = new_plugin("").unwrap();
        let resp = respond(&plugin, "1.1.1.1", "").await.unwrap();
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);
        assert_eq!(
            "Service is under maintenance",
            String::from_utf8_lossy(&resp.body)
        );
        assert_eq!(
            Some("text/plain; charset=utf-8".to_string()),
            header_of(&resp, "content-type")
        );
        assert_eq!(None, header_of(&resp, "retry-after"));

        let plugin = new_plugin(
            r#"
status = 500
retry_after = "10m"
html = "<h1>Back soon</h1>"
allow_ip_list = ["10.0.0.0/8", "192.168.1.9"]
allow_header = "X-Maintenance-Pass: s3cret"
"#,
        )
        .unwrap();
        let resp = respond(&plugin, "1.1.1.1", "").await.unwrap();
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, resp.status);
        assert_eq!("<h1>Back soon</h1>", String::from_utf8_lossy(&resp.body));
        assert_eq!(
            Some("text/html; charset=utf-8".to_string()),
            header_of(&resp, "content-type")
        );
        assert_eq!(Some("600".to_string()), header_of(&resp, "retry-after"));

        // The addresses on the list are let through, and only those. What
        // a request says of its address is not what it is taken by.
        for peer in ["10.2.3.4", "192.168.1.9"] {
            assert_eq!(
                true,
                respond(&plugin, peer, "").await.is_none(),
                "{peer}"
            );
        }
        for (peer, headers) in [
            ("192.168.1.10", ""),
            ("1.1.1.1", "X-Forwarded-For: 10.2.3.4\r\n"),
            ("1.1.1.1", "X-Real-IP: 10.2.3.4\r\n"),
        ] {
            assert_eq!(
                true,
                respond(&plugin, peer, headers).await.is_some(),
                "{peer} {headers}"
            );
        }
        // And whoever sends the header with its value.
        assert_eq!(
            true,
            respond(&plugin, "1.1.1.1", "X-Maintenance-Pass: s3cret\r\n")
                .await
                .is_none()
        );
        for headers in [
            "X-Maintenance-Pass: guess\r\n",
            "X-Maintenance-Pass: s3cret2\r\n",
            "X-Maintenance-Pass:\r\n",
        ] {
            assert_eq!(
                true,
                respond(&plugin, "1.1.1.1", headers).await.is_some(),
                "{headers}"
            );
        }

        // Switched off, it is as if it were not listed.
        let plugin = new_plugin("enabled = false").unwrap();
        assert_eq!(true, respond(&plugin, "1.1.1.1", "").await.is_none());
        let plugin = new_plugin("enabled = true").unwrap();
        assert_eq!(true, respond(&plugin, "1.1.1.1", "").await.is_some());
    }

    #[test]
    fn test_maintenance_params() {
        let error = |conf: &str| new_plugin(conf).err().unwrap().to_string();
        let prefix = "Plugin maintenance invalid, message: ";
        for status in [200, 302, 600] {
            assert_eq!(
                format!("{prefix}status must be between 400 and 599"),
                error(&format!("status = {status}"))
            );
        }
        assert_eq!(
            true,
            error(r#"retry_after = "soon""#)
                .starts_with(&format!("{prefix}invalid retry_after: ")),
        );
        assert_eq!(
            format!(
                "{prefix}message and html are two forms of one body, set one of them"
            ),
            error("message = \"a\"\nhtml = \"<p>a</p>\"")
        );
        assert_eq!(
            true,
            error(r#"allow_ip_list = ["not-an-ip"]"#)
                .starts_with(&format!("{prefix}allow_ip_list: ")),
        );
        // A header has to come with the value that lets a request through.
        for header in ["X-Pass", "X-Pass:"] {
            assert_eq!(
                format!(
                    "{prefix}allow_header: {header:?} should be name:value"
                ),
                error(&format!("allow_header = \"{header}\""))
            );
        }
    }
}
