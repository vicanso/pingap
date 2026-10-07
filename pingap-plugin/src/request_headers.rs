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

use super::{Error, get_hash_key, get_step_conf_in, get_str_slice_conf};
use async_trait::async_trait;
use http::HeaderValue;
use http::header::{CONTENT_LENGTH, HOST, HeaderName, TRANSFER_ENCODING};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpHeader, Plugin, PluginStep, RequestPluginResult, convert_header,
    convert_header_value, protect_from_connection_header,
    resolve_static_header_value,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::str::FromStr;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "request_headers";

/// Changes the headers of a request before it goes on: to the plugins
/// after this one, and to the upstream.
///
/// A location could set and append headers for the upstream
/// (`proxy_set_headers`, `proxy_add_headers`) and nothing else: no header
/// could be taken off or renamed, and a set of rules could not be shared
/// by several locations. This is the counterpart of `response_headers`,
/// with the same settings and the same order.
pub struct RequestHeaders {
    /// Appended, whatever the request has under the name already.
    add_headers: Vec<HttpHeader>,
    /// Taken off, every value of them.
    remove_headers: Vec<HeaderName>,
    /// Put in place of what the request has under the name.
    set_headers: Vec<HttpHeader>,
    /// Set where the request has none under the name.
    set_headers_not_exists: Vec<HttpHeader>,
    /// Moved to another name, every value of them.
    rename_headers: Vec<(HeaderName, HeaderName)>,
    /// The names this plugin puts a header under. They are the proxy's
    /// from then on, and not for the client to call hop-by-hop: see
    /// `protect_from_connection_header`.
    own_headers: Vec<HeaderName>,
    plugin_step: PluginStep,
    hash_value: String,
}

/// Why a header is not this plugin's to change, if it is not.
///
/// `Content-Length` and `Transfer-Encoding` say how the body is framed:
/// with another length or coding than the body has, the upstream reads a
/// request that is not the one the client sent. `Host` is set again from
/// the authority of the request when a client on HTTP/2 is served by an
/// upstream on HTTP/1, after this plugin has run, so a rule for it would
/// hold for some clients and not for others; the location's
/// `proxy_set_headers` sets it for all of them.
fn not_to_change(name: &HeaderName) -> Option<&'static str> {
    if name == CONTENT_LENGTH || name == TRANSFER_ENCODING {
        Some("is not for this plugin to change")
    } else if name == HOST {
        Some("is set with proxy_set_headers of the location")
    } else {
        None
    }
}

impl TryFrom<&PluginConf> for RequestHeaders {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let step = get_step_conf_in(
            value,
            CATEGORY,
            PluginStep::Request,
            &[PluginStep::Request, PluginStep::ProxyUpstream],
        )?;
        let name_of = |key: &str, name: &str| -> Result<HeaderName> {
            let name = HeaderName::from_str(name.trim()).map_err(|_| {
                invalid(format!("{key}: {name:?} is not a header name"))
            })?;
            if let Some(reason) = not_to_change(&name) {
                return Err(invalid(format!("{key}: {name} {reason}")));
            }
            Ok(name)
        };
        // `name:value`, the name a header name. An entry without the colon
        // is an error, not a rule that is quietly left out.
        let headers_of = |key: &str| -> Result<Vec<HttpHeader>> {
            get_str_slice_conf(value, key)
                .iter()
                .map(|item| {
                    let header = convert_header(item)
                        .map_err(|e| invalid(format!("{key}: {e}")))?;
                    let (name, value) = header.ok_or_else(|| {
                        invalid(format!("{key}: {item:?} should be name:value"))
                    })?;
                    let name = name_of(key, name.as_str())?;
                    Ok((name, resolve_static_header_value(value)))
                })
                .collect()
        };
        let add_headers = headers_of("add_headers")?;
        let set_headers = headers_of("set_headers")?;
        let set_headers_not_exists = headers_of("set_headers_not_exists")?;
        let remove_headers = get_str_slice_conf(value, "remove_headers")
            .iter()
            .map(|item| name_of("remove_headers", item))
            .collect::<Result<Vec<_>>>()?;
        let rename_headers = get_str_slice_conf(value, "rename_headers")
            .iter()
            .map(|item| {
                let (from, to) = item.split_once(':').ok_or_else(|| {
                    invalid(format!(
                        "rename_headers: {item:?} should be old-name:new-name"
                    ))
                })?;
                Ok((
                    name_of("rename_headers", from)?,
                    name_of("rename_headers", to)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        let own_headers = add_headers
            .iter()
            .chain(set_headers.iter())
            .chain(set_headers_not_exists.iter())
            .map(|(name, _)| name)
            .chain(rename_headers.iter().map(|(_, to)| to))
            .cloned()
            .collect();

        Ok(Self {
            hash_value,
            add_headers,
            remove_headers,
            set_headers,
            set_headers_not_exists,
            rename_headers,
            own_headers,
            plugin_step: step,
        })
    }
}

impl RequestHeaders {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new request headers plugin"
        );
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for RequestHeaders {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Applies the rules, in the order `response_headers` applies its own:
    /// add, remove, set, set where missing, rename.
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        // The values first, from the request as it came: a `$http_x` in
        // one rule is what the client sent, whatever another rule does to
        // that header. One that does not resolve is sent as it is written.
        let resolve = |headers: &[HttpHeader]| -> Vec<HeaderValue> {
            headers
                .iter()
                .map(|(_, value)| {
                    convert_header_value(value, session, ctx)
                        .unwrap_or_else(|| value.clone())
                })
                .collect()
        };
        let add_values = resolve(&self.add_headers);
        let set_values = resolve(&self.set_headers);
        let default_values = resolve(&self.set_headers_not_exists);

        let header = session.req_header_mut();
        for ((name, _), value) in self.add_headers.iter().zip(add_values) {
            let _ = header.append_header(name, value);
        }
        for name in &self.remove_headers {
            header.remove_header(name);
        }
        for ((name, _), value) in self.set_headers.iter().zip(set_values) {
            let _ = header.insert_header(name, value);
        }
        for ((name, _), value) in
            self.set_headers_not_exists.iter().zip(default_values)
        {
            if !header.headers.contains_key(name) {
                let _ = header.insert_header(name, value);
            }
        }
        // Every value moves: `remove_header` hands back the first of a
        // header that is there several times, and the rest would be lost.
        for (from, to) in &self.rename_headers {
            let values: Vec<HeaderValue> =
                header.headers.get_all(from).iter().cloned().collect();
            if values.is_empty() {
                continue;
            }
            header.remove_header(from);
            for value in values {
                let _ = header.append_header(to, value);
            }
        }
        // What was set here goes to the upstream, whatever the client's
        // `Connection` says of these names.
        protect_from_connection_header(header, &self.own_headers);
        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("request_headers", RequestHeaders);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    fn new_plugin(conf: &str) -> Result<RequestHeaders> {
        RequestHeaders::new(&toml::from_str::<PluginConf>(conf).unwrap())
    }

    /// The headers of `request` after the plugin, as sorted `name: value`
    /// lines.
    async fn headers_after(
        plugin: &RequestHeaders,
        step: PluginStep,
        request: &str,
    ) -> (RequestPluginResult, Vec<String>) {
        let mock_io = Builder::new().read(request.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = plugin
            .handle_request(step, &mut session, &mut Ctx::default())
            .await
            .unwrap();
        let mut headers: Vec<String> = session
            .req_header()
            .headers
            .iter()
            .map(|(name, value)| {
                format!("{name}: {}", value.to_str().unwrap_or_default())
            })
            .collect();
        headers.sort();
        (result, headers)
    }

    const REQUEST: &str = "GET /api?id=1 HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\nCookie: b=2\r\nX-Old: one\r\nX-Old: two\r\nX-Keep: kept\r\nX-Client: curl\r\n\r\n";

    #[tokio::test]
    async fn test_request_headers() {
        let plugin = new_plugin(
            r#"
add_headers = ["X-Keep: added", "X-New: 1"]
remove_headers = ["Cookie"]
set_headers = ["X-Client: pingap", "X-From: $http_x_client", "X-Scheme: $scheme"]
set_headers_not_exists = ["X-Keep: default", "X-Trace: none"]
rename_headers = ["X-Old: X-Renamed", "X-Missing: X-Never"]
"#,
        )
        .unwrap();
        let (result, headers) =
            headers_after(&plugin, PluginStep::Request, REQUEST).await;
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!(
            vec![
                "host: example.com",
                // Put in place of the client's...
                "x-client: pingap",
                // ...which a rule beside it still reads as it came.
                "x-from: curl",
                // Appended to what was there, and left alone by the rule
                // that only sets what is missing.
                "x-keep: added",
                "x-keep: kept",
                "x-new: 1",
                // Both values, under the new name.
                "x-renamed: one",
                "x-renamed: two",
                "x-scheme: http",
                "x-trace: none",
            ],
            headers
        );

        // At another step than its own it does nothing.
        let (result, headers) =
            headers_after(&plugin, PluginStep::ProxyUpstream, REQUEST).await;
        assert_eq!(true, result == RequestPluginResult::Skipped);
        assert_eq!(true, headers.contains(&"cookie: a=1".to_string()));

        // The acceptance of the feature: the upstream gets no cookie.
        let plugin = new_plugin(
            "step = \"proxy_upstream\"\nremove_headers = [\"Cookie\"]",
        )
        .unwrap();
        let (result, headers) =
            headers_after(&plugin, PluginStep::ProxyUpstream, REQUEST).await;
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!(
            false,
            headers.iter().any(|header| header.starts_with("cookie")),
            "{headers:?}"
        );
    }

    /// Regression: a client that named one of the plugin's headers in
    /// its `Connection` had it removed again on the way to the upstream.
    #[tokio::test]
    async fn test_request_headers_are_not_the_clients_to_drop() {
        let plugin = new_plugin(
            r#"
add_headers = ["X-Added: 1"]
set_headers = ["X-Real-IP: $remote_addr"]
set_headers_not_exists = ["X-Trace: none"]
rename_headers = ["X-Api-Key: X-Internal-Key"]
"#,
        )
        .unwrap();
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Api-Key: k\r\nX-Mine: 1\r\nConnection: x-real-ip, X-Added, keep-alive, X-Internal-Key, X-Trace, X-Mine\r\n\r\n";
        let (_, headers) =
            headers_after(&plugin, PluginStep::Request, request).await;
        let connection: Vec<_> = headers
            .iter()
            .filter(|header| header.starts_with("connection:"))
            .collect();
        // Its own header the client may still call hop-by-hop.
        assert_eq!(vec!["connection: keep-alive, X-Mine"], connection);
    }

    #[test]
    fn test_request_headers_params() {
        let error = |conf: &str| new_plugin(conf).err().unwrap().to_string();
        let prefix = "Plugin request_headers invalid, message: ";
        for (conf, message) in [
            (
                r#"set_headers = ["X-Client"]"#,
                r#"set_headers: "X-Client" should be name:value"#,
            ),
            (
                r#"remove_headers = ["X Bad"]"#,
                r#"remove_headers: "X Bad" is not a header name"#,
            ),
            (
                r#"rename_headers = ["X-Old"]"#,
                r#"rename_headers: "X-Old" should be old-name:new-name"#,
            ),
            (
                r#"rename_headers = ["X-Old: X New"]"#,
                r#"rename_headers: " X New" is not a header name"#,
            ),
            // What says how the body is framed stays as it is.
            (
                r#"remove_headers = ["Content-Length"]"#,
                "remove_headers: content-length is not for this plugin to change",
            ),
            (
                r#"set_headers = ["Transfer-Encoding: chunked"]"#,
                "set_headers: transfer-encoding is not for this plugin to change",
            ),
            // Set for every client by the location, and only there.
            (
                r#"set_headers = ["Host: internal.example.com"]"#,
                "set_headers: host is set with proxy_set_headers of the location",
            ),
            (
                r#"rename_headers = ["X-Host: Host"]"#,
                "rename_headers: host is set with proxy_set_headers of the location",
            ),
            (
                r#"step = "response""#,
                "Invalid step(response), expect one of: request, proxy_upstream",
            ),
        ] {
            assert_eq!(format!("{prefix}{message}"), error(conf), "{conf}");
        }
        // Nothing to do is not an error.
        assert_eq!(true, new_plugin("").is_ok());
    }
}
