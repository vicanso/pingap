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
    Error, get_bool_conf, get_hash_key, get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use http::HeaderValue;
use http::header::HeaderName;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::ModifiedMode;
use pingap_core::client_used_https;
use pingap_core::{
    Ctx, HttpHeader, Plugin, ResponsePluginResult, convert_header,
    convert_header_value, resolve_static_header_value,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::borrow::Cow;
use std::str::FromStr;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// ResponseHeaders plugin handles HTTP response header modifications.
/// It provides functionality to add, remove, set, and rename response headers
/// based on configuration provided in TOML format.
pub struct ResponseHeaders {
    /// Headers to be appended to the response
    /// - Allows multiple values for the same header name
    /// - Preserves any existing header values
    /// - Format: Vec of (header_name, header_value) pairs
    ///   Example: [("x-service", "1"), ("x-service", "2")]
    add_headers: Vec<HttpHeader>,

    /// Headers to be completely removed from the response
    /// - Removes all values for specified header names
    /// - Headers are removed regardless of their values
    ///   Example: ["content-type", "x-powered-by"]
    remove_headers: Vec<HeaderName>,

    /// Headers to be set with specific values
    /// - Overwrites any existing values for the header
    /// - If header doesn't exist, it will be created
    /// - Format: Vec of (header_name, header_value) pairs
    ///   Example: [("x-response-id", "123")]
    set_headers: Vec<HttpHeader>,

    /// Headers to be renamed while preserving their values
    /// - Format: Vec of (original_name, new_name) tuples
    /// - Values are moved from original name to new name
    /// - If new name already exists, values are appended
    ///   Example: [("x-old-header", "x-new-header")]
    rename_headers: Vec<(HeaderName, HeaderName)>,

    /// Headers to be set only if they don't already exist in the response
    /// - Only sets the header if it's not present
    /// - Does not modify existing header values
    /// - Format: Vec of (header_name, header_value) pairs
    ///   Example: [("x-default-header", "default-value")]
    set_headers_not_exists: Vec<HttpHeader>,

    /// The headers of a `preset`, set where the response has none of
    /// the name: what the upstream or a rule of this plugin says of one of
    /// them stands.
    preset_headers: Vec<HttpHeader>,

    /// Whether the preset has `Strict-Transport-Security`, which is only
    /// for a response that went out over TLS.
    preset_hsts: bool,

    /// Whether the rules are also for what did not come from the
    /// upstream: the response another plugin of the location answers
    /// with, and the error page of the proxy itself.
    always: bool,

    // upstream or response
    mode: ModifiedMode,

    /// Unique identifier for this plugin instance
    /// Generated from the plugin configuration to track changes
    hash_value: String,
}

/// A year, which is what browsers and the preload lists go by.
static HSTS: HttpHeader = (
    http::header::STRICT_TRANSPORT_SECURITY,
    HeaderValue::from_static("max-age=31536000"),
);

/// The headers of the `security` preset: what a site is usually better off
/// with, and what is left out of an error page more often than not.
fn security_preset() -> Vec<HttpHeader> {
    vec![
        (
            http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        (
            http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("SAMEORIGIN"),
        ),
        (
            http::header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ),
    ]
}

impl TryFrom<&PluginConf> for ResponseHeaders {
    type Error = Error;

    /// Attempts to create a ResponseHeaders plugin from a plugin configuration.
    ///
    /// # Arguments
    /// * `value` - The plugin configuration containing header modification rules
    ///
    /// # Returns
    /// * `Ok(ResponseHeaders)` - Successfully created plugin instance
    /// * `Err(Error)` - If configuration is invalid or step is not "response"
    ///
    /// # Configuration Format
    /// ```toml
    /// step = "response"
    /// add_headers = ["Header-Name:Value"]
    /// remove_headers = ["Header-Name"]
    /// set_headers = ["Header-Name:Value"]
    /// rename_headers = ["Old-Name:New-Name"]
    /// ```
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate unique hash for this plugin configuration
        let hash_value = get_hash_key(value);

        let invalid = |message: String| Error::Invalid {
            category: PluginCategory::ResponseHeaders.to_string(),
            message,
        };
        // `name:value`, the name a header name. An entry without the
        // colon used to be dropped without a word, and the plugin went on
        // to do less than its configuration says.
        let headers_of = |key: &str| -> Result<Vec<HttpHeader>> {
            get_str_slice_conf(value, key)
                .iter()
                .map(|item| {
                    let header = convert_header(item)
                        .map_err(|e| invalid(e.to_string()))?;
                    let (name, value) = header.ok_or_else(|| {
                        invalid(format!("{key}: {item:?} should be name:value"))
                    })?;
                    Ok((name, resolve_static_header_value(value)))
                })
                .collect()
        };
        let add_headers = headers_of("add_headers")?;
        let set_headers = headers_of("set_headers")?;
        let set_headers_not_exists = headers_of("set_headers_not_exists")?;

        let mut remove_headers = vec![];
        for item in get_str_slice_conf(value, "remove_headers").iter() {
            let item = HeaderName::from_str(item)
                .map_err(|e| invalid(e.to_string()))?;
            remove_headers.push(item);
        }
        let mut rename_headers = vec![];
        for item in get_str_slice_conf(value, "rename_headers").iter() {
            let (k, v) = item
                .split_once(':')
                .map(|(k, v)| (k.trim(), v.trim()))
                .ok_or_else(|| {
                    invalid(format!(
                        "rename_headers: {item:?} should be old-name:new-name"
                    ))
                })?;
            let original_name =
                HeaderName::from_str(k).map_err(|e| invalid(e.to_string()))?;
            let new_name =
                HeaderName::from_str(v).map_err(|e| invalid(e.to_string()))?;
            rename_headers.push((original_name, new_name));
        }

        // A mode that is not one of the two was the default one: a typo in
        // `upstream` moved the headers to the other hook, where a cached
        // response does not get them stored.
        let mode = match get_str_conf(value, "mode").as_str() {
            "" | "response" => ModifiedMode::Response,
            "upstream" => ModifiedMode::Upstream,
            other => {
                return Err(invalid(format!(
                    "mode should be response or upstream, got {other:?}"
                )));
            },
        };

        let (preset_headers, preset_hsts) =
            match get_str_conf(value, "preset").as_str() {
                "" => (vec![], false),
                "security" => (security_preset(), true),
                other => {
                    return Err(invalid(format!(
                        "preset should be security, got {other:?}"
                    )));
                },
            };
        // The response of another plugin and the error page never pass
        // the hook of the upstream's response, which is the one
        // `mode = "upstream"` is for.
        let always = get_bool_conf(value, "always");
        if always && mode == ModifiedMode::Upstream {
            return Err(invalid(
                "always is for mode response, the upstream mode only sees what the upstream sent"
                    .to_string(),
            ));
        }

        let params = Self {
            hash_value,
            add_headers,
            set_headers,
            remove_headers,
            rename_headers,
            set_headers_not_exists,
            preset_headers,
            preset_hsts,
            always,
            mode,
        };

        Ok(params)
    }
}

impl ResponseHeaders {
    /// Creates a new ResponseHeaders plugin instance from the given configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration containing header modification rules
    ///
    /// # Returns
    /// * `Ok(ResponseHeaders)` - Successfully created plugin instance
    /// * `Err(Error)` - If configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new response headers plugin"
        );
        Self::try_from(params)
    }

    #[inline]
    fn handle_headers(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        // Headers are processed in a specific order to ensure predictable behavior:
        // 1. Add new headers (allows multiple values)
        //    - Uses append_header which preserves existing values
        //    - Supports dynamic value substitution via convert_header_value
        // 2. Remove specified headers
        //    - Completely removes headers regardless of value
        // 3. Set headers (overwrites existing values)
        //    - Uses insert_header which replaces any existing values
        //    - Supports dynamic value substitution via convert_header_value
        // 4. Rename headers (moves values to new header name)
        //    - Removes original header and moves its value to new name
        //    - If new name already exists, value is appended

        // A dynamic value that does not resolve is emitted as configured.
        let resolve = |value: &HeaderValue, session: &Session, ctx: &Ctx| {
            convert_header_value(value, session, ctx)
                .unwrap_or_else(|| value.clone())
        };

        // Add new headers (append mode)
        for (name, value) in &self.add_headers {
            let value = resolve(value, session, ctx);
            let _ = upstream_response.append_header(name, value);
        }

        // Remove specified headers
        for name in &self.remove_headers {
            let _ = upstream_response.remove_header(name);
        }

        // Set headers (overwrite mode)
        for (name, value) in &self.set_headers {
            let value = resolve(value, session, ctx);
            let _ = upstream_response.insert_header(name, value);
        }

        // Set headers that don't exist (conditional set)
        for (name, value) in &self.set_headers_not_exists {
            if !upstream_response.headers.contains_key(name) {
                let value = resolve(value, session, ctx);
                let _ = upstream_response.insert_header(name, value);
            }
        }

        // The preset, where nothing above and nothing from the upstream
        // has said otherwise.
        for (name, value) in &self.preset_headers {
            if !upstream_response.headers.contains_key(name) {
                let _ = upstream_response.insert_header(name, value);
            }
        }
        // Over TLS only: a browser takes no notice of it on plain http,
        // and on a site that has no https it would be a promise of one.
        // TLS as the client has it, which behind a trusted proxy that
        // ends it is not this connection.
        if self.preset_hsts
            && !upstream_response.headers.contains_key(&HSTS.0)
            && client_used_https(session, ctx)
        {
            let _ = upstream_response.insert_header(&HSTS.0, &HSTS.1);
        }

        // Rename headers: every value moves. `remove_header` hands back
        // only the first of a multi-valued header, so renaming
        // `Set-Cookie` used to keep one cookie and drop the rest.
        for (original_name, new_name) in &self.rename_headers {
            let values: Vec<HeaderValue> = upstream_response
                .headers
                .get_all(original_name)
                .iter()
                .cloned()
                .collect();
            if values.is_empty() {
                continue;
            }
            upstream_response.remove_header(original_name);
            for value in values {
                let _ = upstream_response.append_header(new_name, value);
            }
        }
        Ok(ResponsePluginResult::Modified)
    }
}

#[async_trait]
impl Plugin for ResponseHeaders {
    /// Returns the unique hash key for this plugin instance.
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handle upstream response header modifications.
    #[inline]
    fn handle_upstream_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if self.mode != ModifiedMode::Upstream {
            return Ok(ResponsePluginResult::Unchanged);
        }
        self.handle_headers(session, ctx, upstream_response)
    }

    /// Handles response header modifications during the response phase.
    ///
    /// # Arguments
    /// * `session` - Current HTTP session
    /// * `ctx` - Plugin state context
    /// * `upstream_response` - Response headers to modify
    ///
    /// # Processing Order
    /// 1. Add new headers (preserving existing values)
    /// 2. Remove specified headers
    /// 3. Set headers (overwriting existing values)
    /// 4. Rename headers (moving values to new names)
    ///
    /// # Returns
    /// * `Ok(())` - Headers processed successfully
    /// * `Err(...)` - If a critical error occurs
    ///
    /// Note: Individual header operation failures are ignored to ensure
    /// the response can still be processed.
    #[inline]
    async fn handle_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if self.mode == ModifiedMode::Upstream {
            return Ok(ResponsePluginResult::Unchanged);
        }
        self.handle_headers(session, ctx, upstream_response)
    }

    /// With `always`, a `401` of an auth plugin, a redirect or the error
    /// page for an upstream that is down leaves with the same headers as
    /// everything else of the location. They are the responses a security
    /// header is most often missing from.
    #[inline]
    fn handles_plugin_response(&self) -> bool {
        self.always
    }
}

register_plugin!("response_headers", ResponseHeaders);

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::Ctx;
    use pingora::http::ResponseHeader;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// `preset = "security"` and `always`: the usual security headers,
    /// where nothing has set them, on every response of the location.
    #[tokio::test]
    async fn test_response_headers_preset_and_always() {
        let new = |conf: &str| {
            ResponseHeaders::new(&toml::from_str::<PluginConf>(conf).unwrap())
        };
        let headers_after =
            async |plugin: &ResponseHeaders,
                   tls: bool,
                   upstream: &[(&str, &str)]| {
                let mock_io =
                    Builder::new().read(b"GET / HTTP/1.1\r\n\r\n").build();
                let mut session = Session::new_h1(Box::new(mock_io));
                session.read_request().await.unwrap();
                let mut ctx = Ctx::default();
                if tls {
                    ctx.conn.tls_version = Some("TLSv1.3".into());
                }
                let mut header = ResponseHeader::build(200, None).unwrap();
                for (name, value) in upstream {
                    header
                        .insert_header(name.to_string(), value.to_string())
                        .unwrap();
                }
                plugin
                    .handle_response(&mut session, &mut ctx, &mut header)
                    .await
                    .unwrap();
                let mut headers: Vec<String> = header
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        format!("{name}: {}", value.to_str().unwrap())
                    })
                    .collect();
                headers.sort();
                headers
            };

        let preset = new("preset = \"security\"").unwrap();
        assert_eq!(false, preset.handles_plugin_response());
        assert_eq!(
            vec![
                "referrer-policy: strict-origin-when-cross-origin",
                "x-content-type-options: nosniff",
                "x-frame-options: SAMEORIGIN",
            ],
            headers_after(&preset, false, &[]).await
        );
        // `Strict-Transport-Security` is for a response that went out
        // over TLS, and what the upstream says of a header stands.
        assert_eq!(
            vec![
                "referrer-policy: strict-origin-when-cross-origin",
                "strict-transport-security: max-age=31536000",
                "x-content-type-options: nosniff",
                "x-frame-options: DENY",
            ],
            headers_after(&preset, true, &[("X-Frame-Options", "DENY")]).await
        );
        assert_eq!(
            true,
            headers_after(
                &preset,
                true,
                &[("Strict-Transport-Security", "max-age=60")]
            )
            .await
            .contains(&"strict-transport-security: max-age=60".to_string())
        );
        // And so does a rule of the plugin itself.
        let own = new(
            "preset = \"security\"\nset_headers = [\"Referrer-Policy: no-referrer\"]",
        )
        .unwrap();
        assert_eq!(
            true,
            headers_after(&own, false, &[])
                .await
                .contains(&"referrer-policy: no-referrer".to_string())
        );

        // `always`: also for what another plugin answers and for the
        // error page, which is what `handles_plugin_response` is asked
        // for.
        let always = new("preset = \"security\"\nalways = true").unwrap();
        assert_eq!(true, always.handles_plugin_response());
        assert_eq!(false, new("").unwrap().handles_plugin_response());

        let error = |conf: &str| new(conf).err().unwrap().to_string();
        assert_eq!(
            "Plugin response_headers invalid, message: preset should be security, got \"strict\"",
            error("preset = \"strict\"")
        );
        assert_eq!(
            "Plugin response_headers invalid, message: always is for mode response, the upstream mode only sees what the upstream sent",
            error("always = true\nmode = \"upstream\"")
        );
    }

    /// Regression: an entry without its colon was dropped, and a mode that
    /// is neither of the two was the default one. Either way the plugin
    /// did something else than its configuration says, without a word.
    #[test]
    fn test_response_headers_rejects_what_it_would_ignore() {
        let error = |conf: &str| {
            ResponseHeaders::try_from(
                &toml::from_str::<PluginConf>(conf).unwrap(),
            )
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
        };
        // spellchecker:off
        assert_eq!(
            true,
            error("mode = \"upstrem\"").contains("response or upstream")
        );
        // spellchecker:on
        for key in ["add_headers", "set_headers", "set_headers_not_exists"] {
            let message = error(&format!("{key} = [\"X-Frame-Options DENY\"]"));
            assert_eq!(
                true,
                message.contains("name:value"),
                "{key}: {message}"
            );
        }
        assert_eq!(
            true,
            error("rename_headers = [\"X-Old\"]").contains("old-name:new-name")
        );
        for conf in [
            "",
            "mode = \"upstream\"",
            "mode = \"response\"",
            "add_headers = [\"X-A:1\"]\nrename_headers = [\"X-Old:X-New\"]",
        ] {
            assert_eq!("", error(conf), "{conf}");
        }
    }

    /// Tests parsing of plugin configuration parameters.
    ///
    /// Verifies:
    /// - Valid configuration is parsed correctly
    /// - Headers are properly formatted
    /// - Invalid step returns appropriate error
    #[test]
    fn test_response_headers_params() {
        let params = ResponseHeaders::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
add_headers = [
"X-Service:1",
"X-Service:2",
]
set_headers = [
"X-Response-Id:123"
]
remove_headers = [
"Content-Type"
]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            r#"[("x-service", "1"), ("x-service", "2")]"#,
            format!("{:?}", params.add_headers)
        );
        assert_eq!(
            r#"[("x-response-id", "123")]"#,
            format!("{:?}", params.set_headers)
        );
        assert_eq!(
            r#"["content-type"]"#,
            format!("{:?}", params.remove_headers)
        );
    }

    /// Tests header modification functionality.
    ///
    /// Verifies:
    /// - Headers are added correctly
    /// - Headers are removed as specified
    /// - Headers are set with new values
    /// - Response contains expected final headers
    #[tokio::test]
    async fn test_response_headers() {
        let response_headers = ResponseHeaders::new(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
add_headers = [
    "X-Service:1",
    "X-Service:2",
]
set_headers = [
    "X-Response-Id:123"
]
remove_headers = [
    "Content-Type"
]
set_headers_not_exists = [
    "X-Response-Id:abc",
    "X-Tag:userTag",
]
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();

        upstream_response
            .append_header("Content-Type", "application/json")
            .unwrap();

        response_headers
            .handle_response(
                &mut session,
                &mut Ctx::default(),
                &mut upstream_response,
            )
            .await
            .unwrap();

        assert_eq!(
            r###"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"x-service": "1", "x-service": "2", "x-response-id": "123", "x-tag": "userTag"} }, header_name_map: None, reason_phrase: None }"###,
            format!("{upstream_response:?}")
        )
    }

    /// Renaming moves every value of a multi-valued header.
    #[tokio::test]
    async fn test_rename_keeps_every_value() {
        let response_headers = ResponseHeaders::new(
            &toml::from_str::<PluginConf>(
                r###"
rename_headers = ["Set-Cookie: X-Set-Cookie", "X-Missing: X-Other"]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let mock_io = Builder::new().read(b"GET / HTTP/1.1\r\n\r\n").build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();
        upstream_response
            .append_header("Set-Cookie", "a=1")
            .unwrap();
        upstream_response
            .append_header("Set-Cookie", "b=2")
            .unwrap();
        response_headers
            .handle_response(
                &mut session,
                &mut Ctx::default(),
                &mut upstream_response,
            )
            .await
            .unwrap();
        let moved: Vec<&str> = upstream_response
            .headers
            .get_all("X-Set-Cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        assert_eq!(vec!["a=1", "b=2"], moved);
        assert_eq!(false, upstream_response.headers.contains_key("Set-Cookie"));
        assert_eq!(false, upstream_response.headers.contains_key("X-Other"));
    }
}
