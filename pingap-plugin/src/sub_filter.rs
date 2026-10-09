// Copyright 2025 Tree xie.
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
    Error, body_will_change, get_hash_key, get_str_conf, get_str_slice_conf,
    is_partial_content,
};
use async_trait::async_trait;
use bstr::ByteSlice;
use bytes::{Bytes, BytesMut};
use bytesize::ByteSize;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http::{Method, StatusCode};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_TRANSFER_CHUNKED, ModifyResponseBody, Plugin, PluginStep,
    RequestPluginResult, ResponseBodyPluginResult, ResponsePluginResult,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use regex::Regex;
use regex::bytes::RegexBuilder;
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};

const PLUGIN_ID: &str = "_sub_filter_";

type Result<T, E = Error> = std::result::Result<T, E>;

/// SubFilter plugin for modifying response content using pattern matching and replacement.
/// This plugin supports two types of content replacement:
/// 1. Regex-based replacement (subs_filter)
/// 2. Literal string replacement (sub_filter)
pub struct SubFilter {
    /// The name this instance keeps its body handler under, see
    /// `new_body_handler_id`.
    handler_id: String,
    /// Regex pattern that matches against request paths
    /// Only requests with matching paths will be processed by this filter
    path: Option<Regex>,

    /// The rules, in order. Shared with every response's replacer, so
    /// starting one costs a reference count rather than a copy of every
    /// pattern and replacement.
    filters: Arc<[SubFilterParams]>,

    /// Unique identifier for this plugin instance
    /// Used for tracking and managing multiple instances of the plugin
    hash_value: String,

    /// Status codes to apply the filter to
    /// If None, the filter will be applied to all status codes
    /// If Some, the filter will be applied to the specified status codes
    /// The status codes are in the format of "200,201,202,..."
    status_codes: Option<Vec<u16>>,

    /// The content types whose responses are rewritten, as prefixes in
    /// lower case (`text/html`, `application/json`, `text/`). `None` is
    /// every response, whatever it is: an image or a download is then
    /// held in memory to its end and searched like a page.
    types: Option<Vec<String>>,

    /// The largest body that is rewritten. A larger one is passed on as
    /// it came: the rules are applied to a whole body, which is held in
    /// memory until its end. `None` is no limit.
    max_size: Option<usize>,
}

// Regular expression for parsing filter rules in the format:
// subs_filter|sub_filter 'pattern' 'replacement' [flags]
//
// Either of the two in single or in double quotes, so that a text with
// the one kind of quote in it is written in the other, and a replacement
// may be empty: what is found is taken out. `'[^']+'` twice had no way
// to say either.
static SUBS_FILTER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(subs_filter|sub_filter)\s+(?:'([^']+)'|"([^"]+)")\s+(?:'([^']*)'|"([^"]*)")(?:\s+([ig]+))?"#,
    )
    .expect("Failed to compile subs filter regex")
});

/// Parameters for configuring a single substitution filter rule
#[derive(Debug)]
struct SubFilterParams {
    /// Compiled regex pattern for `subs_filter` type replacements
    /// - None for literal string replacements (sub_filter)
    /// - Some(regex) for pattern-based replacements (subs_filter)
    regex_pattern: Option<regex::bytes::Regex>,

    /// Raw bytes pattern for `sub_filter` type replacements
    /// Only used when regex_pattern is None
    /// Stores the literal string to search for as UTF-8 bytes
    pattern: Vec<u8>,

    /// The content to substitute in place of matches
    /// Stored as UTF-8 bytes to support both text and binary replacements
    replacement: Vec<u8>,

    /// The `g` flag: replace every occurrence rather than the first.
    global: bool,
}

impl SubFilterParams {
    /// Applies this rule to `data`, which is returned untouched (no
    /// allocation) when nothing matches.
    fn apply(&self, data: Vec<u8>) -> Vec<u8> {
        if let Some(regex_pattern) = &self.regex_pattern {
            let replaced = if self.global {
                regex_pattern.replace_all(&data, &self.replacement)
            } else {
                regex_pattern.replace(&data, &self.replacement)
            };
            match replaced {
                Cow::Borrowed(_) => data,
                Cow::Owned(replaced) => replaced,
            }
        } else if data.find(&self.pattern).is_none() {
            data
        } else if self.global {
            data.replace(&self.pattern, &self.replacement)
        } else {
            data.replacen(&self.pattern, &self.replacement, 1)
        }
    }
}

/// Parses a substitution filter rule string into structured parameters.
///
/// # Arguments
/// * `rule` - A string in the format: "subs_filter|sub_filter 'pattern' 'replacement' [flags]"
///
/// # Returns
/// * `Option<SubFilterParams>` - Parsed parameters or None if parsing fails
fn parse_subs_filter(rule: &str) -> Option<SubFilterParams> {
    let captures = SUBS_FILTER_REGEX.captures(rule)?;
    let flags = captures.get(6).map(|m| m.as_str()).unwrap_or_default();
    let pattern = captures.get(2).or_else(|| captures.get(3))?.as_str();
    let replacement = captures.get(4).or_else(|| captures.get(5))?.as_str();
    let mut params = SubFilterParams {
        regex_pattern: None,
        pattern: vec![],
        replacement: replacement.as_bytes().to_vec(),
        global: flags.contains('g'),
    };
    if captures.get(1)?.as_str() == "subs_filter" {
        params.regex_pattern = Some(
            RegexBuilder::new(pattern)
                .case_insensitive(flags.contains('i'))
                .build()
                .ok()?,
        );
    } else {
        params.pattern = pattern.as_bytes().to_vec();
    }
    Some(params)
}

/// Buffers one response's body and applies the rules to it at the end.
struct SubFilterReplacer {
    filters: Arc<[SubFilterParams]>,
    buffer: BytesMut,
    /// The most that is held, see `SubFilter::max_size`.
    max_size: Option<usize>,
    /// The body turned out larger than that: what was held has gone out
    /// as it came, and the rest follows as it comes.
    passing: bool,
}

impl ModifyResponseBody for SubFilterReplacer {
    fn handle(
        &mut self,
        _session: &Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if self.passing {
            return Ok(());
        }
        if let Some(data) = body {
            self.buffer.extend_from_slice(data);
            data.clear();
        }
        // A body whose length was not known when the response began, and
        // that is larger than what is rewritten: nothing of it is.
        if self.max_size.is_some_and(|max| self.buffer.len() > max) {
            self.passing = true;
            *body = Some(std::mem::take(&mut self.buffer).freeze());
            return Ok(());
        }
        if !end_of_stream {
            return Ok(());
        }
        // The buffer becomes the working copy outright instead of being
        // duplicated, and a rule only allocates when it changes something.
        let mut data: Vec<u8> = std::mem::take(&mut self.buffer).into();
        for item in self.filters.iter() {
            data = item.apply(data);
        }
        *body = Some(Bytes::from(data));
        Ok(())
    }
    fn name(&self) -> &str {
        "sub_filter"
    }
}

/// Responses whose body is not there to rewrite: HEAD answers, 1xx, 204,
/// 304, a part of a body (206), and anything compressed, which is opaque
/// bytes to the rules.
fn has_no_rewritable_body(
    session: &Session,
    upstream_response: &ResponseHeader,
) -> bool {
    let status = upstream_response.status;
    session.req_header().method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || is_partial_content(upstream_response)
        || upstream_response.headers.get(CONTENT_ENCODING).is_some_and(
            |value| !value.as_bytes().eq_ignore_ascii_case(b"identity"),
        )
}

impl TryFrom<&PluginConf> for SubFilter {
    type Error = Error;

    /// Creates a SubFilter instance from plugin configuration
    ///
    /// # Arguments
    /// * `value` - Plugin configuration containing path, filters, and other settings
    ///
    /// # Returns
    /// * `Result<Self>` - Configured SubFilter instance or error if configuration is invalid
    fn try_from(value: &PluginConf) -> Result<Self> {
        let invalid = |message: String| Error::Invalid {
            category: PluginCategory::SubFilter.to_string(),
            message,
        };
        let path_value = get_str_conf(value, "path");
        let path = if path_value.is_empty() {
            None
        } else {
            Some(Regex::new(&path_value).map_err(|e| invalid(e.to_string()))?)
        };
        let filters = get_str_slice_conf(value, "filters")
            .iter()
            .map(|s| {
                parse_subs_filter(s)
                    .ok_or_else(|| invalid(format!("invalid subs filter: {s}")))
            })
            .collect::<Result<Vec<_>>>()?;
        let status_codes = get_str_conf(value, "status_codes");
        let status_codes = if !status_codes.is_empty() {
            // A code that does not parse used to be dropped, which widened
            // the filter to every status when it was the only one.
            Some(
                status_codes
                    .split(',')
                    .map(|s| {
                        s.trim().parse::<u16>().map_err(|e| {
                            invalid(format!("invalid status code({s}): {e}"))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            )
        } else {
            None
        };
        let types: Vec<String> = get_str_slice_conf(value, "types")
            .iter()
            .map(|item| item.trim().to_ascii_lowercase())
            .filter(|item| !item.is_empty())
            .collect();
        let max_size = get_str_conf(value, "max_size");
        let max_size = if max_size.trim().is_empty() {
            None
        } else {
            let size = ByteSize::from_str(max_size.trim()).map_err(|e| {
                invalid(format!("invalid max_size({max_size}): {e}"))
            })?;
            // Nothing would ever be rewritten.
            if size.as_u64() == 0 {
                return Err(invalid(
                    "max_size should be more than 0".to_string(),
                ));
            }
            Some(usize::try_from(size.as_u64()).unwrap_or(usize::MAX))
        };
        let hash_value = get_hash_key(value);

        Ok(Self {
            path,
            filters: filters.into(),
            hash_value,
            handler_id: crate::new_body_handler_id(PLUGIN_ID),
            status_codes,
            types: (!types.is_empty()).then_some(types),
            max_size,
        })
    }
}

impl SubFilter {
    /// Creates a new SubFilter instance from plugin configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Self>` - Configured SubFilter instance or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for SubFilter {
    /// Returns a unique identifier for this plugin instance
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Takes the range off a request whose response is to be rewritten.
    ///
    /// The rules are applied to a whole body. A part of one is passed on
    /// as it is (see `has_no_rewritable_body`), and which of the two a
    /// response is was the client's to choose: `Range: bytes=0-` got the
    /// body unrewritten from an upstream that answers `206`, and from the
    /// cache every time, where pingora cuts the range out of the stored
    /// response itself. Without the header there is only the whole body;
    /// a server is free to answer a range request with all of it.
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }
        if let Some(regex) = &self.path
            && !regex.is_match(session.req_header().uri.path())
        {
            return Ok(RequestPluginResult::Skipped);
        }
        let header = session.req_header_mut();
        if header.headers.contains_key(http::header::RANGE) {
            header.remove_header(&http::header::RANGE);
            header.remove_header(&http::header::IF_RANGE);
        }
        Ok(RequestPluginResult::Continue)
    }

    /// Handles the response phase of the HTTP request/response lifecycle
    ///
    /// # Arguments
    /// * `session` - HTTP session information
    /// * `ctx` - Plugin state context
    /// * `upstream_response` - Response headers from upstream server
    ///
    /// # Returns
    /// * `pingora::Result<()>` - Success or error status
    async fn handle_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if let Some(status_codes) = &self.status_codes
            && !status_codes.contains(&upstream_response.status.as_u16())
        {
            return Ok(ResponsePluginResult::Unchanged);
        }
        if has_no_rewritable_body(session, upstream_response) {
            return Ok(ResponsePluginResult::Unchanged);
        }
        // If request path matches, modify the response
        if let Some(regex) = &self.path
            && !regex.is_match(session.req_header().uri.path())
        {
            return Ok(ResponsePluginResult::Unchanged);
        }
        // Only what is of a type the rules are for.
        if let Some(types) = &self.types
            && !crate::compression::matches_types(
                types,
                &upstream_response.headers,
            )
        {
            return Ok(ResponsePluginResult::Unchanged);
        }
        // A body that says it is larger than what is rewritten goes
        // through as it is, streamed and with its length.
        if let Some(max_size) = self.max_size
            && upstream_response
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .is_some_and(|length| length > max_size as u64)
        {
            return Ok(ResponsePluginResult::Unchanged);
        }

        // Remove content-length since we're modifying the body
        upstream_response.remove_header(&http::header::CONTENT_LENGTH);
        body_will_change(upstream_response);
        // Switch to chunked transfer encoding
        let _ = upstream_response.insert_header(
            http::header::TRANSFER_ENCODING,
            HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
        );
        // Set up the response body modifier
        ctx.add_modify_body_handler(
            &self.handler_id,
            Box::new(SubFilterReplacer {
                filters: self.filters.clone(),
                buffer: BytesMut::new(),
                max_size: self.max_size,
                passing: false,
            }),
        );
        Ok(ResponsePluginResult::Modified)
    }
    fn handle_response_body(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        if let Some(modifier) = ctx.get_modify_body_handler(&self.handler_id) {
            modifier.handle(session, body, end_of_stream)?;
            let result = if end_of_stream {
                ResponseBodyPluginResult::FullyReplaced
            } else {
                ResponseBodyPluginResult::PartialReplaced
            };
            Ok(result)
        } else {
            Ok(ResponseBodyPluginResult::Unchanged)
        }
    }
}

register_plugin!("sub_filter", SubFilter);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_parse_subs_filter() {
        let rule = "subs_filter 'http://pingap.io' 'https://pingap.io/api' ig";
        let params = parse_subs_filter(rule).unwrap();
        assert_eq!(params.regex_pattern.unwrap().as_str(), "http://pingap.io");
        assert_eq!(params.pattern, b"");
        assert_eq!(params.replacement, b"https://pingap.io/api");
        assert_eq!(true, params.global);

        let rule = "sub_filter 'http://pingap.io' 'https://pingap.io/api'";
        let params = parse_subs_filter(rule).unwrap();
        assert_eq!(params.regex_pattern.is_none(), true);
        assert_eq!(params.pattern, b"http://pingap.io");
        assert_eq!(params.replacement, b"https://pingap.io/api");
        assert_eq!(false, params.global);

        assert_eq!(true, parse_subs_filter("sub_filter 'a'").is_none());
        assert_eq!(true, parse_subs_filter("subs_filter '(' 'b'").is_none());
    }

    /// Each rule applied to a body, one behaviour per case.
    #[test]
    fn test_apply() {
        let apply = |rule: &str, data: &[u8]| {
            String::from_utf8(
                parse_subs_filter(rule).unwrap().apply(data.to_vec()),
            )
            .unwrap()
        };
        let data = b"http://pingap.io http://PinGap.io http://pingap.io";
        assert_eq!(
            "https://pingap.io/api https://pingap.io/api https://pingap.io/api",
            apply(
                "subs_filter 'http://pingap.io' 'https://pingap.io/api' ig",
                data
            )
        );
        assert_eq!(
            "https://pingap.io/api http://PinGap.io https://pingap.io/api",
            apply(
                "subs_filter 'http://pingap.io' 'https://pingap.io/api' g",
                data
            )
        );
        assert_eq!(
            "https://pingap.io/api http://PinGap.io http://pingap.io",
            apply(
                "subs_filter 'http://pingap.io' 'https://pingap.io/api'",
                data
            )
        );
        assert_eq!(
            "https://pingap.io/api http://PinGap.io http://pingap.io",
            apply(
                "sub_filter 'http://pingap.io' 'https://pingap.io/api'",
                data
            )
        );
        assert_eq!(
            "https://pingap.io/api http://PinGap.io https://pingap.io/api",
            apply(
                "sub_filter 'http://pingap.io' 'https://pingap.io/api' g",
                data
            )
        );
        // Capture groups, and a rule that matches nothing.
        assert_eq!(
            "<title>Docs - x</title>",
            apply(
                "subs_filter '<title>(.*?)</title>' '<title>Docs - $1</title>'",
                b"<title>x</title>"
            )
        );
        assert_eq!("untouched", apply("sub_filter 'zzz' 'y' g", b"untouched"));
    }

    async fn new_session(input: &str) -> Session {
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    fn new_plugin(extra: &str) -> SubFilter {
        SubFilter::try_from(
            &toml::from_str::<PluginConf>(&format!(
                "filters = [\"sub_filter 'old' 'new' g\"]\n{extra}"
            ))
            .unwrap(),
        )
        .unwrap()
    }

    /// The body arrives in chunks and is rewritten as a whole at the end.
    #[tokio::test]
    async fn test_sub_filter() {
        let plugin = new_plugin("status_codes = \"200, 201\"");
        assert_eq!(Some(vec![200, 201]), plugin.status_codes);
        let mut session = new_session("GET / HTTP/1.1\r\n\r\n").await;
        let mut ctx = Ctx::default();
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.append_header("Content-Length", "7").unwrap();
        let result = plugin
            .handle_response(&mut session, &mut ctx, &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
        assert_eq!(false, resp.headers.contains_key("Content-Length"));

        let mut body = Some(Bytes::from_static(b"old "));
        let result = plugin
            .handle_response_body(&mut session, &mut ctx, &mut body, false)
            .unwrap();
        assert_eq!(ResponseBodyPluginResult::PartialReplaced, result);
        assert_eq!(true, body.as_ref().unwrap().is_empty());
        let mut body = Some(Bytes::from_static(b"old"));
        let result = plugin
            .handle_response_body(&mut session, &mut ctx, &mut body, true)
            .unwrap();
        assert_eq!(ResponseBodyPluginResult::FullyReplaced, result);
        assert_eq!(b"new new".as_ref(), body.unwrap().as_ref());

        // A status outside the list is left alone.
        let mut resp = ResponseHeader::build(404, None).unwrap();
        let result = plugin
            .handle_response(&mut session, &mut Ctx::default(), &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);

        let err = SubFilter::try_from(
            &toml::from_str::<PluginConf>("status_codes = \"200,abc\"")
                .unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert_eq!(true, err.contains("invalid status code(abc)"), "{err}");
    }

    /// A rule may take something out, and may have a quote of the one
    /// kind in a text that is written in the other.
    #[test]
    fn test_parse_empty_replacement_and_quotes() {
        let apply = |rule: &str, data: &str| {
            let rule = parse_subs_filter(rule).unwrap();
            String::from_utf8(rule.apply(data.as_bytes().to_vec())).unwrap()
        };
        assert_eq!("a  c", apply("sub_filter 'b' ''", "a b c"));
        assert_eq!("a c", apply("subs_filter 'b ' \"\" g", "a b c"));
        assert_eq!(
            "it is here",
            apply("sub_filter \"it's\" 'it is'", "it's here")
        );
        assert_eq!(
            "say \"hi\"",
            apply("sub_filter 'hello' '\"hi\"'", "say hello")
        );
        assert_eq!("x1y", apply("subs_filter \"a'+\" '1' i", "xA'y"));
        // As before: nothing to look for is no rule.
        assert_eq!(true, parse_subs_filter("sub_filter '' 'x'").is_none());
        assert_eq!(true, parse_subs_filter("sub_filter \"\" 'x'").is_none());
    }

    /// `types`: only what is of a type the rules are for is held and
    /// rewritten. `max_size`: nor what is too large to be held.
    #[tokio::test]
    async fn test_sub_filter_types_and_max_size() {
        let handled = async |plugin: &SubFilter, headers: &[(&str, &str)]| {
            let mut session = new_session("GET / HTTP/1.1\r\n\r\n").await;
            let mut ctx = Ctx::default();
            let mut resp = ResponseHeader::build(200, None).unwrap();
            for (name, value) in headers {
                resp.append_header(name.to_string(), *value).unwrap();
            }
            let result = plugin
                .handle_response(&mut session, &mut ctx, &mut resp)
                .await
                .unwrap();
            (result == ResponsePluginResult::Modified, session, ctx, resp)
        };

        let plugin =
            new_plugin("types = [\"text/html\", \" Application/JSON \"]");
        for (content_type, expected) in [
            (Some("text/html"), true),
            (Some("text/html; charset=utf-8"), true),
            (Some("TEXT/HTML"), true),
            (Some("application/json"), true),
            (Some("text/css"), false),
            (Some("image/png"), false),
            (Some("application/octet-stream"), false),
            // nothing is known of it
            (None, false),
        ] {
            let headers: Vec<(&str, &str)> = content_type
                .iter()
                .map(|value| ("Content-Type", *value))
                .collect();
            let (rewritten, _, _, resp) = handled(&plugin, &headers).await;
            assert_eq!(expected, rewritten, "{content_type:?}");
            // What is left alone keeps its length and is streamed.
            if !expected {
                assert_eq!(
                    false,
                    resp.headers.contains_key("Transfer-Encoding")
                );
            }
        }
        // Without the option every type is, as before.
        let (rewritten, ..) =
            handled(&new_plugin(""), &[("Content-Type", "image/png")]).await;
        assert_eq!(true, rewritten);

        // A length over the limit: not touched at all.
        let plugin = new_plugin("max_size = \"10b\"");
        assert_eq!(Some(10), plugin.max_size);
        let (rewritten, _, _, resp) =
            handled(&plugin, &[("Content-Length", "11")]).await;
        assert_eq!(false, rewritten);
        assert_eq!(true, resp.headers.contains_key("Content-Length"));
        let (rewritten, ..) =
            handled(&plugin, &[("Content-Length", "10")]).await;
        assert_eq!(true, rewritten);

        // No length given, and more than the limit comes: what was held
        // goes out as it came when the limit is passed, the rest as it
        // comes, and none of it is rewritten.
        let (rewritten, mut session, mut ctx, _) = handled(&plugin, &[]).await;
        assert_eq!(true, rewritten);
        let mut out = vec![];
        for (chunk, end) in [
            ("old old ", false),
            ("old ", false),
            ("old", false),
            ("", true),
        ] {
            let mut body = Some(Bytes::copy_from_slice(chunk.as_bytes()));
            plugin
                .handle_response_body(&mut session, &mut ctx, &mut body, end)
                .unwrap();
            out.push(String::from_utf8(body.unwrap().to_vec()).unwrap());
        }
        assert_eq!(vec!["", "old old old ", "old", ""], out);
        // Within the limit it is rewritten as ever.
        let (_, mut session, mut ctx, _) = handled(&plugin, &[]).await;
        let mut body = Some(Bytes::from_static(b"old old"));
        plugin
            .handle_response_body(&mut session, &mut ctx, &mut body, true)
            .unwrap();
        assert_eq!(b"new new".as_ref(), body.unwrap().as_ref());

        for (conf, message) in [
            ("max_size = \"lots\"", "invalid max_size(lots)"),
            ("max_size = \"0\"", "max_size should be more than 0"),
        ] {
            let err = SubFilter::try_from(
                &toml::from_str::<PluginConf>(conf).unwrap(),
            )
            .err()
            .unwrap()
            .to_string();
            assert_eq!(true, err.contains(message), "{err}");
        }
    }

    /// Regression: two sub_filter plugins on one location shared one
    /// handler slot. The second took the place of the first and then ran
    /// twice: its rule was applied two times and the other's not at all.
    #[tokio::test]
    async fn test_two_sub_filters_on_one_request() {
        let new_filter = |rule: &str| {
            SubFilter::try_from(
                &toml::from_str::<PluginConf>(&format!(
                    "filters = [\"{rule}\"]"
                ))
                .unwrap(),
            )
            .unwrap()
        };
        // `a` becomes `ab`, then `b` becomes `bb`: `a` ends as `abb`.
        let first = new_filter("sub_filter 'a' 'ab' g");
        let second = new_filter("sub_filter 'b' 'bb' g");
        assert_ne!(first.handler_id, second.handler_id);

        let mut session = new_session("GET / HTTP/1.1\r\n\r\n").await;
        let mut ctx = Ctx::default();
        let mut resp = ResponseHeader::build(200, None).unwrap();
        for plugin in [&first, &second] {
            let result = plugin
                .handle_response(&mut session, &mut ctx, &mut resp)
                .await
                .unwrap();
            assert_eq!(ResponsePluginResult::Modified, result);
        }
        let mut body = Some(Bytes::from_static(b"a-b"));
        for plugin in [&first, &second] {
            plugin
                .handle_response_body(&mut session, &mut ctx, &mut body, true)
                .unwrap();
        }
        // It used to be `a-bbbb`: the second rule twice, the first never.
        assert_eq!(b"abb-bb".as_ref(), body.unwrap().as_ref());
    }

    /// Nothing to rewrite: HEAD, 204, 304, or a compressed body.
    #[tokio::test]
    async fn test_sub_filter_leaves_bodiless_responses() {
        let plugin = new_plugin("");
        let mut session = new_session("GET / HTTP/1.1\r\n\r\n").await;
        for status in [204, 304, 100] {
            let mut resp = ResponseHeader::build(status, None).unwrap();
            let result = plugin
                .handle_response(&mut session, &mut Ctx::default(), &mut resp)
                .await
                .unwrap();
            assert_eq!(ResponsePluginResult::Unchanged, result, "{status}");
        }
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.append_header("Content-Encoding", "gzip").unwrap();
        resp.append_header("Content-Length", "7").unwrap();
        let result = plugin
            .handle_response(&mut session, &mut Ctx::default(), &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);
        assert_eq!(true, resp.headers.contains_key("Content-Length"));

        let mut session = new_session("HEAD / HTTP/1.1\r\n\r\n").await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        let result = plugin
            .handle_response(&mut session, &mut Ctx::default(), &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);
    }

    /// A part of a body is not rewritten, so a request must not be able to
    /// ask for one: with `Range: bytes=0-` the whole body came back as a
    /// `206`, past the rules.
    #[tokio::test]
    async fn test_sub_filter_takes_the_range_off_the_request() {
        let ranged = async |plugin: &SubFilter, path: &str| {
            let mut session = new_session(&format!(
                "GET {path} HTTP/1.1\r\nRange: bytes=0-\r\nIf-Range: \"v1\"\r\n\r\n"
            ))
            .await;
            let result = plugin
                .handle_request(
                    PluginStep::Request,
                    &mut session,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            let headers = &session.req_header().headers;
            (
                result,
                headers.contains_key("Range")
                    || headers.contains_key("If-Range"),
            )
        };
        let plugin = new_plugin("");
        assert_eq!(
            (RequestPluginResult::Continue, false),
            ranged(&plugin, "/").await
        );
        // Only where the plugin rewrites.
        let scoped = new_plugin("path = \"^/docs\"");
        assert_eq!(
            (RequestPluginResult::Continue, false),
            ranged(&scoped, "/docs/a").await
        );
        assert_eq!(
            (RequestPluginResult::Skipped, true),
            ranged(&scoped, "/files/a").await
        );
    }

    /// Regression: the part of a body a range request got was rewritten
    /// like a whole one, under the `Content-Range` of the original; and a
    /// rewritten body kept the upstream's strong `ETag` and
    /// `Accept-Ranges`.
    #[tokio::test]
    async fn test_sub_filter_and_the_validators() {
        let plugin = new_plugin("");
        let mut session = new_session("GET / HTTP/1.1\r\n\r\n").await;
        let response = |status: u16| {
            let mut resp = ResponseHeader::build(status, None).unwrap();
            resp.append_header("Content-Length", "100").unwrap();
            resp.append_header("ETag", "\"v1\"").unwrap();
            resp.append_header("Accept-Ranges", "bytes").unwrap();
            resp
        };

        let mut part = response(206);
        part.append_header("Content-Range", "bytes 0-99/4000")
            .unwrap();
        let result = plugin
            .handle_response(&mut session, &mut Ctx::default(), &mut part)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);
        assert_eq!(true, part.headers.contains_key("Content-Length"));
        assert_eq!("\"v1\"", part.headers.get("ETag").unwrap());

        let mut whole = response(200);
        let result = plugin
            .handle_response(&mut session, &mut Ctx::default(), &mut whole)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
        assert_eq!("W/\"v1\"", whole.headers.get("ETag").unwrap());
        assert_eq!(false, whole.headers.contains_key("Accept-Ranges"));
    }
}
