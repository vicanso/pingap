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
    get_hash_key, get_plugin_factory, get_str_conf, get_str_slice_conf, Error,
};
use async_trait::async_trait;
use bstr::ByteSlice;
use bytes::{Bytes, BytesMut};
use ctor::ctor;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, ModifyResponseBody, Plugin, ResponseBodyPluginResult,
    ResponsePluginResult, HTTP_HEADER_TRANSFER_CHUNKED,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use regex::bytes::RegexBuilder;
use regex::Regex;
use std::borrow::Cow;
use std::sync::Arc;
use std::sync::LazyLock;

const PLUGIN_ID: &str = "_sub_filter_";

type Result<T, E = Error> = std::result::Result<T, E>;

/// SubFilter plugin for modifying response content using pattern matching and replacement.
/// This plugin supports two types of content replacement:
/// 1. Regex-based replacement (subs_filter)
/// 2. Literal string replacement (sub_filter)
pub struct SubFilter {
    /// Regex pattern that matches against request paths
    /// Only requests with matching paths will be processed by this filter
    path: Regex,

    /// The content replacement engine that handles both regex and literal replacements
    /// Contains a collection of filter rules that will be applied in sequence
    replacer: SubFilterReplacer,

    /// Unique identifier for this plugin instance
    /// Used for tracking and managing multiple instances of the plugin
    hash_value: String,
}

// Regular expression for parsing filter rules in the format:
// subs_filter|sub_filter 'pattern' 'replacement' [flags]
static SUBS_FILTER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(subs_filter|sub_filter)\s+'([^']+)'\s+'([^']+)'(?:\s+([ig]+))?",
    )
    .expect("Failed to compile subs filter regex")
});

/// Parameters for configuring a single substitution filter rule
#[derive(Debug, Default, Clone)]
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

    /// Special flags that modify the replacement behavior:
    /// - 'i': case-insensitive matching
    /// - 'g': global replacement (replace all occurrences)
    ///   If 'g' is not present, only the first match is replaced
    flags: Vec<char>,
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

    let mut params = SubFilterParams {
        flags: captures
            .get(4)
            .map(|m| m.as_str().chars().collect())
            .unwrap_or_default(),
        replacement: captures.get(3)?.as_str().as_bytes().to_vec(),
        ..Default::default()
    };

    let pattern = captures.get(2)?.as_str();

    match captures.get(1)?.as_str() {
        "subs_filter" => {
            let regex_pattern = RegexBuilder::new(pattern)
                .case_insensitive(params.flags.contains(&'i'))
                .build()
                .ok()?;
            params.regex_pattern = Some(regex_pattern);
        },
        _ => {
            params.pattern = pattern.as_bytes().to_vec();
        },
    };

    Some(params)
}

/// Handles the actual content replacement logic for both regex and literal string replacements
#[derive(Debug, Default, Clone)]
struct SubFilterReplacer {
    filters: Vec<SubFilterParams>,
    buffer: BytesMut,
}

impl ModifyResponseBody for SubFilterReplacer {
    /// Processes the response body data by applying all configured filters
    ///
    /// # Arguments
    /// * `data` - The response body bytes to be modified
    ///
    /// # Returns
    /// * `Bytes` - The modified response body
    fn handle(
        &mut self,
        _session: &Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if let Some(data) = body {
            self.buffer.extend(&data[..]);
            data.clear();
        }
        if !end_of_stream {
            return Ok(());
        }
        let mut data = self.buffer.to_vec();
        for item in self.filters.iter() {
            if let Some(regex_pattern) = &item.regex_pattern {
                // Handle regex-based replacement (subs_filter)
                if item.flags.contains(&'g') {
                    // Global replacement - replace all occurrences
                    data = regex_pattern
                        .replace_all(&data, &item.replacement)
                        .to_vec();
                } else {
                    // Replace first occurrence only
                    data = regex_pattern
                        .replace(&data, &item.replacement)
                        .to_vec();
                }
            } else {
                // Handle literal string replacement (sub_filter)
                if item.flags.contains(&'g') {
                    // Global replacement
                    data = data.replace(&item.pattern, &item.replacement);
                } else {
                    // Replace first occurrence only
                    data = data.replacen(&item.pattern, &item.replacement, 1);
                }
            }
        }
        *body = Some(Bytes::from(data));
        Ok(())
    }
    fn name(&self) -> String {
        "sub_filter".to_string()
    }
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
        let path =
            Regex::new(get_str_conf(value, "path").as_str()).map_err(|e| {
                Error::Invalid {
                    category: PluginCategory::SubFilter.to_string(),
                    message: e.to_string(),
                }
            })?;
        let filters = get_str_slice_conf(value, "filters")
            .iter()
            .map(|s| {
                parse_subs_filter(s).ok_or(Error::Invalid {
                    category: PluginCategory::SubFilter.to_string(),
                    message: format!("invalid subs filter: {s}"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let hash_value = get_hash_key(value);

        Ok(Self {
            path,
            replacer: SubFilterReplacer {
                filters,
                buffer: BytesMut::new(),
            },
            hash_value,
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
        // If request path matches, modify the response
        if self.path.is_match(session.req_header().uri.path()) {
            // Remove content-length since we're modifying the body
            upstream_response.remove_header(&http::header::CONTENT_LENGTH);
            // Switch to chunked transfer encoding
            let _ = upstream_response.insert_header(
                http::header::TRANSFER_ENCODING,
                HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
            );
            // Set up the response body modifier
            ctx.add_modify_body_handler(
                PLUGIN_ID,
                Box::new(self.replacer.clone()),
            );
            return Ok(ResponsePluginResult::Modified);
        }
        Ok(ResponsePluginResult::Unchanged)
    }
    fn handle_response_body(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        if let Some(modifier) = ctx.get_modify_body_handler(PLUGIN_ID) {
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

#[ctor]
fn init() {
    get_plugin_factory()
        .register("sub_filter", |params| Ok(Arc::new(SubFilter::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_subs_filter() {
        let rule = "subs_filter 'http://pingap.io' 'https://pingap.io/api' ig";
        let params = parse_subs_filter(rule).unwrap();
        // assert_eq!(params.directive, "subs_filter");
        assert_eq!(params.regex_pattern.unwrap().as_str(), "http://pingap.io");
        assert_eq!(params.pattern, b"");
        assert_eq!(params.replacement, b"https://pingap.io/api");
        assert_eq!(params.flags, vec!['i', 'g']);

        let rule = "sub_filter 'http://pingap.io' 'https://pingap.io/api' ig";
        let params = parse_subs_filter(rule).unwrap();
        assert_eq!(params.regex_pattern.is_none(), true);
        assert_eq!(params.pattern, b"http://pingap.io");
        assert_eq!(params.replacement, b"https://pingap.io/api");
        assert_eq!(params.flags, vec!['i', 'g']);
    }

    #[test]
    fn test_sub_filter_replacer() {
        // let replacer = SubFilterReplacer {
        //     filters: vec![parse_subs_filter(
        //         "subs_filter 'http://pingap.io' 'https://pingap.io/api' ig",
        //     )
        //     .unwrap()],
        //     buffer: BytesMut::new(),
        // };
        // let data = b"http://pingap.io http://PinGap.io";
        // let result = replacer.handle(Bytes::from_static(data)).unwrap();
        // assert_eq!(
        //     result,
        //     Bytes::from_static(b"https://pingap.io/api https://pingap.io/api")
        // );

        // // case sensitive
        // let replacer = SubFilterReplacer {
        //     filters: vec![parse_subs_filter(
        //         "subs_filter 'http://pingap.io' 'https://pingap.io/api' g",
        //     )
        //     .unwrap()],
        // };
        // let data = b"http://pingap.io http://PinGap.io";
        // let result = replacer.handle(Bytes::from_static(data)).unwrap();
        // assert_eq!(
        //     result,
        //     Bytes::from_static(b"https://pingap.io/api http://PinGap.io")
        // );

        // // case sensitive and not global
        // let replacer = SubFilterReplacer {
        //     filters: vec![parse_subs_filter(
        //         "subs_filter 'http://pingap.io' 'https://pingap.io/api'",
        //     )
        //     .unwrap()],
        // };
        // let data = b"http://pingap.io http://PinGap.io http://pingap.io";
        // let result = replacer.handle(Bytes::from_static(data)).unwrap();
        // assert_eq!(
        //     result,
        //     Bytes::from_static(
        //         b"https://pingap.io/api http://PinGap.io http://pingap.io"
        //     )
        // );

        // // sub filter
        // let replacer = SubFilterReplacer {
        //     filters: vec![parse_subs_filter(
        //         "sub_filter 'http://pingap.io' 'https://pingap.io/api'",
        //     )
        //     .unwrap()],
        // };
        // let data = b"http://pingap.io http://PinGap.io http://pingap.io";
        // let result = replacer.handle(Bytes::from_static(data)).unwrap();
        // assert_eq!(
        //     result,
        //     Bytes::from_static(
        //         b"https://pingap.io/api http://PinGap.io http://pingap.io"
        //     )
        // );

        // // sub filter global
        // let replacer = SubFilterReplacer {
        //     filters: vec![parse_subs_filter(
        //         "sub_filter 'http://pingap.io' 'https://pingap.io/api' g",
        //     )
        //     .unwrap()],
        // };
        // let data = b"http://pingap.io http://PinGap.io http://pingap.io";
        // let result = replacer.handle(Bytes::from_static(data)).unwrap();
        // assert_eq!(
        //     result,
        //     Bytes::from_static(
        //         b"https://pingap.io/api http://PinGap.io https://pingap.io/api"
        //     )
        // );
    }
}
