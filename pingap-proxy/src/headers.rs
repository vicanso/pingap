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

use once_cell::sync::Lazy;
use pingap_core::{convert_header_value, convert_headers, Ctx, HttpHeader};
use pingap_location::Location;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use std::sync::Arc;

// proxy_set_header X-Real-IP $remote_addr;
// proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
// proxy_set_header X-Forwarded-Proto $scheme;
// proxy_set_header X-Forwarded-Host $host;
// proxy_set_header X-Forwarded-Port $server_port;

static DEFAULT_PROXY_SET_HEADERS: Lazy<Vec<HttpHeader>> = Lazy::new(|| {
    convert_headers(&[
        "X-Real-IP:$remote_addr".to_string(),
        "X-Forwarded-For:$proxy_add_x_forwarded_for".to_string(),
        "X-Forwarded-Proto:$scheme".to_string(),
        "X-Forwarded-Host:$host".to_string(),
        "X-Forwarded-Port:$server_port".to_string(),
    ])
    .unwrap()
});

/// Sets or appends proxy-related headers before forwarding request
/// Handles both default reverse proxy headers and custom configured headers
#[inline]
pub fn set_append_proxy_headers(
    session: &Session,
    ctx: &Ctx,
    header: &mut RequestHeader,
    location: Arc<Location>,
) {
    let default_headers = location
        .enable_reverse_proxy_headers
        .then_some(DEFAULT_PROXY_SET_HEADERS.iter())
        .into_iter()
        .flatten()
        .map(|(k, v)| (k, v, false)); // false means set, not append

    // custom set headers for location
    let custom_set_headers = location
        .proxy_set_headers
        .iter()
        .flatten() // if proxy_set_headers is None, this will produce an empty iterator
        .map(|(k, v)| (k, v, false)); // false means set, not append

    // custom add headers for location
    let custom_add_headers = location
        .proxy_add_headers
        .iter()
        .flatten() // same as proxy_set_headers
        .map(|(k, v)| (k, v, true)); // true means append, not set

    // link all iterators and iterate once
    default_headers
        .chain(custom_set_headers)
        .chain(custom_add_headers)
        .for_each(|(k, v, append)| {
            // same as the original `set_header` closure
            let value = convert_header_value(v, session, ctx)
                .unwrap_or_else(|| v.clone());

            if append {
                let _ = header.append_header(k, value);
            } else {
                let _ = header.insert_header(k, value);
            }
        });
}
