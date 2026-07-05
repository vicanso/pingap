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

//! Cache-control interpretation and cache-timing response headers, split out
//! of the `Server` `ProxyHttp` implementation to keep `server.rs` focused.
//! These are free functions (they never touched `Server`'s state).

use pingap_core::Ctx;
use pingora::cache::NoCacheReason;
use pingora::cache::cache_control::{
    CacheControl, DirectiveValue, InterpretCacheControl,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::time::Duration;

#[cfg(feature = "tracing")]
use crate::tracing::update_otel_cache_attrs;

/// Applies the cache-control policy to `c`, capping the freshness at `max_ttl`
/// and rejecting responses that must not be cached.
pub(crate) fn process_cache_control(
    c: &mut CacheControl,
    max_ttl: Option<Duration>,
) -> Result<(), NoCacheReason> {
    // no-cache, no-store, private
    if c.no_cache() || c.no_store() || c.private() {
        return Err(NoCacheReason::OriginNotCache);
    }

    // max-age=0
    if c.max_age().ok().flatten().unwrap_or_default() == 0 {
        return Err(NoCacheReason::OriginNotCache);
    }

    // set cache max ttl
    if let Some(d) = max_ttl
        && c.fresh_duration().unwrap_or_default() > d
    {
        // 更新 s-maxage 的值
        let s_maxage_value =
            itoa::Buffer::new().format(d.as_secs()).as_bytes().to_vec();
        c.directives.insert(
            "s-maxage".to_string(),
            Some(DirectiveValue(s_maxage_value)),
        );
    }

    Ok(())
}

/// Adds the `x-cache-status` / `x-cache-lookup` / `x-cache-lock` headers (and,
/// under `tracing`, the matching OpenTelemetry attributes).
#[inline]
pub(crate) fn handle_cache_headers(
    session: &Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut Ctx,
) {
    let cache_status = session.cache.phase().as_str();
    let _ = upstream_response.insert_header("x-cache-status", cache_status);

    // process lookup duration
    let lookup_duration_str = process_cache_timing(
        session.cache.lookup_duration(),
        "x-cache-lookup",
        upstream_response,
        &mut ctx.timing.cache_lookup,
    );

    // process lock duration
    let lock_duration_str = process_cache_timing(
        session.cache.lock_duration(),
        "x-cache-lock",
        upstream_response,
        &mut ctx.timing.cache_lock,
    );

    #[cfg(not(feature = "tracing"))]
    {
        let _ = lookup_duration_str;
        let _ = lock_duration_str;
    }

    // (optional) process OpenTelemetry
    #[cfg(feature = "tracing")]
    update_otel_cache_attrs(
        ctx,
        cache_status,
        lookup_duration_str,
        lock_duration_str,
    );
}

/// Writes a `<n>ms` timing header, records it on `ctx_field`, and returns the
/// human-readable duration (only used under `tracing`).
#[inline]
pub(crate) fn process_cache_timing(
    duration_opt: Option<Duration>,
    header_name: &'static str,
    resp: &mut ResponseHeader,
    ctx_field: &mut Option<i32>,
) -> String {
    if let Some(d) = duration_opt {
        let ms = d.as_millis() as i32;

        // use itoa to avoid format! heap memory allocation
        let mut buffer = itoa::Buffer::new();
        let mut value_bytes = Vec::with_capacity(6);
        value_bytes.extend_from_slice(buffer.format(ms).as_bytes());
        value_bytes.extend_from_slice(b"ms");

        let _ = resp.insert_header(header_name, value_bytes);
        *ctx_field = Some(ms);

        #[cfg(feature = "tracing")]
        return humantime::Duration::from(d).to_string();
    }
    String::new()
}
