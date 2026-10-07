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
use pingora::cache::cache_control::{
    CacheControl, DirectiveKey, DirectiveValue, InterpretCacheControl,
};
use pingora::cache::{NoCacheReason, RespCacheable};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::time::{Duration, SystemTime};

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

    // The lifetime a shared cache goes by: `s-maxage`, and `max-age` only
    // without it (RFC 9111 §5.2.2.10). An explicit zero means the response
    // must not be served without asking the origin, so it is not stored.
    // No lifetime at all is not zero: such a response, `public` alone for
    // instance, gets the default like one without `Cache-Control`.
    let fresh = c.fresh_duration();
    if fresh.is_some_and(|fresh| fresh.is_zero()) {
        return Err(NoCacheReason::OriginNotCache);
    }

    // set cache max ttl
    if let Some(d) = max_ttl
        && fresh.is_some_and(|fresh| fresh > d)
    {
        // 更新 s-maxage 的值
        let s_maxage_value =
            itoa::Buffer::new().format(d.as_secs()).as_bytes().to_vec();
        c.directives.insert(
            DirectiveKey::SMaxAge,
            Some(DirectiveValue(s_maxage_value)),
        );
    }

    Ok(())
}

/// Holds a response that is about to be stored to the rules its lifetime
/// went past when it came from `Expires`.
///
/// [`process_cache_control`] caps the lifetime `Cache-Control` names and
/// refuses one of zero. A response with `Expires` and no lifetime in
/// `Cache-Control` has neither applied to it by then: pingora reads the
/// header after that, so `Expires` a year ahead was kept for a year
/// whatever `max_ttl` said, and one in the past - `0` and `-1` are what
/// origins send to say "do not cache" - was stored on every request, an
/// entry that had expired before it was written.
pub(crate) fn limit_freshness(
    cacheable: RespCacheable,
    max_ttl: Option<Duration>,
) -> RespCacheable {
    let RespCacheable::Cacheable(mut meta) = cacheable else {
        return cacheable;
    };
    let now = SystemTime::now();
    if meta.fresh_until() <= now {
        return RespCacheable::Uncacheable(NoCacheReason::OriginNotCache);
    }
    if let Some(max_ttl) = max_ttl
        && let Some(latest) = now.checked_add(max_ttl)
    {
        // Only ever moves the expiry earlier.
        meta.expire_at(latest);
    }
    RespCacheable::Cacheable(meta)
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
    let lookup_duration = session.cache.lookup_duration();
    process_cache_timing(
        lookup_duration,
        "x-cache-lookup",
        upstream_response,
        &mut ctx.timing.cache_lookup,
    );

    // process lock duration
    let lock_duration = session.cache.lock_duration();
    process_cache_timing(
        lock_duration,
        "x-cache-lock",
        upstream_response,
        &mut ctx.timing.cache_lock,
    );

    // (optional) process OpenTelemetry
    #[cfg(feature = "tracing")]
    update_otel_cache_attrs(ctx, cache_status, lookup_duration, lock_duration);
}

/// Writes a `<n>ms` timing header and records it on `ctx_field`.
#[inline]
pub(crate) fn process_cache_timing(
    duration_opt: Option<Duration>,
    header_name: &'static str,
    resp: &mut ResponseHeader,
    ctx_field: &mut Option<i32>,
) {
    if let Some(d) = duration_opt {
        let ms = d.as_millis() as i32;

        // use itoa to avoid format! heap memory allocation
        let mut buffer = itoa::Buffer::new();
        let mut value_bytes = Vec::with_capacity(6);
        value_bytes.extend_from_slice(buffer.format(ms).as_bytes());
        value_bytes.extend_from_slice(b"ms");

        let _ = resp.insert_header(header_name, value_bytes);
        *ctx_field = Some(ms);
    }
}

#[cfg(test)]
mod tests {
    use super::{limit_freshness, process_cache_control};
    use pingora::cache::cache_control::{CacheControl, InterpretCacheControl};
    use pingora::cache::filters::resp_cacheable;
    use pingora::cache::{CacheMetaDefaults, RespCacheable};
    use pingora::http::ResponseHeader;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use std::time::SystemTime;

    fn cache_control(value: &str) -> CacheControl {
        let mut resp = ResponseHeader::build_no_case(200, None).unwrap();
        resp.append_header("Cache-Control", value).unwrap();
        CacheControl::from_resp_headers(&resp).unwrap()
    }

    /// `s-maxage` is the lifetime for a shared cache and wins over
    /// `max-age`; only an explicit zero rules the response out.
    #[test]
    fn test_process_cache_control() {
        for (value, storable) in [
            ("max-age=60", true),
            ("s-maxage=600", true),
            ("public, s-maxage=600", true),
            ("max-age=0, s-maxage=600", true),
            // no lifetime: the default applies, as without the header
            ("public", true),
            ("must-revalidate", true),
            ("max-age=0", false),
            ("s-maxage=0, max-age=600", false),
            ("no-cache", false),
            ("no-store", false),
            ("private, max-age=60", false),
        ] {
            let mut c = cache_control(value);
            assert_eq!(
                storable,
                process_cache_control(&mut c, None).is_ok(),
                "{value}"
            );
        }
    }

    /// `max_ttl` shortens a longer lifetime and leaves the rest alone.
    #[test]
    fn test_process_cache_control_max_ttl() {
        let max_ttl = Some(Duration::from_secs(60));
        for (value, expected) in [
            ("max-age=3600", Some(60)),
            ("max-age=10, s-maxage=3600", Some(60)),
            ("max-age=30", Some(30)),
            ("s-maxage=30, max-age=3600", Some(30)),
            ("public", None),
        ] {
            let mut c = cache_control(value);
            process_cache_control(&mut c, max_ttl).unwrap();
            assert_eq!(
                expected.map(Duration::from_secs),
                c.fresh_duration(),
                "{value}"
            );
        }
    }

    /// What `response_cache_filter` does with a response that has `headers`
    /// and no `Cache-Control`.
    fn stored_for(
        headers: &[(&'static str, &str)],
        max_ttl: Option<Duration>,
    ) -> Option<Duration> {
        const DEFAULTS: CacheMetaDefaults =
            CacheMetaDefaults::new(|_| Some(Duration::from_secs(1)), 0, 1);
        let mut resp = ResponseHeader::build_no_case(200, None).unwrap();
        for (name, value) in headers {
            resp.append_header(*name, *value).unwrap();
        }
        let cacheable = resp_cacheable(None, resp, false, &DEFAULTS);
        match limit_freshness(cacheable, max_ttl) {
            RespCacheable::Cacheable(meta) => Some(
                meta.fresh_until()
                    .duration_since(SystemTime::now())
                    .unwrap_or_default(),
            ),
            RespCacheable::Uncacheable(_) => None,
        }
    }

    /// Regression: `max_ttl` held a lifetime from `Cache-Control` and let
    /// one from `Expires` through, and an `Expires` that is over was
    /// stored all the same, on every request.
    #[test]
    fn test_expires_is_held_to_the_cache_rules() {
        let hour = Duration::from_secs(3600);
        let far = [("Expires", "Wed, 21 Oct 2099 07:28:00 GMT")];
        // Without a cap it is what the origin says: decades.
        assert_eq!(true, stored_for(&far, None).unwrap() > 24 * hour);
        // With one it is the cap.
        let capped = stored_for(&far, Some(hour)).unwrap();
        assert_eq!(true, capped <= hour, "{capped:?}");
        assert_eq!(true, capped > hour - Duration::from_secs(5), "{capped:?}");

        // Over already, or not a date: not stored.
        for expires in ["Wed, 21 Oct 2015 07:28:00 GMT", "0", "-1", "soon"] {
            assert_eq!(
                None,
                stored_for(&[("Expires", expires)], Some(hour)),
                "{expires}"
            );
            assert_eq!(None, stored_for(&[("Expires", expires)], None));
        }

        // Nothing said: the default second, with or without a cap.
        let default = stored_for(&[], Some(hour)).unwrap();
        assert_eq!(true, default <= Duration::from_secs(1), "{default:?}");
        assert_eq!(true, stored_for(&[], None).is_some());
    }
}
