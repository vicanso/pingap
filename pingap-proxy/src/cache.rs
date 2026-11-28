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

use http::StatusCode;
use pingap_core::{CacheUseStale, Ctx};
use pingora::cache::cache_control::{
    CacheControl, DirectiveKey, DirectiveValue, InterpretCacheControl,
};
use pingora::cache::filters::calculate_serve_stale_durations;
use pingora::cache::{
    CacheMeta, CacheMetaDefaults, NoCacheReason, RespCacheable,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::time::{Duration, SystemTime};

#[cfg(feature = "tracing")]
use crate::tracing::update_otel_cache_attrs;

/// How long a response that names no lifetime of its own stays fresh: one
/// second, and only for the statuses RFC 9110 section 15.1 lists as
/// heuristically cacheable. Anything else - a 5xx, a 302, a 401 - is only
/// stored when the origin asks for it, so one client's error is not
/// replayed to the next.
pub(crate) fn default_fresh_duration(status: StatusCode) -> Option<Duration> {
    match status.as_u16() {
        200 | 203 | 204 | 206 | 300 | 301 | 308 | 404 | 405 | 410 | 414
        | 501 => Some(Duration::from_secs(1)),
        _ => None,
    }
}

/// Builds `CacheMetaDefaults` using `default_fresh_duration` and optional
/// fallback `stale-while-revalidate` / `stale-if-error` durations (matching
/// Pingora's defaults of `0` and `1` second when unset).
pub(crate) fn meta_defaults(
    stale_while_revalidate: Option<Duration>,
    stale_if_error: Option<Duration>,
) -> CacheMetaDefaults {
    let stale_while_revalidate_sec = stale_while_revalidate
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
    let stale_if_error_sec = stale_if_error
        .map_or(1, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
    CacheMetaDefaults::new(
        default_fresh_duration,
        stale_while_revalidate_sec,
        stale_if_error_sec,
    )
}

/// Returns whether a stale cached response may be served for `error` (or
/// while updating in the background when `error` is `None`) under `use_stale`.
pub(crate) fn error_matches_use_stale(
    use_stale: Option<CacheUseStale>,
    error: Option<&pingora::Error>,
    is_h2_writer: bool,
) -> bool {
    match error {
        None => !is_h2_writer && use_stale.is_none_or(|u| u.allows_updating()),
        Some(err) => {
            if err.esource() != &pingora::ErrorSource::Upstream {
                return false;
            }
            let Some(mask) = use_stale else {
                return true;
            };
            match err.etype() {
                pingora::ErrorType::HTTPStatus(code) => {
                    mask.allows_status(*code)
                },
                pingora::ErrorType::ConnectTimedout
                | pingora::ErrorType::ReadTimedout
                | pingora::ErrorType::WriteTimedout => mask.allows_timeout(),
                _ => mask.allows_error(),
            }
        },
    }
}

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

/// Whether the origin says how long its response may be kept: a lifetime
/// in `Cache-Control`, or an `Expires`.
pub(crate) fn names_a_lifetime(
    cc: Option<&CacheControl>,
    resp: &ResponseHeader,
) -> bool {
    // By the directive being there, not by its value reading: `max-age=abc`
    // is the origin having said something, and not what the plugin gives
    // a response that says nothing.
    cc.is_some_and(|cc| {
        cc.directives.contains_key(&DirectiveKey::MaxAge)
            || cc.directives.contains_key(&DirectiveKey::SMaxAge)
    }) || resp.headers.contains_key(http::header::EXPIRES)
}

/// How long the `cache` plugin keeps a response of `status` that names no
/// lifetime: what `status_ttl` says of the status, else `default_ttl` for
/// the statuses `kept_by_default` knows, else what `kept_by_default`
/// says. `None`, or a lifetime of zero, is "not kept".
///
/// A `304` is the answer to a revalidation of what was stored as a `200`,
/// and renews it for as long as a `200` is kept.
pub(crate) fn own_lifetime(
    status: StatusCode,
    default_ttl: Option<Duration>,
    status_ttl: Option<&[(u16, Duration)]>,
    kept_by_default: fn(StatusCode) -> Option<Duration>,
) -> Option<Duration> {
    let status = if status == StatusCode::NOT_MODIFIED {
        StatusCode::OK
    } else {
        status
    };
    let listed = status_ttl.and_then(|list| {
        list.iter()
            .find(|(code, _)| *code == status.as_u16())
            .map(|(_, ttl)| *ttl)
    });
    listed
        .or_else(|| {
            kept_by_default(status).map(|ttl| default_ttl.unwrap_or(ttl))
        })
        .filter(|ttl| !ttl.is_zero())
}

/// The response as one to store for `ttl`, the way pingora's
/// `resp_cacheable` makes one of a response with a lifetime of its own.
pub(crate) fn cacheable_for(
    cc: Option<&CacheControl>,
    resp: &ResponseHeader,
    ttl: Option<Duration>,
    defaults: &CacheMetaDefaults,
) -> RespCacheable {
    let now = SystemTime::now();
    let Some(fresh_until) = ttl.and_then(|ttl| now.checked_add(ttl)) else {
        return RespCacheable::Uncacheable(NoCacheReason::OriginNotCache);
    };
    let (stale_while_revalidate, stale_if_error) =
        calculate_serve_stale_durations(cc, defaults);
    let mut header = resp.clone();
    if let Some(cc) = cc {
        cc.strip_private_headers(&mut header);
    }
    RespCacheable::Cacheable(CacheMeta::new(
        fresh_until,
        now,
        stale_while_revalidate,
        stale_if_error,
        header,
    ))
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

    /// The lifetime the plugin gives a response that names none.
    #[test]
    fn test_own_lifetime() {
        use super::{cacheable_for, names_a_lifetime, own_lifetime};
        use http::StatusCode;
        // The statuses that are kept without being told to, as the proxy
        // has them: one second each.
        fn kept(status: StatusCode) -> Option<Duration> {
            matches!(status.as_u16(), 200 | 301 | 404)
                .then_some(Duration::from_secs(1))
        }
        let status = |code: u16| StatusCode::from_u16(code).unwrap();
        let secs = Duration::from_secs;
        let listed = [(404, secs(10)), (302, secs(60)), (301, Duration::ZERO)];

        // `default_ttl` in place of the second, for the same statuses.
        assert_eq!(
            Some(secs(30)),
            own_lifetime(status(200), Some(secs(30)), None, kept)
        );
        assert_eq!(None, own_lifetime(status(500), Some(secs(30)), None, kept));
        assert_eq!(None, own_lifetime(status(302), Some(secs(30)), None, kept));
        // `status_ttl` for its status, also one that is not kept by
        // default; the others as before.
        assert_eq!(
            Some(secs(10)),
            own_lifetime(status(404), Some(secs(30)), Some(&listed), kept)
        );
        assert_eq!(
            Some(secs(60)),
            own_lifetime(status(302), None, Some(&listed), kept)
        );
        assert_eq!(
            Some(secs(1)),
            own_lifetime(status(200), None, Some(&listed), kept)
        );
        // Zero keeps a status out, in either option.
        assert_eq!(None, own_lifetime(status(301), None, Some(&listed), kept));
        assert_eq!(
            None,
            own_lifetime(status(200), Some(Duration::ZERO), None, kept)
        );
        // A `304` renews what was stored as a `200`.
        assert_eq!(
            Some(secs(30)),
            own_lifetime(status(304), Some(secs(30)), None, kept)
        );

        // Only for a response that names no lifetime itself.
        let response = |headers: &[(&'static str, &str)]| {
            let mut resp = ResponseHeader::build_no_case(200, None).unwrap();
            for (name, value) in headers {
                resp.append_header(*name, *value).unwrap();
            }
            let cc = CacheControl::from_resp_headers(&resp);
            (names_a_lifetime(cc.as_ref(), &resp), cc, resp)
        };
        assert_eq!(false, response(&[]).0);
        assert_eq!(false, response(&[("Cache-Control", "public")]).0);
        assert_eq!(true, response(&[("Cache-Control", "max-age=5")]).0);
        assert_eq!(true, response(&[("Cache-Control", "s-maxage=5")]).0);
        // Said, and not understood: still the origin's word.
        assert_eq!(true, response(&[("Cache-Control", "max-age=abc")]).0);
        assert_eq!(true, response(&[("Cache-Control", "max-age=-1")]).0);
        assert_eq!(
            true,
            response(&[("Expires", "Wed, 21 Oct 2015 07:28:00 GMT")]).0
        );

        // What is made of it: fresh for that long, and nothing at all
        // without a lifetime.
        const DEFAULTS: CacheMetaDefaults = CacheMetaDefaults::new(kept, 0, 1);
        let (_, cc, resp) = response(&[("Cache-Control", "public")]);
        let RespCacheable::Cacheable(meta) =
            cacheable_for(cc.as_ref(), &resp, Some(secs(30)), &DEFAULTS)
        else {
            panic!("a response with a lifetime should be cacheable");
        };
        let fresh = meta
            .fresh_until()
            .duration_since(SystemTime::now())
            .unwrap();
        assert_eq!(true, fresh > secs(28) && fresh <= secs(30), "{fresh:?}");
        assert_eq!(
            true,
            matches!(
                cacheable_for(cc.as_ref(), &resp, None, &DEFAULTS),
                RespCacheable::Uncacheable(_)
            )
        );
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

    #[test]
    fn test_meta_defaults() {
        use super::meta_defaults;

        let defaults = meta_defaults(None, None);
        assert_eq!(0, defaults.serve_stale_while_revalidate_sec());
        assert_eq!(1, defaults.serve_stale_if_error_sec());
        assert_eq!(
            Some(Duration::from_secs(1)),
            defaults.fresh_sec(http::StatusCode::OK)
        );
        assert_eq!(
            None,
            defaults.fresh_sec(http::StatusCode::INTERNAL_SERVER_ERROR)
        );

        let configured = meta_defaults(
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(120)),
        );
        assert_eq!(30, configured.serve_stale_while_revalidate_sec());
        assert_eq!(120, configured.serve_stale_if_error_sec());

        let zeroed = meta_defaults(Some(Duration::ZERO), Some(Duration::ZERO));
        assert_eq!(0, zeroed.serve_stale_while_revalidate_sec());
        assert_eq!(0, zeroed.serve_stale_if_error_sec());

        let saturated = meta_defaults(
            Some(Duration::from_secs(u64::MAX)),
            Some(Duration::from_secs(u64::MAX)),
        );
        assert_eq!(u32::MAX, saturated.serve_stale_while_revalidate_sec());
        assert_eq!(u32::MAX, saturated.serve_stale_if_error_sec());

        let resp = ResponseHeader::build_no_case(200, None).unwrap();
        let RespCacheable::Cacheable(meta) =
            resp_cacheable(None, resp, false, &configured)
        else {
            panic!("200 without Cache-Control should be cacheable");
        };
        assert_eq!(30, meta.stale_while_revalidate_sec());
        assert_eq!(120, meta.stale_if_error_sec());

        let mut explicit_resp =
            ResponseHeader::build_no_case(200, None).unwrap();
        explicit_resp
            .append_header(
                "Cache-Control",
                "max-age=60, stale-while-revalidate=5, stale-if-error=10",
            )
            .unwrap();
        let cc = CacheControl::from_resp_headers(&explicit_resp);
        let RespCacheable::Cacheable(explicit_meta) =
            resp_cacheable(cc.as_ref(), explicit_resp, false, &configured)
        else {
            panic!("explicit Cache-Control should be cacheable");
        };
        assert_eq!(5, explicit_meta.stale_while_revalidate_sec());
        assert_eq!(10, explicit_meta.stale_if_error_sec());
    }

    #[test]
    fn test_error_matches_use_stale() {
        use super::error_matches_use_stale;
        use pingap_core::CacheUseStale;
        use pingora::{Error, ErrorSource, ErrorType};

        let upstream_status = |code: u16| {
            Error::create(
                ErrorType::HTTPStatus(code),
                ErrorSource::Upstream,
                None,
                None,
            )
        };

        // Updating (`error == None`): unset allows non-h2-writer; configured requires `updating`.
        assert!(error_matches_use_stale(None, None, false));
        assert!(!error_matches_use_stale(None, None, true));
        assert!(error_matches_use_stale(
            Some(CacheUseStale::UPDATING),
            None,
            false
        ));
        assert!(!error_matches_use_stale(
            Some(CacheUseStale::UPDATING),
            None,
            true
        ));
        assert!(!error_matches_use_stale(
            Some(CacheUseStale::ERROR | CacheUseStale::HTTP_503),
            None,
            false
        ));

        // Downstream/internal errors never serve stale.
        let down_err = Error::new_down(ErrorType::ConnectionClosed);
        assert!(!error_matches_use_stale(None, Some(&down_err), false));
        assert!(!error_matches_use_stale(
            Some(CacheUseStale::ERROR),
            Some(&down_err),
            false
        ));

        // Unset `use_stale`: any upstream error serves stale (backward compat).
        let connect_err = Error::new_up(ErrorType::ConnectRefused);
        let read_to = Error::new_up(ErrorType::ReadTimedout);
        let s503 = upstream_status(503);
        let s429 = upstream_status(429);
        assert!(error_matches_use_stale(None, Some(&connect_err), false));
        assert!(error_matches_use_stale(None, Some(&read_to), false));
        assert!(error_matches_use_stale(None, Some(&s503), false));

        // Configured `use_stale`: matches each category strictly.
        let mask = CacheUseStale::ERROR
            | CacheUseStale::TIMEOUT
            | CacheUseStale::HTTP_503
            | CacheUseStale::HTTP_429;
        assert!(error_matches_use_stale(
            Some(mask),
            Some(&connect_err),
            false
        ));
        assert!(error_matches_use_stale(
            Some(CacheUseStale::TIMEOUT),
            Some(&Error::new_up(ErrorType::ConnectTimedout)),
            false
        ));
        assert!(error_matches_use_stale(
            Some(CacheUseStale::TIMEOUT),
            Some(&Error::new_up(ErrorType::ReadTimedout)),
            false
        ));
        assert!(error_matches_use_stale(
            Some(CacheUseStale::TIMEOUT),
            Some(&Error::new_up(ErrorType::WriteTimedout)),
            false
        ));
        assert!(!error_matches_use_stale(
            Some(CacheUseStale::ERROR),
            Some(&read_to),
            false
        ));
        assert!(!error_matches_use_stale(
            Some(CacheUseStale::TIMEOUT),
            Some(&connect_err),
            false
        ));
        assert!(error_matches_use_stale(Some(mask), Some(&s503), false));
        assert!(error_matches_use_stale(Some(mask), Some(&s429), false));
        assert!(!error_matches_use_stale(
            Some(mask),
            Some(&upstream_status(502)),
            false
        ));
        assert!(!error_matches_use_stale(
            Some(CacheUseStale::ERROR | CacheUseStale::TIMEOUT),
            Some(&s503),
            false
        ));
    }
}
