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

// Import necessary modules and types from supervisors and external crates.
use super::{Ctx, get_hostname};
use ahash::AHashSet;
use arc_swap::ArcSwapOption;
use bytes::BytesMut;
use http::header;
use http::{HeaderName, HeaderValue};
use ipnet::IpNet;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use snafu::{ResultExt, Snafu};
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// Define string constants for commonly used HTTP header names.
const HTTP_HEADER_X_FORWARDED_FOR: &str = "x-forwarded-for";
const HTTP_HEADER_X_REAL_IP: &str = "x-real-ip";

// Define byte slice constants for special variable tags used in header value processing.
// These are matched against the raw bytes of a header value.
pub const HOST_NAME_TAG: &[u8] = b"$hostname";
const HOST_TAG: &[u8] = b"$host";
const SCHEME_TAG: &[u8] = b"$scheme";
const REMOTE_ADDR_TAG: &[u8] = b"$remote_addr";
const REMOTE_PORT_TAG: &[u8] = b"$remote_port";
const SERVER_ADDR_TAG: &[u8] = b"$server_addr";
const SERVER_PORT_TAG: &[u8] = b"$server_port";
const PROXY_ADD_FORWARDED_TAG: &[u8] = b"$proxy_add_x_forwarded_for";
const UPSTREAM_ADDR_TAG: &[u8] = b"$upstream_addr";
const JA4_TAG: &[u8] = b"$ja4";
const CLIENT_IP_TAG: &[u8] = b"$client_ip";
const FORWARDED_PROTO_TAG: &[u8] = b"$forwarded_proto";
const FORWARDED_HOST_TAG: &[u8] = b"$forwarded_host";
const FORWARDED_PORT_TAG: &[u8] = b"$forwarded_port";

// Define static HeaderValues for HTTP and HTTPS schemes to avoid re-creation.
static SCHEME_HTTPS: HeaderValue = HeaderValue::from_static("https");
static SCHEME_HTTP: HeaderValue = HeaderValue::from_static("http");

/// Defines the custom error types for this module using the snafu crate.
#[derive(Debug, Snafu)]
pub enum Error {
    /// Error for when a string cannot be parsed into a valid HeaderValue.
    #[snafu(display("invalid header value: {value} - {source}"))]
    InvalidHeaderValue {
        value: String,
        source: header::InvalidHeaderValue,
    },
    /// Error for when a string cannot be parsed into a valid HeaderName.
    #[snafu(display("invalid header name: {value} - {source}"))]
    InvalidHeaderName {
        value: String,
        source: header::InvalidHeaderName,
    },
}
/// A convenient type alias for `Result` with the module's `Error` type.
type Result<T, E = Error> = std::result::Result<T, E>;

/// A type alias for a tuple representing an HTTP header.
pub type HttpHeader = (HeaderName, HeaderValue);

/// Gets the request host by checking the URI first, then falling back to the "Host" header.
///
/// This function follows the common practice of prioritizing the host from the absolute URI
/// (e.g., in `GET http://example.com/path HTTP/1.1`) over the `Host` header field.
pub fn get_host(header: &RequestHeader) -> Option<&str> {
    get_request_host(header).map(strip_root_label)
}

/// The host of the request as it was sent, less its port: what
/// [`get_host`] gives before it drops the root label.
///
/// The cache key is made of this one. The request goes to the upstream
/// with the `Host` it came with, and an upstream that answers
/// `example.com.` differently from `example.com` - it does not know the
/// name, or writes it into a redirect - must not have that answer stored
/// as the answer for the other.
pub fn get_request_host(header: &RequestHeader) -> Option<&str> {
    // First, try to get the host directly from the parsed URI.
    // http2 will always have a host in the uri
    match header.uri.host() {
        Some(host) => Some(host),
        // If not in the URI, fall back to the "Host" header.
        None => header
            .headers
            .get(http::header::HOST)
            // Convert the header value to a string slice.
            .and_then(|value| value.to_str().ok())
            .map(strip_port),
    }
}

/// `example.com.` is `example.com` with the root label written out, and
/// names the same host. Matched as it came, it missed every location
/// configured for the host and fell through to the catch-all, past the
/// plugins that guard the host, while the upstream served it as that host.
#[inline]
pub fn strip_root_label(host: &str) -> &str {
    match host.strip_suffix('.') {
        Some(name) if !name.is_empty() => name,
        _ => host,
    }
}

/// Puts the cookies of a request into one `Cookie` field.
///
/// HTTP/2 lets a client send them as several fields (RFC 9113 8.2.3), and
/// everything that reads a cookie reads the first field: a token in the
/// second was not found by `jwt`, a sticky cookie not by the traffic
/// split, a `{~name}` not by the access log. An HTTP/1.1 upstream is owed
/// the single field anyway. A request with one field, or none, is left as
/// it is.
pub fn merge_cookie_headers(header: &mut RequestHeader) {
    let mut values = header.headers.get_all(http::header::COOKIE).iter();
    let (Some(first), Some(second)) = (values.next(), values.next()) else {
        return;
    };
    let mut merged = Vec::with_capacity(
        first.len() + second.len() + 2 + values.size_hint().0 * 16,
    );
    merged.extend_from_slice(first.as_bytes());
    for value in std::iter::once(second).chain(values) {
        merged.extend_from_slice(b"; ");
        merged.extend_from_slice(value.as_bytes());
    }
    if let Ok(value) = HeaderValue::from_bytes(&merged) {
        let _ = header.insert_header(http::header::COOKIE, value);
    }
}

/// Drops the `:port` suffix of a `Host` value. An IPv6 literal keeps its
/// brackets, and the colons inside them are not a port separator:
/// `[::1]:8080` is `[::1]`, the same form `Uri::host` reports.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        };
    }
    host.split(':').next().unwrap_or(host)
}

/// Converts a single string in "name: value" format into an `HttpHeader` tuple.
///
/// This is a utility function for parsing header configurations. It trims whitespace
/// from both the name and the value.
pub fn convert_header(value: &str) -> Result<Option<HttpHeader>> {
    // `split_once` is an efficient way to split the string into two parts at the first colon.
    value
        .split_once(':')
        // If a colon exists, map the key and value parts.
        .map(|(k, v)| {
            // Parse the trimmed key into a HeaderName, wrapping errors.
            let name = HeaderName::from_str(k.trim())
                .context(InvalidHeaderNameSnafu { value: k })?;
            // Parse the trimmed value into a HeaderValue, wrapping errors.
            let value = HeaderValue::from_str(v.trim())
                .context(InvalidHeaderValueSnafu { value: v })?;
            // If both parsing steps succeed, return the header tuple.
            Ok(Some((name, value)))
        })
        // If `split_once` returns None (no colon), default to `Ok(None)`.
        .unwrap_or(Ok(None))
}

/// Converts a slice of strings into a `Vec` of `HttpHeader`s.
///
/// This function iterates over a list of header strings and uses `convert_header`
/// on each, collecting the valid results into a vector.
pub fn convert_headers(header_values: &[String]) -> Result<Vec<HttpHeader>> {
    header_values
        .iter()
        // `filter_map` is used to iterate, convert, and filter out `None` results elegantly.
        // `transpose` flips `Option<Result<T>>` to `Result<Option<T>>`, which is what `filter_map` expects.
        .filter_map(|item| convert_header(item).transpose())
        // `collect` gathers the `Result<HttpHeader>` items. If any item is an `Err`, `collect` will return that `Err`.
        .collect()
}

// Define common, pre-built HTTP headers as static constants for reuse and performance.
pub static HTTP_HEADER_NO_STORE: HttpHeader = (
    header::CACHE_CONTROL,
    HeaderValue::from_static("private, no-store"),
);
pub static HTTP_HEADER_NO_CACHE: HttpHeader = (
    header::CACHE_CONTROL,
    HeaderValue::from_static("private, no-cache"),
);
pub static HTTP_HEADER_CONTENT_JSON: HttpHeader = (
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json; charset=utf-8"),
);
pub static HTTP_HEADER_CONTENT_HTML: HttpHeader = (
    header::CONTENT_TYPE,
    HeaderValue::from_static("text/html; charset=utf-8"),
);
pub static HTTP_HEADER_CONTENT_TEXT: HttpHeader = (
    header::CONTENT_TYPE,
    HeaderValue::from_static("text/plain; charset=utf-8"),
);
pub static HTTP_HEADER_TRANSFER_CHUNKED: HttpHeader = (
    header::TRANSFER_ENCODING,
    HeaderValue::from_static("chunked"),
);
pub static HTTP_HEADER_NAME_X_REQUEST_ID: HeaderName =
    HeaderName::from_static("x-request-id");

/// Resolves a header value that cannot change for the life of the process -
/// `$hostname` and `$<ENV_VAR>` - so it can be stored as a plain value when
/// the configuration is loaded instead of being looked up on every request
/// (`std::env::var` takes a process-wide lock and allocates each time).
/// Values that depend on the request (`$host`, `$http_*`, `:key`, ...) and
/// plain values come back unchanged, as does a `$NAME` whose variable is not
/// set, so the request path treats it exactly as before.
pub fn resolve_static_header_value(value: HeaderValue) -> HeaderValue {
    let buf = value.as_bytes();
    if buf.first() != Some(&b'$') {
        return value;
    }
    if buf == HOST_NAME_TAG {
        return HeaderValue::from_str(get_hostname()).unwrap_or(value);
    }
    let request_tags: [&[u8]; 13] = [
        HOST_TAG,
        SCHEME_TAG,
        REMOTE_ADDR_TAG,
        REMOTE_PORT_TAG,
        SERVER_ADDR_TAG,
        SERVER_PORT_TAG,
        PROXY_ADD_FORWARDED_TAG,
        UPSTREAM_ADDR_TAG,
        JA4_TAG,
        CLIENT_IP_TAG,
        FORWARDED_PROTO_TAG,
        FORWARDED_HOST_TAG,
        FORWARDED_PORT_TAG,
    ];
    if request_tags.contains(&buf) || buf.starts_with(b"$http_") {
        return value;
    }
    let Ok(name) = std::str::from_utf8(&buf[1..]) else {
        return value;
    };
    match std::env::var(name) {
        Ok(env_value) => HeaderValue::from_str(&env_value).unwrap_or(value),
        Err(_) => value,
    }
}

/// Processes a `HeaderValue` that may contain a special dynamic variable (e.g., `$host`).
/// It replaces the variable with its corresponding runtime value.
#[inline]
pub fn convert_header_value(
    value: &HeaderValue,
    session: &Session,
    ctx: &Ctx,
) -> Option<HeaderValue> {
    // Work with the raw byte representation of the header value for efficient matching.
    let buf = value.as_bytes();

    // Perform a quick check for the special variable prefix ('$' or ':') to exit early
    // for normal header values, which is the most common case.
    if buf.is_empty() || !(buf[0] == b'$' || buf[0] == b':') {
        return None;
    }

    // A helper closure to reduce boilerplate when converting a string slice to a HeaderValue.
    let to_header_value = |s: &str| HeaderValue::from_str(s).ok();

    // Match the entire byte slice against the predefined variable tags.
    match buf {
        HOST_TAG => get_host(session.req_header()).and_then(to_header_value),
        SCHEME_TAG => Some(if ctx.conn.tls_version.is_some() {
            SCHEME_HTTPS.clone()
        } else {
            SCHEME_HTTP.clone()
        }),
        HOST_NAME_TAG => to_header_value(get_hostname()),
        REMOTE_ADDR_TAG => {
            ctx.conn.remote_addr.as_deref().and_then(to_header_value)
        },
        REMOTE_PORT_TAG => ctx.conn.remote_port.and_then(|p| {
            // Use `itoa` to format the integer directly into a valid header value
            // without creating an intermediate `String`.
            HeaderValue::from_str(itoa::Buffer::new().format(p)).ok()
        }),
        SERVER_ADDR_TAG => {
            ctx.conn.server_addr.as_deref().and_then(to_header_value)
        },
        SERVER_PORT_TAG => ctx.conn.server_port.and_then(|p| {
            HeaderValue::from_str(itoa::Buffer::new().format(p)).ok()
        }),
        UPSTREAM_ADDR_TAG => {
            if !ctx.upstream.address.is_empty() {
                to_header_value(&ctx.upstream.address)
            } else {
                None
            }
        },
        JA4_TAG => ctx
            .conn
            .ja4
            .as_deref()
            .and_then(|fingerprint| to_header_value(fingerprint.ja4())),
        // The address of the client, as far as it can be vouched for:
        // what a trusted proxy says of it, and the peer's own where there
        // is none - or no list of them, in which case a forwarded header
        // is only what the request claims.
        CLIENT_IP_TAG => {
            if has_trusted_proxies() {
                match ctx.conn.client_ip.as_deref() {
                    Some(client_ip) => to_header_value(client_ip),
                    None => to_header_value(&get_client_ip(session)),
                }
            } else {
                ctx.conn.remote_addr.as_deref().and_then(to_header_value)
            }
        },
        // The scheme and the host the client used, which behind a proxy
        // that ends TLS are not the ones this connection has: what a
        // trusted proxy says of them, and this connection's otherwise.
        FORWARDED_PROTO_TAG => Some(if client_used_https(session, ctx) {
            SCHEME_HTTPS.clone()
        } else {
            SCHEME_HTTP.clone()
        }),
        // Only what reads as the name of a host, with or without a port:
        // it goes into a header the upstream may build links from.
        FORWARDED_HOST_TAG => {
            forwarded_by_trusted_proxy(session, &HTTP_HEADER_X_FORWARDED_HOST)
                .filter(|host| is_host_name(host))
                .and_then(to_header_value)
                .or_else(|| {
                    get_host(session.req_header()).and_then(to_header_value)
                })
        },
        // The port that goes with the scheme above: the one the proxy
        // names, or the default of the scheme it names. Without either it
        // is the port of this listener, as it has always been.
        FORWARDED_PORT_TAG => {
            let forwarded = forwarded_by_trusted_proxy(
                session,
                &HTTP_HEADER_X_FORWARDED_PORT,
            )
            .and_then(|port| port.parse::<u16>().ok())
            .filter(|port| *port > 0)
            .or_else(|| {
                forwarded_scheme(session)
                    .map(|https| if https { 443 } else { 80 })
            })
            .or(ctx.conn.server_port);
            forwarded.and_then(|port| {
                HeaderValue::from_str(itoa::Buffer::new().format(port)).ok()
            })
        },
        PROXY_ADD_FORWARDED_TAG => {
            ctx.conn.remote_addr.as_deref().and_then(|remote_addr| {
                // Build the new `x-forwarded-for` value efficiently using `BytesMut` to avoid `format!`.
                // Every line of the request goes in, in order: a proxy in
                // front may add its entry as a line of its own, and with
                // only the first line kept that entry - the client's real
                // address - was lost, leaving what the client wrote.
                let existing = session
                    .req_header()
                    .headers
                    .get_all(HTTP_HEADER_X_FORWARDED_FOR);
                let capacity = existing
                    .iter()
                    .map(|v| v.as_bytes().len() + 2)
                    .sum::<usize>()
                    + remote_addr.len();
                let mut value_buf = BytesMut::with_capacity(capacity);
                for value in existing.iter() {
                    value_buf.extend_from_slice(value.as_bytes());
                    value_buf.extend_from_slice(b", ");
                }
                value_buf.extend_from_slice(remote_addr.as_bytes());
                HeaderValue::from_bytes(&value_buf).ok()
            })
        },
        // If no predefined tag matches, it might be a different type of variable (e.g., `$http_...`).
        _ => handle_special_headers(buf, session, ctx),
    }
}

/// A helper function to handle more complex or less common special header variables.
/// This function is called as a fallback from `convert_header_value`.
#[inline]
fn handle_special_headers(
    buf: &[u8],
    session: &Session,
    ctx: &Ctx,
) -> Option<HeaderValue> {
    // Handle variables that reference other request headers, like `$http_user_agent`.
    if let Some(name) = buf.strip_prefix(b"$http_") {
        let key = std::str::from_utf8(name).ok()?;
        // nginx spelling: `$http_user_agent` names `User-Agent`. Header names
        // never contain underscores, so mapping them is unambiguous.
        if key.contains('_') {
            return session.get_header(key.replace('_', "-")).cloned();
        }
        return session.get_header(key).cloned();
    }
    // Handle variables that reference environment variables, like `$PATH`.
    if buf.starts_with(b"$") {
        let var_name = std::str::from_utf8(&buf[1..]).ok()?;
        // Look up the environment variable and convert its value to a HeaderValue.
        return std::env::var(var_name)
            .ok()
            .and_then(|v| HeaderValue::from_str(&v).ok());
    }
    // Handle variables that reference fields in the `Ctx` struct, like `:connection_id`.
    if buf.starts_with(b":") {
        let key = std::str::from_utf8(&buf[1..]).ok()?;
        // Use `append_log_value` to get the string representation of the context field.
        let mut value = BytesMut::with_capacity(20);
        ctx.append_log_value(&mut value, key);
        if !value.is_empty() {
            // Convert the resulting bytes to a HeaderValue.
            return HeaderValue::from_bytes(&value).ok();
        }
    }
    // If no pattern matches, return None.
    None
}

/// Gets the remote address (IP and port) from the session.
///
/// An IPv4 client of a dual-stack listener (`[::]:80`) has the address
/// `::ffff:1.2.3.4`. It is reported as `1.2.3.4`: left in the mapped form
/// it matched no IPv4 entry of an allow or deny list, no IPv4 trusted
/// proxy, and no country.
pub fn get_remote_addr(session: &Session) -> Option<(String, u16)> {
    session
        .client_addr()
        // Ensure the address is an IP address (v4 or v6).
        .and_then(|addr| addr.as_inet())
        // Map it to a tuple of (String, u16).
        .map(|addr| (addr.ip().to_canonical().to_string(), addr.port()))
}

/// Parsed trusted downstream proxy addresses: individual IPs plus CIDR
/// networks. Kept small and local since it is only used by `get_client_ip`.
struct TrustedProxies {
    nets: Vec<IpNet>,
    ips: AHashSet<IpAddr>,
}

impl TrustedProxies {
    /// Parses a list of IPs / CIDR ranges. Invalid entries are ignored (a
    /// mistyped proxy simply fails closed: its forwarded headers are dropped).
    fn parse(values: &[String]) -> Self {
        let mut nets = Vec::new();
        let mut ips = AHashSet::new();
        for item in values {
            if let Ok(net) = IpNet::from_str(item) {
                nets.push(net);
            } else if let Ok(ip) = IpAddr::from_str(item) {
                ips.insert(ip.to_canonical());
            }
        }
        Self { nets, ips }
    }

    /// Returns true if `peer` is one of the trusted proxies.
    fn contains(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.ips.contains(&peer)
            || self.nets.iter().any(|net| net.contains(&peer))
    }
}

// Trusted downstream proxies. When configured, the forwarded client-IP headers
// (`X-Forwarded-For` / `X-Real-IP`) are only honoured for connections whose
// direct TCP peer is one of these addresses; a client connecting directly must
// not be able to spoof its IP for IP-based access control, rate limiting, etc.
// A cheap atomic flag keeps the common "not configured" path to one load;
// the configured path reads the list through an `ArcSwap`, so a reload never
// makes a request wait on a lock.
static TRUSTED_PROXIES_ENABLED: AtomicBool = AtomicBool::new(false);
static TRUSTED_PROXIES: ArcSwapOption<TrustedProxies> =
    ArcSwapOption::const_empty();

static HTTP_HEADER_X_FORWARDED_PROTO: HeaderName =
    HeaderName::from_static("x-forwarded-proto");
static HTTP_HEADER_X_FORWARDED_HOST: HeaderName =
    HeaderName::from_static("x-forwarded-host");
static HTTP_HEADER_X_FORWARDED_PORT: HeaderName =
    HeaderName::from_static("x-forwarded-port");

/// Whether the connection of the request comes from one of the trusted
/// proxies. Never without a list of them: there is then nobody whose word
/// about a client could be taken.
pub fn peer_is_trusted_proxy(session: &Session) -> bool {
    if !has_trusted_proxies() {
        return false;
    }
    let Some(peer) = session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip())
    else {
        return false;
    };
    TRUSTED_PROXIES
        .load()
        .as_ref()
        .is_some_and(|trusted| trusted.contains(peer))
}

/// The first entry of a forwarded header, over all of its lines: the
/// one the proxy nearest to the client wrote, in a chain of proxies that
/// each add theirs. `https, http` is a client on https and a hop inside
/// the chain on plain http.
fn first_forwarded_entry<'a>(
    values: impl Iterator<Item = &'a HeaderValue>,
) -> Option<&'a str> {
    values
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .find(|entry| !entry.is_empty())
}

/// What a trusted proxy says under `name`: the first entry of the header,
/// when the request came through one and has it. From anyone else the
/// header is something the client wrote.
///
/// The proxy has to write the header itself and not pass on what it was
/// sent: one that only appends, or leaves the client's in place, hands on
/// the client's word under its own name.
fn forwarded_by_trusted_proxy<'a>(
    session: &'a Session,
    name: &HeaderName,
) -> Option<&'a str> {
    let entry = first_forwarded_entry(
        session.req_header().headers.get_all(name).iter(),
    )?;
    peer_is_trusted_proxy(session).then_some(entry)
}

/// The scheme a trusted proxy says the client used: `Some(true)` for
/// https, `Some(false)` for http, `None` when there is no proxy to say or
/// it says something else.
fn forwarded_scheme(session: &Session) -> Option<bool> {
    let scheme =
        forwarded_by_trusted_proxy(session, &HTTP_HEADER_X_FORWARDED_PROTO)?;
    if scheme.eq_ignore_ascii_case("https") {
        Some(true)
    } else if scheme.eq_ignore_ascii_case("http") {
        Some(false)
    } else {
        None
    }
}

/// Whether the client reached the site over https, as far as that can be
/// vouched for: what a trusted proxy says of it, and otherwise whether
/// this connection is one.
pub fn client_used_https(session: &Session, ctx: &Ctx) -> bool {
    forwarded_scheme(session).unwrap_or(ctx.conn.tls_version.is_some())
}

/// Whether `value` reads as a host, with or without a port, and nothing
/// more: no user in front of it, no path behind it.
fn is_host_name(value: &str) -> bool {
    value
        .parse::<http::uri::Authority>()
        .is_ok_and(|authority| {
            !authority.host().is_empty() && !authority.as_str().contains('@')
        })
}

/// Sets the trusted downstream proxy addresses (individual IPs or CIDR ranges).
///
/// When a non-empty list is configured, forwarded headers are only trusted for
/// connections coming directly from one of these addresses. Passing `None` or
/// an empty list restores the default behaviour of trusting forwarded headers
/// unconditionally (backwards compatible). Safe to call repeatedly on reload.
pub fn set_trusted_proxies(proxies: &Option<Vec<String>>) {
    let parsed = match proxies {
        Some(list) if !list.is_empty() => Some(TrustedProxies::parse(list)),
        _ => None,
    };
    let enabled = parsed.is_some();
    TRUSTED_PROXIES.store(parsed.map(Arc::new));
    // Set last: a request that sees the flag also sees the list.
    TRUSTED_PROXIES_ENABLED.store(enabled, Ordering::Relaxed);
}

/// An `X-Forwarded-For` entry as an address. Besides the plain form some
/// proxies write `ip:port` or `[v6]:port`.
fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let ip = if let Ok(ip) = IpAddr::from_str(value) {
        ip
    } else if let Ok(addr) = SocketAddr::from_str(value) {
        addr.ip()
    } else {
        value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| IpAddr::from_str(value).ok())?
    };
    // `::ffff:1.2.3.4` is `1.2.3.4`, see `get_remote_addr`.
    Some(ip.to_canonical())
}

/// The client address out of the `X-Forwarded-For` lines of a request that
/// came through a trusted proxy.
///
/// Each proxy appends the address it received the request from, so the list
/// is read from the right: entries that are trusted proxies themselves are
/// skipped, and the first one that is not is the client. Everything further
/// left was written by that client and proves nothing - taking the first
/// entry, as this used to, let `X-Forwarded-For: 6.6.6.6` through a trusted
/// proxy pick the address the access rules saw.
///
/// When every entry is a trusted proxy the request started at one of them,
/// and the left-most is returned.
fn forwarded_client_ip<'a>(
    values: impl DoubleEndedIterator<Item = &'a HeaderValue>,
    trusted: &TrustedProxies,
) -> Option<String> {
    let mut first_proxy = None;
    for value in values.rev() {
        // Entry by entry on the bytes, never the line as text. A line is
        // text only when all of it is, and its left end is the client's to
        // write: one byte there that is not ASCII would discard the line,
        // and with it the address the proxy appended on the right.
        for item in value.as_bytes().rsplit(|b| *b == b',') {
            let item = item.trim_ascii();
            if item.is_empty() {
                continue;
            }
            // Not text, so not an address and not a trusted proxy.
            let Ok(item) = std::str::from_utf8(item) else {
                return Some(String::from_utf8_lossy(item).into_owned());
            };
            match parse_forwarded_ip(item) {
                Some(ip) if trusted.contains(ip) => first_proxy = Some(ip),
                Some(ip) => return Some(ip.to_string()),
                None => return Some(item.to_string()),
            }
        }
    }
    first_proxy.map(|ip| ip.to_string())
}

/// Whether `basic.trusted_proxies` is set.
#[inline]
pub fn has_trusted_proxies() -> bool {
    TRUSTED_PROXIES_ENABLED.load(Ordering::Relaxed)
}

/// The address to check a request by when the check grants something to the
/// few, such as the allow list of the cache's `PURGE`.
///
/// With trusted proxies configured this is the client ip, which a client
/// can not choose then. Without them the forwarded headers are simply what
/// the request says, so the address is the peer's own: a list that allows
/// `127.0.0.1` used to let in anyone who sent `X-Forwarded-For: 127.0.0.1`.
#[inline]
pub fn ensure_verified_client_ip<'a>(
    session: &Session,
    ctx: &'a mut Ctx,
) -> &'a str {
    if has_trusted_proxies() {
        return ensure_client_ip(session, ctx);
    }
    ctx.conn.remote_addr.as_deref().unwrap_or_default()
}

/// Ensures `ctx.conn.client_ip` is populated and returns a borrowed reference.
///
/// Prefer this on the request path over calling [`get_client_ip`] repeatedly —
/// the first call allocates once and subsequent callers reuse the cached value.
#[inline]
pub fn ensure_client_ip<'a>(session: &Session, ctx: &'a mut Ctx) -> &'a str {
    if ctx.conn.client_ip.is_none() {
        ctx.conn.client_ip = Some(get_client_ip(session));
    }
    // Just inserted or already present — never None after the block above.
    ctx.conn.client_ip.as_deref().unwrap_or_default()
}

/// Gets the client's IP address.
///
/// When trusted proxies are configured, `X-Forwarded-For` / `X-Real-IP` are
/// only honoured if the direct TCP peer is a trusted proxy; otherwise the
/// peer's own address is returned. Through a trusted proxy the address is
/// the right-most `X-Forwarded-For` entry that is not a trusted proxy (see
/// [`forwarded_client_ip`]), then `X-Real-IP`, then the peer.
///
/// When no trusted proxies are configured the lookup order is:
/// 1. `X-Forwarded-For` (taking the first IP in the list)
/// 2. `X-Real-IP`
/// 3. The remote address of the direct TCP connection
pub fn get_client_ip(session: &Session) -> String {
    // When trusted proxies are configured, a direct (untrusted) peer's
    // forwarded headers must be ignored to prevent client-IP spoofing.
    if TRUSTED_PROXIES_ENABLED.load(Ordering::Relaxed) {
        // Compare the address itself; formatting it only to parse it back
        // would cost an allocation per request.
        let Some(peer) = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|addr| addr.ip().to_canonical())
        else {
            return String::new();
        };
        let trusted = TRUSTED_PROXIES.load();
        let Some(trusted) =
            trusted.as_ref().filter(|trusted| trusted.contains(peer))
        else {
            return peer.to_string();
        };
        let headers = &session.req_header().headers;
        if let Some(ip) = forwarded_client_ip(
            headers.get_all(HTTP_HEADER_X_FORWARDED_FOR).iter(),
            trusted,
        ) {
            return ip;
        }
        if let Some(ip) = headers
            .get(HTTP_HEADER_X_REAL_IP)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            return ip.to_string();
        }
        return peer.to_string();
    }
    // 1. Check `X-Forwarded-For`.
    if let Some(value) = session.get_header(HTTP_HEADER_X_FORWARDED_FOR) {
        // Efficiently take the first IP without creating an intermediate Vec.
        if let Ok(s) = value.to_str()
            && let Some(ip) = s.split(',').next()
        {
            let trimmed_ip = ip.trim();
            if !trimmed_ip.is_empty() {
                return trimmed_ip.to_string();
            }
        }
    }
    // 2. Check `X-Real-IP`.
    if let Some(value) = session.get_header(HTTP_HEADER_X_REAL_IP) {
        return value.to_str().unwrap_or_default().to_string();
    }
    // 3. Fall back to the direct connection's remote address.
    if let Some((addr, _)) = get_remote_addr(session) {
        return addr;
    }
    // If all checks fail, return an empty string.
    "".to_string()
}

/// A convenient helper to get a header value as a `&str` from a `RequestHeader`.
pub fn get_req_header_value<'a>(
    req_header: &'a RequestHeader,
    key: &str,
) -> Option<&'a str> {
    // Get the header by its key.
    if let Some(value) = req_header.headers.get(key) {
        // Try to convert it to a string slice. Fails if the value is not valid UTF-8.
        if let Ok(value) = value.to_str() {
            return Some(value);
        }
    }
    None
}

/// Parses the "Cookie" header to find the value of a specific cookie.
pub fn get_cookie_value<'a>(
    req_header: &'a RequestHeader,
    cookie_name: &str,
) -> Option<&'a str> {
    // First, get the entire "Cookie" header string. The '?' operator will short-circuit if it's not present.
    get_req_header_value(req_header, "cookie")?
        // Split the string into individual cookies.
        .split(';')
        // `find_map` is an efficient way to find the first cookie that matches our criteria.
        .find_map(|item| {
            // This chained logic attempts to quickly find a match.
            // It's more complex to handle cases like "key=value" vs "key=" correctly.
            item.trim()
                .strip_prefix(cookie_name)?
                .strip_prefix('=')
                .or_else(|| {
                    // Fallback logic to ensure the cookie name is an exact match.
                    let (k, v) = item.split_once('=')?;
                    if k.trim() == cookie_name {
                        Some(v.trim())
                    } else {
                        None
                    }
                })
        })
}

/// Gets the value of a specific query parameter from the request URI.
pub fn get_query_value<'a>(
    req_header: &'a RequestHeader,
    name: &str,
) -> Option<&'a str> {
    // Get the query string from the URI, exiting if it doesn't exist.
    req_header
        .uri
        .query()?
        // Split the query string into key-value pairs.
        .split('&')
        // `find_map` efficiently searches for the first pair where the key matches.
        .find_map(|item| {
            // Split the pair into key and value.
            let (k, v) = item.split_once('=')?;
            // If the key matches, return the value.
            if k == name { Some(v) } else { None }
        })
}

/// Removes a specific query parameter from the request header's URI.
///
/// This function modifies the `req_header` in place.
pub fn remove_query_from_header(
    req_header: &mut RequestHeader,
    name: &str,
) -> Result<(), http::Error> {
    // If there is no query string, there is nothing to do.
    let Some(query_str) = req_header.uri.query() else {
        return Ok(());
    };

    // Pre-allocate a String with enough capacity to hold the new query string,
    // which is a performance optimization to avoid reallocations.
    let mut new_query = String::with_capacity(query_str.len());

    // Iterate over each key-value pair in the original query string.
    for item in query_str.split('&') {
        // Get the key part of the pair.
        let key = item.split('=').next().unwrap_or(item);

        // If the key is not the one we want to remove, keep the item.
        if key != name {
            // If the new query string is not empty, add a separator first.
            if !new_query.is_empty() {
                new_query.push('&');
            }
            // Append the original "key=value" slice, which is allocation-free.
            new_query.push_str(item);
        }
    }

    // The path as it was, with what is left of the query.
    let path = req_header.uri.path();
    let mut path_and_query =
        String::with_capacity(path.len() + 1 + new_query.len());
    path_and_query.push_str(path);
    if !new_query.is_empty() {
        path_and_query.push('?');
        path_and_query.push_str(&new_query);
    }

    set_path_and_query(req_header, &path_and_query)
}

/// Whether `path` has anything for `normalize_path` to do: a `%`, a path
/// parameter (`;`), a backslash, an empty segment (`//`), or a segment that
/// is `.` or `..`.
fn path_needs_normalizing(path: &[u8]) -> bool {
    let mut after_slash = false;
    for (index, byte) in path.iter().enumerate() {
        match byte {
            b'%' | b';' | b'\\' => return true,
            b'/' if after_slash => return true,
            b'.' if after_slash => {
                let rest = &path[index + 1..];
                let rest = rest.strip_prefix(b".").unwrap_or(rest);
                if rest.first().is_none_or(|next| *next == b'/') {
                    return true;
                }
            },
            _ => {},
        }
        after_slash = *byte == b'/';
    }
    false
}

/// The path of a request in the form it is matched by: percent-encoding
/// decoded, path parameters left out, a backslash taken for a slash, `.`
/// and `..` segments resolved, repeated slashes merged.
///
/// Which location a request belongs to is decided on this form, because it
/// is the form most upstreams go on to serve. Matching the path as it was
/// sent let `/%61dmin`, `//admin` and `/public/../admin` slip past a
/// location for `/admin`, and whatever plugins guard it, on their way to
/// an upstream that reads all three as `/admin`. Only the matching uses
/// it; the request is forwarded as it came.
///
/// Two of these are what some upstreams read and others do not. A servlet
/// container drops the `;name=value` of a segment before it looks at the
/// path, so to Tomcat `/public/..;/admin` and `/api;v=1/admin` are
/// `/admin` and `/api/admin`; IIS takes `\` for `/`. An upstream that does
/// neither has nothing at such a path, so reading it the way the others do
/// costs it nothing, and the ones that do are no longer reached past the
/// location that was meant to stand in front of them.
///
/// A path with nothing to change, which is nearly every path, is returned
/// as it is.
pub fn normalize_path(path: &str) -> Cow<'_, str> {
    match normalized_path_bytes(path) {
        None => Cow::Borrowed(path),
        Some(normalized) => {
            Cow::Owned(String::from_utf8_lossy(&normalized).into_owned())
        },
    }
}

/// [`normalize_path`] in a form that can be sent on: the same path, with
/// what a uri cannot carry as it is - a space, a `?` that was `%3F`, a
/// byte that is not ASCII - percent-encoded again.
///
/// This is the path a location's `rewrite` falls back on. The rule used
/// to be matched against the path as it was sent and nothing else, while
/// the location had been chosen by the normalized one: `/%75sers/x`
/// reached the location for `/users` and then slipped past its
/// `^/users/(.*)$ /acme/$1`, to arrive at the upstream as `/users/x`
/// without the prefix; `/users/../other` took the prefix and left it again
/// one segment later.
///
/// It is not the path to rewrite every request by: it says less than the
/// path that was sent. `%2F` has become a separator, `;jsessionid=...` is
/// gone, `//` is one slash. See `Location::rewrite` for when it is used.
///
/// A path with nothing to change is returned as it is, like there.
pub fn canonical_path(path: &str) -> Cow<'_, str> {
    let Some(normalized) = normalized_path_bytes(path) else {
        return Cow::Borrowed(path);
    };
    let mut encoded = String::with_capacity(normalized.len() + 8);
    for byte in normalized {
        // What a path may hold unencoded (RFC 3986 `pchar`, and the `/`
        // between segments).
        let plain = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'-'
                    | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            );
        if plain {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            encoded.push(char::from(b"0123456789ABCDEF"[(byte & 15) as usize]));
        }
    }
    Cow::Owned(encoded)
}

/// Whether `path` has a `.` or `..` segment, read the way
/// [`normalize_path`] reads it: `%2e%2e`, `..;x`, and the ones that only
/// show once `%2F` or `\` is taken for a separator (`a%2F..%2Fb`).
///
/// A path without one cannot leave the directory it names under any of
/// those readings, since each of them finds its segments among the ones
/// found here. That is what makes such a path safe to rewrite as it was
/// sent.
pub fn has_dot_segments(path: &str) -> bool {
    normalized_path(path).is_some_and(|(_, dot_segments)| dot_segments)
}

/// The bytes of the normalized path, `None` when the path is in that form
/// already - which is nearly every path.
fn normalized_path_bytes(path: &str) -> Option<Vec<u8>> {
    normalized_path(path).map(|(bytes, _)| bytes)
}

/// [`normalized_path_bytes`], and whether a `.` or `..` segment was
/// resolved on the way.
fn normalized_path(path: &str) -> Option<(Vec<u8>, bool)> {
    let bytes = path.as_bytes();
    if !path.starts_with('/') || !path_needs_normalizing(bytes) {
        return None;
    }
    let hex = |byte: Option<&u8>| {
        byte.and_then(|byte| (*byte as char).to_digit(16))
            .map(|value| value as u8)
    };
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(high), Some(low)) =
                (hex(bytes.get(index + 1)), hex(bytes.get(index + 2)))
        {
            decoded.push(high << 4 | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    let mut segments: Vec<&[u8]> = vec![];
    let mut dot_segments = false;
    // Whether the path ends in a directory, `/a/` as well as `/a/.`.
    let mut trailing_slash = false;
    for segment in decoded.split(|byte| matches!(byte, b'/' | b'\\')) {
        trailing_slash = true;
        // The name of the segment, without its parameters.
        let name = segment
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or(segment);
        match name {
            b"" => {},
            b"." => dot_segments = true,
            b".." => {
                dot_segments = true;
                segments.pop();
            },
            _ => {
                segments.push(name);
                trailing_slash = false;
            },
        }
    }
    let mut normalized = Vec::with_capacity(decoded.len());
    for segment in segments.iter() {
        normalized.push(b'/');
        normalized.extend_from_slice(segment);
    }
    if trailing_slash || normalized.is_empty() {
        normalized.push(b'/');
    }
    Some((normalized, dot_segments))
}

/// Replaces the path and query of the request, and nothing else.
///
/// An HTTP/2 request carries its host in the uri (`:authority`) and usually
/// has no `Host` header. Setting a uri parsed from the path alone took the
/// host away with it: the upstream request went out without a `Host`, and
/// whatever asked for the request's host afterwards - the cache key, the
/// access log - found none.
pub fn set_path_and_query(
    req_header: &mut RequestHeader,
    path_and_query: &str,
) -> Result<(), http::Error> {
    if req_header.uri.authority().is_none() {
        req_header.set_uri(http::Uri::from_str(path_and_query)?);
        return Ok(());
    }
    let path_and_query = http::uri::PathAndQuery::from_str(path_and_query)?;
    let mut parts = req_header.uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query);
    // Scheme and authority are those of a uri that was valid already. One
    // that has an authority and no scheme takes no path at all: that is an
    // error like any other, not a path that was set.
    req_header.set_uri(http::Uri::from_parts(parts)?);

    Ok(())
}

/// Takes `names` out of what the `Connection` header of a request
/// nominates, for the headers the proxy itself has put on the request.
///
/// A header named in `Connection` is one its sender calls hop-by-hop, and
/// it is removed from the request that goes to the upstream. For a header
/// of the client's own that is as it should be. For one a plugin set - the
/// address of the client, what the auth service said of it - it let the
/// client decide that the upstream does not get it: `Connection: X-User-Id`
/// was enough. Only `Host` and the `X-Forwarded-*` headers were safe from
/// that.
///
/// The rest of the header stays as it is: `keep-alive`, `upgrade` and what
/// else the client nominated.
pub fn protect_from_connection_header(
    req: &mut RequestHeader,
    names: &[HeaderName],
) {
    if names.is_empty() || !req.headers.contains_key(header::CONNECTION) {
        return;
    }
    let nominated = |token: &str| {
        names
            .iter()
            .any(|name| name.as_str().eq_ignore_ascii_case(token))
    };
    let mut kept = vec![];
    let mut removed = false;
    for value in req.headers.get_all(header::CONNECTION).iter() {
        // A value that is not text has no name in it to take out.
        let Ok(value) = value.to_str() else {
            return;
        };
        for token in value.split(',').map(str::trim) {
            if token.is_empty() {
                continue;
            }
            if nominated(token) {
                removed = true;
            } else {
                kept.push(token);
            }
        }
    }
    if !removed {
        return;
    }
    let kept = kept.join(", ");
    req.remove_header(&header::CONNECTION);
    if !kept.is_empty() {
        let _ = req.insert_header(header::CONNECTION, kept);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectionInfo, UpstreamInfo, new_test_session};
    use pretty_assertions::assert_eq;

    /// Regression: a client could name a header the proxy set in its
    /// `Connection`, and the upstream never got it.
    #[test]
    fn test_protect_from_connection_header() {
        let protected = [
            HeaderName::from_static("x-real-ip"),
            HeaderName::from_static("x-user-id"),
        ];
        let after = |connection: &[&str]| {
            let mut req = RequestHeader::build("GET", b"/", None).unwrap();
            for value in connection {
                req.append_header(header::CONNECTION, *value).unwrap();
            }
            protect_from_connection_header(&mut req, &protected);
            req.headers
                .get_all(header::CONNECTION)
                .iter()
                .map(|value| value.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        // Taken out, in whatever case and among whatever else.
        assert_eq!(Vec::<String>::new(), after(&["X-Real-IP"]));
        assert_eq!(vec!["keep-alive"], after(&["keep-alive, x-real-ip"]));
        assert_eq!(
            vec!["keep-alive, upgrade, X-Other"],
            after(&[" keep-alive ,X-USER-ID,upgrade", "x-real-ip, X-Other"])
        );
        // Nothing of ours in it: left exactly as it came.
        assert_eq!(
            vec!["keep-alive , Upgrade"],
            after(&["keep-alive , Upgrade"])
        );
        assert_eq!(vec!["close", "X-Other"], after(&["close", "X-Other"]));
        assert_eq!(Vec::<String>::new(), after(&[]));
        // A name that only begins like one of ours is another name.
        assert_eq!(vec!["x-real-ip-2"], after(&["x-real-ip-2"]));
    }

    #[test]
    fn test_convert_headers() {
        let headers = convert_headers(&[
            "Content-Type: application/octet-stream".to_string(),
            "X-Server: $hostname".to_string(),
            "X-User: $USER".to_string(),
        ])
        .unwrap();
        assert_eq!(3, headers.len());
        assert_eq!("content-type", headers[0].0.to_string());
        assert_eq!("application/octet-stream", headers[0].1.to_str().unwrap());
        assert_eq!("x-server", headers[1].0.to_string());
        assert_eq!(false, headers[1].1.to_str().unwrap().is_empty());
        assert_eq!("x-user", headers[2].0.to_string());
        assert_eq!(false, headers[2].1.to_str().unwrap().is_empty());
    }

    #[test]
    fn test_static_value() {
        assert_eq!(
            "cache-control: private, no-store",
            format!(
                "{}: {}",
                HTTP_HEADER_NO_STORE.0.to_string(),
                HTTP_HEADER_NO_STORE.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "cache-control: private, no-cache",
            format!(
                "{}: {}",
                HTTP_HEADER_NO_CACHE.0.to_string(),
                HTTP_HEADER_NO_CACHE.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "content-type: application/json; charset=utf-8",
            format!(
                "{}: {}",
                HTTP_HEADER_CONTENT_JSON.0.to_string(),
                HTTP_HEADER_CONTENT_JSON.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "content-type: text/html; charset=utf-8",
            format!(
                "{}: {}",
                HTTP_HEADER_CONTENT_HTML.0.to_string(),
                HTTP_HEADER_CONTENT_HTML.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "transfer-encoding: chunked",
            format!(
                "{}: {}",
                HTTP_HEADER_TRANSFER_CHUNKED.0.to_string(),
                HTTP_HEADER_TRANSFER_CHUNKED.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!("x-request-id", HTTP_HEADER_NAME_X_REQUEST_ID.to_string());

        assert_eq!(
            "content-type: text/plain; charset=utf-8",
            format!(
                "{}: {}",
                HTTP_HEADER_CONTENT_TEXT.0.to_string(),
                HTTP_HEADER_CONTENT_TEXT.1.to_str().unwrap_or_default()
            )
        );
    }

    #[tokio::test]
    async fn test_convert_header_value() {
        let session =
            new_test_session(&["Host: pingap.io"], "/vicanso/pingap?size=1")
                .await;
        let default_state = Ctx {
            upstream: UpstreamInfo {
                address: "10.1.1.3:4123".to_string(),
                ..Default::default()
            },
            conn: ConnectionInfo {
                id: 102,
                remote_addr: Some("10.1.1.1".to_string()),
                remote_port: Some(6000),
                server_addr: Some("10.1.1.2".to_string()),
                server_port: Some(6001),
                tls_version: Some("tls1.3".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let value = convert_header_value(
            &HeaderValue::from_str("$host").unwrap(),
            &session,
            &Ctx {
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("pingap.io", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$scheme").unwrap(),
            &session,
            &Ctx {
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("http", value.unwrap().to_str().unwrap());
        let value = convert_header_value(
            &HeaderValue::from_str("$scheme").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("https", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$remote_addr").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$remote_port").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("6000", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$server_addr").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.2", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$server_port").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("6001", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$upstream_addr").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.3:4123", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str(":connection_id").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("102", value.unwrap().to_str().unwrap());

        let session = new_test_session(
            &["X-Forwarded-For: 1.1.1.1, 2.2.2.2"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("$proxy_add_x_forwarded_for").unwrap(),
            &session,
            &Ctx {
                conn: ConnectionInfo {
                    remote_addr: Some("10.1.1.1".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!(
            "1.1.1.1, 2.2.2.2, 10.1.1.1",
            value.unwrap().to_str().unwrap()
        );

        let session = new_test_session(&[""], "/vicanso/pingap?size=1").await;
        let value = convert_header_value(
            &HeaderValue::from_str("$proxy_add_x_forwarded_for").unwrap(),
            &session,
            &Ctx {
                conn: ConnectionInfo {
                    remote_addr: Some("10.1.1.1".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1", value.unwrap().to_str().unwrap());

        let session = new_test_session(&[""], "/vicanso/pingap?size=1").await;
        let value = convert_header_value(
            &HeaderValue::from_str("$upstream_addr").unwrap(),
            &session,
            &Ctx {
                upstream: UpstreamInfo {
                    address: "10.1.1.1:8001".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1:8001", value.unwrap().to_str().unwrap());

        // `$ja4` and the log-field form `:ja4` read the connection's
        // fingerprint; without one there is nothing to set.
        let session = new_test_session(&[""], "/vicanso/pingap?size=1").await;
        let mut ctx = Ctx::default();
        for tag in ["$ja4", ":ja4"] {
            let value = convert_header_value(
                &HeaderValue::from_str(tag).unwrap(),
                &session,
                &ctx,
            );
            assert_eq!(true, value.is_none(), "{tag}");
        }
        ctx.conn.ja4 = Some(std::sync::Arc::new(
            crate::Ja4Fingerprint::from_client_hello(
                &crate::ja4::testing::spec_example_body(),
            )
            .unwrap(),
        ));
        for tag in ["$ja4", ":ja4"] {
            let value = convert_header_value(
                &HeaderValue::from_str(tag).unwrap(),
                &session,
                &ctx,
            );
            assert_eq!(
                "t13d1516h2_8daaf6152771_e5627efa2ab1",
                value.unwrap().to_str().unwrap(),
                "{tag}"
            );
        }
        // Never resolved as an environment variable at load time.
        assert_eq!(
            "$ja4",
            resolve_static_header_value(HeaderValue::from_static("$ja4"))
        );

        let session = new_test_session(
            &["Origin: https://github.com"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("$http_origin").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(true, value.is_some());
        assert_eq!("https://github.com", value.unwrap().to_str().unwrap());

        let session = new_test_session(
            &["Origin: https://github.com"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("$hostname").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(true, value.is_some());

        let session = new_test_session(
            &["Origin: https://github.com"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("$HOME").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(true, value.is_some());

        let session = new_test_session(
            &["Origin: https://github.com"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("UUID").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(false, value.is_some());
    }

    #[tokio::test]
    async fn test_get_host() {
        let session =
            new_test_session(&["Host: pingap.io"], "/vicanso/pingap?size=1")
                .await;
        assert_eq!(get_host(session.req_header()), Some("pingap.io"));
    }

    #[test]
    fn test_remove_query_from_header() {
        let mut req =
            RequestHeader::build("GET", b"/?apikey=123", None).unwrap();
        remove_query_from_header(&mut req, "apikey").unwrap();
        assert_eq!("/", req.uri.to_string());

        let mut req =
            RequestHeader::build("GET", b"/?apikey=123&name=pingap", None)
                .unwrap();
        remove_query_from_header(&mut req, "apikey").unwrap();
        assert_eq!("/?name=pingap", req.uri.to_string());
    }

    #[tokio::test]
    async fn test_get_client_ip() {
        let session = new_test_session(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
        )
        .await;
        assert_eq!(get_client_ip(&session), "192.168.1.1");

        let session = new_test_session(
            &["X-Real-Ip:192.168.1.2"],
            "/vicanso/pingap?size=1",
        )
        .await;
        assert_eq!(get_client_ip(&session), "192.168.1.2");

        // What is passed on about the client is what can be vouched for.
        // Without trusted proxies that is this connection: its peer, its
        // scheme and the host it asked for, whatever the request claims
        // in the headers a proxy would set.
        let claims = [
            "Host: pingap.io",
            "X-Forwarded-For: 192.168.1.1",
            "X-Forwarded-Proto: https",
            "X-Forwarded-Host: other.example",
        ];
        let session = new_test_session(&claims, "/").await;
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some("10.1.1.1".to_string());
        let resolve = |name: &'static str, session: &Session, ctx: &Ctx| {
            convert_header_value(&HeaderValue::from_static(name), session, ctx)
                .map(|value| value.to_str().unwrap().to_string())
        };
        assert_eq!(false, peer_is_trusted_proxy(&session));
        ctx.conn.server_port = Some(8080);
        for (name, expected) in [
            ("$client_ip", "10.1.1.1"),
            ("$forwarded_proto", "http"),
            ("$forwarded_host", "pingap.io"),
            ("$forwarded_port", "8080"),
        ] {
            assert_eq!(
                Some(expected.to_string()),
                resolve(name, &session, &ctx),
                "{name}"
            );
        }
        ctx.conn.tls_version = Some(Cow::Borrowed("TLSv1.3"));
        assert_eq!(
            Some("https".to_string()),
            resolve("$forwarded_proto", &session, &ctx)
        );
        // They are of the request, not of the environment: left for the
        // request path when the configuration is loaded.
        for name in [
            "$client_ip",
            "$forwarded_proto",
            "$forwarded_host",
            "$forwarded_port",
        ] {
            assert_eq!(
                name,
                resolve_static_header_value(HeaderValue::from_static(name))
            );
        }

        // Of a header a chain of proxies each added to, the first entry
        // is the client's end of it, whether they wrote one line or
        // several.
        let entry = |lines: &[&'static str]| {
            let values: Vec<HeaderValue> = lines
                .iter()
                .map(|line| HeaderValue::from_static(line))
                .collect();
            first_forwarded_entry(values.iter()).map(str::to_string)
        };
        assert_eq!(Some("https".to_string()), entry(&["https, http"]));
        assert_eq!(Some("https".to_string()), entry(&[" , https", "http"]));
        assert_eq!(Some("https".to_string()), entry(&["https", "http"]));
        assert_eq!(None, entry(&[]));
        assert_eq!(None, entry(&[" , "]));
        // What is passed on as a host has to read as one.
        for host in ["shop.example.com", "shop.example.com:8443", "[::1]:80"] {
            assert_eq!(true, is_host_name(host), "{host}");
        }
        for host in [
            "",
            "user@shop.example.com",
            "shop.example.com/path",
            "shop example.com",
            "evil.example\r\nx: 1",
        ] {
            assert_eq!(false, is_host_name(host), "{host}");
        }

        // With trusted proxies configured, a forwarded header from an untrusted
        // direct peer (the mock session has no trusted peer address) must be
        // ignored instead of being taken at face value.
        set_trusted_proxies(&Some(vec!["10.0.0.0/8".to_string()]));
        let session = new_test_session(&claims, "/").await;
        assert_eq!(false, peer_is_trusted_proxy(&session));
        ctx.conn.tls_version = None;
        assert_eq!(
            Some("http".to_string()),
            resolve("$forwarded_proto", &session, &ctx)
        );
        assert_eq!(
            Some("pingap.io".to_string()),
            resolve("$forwarded_host", &session, &ctx)
        );
        // The client ip that was worked out for the request is the one.
        ctx.conn.client_ip = Some("203.0.113.9".to_string());
        assert_eq!(
            Some("203.0.113.9".to_string()),
            resolve("$client_ip", &session, &ctx)
        );
        let session = new_test_session(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
        )
        .await;
        assert_ne!(get_client_ip(&session), "192.168.1.1");

        // Restoring the default trusts forwarded headers again.
        set_trusted_proxies(&None);
        let session = new_test_session(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
        )
        .await;
        assert_eq!(get_client_ip(&session), "192.168.1.1");
    }

    #[test]
    fn test_forwarded_client_ip() {
        let trusted = TrustedProxies::parse(&[
            "10.0.0.0/8".to_string(),
            "192.168.1.1".to_string(),
            "fd00::/8".to_string(),
        ]);
        let client_ip = |lines: &[&str]| {
            let values: Vec<HeaderValue> = lines
                .iter()
                .map(|line| HeaderValue::from_str(line).unwrap())
                .collect();
            forwarded_client_ip(values.iter(), &trusted)
        };
        let ip = |value: &str| Some(value.to_string());

        assert_eq!(ip("9.9.9.9"), client_ip(&["9.9.9.9"]));
        // Regression: what the client wrote comes first, the address the
        // trusted proxy saw comes last. The first one used to win.
        assert_eq!(ip("9.9.9.9"), client_ip(&["6.6.6.6, 9.9.9.9"]));
        assert_eq!(ip("9.9.9.9"), client_ip(&["6.6.6.6,10.1.1.1 , 9.9.9.9"]));
        // A chain of trusted proxies is skipped from the right.
        assert_eq!(
            ip("9.9.9.9"),
            client_ip(&["6.6.6.6, 9.9.9.9, 10.0.0.2, 192.168.1.1"])
        );
        assert_eq!(ip("2001:db8::1"), client_ip(&["2001:db8::1, fd00::2"]));
        // Several header lines read as one list.
        assert_eq!(
            ip("9.9.9.9"),
            client_ip(&["6.6.6.6", "9.9.9.9", "10.0.0.2"])
        );
        assert_eq!(ip("9.9.9.9"), client_ip(&["6.6.6.6, 9.9.9.9", "10.0.0.2"]));
        // The request started at a trusted proxy: the left-most of them.
        assert_eq!(ip("10.0.0.3"), client_ip(&["10.0.0.3, 10.0.0.2"]));
        // With a port, as some proxies write it.
        assert_eq!(ip("9.9.9.9"), client_ip(&["9.9.9.9:4321, 10.0.0.2:80"]));
        assert_eq!(
            ip("2001:db8::1"),
            client_ip(&["[2001:db8::1]:4321, [fd00::2]"])
        );
        // Not an address: not a trusted proxy either, so that is the answer
        // and nothing to its left is looked at.
        assert_eq!(ip("unknown"), client_ip(&["6.6.6.6, unknown, 10.0.0.2"]));
        assert_eq!(None, client_ip(&[]));
        assert_eq!(None, client_ip(&[" , "]));

        // Regression: the IPv4-mapped form is the IPv4 address, as a
        // trusted proxy and as a client.
        assert_eq!(
            ip("9.9.9.9"),
            client_ip(&["6.6.6.6, ::ffff:9.9.9.9, ::ffff:10.0.0.2"])
        );
        assert_eq!(true, trusted.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert_eq!(
            true,
            trusted.contains("::ffff:192.168.1.1".parse().unwrap())
        );
        assert_eq!(false, trusted.contains("::ffff:9.9.9.9".parse().unwrap()));
        let mapped = TrustedProxies::parse(&["::ffff:172.16.0.1".to_string()]);
        assert_eq!(true, mapped.contains("172.16.0.1".parse().unwrap()));

        // Regression: a byte that is not ASCII, written by the client at
        // the front of the line the proxy appends to. The whole line used
        // to be dropped, leaving the client's own `X-Real-IP` or the
        // proxy's address as the answer.
        let line = HeaderValue::from_bytes(b"\xff\xfe, 9.9.9.9").unwrap();
        assert_eq!(
            ip("9.9.9.9"),
            forwarded_client_ip([&line].into_iter(), &trusted)
        );
        let line = HeaderValue::from_bytes(b"6.6.6.6, \xff, 9.9.9.9, 10.0.0.2")
            .unwrap();
        assert_eq!(
            ip("9.9.9.9"),
            forwarded_client_ip([&line].into_iter(), &trusted)
        );
    }

    #[tokio::test]
    async fn test_get_header_value() {
        let session =
            new_test_session(&["Host: pingap.io"], "/vicanso/pingap?size=1")
                .await;
        assert_eq!(
            get_req_header_value(session.req_header(), "Host"),
            Some("pingap.io")
        );
    }

    #[tokio::test]
    async fn test_get_cookie_value() {
        let session = new_test_session(
            &["Cookie: name=pingap"],
            "/vicanso/pingap?size=1",
        )
        .await;
        assert_eq!(
            get_cookie_value(session.req_header(), "name"),
            Some("pingap")
        );
    }

    #[tokio::test]
    async fn test_get_query_value() {
        let session = new_test_session(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
        )
        .await;
        assert_eq!(get_query_value(session.req_header(), "size"), Some("1"));
    }

    /// Tests `convert_header` with edge cases like empty strings,
    /// strings without colons, and invalid header names/values.
    #[test]
    fn test_convert_header_edge_cases() {
        // Empty string should result in Ok(None).
        assert!(convert_header("").unwrap().is_none());
        // String without a colon should result in Ok(None).
        assert!(convert_header("no-colon").unwrap().is_none());
        // Invalid header name should result in an error.
        assert!(convert_header("Invalid Name: value").is_err());
        // Invalid header value (with newline) should result in an error.
        assert!(convert_header("Valid-Name: invalid\r\nvalue").is_err());
    }

    /// Tests `get_host` logic with different request formats.
    #[test]
    fn test_get_host_variants() {
        // Case 1: Host is in the URI authority.
        let uri_string = "http://user:pass@authority.com/path";

        // 使用 .parse() 或 from_str 来创建 Uri
        let uri = http::Uri::from_str(uri_string).unwrap();
        let mut req_with_authority =
            RequestHeader::build("GET", b"/path", None).unwrap();
        req_with_authority.set_uri(uri);
        assert_eq!(get_host(&req_with_authority), Some("authority.com"));

        // Case 2: Host is in the "Host" header.
        let mut req_with_host_header =
            RequestHeader::build("GET", b"/path", None).unwrap();
        req_with_host_header
            .insert_header("Host", "header-host.com:8080")
            .unwrap();
        assert_eq!(get_host(&req_with_host_header), Some("header-host.com"));

        // Case 3: No host information available.
        let req_no_host = RequestHeader::build("GET", b"/path", None).unwrap();
        assert_eq!(get_host(&req_no_host), None);

        // Case 4: IPv6 literals keep their brackets and lose only the port.
        for (host, expected) in [
            ("[::1]:8080", "[::1]"),
            ("[::1]", "[::1]"),
            ("[2001:db8::1]:443", "[2001:db8::1]"),
            ("example.com", "example.com"),
            ("example.com:8080", "example.com"),
        ] {
            let mut req = RequestHeader::build("GET", b"/path", None).unwrap();
            req.insert_header("Host", host).unwrap();
            assert_eq!(get_host(&req), Some(expected), "{host}");
        }
    }

    /// Regression: `example.com.` is `example.com` with the root label
    /// written out. Matched as it came it missed the locations of the host
    /// and went to the catch-all, past the plugins guarding the host.
    #[test]
    fn test_get_host_drops_the_root_label() {
        for (host, expected) in [
            ("admin.example.com.", "admin.example.com"),
            ("admin.example.com.:8443", "admin.example.com"),
            ("Admin.Example.com.", "Admin.Example.com"),
            ("admin.example.com", "admin.example.com"),
            // Only the one label: this is another, odd, name.
            ("admin.example.com..", "admin.example.com."),
            (".", "."),
        ] {
            let mut req = RequestHeader::build("GET", b"/path", None).unwrap();
            req.insert_header("Host", host).unwrap();
            assert_eq!(get_host(&req), Some(expected), "{host}");
        }
        // The `:authority` of HTTP/2 as well.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.set_uri(http::Uri::from_static("https://admin.example.com./a"));
        assert_eq!(get_host(&req), Some("admin.example.com"));
        // As it was sent, which is what the cache key is made of.
        assert_eq!(get_request_host(&req), Some("admin.example.com."));
    }

    /// The request is routed as `example.com` and goes to the upstream as
    /// `example.com.`. What the upstream answers to that name is not
    /// stored as the answer for the other.
    #[test]
    fn test_cache_key_keeps_the_host_as_sent() {
        let key = |host: &str| {
            let mut req = RequestHeader::build("GET", b"/a", None).unwrap();
            req.insert_header("Host", host).unwrap();
            let ctx = Ctx {
                cache: Some(Default::default()),
                ..Default::default()
            };
            format!("{:?}", crate::get_cache_key(&ctx, "GET", &req))
        };
        assert_ne!(key("example.com"), key("example.com."));
        assert_eq!(key("example.com"), key("EXAMPLE.com:8080"));
    }

    /// Regression: HTTP/2 lets a client send its cookies as several
    /// fields, and every reader of a cookie looked at the first.
    #[test]
    fn test_merge_cookie_headers() {
        let cookies = |values: &[&str]| {
            let mut req = RequestHeader::build("GET", b"/", None).unwrap();
            for value in values {
                req.append_header("cookie", *value).unwrap();
            }
            merge_cookie_headers(&mut req);
            let merged: Vec<String> = req
                .headers
                .get_all(http::header::COOKIE)
                .iter()
                .map(|value| value.to_str().unwrap().to_string())
                .collect();
            let c = get_cookie_value(&req, "c").map(|v| v.to_string());
            (merged, c)
        };
        assert_eq!(
            (vec!["a=1; b=2; c=3".to_string()], Some("3".to_string())),
            cookies(&["a=1", "b=2", "c=3"])
        );
        assert_eq!(
            (vec!["a=1; b=2; c=3".to_string()], Some("3".to_string())),
            cookies(&["a=1; b=2", "c=3"])
        );
        // One field, or none, is left as it is.
        assert_eq!(
            (vec!["a=1; c=3".to_string()], Some("3".to_string())),
            cookies(&["a=1; c=3"])
        );
        assert_eq!((vec![], None), cookies(&[]));
    }

    /// Regression: only the first `X-Forwarded-For` line was carried over.
    /// A proxy in front that adds its entry as a line of its own - the
    /// address it saw the client at - lost that entry, and what was left
    /// was the line the client had written itself.
    #[tokio::test]
    async fn test_proxy_add_x_forwarded_for_keeps_every_line() {
        let session = new_test_session(
            &["X-Forwarded-For: 6.6.6.6", "X-Forwarded-For: 10.0.0.9"],
            "/",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("$proxy_add_x_forwarded_for").unwrap(),
            &session,
            &Ctx {
                conn: ConnectionInfo {
                    remote_addr: Some("10.0.0.1".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(
            "6.6.6.6, 10.0.0.9, 10.0.0.1",
            value.unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn test_resolve_static_header_value() {
        let resolve = |value: &str| {
            resolve_static_header_value(HeaderValue::from_str(value).unwrap())
        };
        assert_eq!(get_hostname(), resolve("$hostname").to_str().unwrap());
        let home = std::env::var("HOME").unwrap();
        assert_eq!(home, resolve("$HOME").to_str().unwrap());
        // Request-time variables, plain values and unset variables are left
        // for the request path.
        for value in [
            "$host",
            "$remote_addr",
            "$proxy_add_x_forwarded_for",
            "$http_origin",
            ":connection_id",
            "plain",
            "$PINGAP_TEST_UNSET_VARIABLE",
        ] {
            assert_eq!(value, resolve(value).to_str().unwrap());
        }
    }

    /// `$http_<name>` accepts the nginx spelling with underscores.
    #[tokio::test]
    async fn test_http_variable_with_underscores() {
        let session = new_test_session(
            &["User-Agent: pingap/1", "X-Env-Name: prod"],
            "/",
        )
        .await;
        for (variable, expected) in [
            ("$http_user_agent", Some("pingap/1")),
            ("$http_user-agent", Some("pingap/1")),
            ("$http_x_env_name", Some("prod")),
            ("$http_missing_header", None),
        ] {
            let value = convert_header_value(
                &HeaderValue::from_str(variable).unwrap(),
                &session,
                &Ctx::default(),
            );
            assert_eq!(
                expected,
                value.as_ref().and_then(|v| v.to_str().ok()),
                "{variable}"
            );
        }
    }

    /// Tests `get_cookie_value` with multiple cookies and edge cases.
    #[test]
    fn test_get_cookie_value_advanced() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Cookie", "id=123; session=abc; theme=dark")
            .unwrap();

        assert_eq!(get_cookie_value(&req, "session"), Some("abc"));
        assert_eq!(get_cookie_value(&req, "id"), Some("123"));
        assert_eq!(get_cookie_value(&req, "theme"), Some("dark"));
        // Test for a non-existent cookie.
        assert_eq!(get_cookie_value(&req, "lang"), None);
        // Test for a cookie name that is a prefix of another.
        assert_eq!(get_cookie_value(&req, "the"), None);
    }

    /// The normalized path as it can be sent on: what `normalize_path`
    /// gives, with whatever a uri cannot carry encoded again.
    #[test]
    fn test_canonical_path() {
        // Nothing to change: the very same string.
        for path in ["/", "/users/x", "/a/b.c/d", "relative"] {
            assert_eq!(
                true,
                matches!(canonical_path(path), Cow::Borrowed(_)),
                "{path}"
            );
        }
        for (path, expected) in [
            ("/%75sers/x", "/users/x"),
            ("/users/../other", "/other"),
            ("//users/./x/", "/users/x/"),
            ("/users;v=1/x", "/users/x"),
            ("/a%20b", "/a%20b"),
            ("/a%3fb", "/a%3Fb"),
            ("/a%23b", "/a%23b"),
            ("/a%2fb", "/a/b"),
            ("/100%25", "/100%25"),
            // decoded once, not twice
            ("/%2561", "/%2561"),
            ("/caf%c3%a9", "/caf%C3%A9"), // spellchecker:disable-line
            // not text, and still the same bytes
            ("/%ff%00", "/%FF%00"),
        ] {
            assert_eq!(expected, canonical_path(path), "{path}");
        }
    }

    #[test]
    fn test_has_dot_segments() {
        for path in [
            "/a/../b",
            "/a/./b",
            "/a/..",
            "/a/%2e%2e/b",
            "/a/%2E./b",
            "/a/..;x=1/b",
            "/a%2F..%2Fb",
            "/a%5c..%5cb",
            "/a\\..\\b",
            "/a/.;/b",
        ] {
            assert_eq!(true, has_dot_segments(path), "{path}");
        }
        for path in [
            "/",
            "/a/b",
            "/a..b/c",
            "/a/..b/c..",
            "/a/.../b",
            "/a%2Fb",
            "/a;x=../b",
            "/a/b;jsessionid=1",
            "//a//b",
            "/%2e%2ea/b",
        ] {
            assert_eq!(false, has_dot_segments(path), "{path}");
        }
    }

    #[test]
    fn test_normalize_path() {
        // Nothing to do: the very same string comes back.
        for path in [
            "/",
            "/admin",
            "/admin/",
            "/a/b.c/d",
            "/.well-known/acme-challenge/token",
            "/.env",
            "/a/..b/c",
            "/a/b../c",
            "/a/...",
            "*",
            "",
        ] {
            assert_eq!(
                true,
                matches!(normalize_path(path), Cow::Borrowed(value) if value == path),
                "{path}"
            );
        }
        for (path, expected) in [
            // what a location for `/admin` used to miss
            ("/%61dmin", "/admin"),
            ("/%61dmin/users", "/admin/users"),
            ("//admin", "/admin"),
            ("/./admin", "/admin"),
            ("/public/../admin", "/admin"),
            ("/public/%2e%2e/admin", "/admin"),
            ("/public/%2E%2E%2Fadmin", "/admin"),
            ("/public/..%2fadmin/x", "/admin/x"),
            // above the root is the root
            ("/../../admin", "/admin"),
            ("/..", "/"),
            ("/.", "/"),
            ("//", "/"),
            // the end of the path keeps its shape
            ("/admin//", "/admin/"),
            ("/admin/.", "/admin/"),
            ("/admin/x/..", "/admin/"),
            ("/admin/x/../", "/admin/"),
            // decoded once, not until nothing is left to decode
            ("/%2561dmin", "/%61dmin"),
            // not an escape: left alone
            ("/100%", "/100%"),
            ("/a%zzb", "/a%zzb"),
            ("/a%4", "/a%4"),
            ("/%E6%96%87%E6%A1%A3/menu", "/文档/menu"),
            ("/a%20b", "/a b"),
            // Regression: a path parameter is no part of the name of its
            // segment. A servlet container reads these as the path on the
            // right, and a location for it was walked past.
            ("/public/..;/admin", "/admin"),
            ("/public/..;x=1/admin", "/admin"),
            ("/public/.;/admin", "/public/admin"),
            ("/public/%2e%2e%3b/admin", "/admin"),
            ("/api;v=1/admin", "/api/admin"),
            ("/admin;jsessionid=A1/users", "/admin/users"),
            ("/login;jsessionid=A1", "/login"),
            ("/a/;x/b", "/a/b"),
            ("/a/b;x/", "/a/b/"),
            ("/a/;x", "/a/"),
            // Regression: so is a backslash a separator to some.
            ("/public\\..\\admin", "/admin"),
            ("/public/..%5cadmin", "/admin"),
            ("/a\\b", "/a/b"),
            ("/a\\\\b\\", "/a/b/"),
        ] {
            assert_eq!(expected, normalize_path(path), "{path}");
        }
        // Bytes that are no text still give a path to match against.
        assert_eq!("/\u{fffd}/x", normalize_path("/%ff/x"));
    }

    /// Regression: an HTTP/2 request has its host in the uri. Replacing the
    /// path, or dropping a query parameter, used to drop the host too.
    #[test]
    fn test_path_and_query_changes_keep_the_authority() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.set_uri(http::Uri::from_static(
            "https://example.com/api/users?apikey=1&page=2",
        ));
        remove_query_from_header(&mut req, "apikey").unwrap();
        assert_eq!("https://example.com/api/users?page=2", req.uri.to_string());
        assert_eq!(Some("example.com"), get_host(&req));

        set_path_and_query(&mut req, "/users?page=2").unwrap();
        assert_eq!("https://example.com/users?page=2", req.uri.to_string());
        set_path_and_query(&mut req, "/").unwrap();
        assert_eq!("https://example.com/", req.uri.to_string());
        // Not a path: the uri is left as it is.
        assert_eq!(true, set_path_and_query(&mut req, "/a b").is_err());
        assert_eq!("https://example.com/", req.uri.to_string());

        // HTTP/1.1: the uri is the path and stays one.
        let mut req = RequestHeader::build("GET", b"/api?a=1", None).unwrap();
        set_path_and_query(&mut req, "/v2/api?a=1").unwrap();
        assert_eq!("/v2/api?a=1", req.uri.to_string());
    }

    #[test]
    fn test_remove_query_from_header_variants() {
        // Case 1: Remove the only query param.
        let mut req =
            RequestHeader::build("GET", b"/path?key=val", None).unwrap();
        remove_query_from_header(&mut req, "key").unwrap();
        assert_eq!(req.uri.to_string(), "/path");

        // Case 2: Remove the first of multiple params.
        let mut req =
            RequestHeader::build("GET", b"/path?key1=val1&key2=val2", None)
                .unwrap();
        remove_query_from_header(&mut req, "key1").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key2=val2");

        // Case 3: Remove the last of multiple params.
        let mut req =
            RequestHeader::build("GET", b"/path?key1=val1&key2=val2", None)
                .unwrap();
        remove_query_from_header(&mut req, "key2").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key1=val1");

        // Case 4: Remove a middle param.
        let mut req =
            RequestHeader::build("GET", b"/path?key1=v1&key2=v2&key3=v3", None)
                .unwrap();
        remove_query_from_header(&mut req, "key2").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key1=v1&key3=v3");

        // Case 5: Param to remove is not present.
        let mut req =
            RequestHeader::build("GET", b"/path?key=val", None).unwrap();
        remove_query_from_header(&mut req, "nonexistent").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key=val");

        // Case 6: No query string to begin with.
        let mut req = RequestHeader::build("GET", b"/path", None).unwrap();
        remove_query_from_header(&mut req, "key").unwrap();
        assert_eq!(req.uri.to_string(), "/path");
    }
}
