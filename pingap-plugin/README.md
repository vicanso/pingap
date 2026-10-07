# Pingap Plugin

Built-in plugins for [Pingap](https://github.com/vicanso/pingap).

A plugin is a small, self-contained unit of request/response logic that runs at a
well-defined point of the proxy lifecycle. Plugins are declared once and then
attached to any number of locations, which keeps routing configuration free of
cross-cutting concerns such as authentication, rate limiting, caching or header
rewriting.

## How plugins are configured

A plugin is declared under `[plugins.<name>]`. `<name>` is arbitrary and is what
locations refer to; `category` selects which implementation is instantiated.

```toml
[plugins.pingPath]
category = "ping"
path = "/ping"

[locations.api]
upstream = "api"
path = "/api"
plugins = ["pingPath"]
```

The same plugin can be declared several times with different settings, and one
location can list several plugins. Plugins run in the order they are listed in
`plugins`.

A location never runs without a plugin it names:

- A name in `plugins` that is neither declared under `[plugins.*]` nor one of
  the built-in `pingap:*` plugins is a configuration error: `--test`, startup
  and a reload all reject it.
- A plugin whose configuration is invalid (an unknown `category` included)
  stops the process at startup. With `--admin` a fresh start stays up so the
  configuration can be repaired through the admin, and the locations naming
  that plugin answer `500` until it is. A process that is to replace a running
  one (`--upgrade`, the restart of `--autorestart`) always exits instead, and
  the running one keeps serving.
- On a hot reload a plugin whose new configuration is invalid keeps running
  with its previous one, and the error is logged and sent as a
  `reload_config_fail` notification. A new plugin that fails to build has
  nothing to fall back to: its locations answer `500`.

A value of the wrong type is an invalid configuration, not a default:
`max = "100"` where an integer is expected, `hide_credentials = "true"` where a
boolean is, a number in a list of strings, a duration that does not parse. The
error names the key and what it takes. Up to 0.15.0 such a value was silently
read as `0`, `false` or an empty list.

A plugin whose category this build was compiled without is not an error by
itself, so one configuration can be shared between builds; it is logged as
unavailable. What a location that names it gets depends on the plugin:

- `image_optim` (the `imageoptim` / `full` builds) does nothing where it is
  missing: the image is served as it is.
- `geo_restriction` (the `geo` feature) is access control, so a location that
  names it is a configuration error on a build without it.

Equivalent HCL and KDL forms are supported — see
[pingap-config](../pingap-config/README.md).

## Lifecycle steps

Pingap maps the pingora callbacks in `pingap-proxy/src/server.rs` onto five
`PluginStep` values. A plugin instance runs at **exactly one** request step:

| Step | When it runs | Typical use |
| --- | --- | --- |
| `early_request` | Right after the request line and headers are read, before routing | Negotiating compression / `Accept-Encoding` |
| `request` | After a location has been matched | Auth, rate limiting, caching, mocking, static files |
| `proxy_upstream` | After the location is resolved, before a backend is chosen | Checks that should not run for cache hits |
| `upstream_response` | When the upstream response header arrives | Rewriting upstream headers, body transformations |
| `response` | When the response header is about to be sent downstream | Adding response headers, body substitution |

Setting `step` to a value a plugin does not implement makes it a silent no-op.
Only `directory`, `limit`, `request_id` and `stats` actually read `step`; every
other plugin pins its own step (documented per plugin below).

Each request-step plugin returns one of three results:

- `Skipped` — the plugin did not apply; processing continues.
- `Continue` — the plugin ran and possibly mutated the request; processing continues.
- `Respond(response)` — the plugin terminates the request and this response is sent.

## Plugin index

### Authentication and authorization

| Category | Purpose | Doc |
| --- | --- | --- |
| `basic_auth` | HTTP Basic authentication | [docs/basic_auth.md](docs/basic_auth.md) |
| `key_auth` | API key in a header or query parameter | [docs/key_auth.md](docs/key_auth.md) |
| `jwt` | JWT verification (HMAC, public key or remote JWKS) and token minting | [docs/jwt.md](docs/jwt.md) |
| `combined_auth` | app id + timestamp + HMAC digest, optionally IP bound | [docs/combined_auth.md](docs/combined_auth.md) |
| `forward_auth` | Delegate the decision to an external HTTP service | [docs/forward_auth.md](docs/forward_auth.md) |
| `csrf` | Double-submit-cookie CSRF protection | [docs/csrf.md](docs/csrf.md) |

### Access control

| Category | Purpose | Doc |
| --- | --- | --- |
| `ip_restriction` | Allow/deny by IP or CIDR | [docs/ip_restriction.md](docs/ip_restriction.md) |
| `referer_restriction` | Allow/deny by `Referer` host | [docs/referer_restriction.md](docs/referer_restriction.md) |
| `ua_restriction` | Allow/deny by `User-Agent` regex | [docs/ua_restriction.md](docs/ua_restriction.md) |
| `geo_restriction` | Allow/deny by GeoIP country (feature `geo`) | [docs/geo_restriction.md](docs/geo_restriction.md) |
| `uri_block` | Block requests by path or query pattern, or by method | [docs/uri_block.md](docs/uri_block.md) |
| `maintenance` | Answer with a maintenance notice, except for allowed addresses or a header | [docs/maintenance.md](docs/maintenance.md) |

### Traffic control

| Category | Purpose | Doc |
| --- | --- | --- |
| `limit` | Rate limiting and concurrency limiting | [docs/limit.md](docs/limit.md) |
| `traffic_splitting` | Send a share of traffic to a different upstream | [docs/traffic_splitting.md](docs/traffic_splitting.md) |
| `cache` | HTTP caching with `PURGE` support | [docs/cache.md](docs/cache.md) |

### Content

| Category | Purpose | Doc |
| --- | --- | --- |
| `compression` | gzip / brotli / zstd response compression | [docs/compression.md](docs/compression.md) |
| `accept_encoding` | Normalise the client `Accept-Encoding` header | [docs/accept_encoding.md](docs/accept_encoding.md) |
| `directory` | Serve static files, with range requests and autoindex | [docs/directory.md](docs/directory.md) |
| `sub_filter` | Literal / regex substitution in the response body | [docs/sub_filter.md](docs/sub_filter.md) |
| `request_headers` | Add / set / remove / rename the request headers sent to the upstream | [docs/request_headers.md](docs/request_headers.md) |
| `response_headers` | Add / set / remove / rename response headers | [docs/response_headers.md](docs/response_headers.md) |
| `cors` | CORS preflight and response headers | [docs/cors.md](docs/cors.md) |
| `redirect` | HTTP↔HTTPS redirects and path prefixing | [docs/redirect.md](docs/redirect.md) |
| `image_optim` | Re-encode PNG/JPEG to WebP/AVIF (feature `imageoptim`) | [docs/image_optim.md](docs/image_optim.md) |

### Operations

| Category | Purpose | Doc |
| --- | --- | --- |
| `ping` | Liveness endpoint returning `pong` | [docs/ping.md](docs/ping.md) |
| `health` | Readiness endpoint: whether the upstreams have enough healthy backends | [docs/health.md](docs/health.md) |
| `mock` | Return a canned response, optionally delayed | [docs/mock.md](docs/mock.md) |
| `request_id` | Generate or propagate a request id | [docs/request_id.md](docs/request_id.md) |
| `stats` | JSON process and request statistics | [docs/stats.md](docs/stats.md) |
| `admin` | Web admin UI and configuration API | [docs/admin.md](docs/admin.md) |

`stats` and `admin` live in the `pingap` binary (`src/plugin/`) rather than in
this crate, because they need access to the process and the configuration
manager. `image_optim` lives in `pingap-imageoptim`. All of them register into
the same factory and are configured exactly the same way.

## Writing a plugin

1. Implement `pingap_core::Plugin`. Only the hooks you need have to be
   overridden — every method has a default no-op implementation.
2. Parse `&PluginConf` in `TryFrom`, using the `get_*_conf` helpers in
   `src/lib.rs`, and reject invalid combinations there so that `pingap -t`
   catches them before the proxy starts. A helper that finds a value of the
   wrong type answers the default and notes it; the factory then fails the
   plugin with that note, so the type of each key needs no check of your own.
3. Return `get_hash_key(conf)` from `config_key()`. Pingap uses it to detect
   whether a hot reload actually changed this plugin instance.
4. Register the category with the `register_plugin!` macro, which expands to a
   pre-main constructor.
5. A plugin that only sets response headers, and should set them on a response
   another plugin answered with as well (as `cors` does for a `401`), returns
   `true` from `handles_plugin_response()`. Its `handle_response` is then also
   called for those responses, which never reach the response step.

```rust
use async_trait::async_trait;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::borrow::Cow;

pub struct MyPlugin {
    hash_value: String,
}

#[async_trait]
impl Plugin for MyPlugin {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        _session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }
        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("my_plugin", MyPlugin);
```

## Features

- `geo` — enables the `geo_restriction` plugin (embedded Tor GeoIP database).

## License

Apache-2.0.
