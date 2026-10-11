# Upgrading

What changes for a deployment that replaces one release with the next and
keeps its configuration. New features are in the
[changelog](https://github.com/vicanso/pingap/blob/main/CHANGELOG.md); this
page is about what can break or surprise.

## From 0.15 to 0.16

0.16 is a large release, and much of it is strictness: configuration that
0.15 accepted and then quietly did not apply is refused, and several
decisions that trusted what a client sent no longer do.

### Before you upgrade

1. **Run `pingap -t` with the new binary** against the configuration in use.
   `-t` now builds every upstream, location, plugin, certificate and server
   the way a start does, so it reports what a start would. The systemd unit
   has always run it as `ExecStartPre`: with the stricter check, a
   configuration 0.15 started with (and logged an error for) leaves the unit
   failed.
2. **Set `basic.trusted_proxies`** if anything stands between the clients and
   Pingap (a CDN, a load balancer). Without it, address rules no longer read
   `X-Forwarded-For`; see [Client addresses](#client-addresses).
3. **Expect a cold cache**: the cache key has changed, so nothing stored by
   0.15 is found. See [Cache](#cache).
4. **Alerting on `502`?** An upstream that times out now answers `504`.
5. Keep the old binary at hand. `install.sh` takes `PINGAP_VERSION=0.15.0` to
   install a given release; see [Going back](#going-back).

### Configuration that is now refused

Refusals are an error at start and with `-t`, a reload that is not applied
(the running configuration stays), and a `400` from the admin.

| What | 0.15 | 0.16 |
| --- | --- | --- |
| A location names a plugin that does not exist, a plugin has an unknown `category`, or a plugin does not build | Logged; the location served **without** the plugin | The start fails, e.g. `plugin(<name>) of location(<location>) is not found` |
| A plugin option of the wrong type (`status = "503"`, `max = "100"`, `lock = 2`) | The default was used silently | `<key> must be an integer, got string "503"` |
| `access_log` that names no request field (`access_log = "/var/log/pingap/access.log"`) | That text was printed once per request | Refused; write `"<path> combined"` or a format with `{...}` |
| Upstream `discovery` that is not one of `static`, `dns`, `srv`, `docker`, `transparent` | Taken for static addresses | Refused; `DNS` in upper case now means DNS discovery |
| `update_frequency = "0s"` with `dns`, `srv` or `docker` discovery | Resolved once and never again | Refused |
| `tcp_idle` / `tcp_interval` under one second, `tcp_probe_count = 0` | Accepted, then every connection failed | Refused |
| `dns_server` that is not `ip` or `ip:port` | Dropped silently | Refused |
| `directory` plugin without `path` | Served the working directory | Refused: `path is required` |
| `geo_restriction` on a location, in a build without the `geo` feature (the released binaries) | Served without the restriction | Refused |
| `--admin=user@addr` (no password), a malformed `authorizations` entry | The admin ran **without authentication** | Refused |
| A certificate whose key does not belong to it | Passed validation | Refused by `-t` and by an admin save |
| `log_compress_algorithm` other than `gzip` or `zstd`, `circuit_break_max_failure_percent` above 100, `auto_restart_check_interval` under one second | Accepted | Refused |
| `webhook_type = "ntfy"` with a `webhook` that is not the url of a topic (no path, or a last part ntfy takes for no topic: `/hook.php`) | A generic JSON post to that url, like any type 0.15 did not know | Refused: `the url of ntfy names no topic`. Name the type anything else to keep the generic post |

**Keys Pingap does not read** (a typo such as `trusted_proxy`, a key that
never existed such as `basic.cache_directory` or `tcp_fast_open` on a server)
were dropped silently. They are now a warning at start, with `-t` and at a
reload: `basic: unknown key "trusted_proxy", did you mean "trusted_proxies"?`.
With `--strict` (or `PINGAP_STRICT` set) they are an error. Keys inside a
plugin are not checked.

**`$ENV:NAME` and `$FILE:/path`** as a whole value are now replaced by the
variable or the file in every text field, where 0.15 took them literally
(except in `dns_service_url`). A variable that is not set and a file that
cannot be read are errors.

### Client addresses

Rules that go by the client's address - `ip_restriction`, `limit` by ip,
`geo_restriction`, the `ip_list` of `combined_auth`, the lockouts of
`basic_auth` and of the admin, the `PURGE` allow list of the cache - used to
take the first entry of `X-Forwarded-For` from anyone. A client could write
whatever address it liked.

- **Without `basic.trusted_proxies`** they now go by the address the
  connection comes from. Behind a proxy that is not listed, that is the
  proxy: an allow list admits everyone or nobody, every client shares one
  rate limit, and a few wrong passwords lock everybody out.
- **With `basic.trusted_proxies`** the client is the right-most entry of
  `X-Forwarded-For` that is not a trusted proxy, where 0.15 took the
  left-most one, which the client writes. List every hop: with a CDN in front
  of a load balancer and only the load balancer listed, the client is the CDN.

The access log's `{client_ip}`, `hash:ip` and the address `forward_auth`
sends still read `X-Forwarded-For` from anyone when no proxy is trusted. With
`basic.trusted_proxies` they follow the same rule as above: the right-most
entry that is not a trusted proxy, where they used to be the left-most one.

### Cache

- **The key has changed** (it has the host in it, and is the same over
  HTTP/1.1 and HTTP/2), so the cache starts empty. Files of 0.15
  stay on disk until they are evicted or swept (`inactive`, 48 hours by
  default); empty the directory to have the space back at once.
- **`PURGE` is per host**: a purge sent to `127.0.0.1` needs
  `-H 'Host: <site>'`.
- **What is stored**: a response with `Set-Cookie` never is; one to a request
  with `Authorization` only when the origin says `public`, `s-maxage` or
  `must-revalidate`; the one-second default lifetime applies to the statuses
  that are cacheable by default and no longer to a `302`, a `401` or a `502`.
- **`headers`** (request headers in the key) are read when the key is made,
  after every request plugin has run: the key has what the upstream is asked
  with. A header another plugin sets is in it, one a plugin removes is not;
  see [cache](../pingap-plugin/docs/cache.md).
- A request with an `Upgrade` header (a WebSocket handshake) is neither
  answered from the cache nor stored.
- `eviction = false` and `predictor = false` now mean off; their presence
  used to mean on.

### Routing and requests

- **Locations are matched by the normalised path**: percent-decoded once,
  `.` and `..` resolved, `//` merged, `;params` dropped, `\` read as `/`. A
  request that used to fall through to a catch-all location under another
  spelling now gets the plugins of the location it belongs to. A regular
  expression written against an encoded spelling (`~^/a%20b`) no longer
  matches. The request is still forwarded as it was sent.
- A request target that is neither a path nor a url is answered `400`.
- **An upstream that times out answers `504`**; other upstream failures stay
  `502`.
- Errors below `500` are logged at `info` as `request refused`, not at `error`
  as `fail to proxy`; an error page no longer shows the upstream's address or
  the error chain.
- `{status}` in the access log and the status metrics are what the client
  received: a cache revalidation no longer counts as a `304`.
- A retry goes to another backend than the one that just failed the request.
- `basic.threads = 0` means one thread per core, as documented; in 0.15 it
  meant one.

### Plugins

- **`limit`** in rate mode: `max` is the number of requests in any one
  `interval`, over a sliding window. 0.15 let about twice as many through
  before the first `429` and kept a client that retried refused. `weight` is
  no longer used and warns.
- **`jwt`** with a `secret`: a token without `exp` is refused (`401`);
  `require_exp = false` brings the old behaviour back. `auth_path` signs
  nothing when the upstream's claims have no `exp`. Expiry now has sixty
  seconds of `leeway`.
- **`directory`**: files and directories whose name begins with a dot are
  `404` (`hidden = true` serves them, `.well-known` is always served);
  methods other than `GET` and `HEAD` get `405`; a directory without its
  closing slash is redirected.
- **`compression`**: the coding is chosen zstd, then brotli, then gzip,
  whatever order the client lists them in; `min_length` applies in the
  default mode too; `text/event-stream`, `Cache-Control: no-transform` and
  partial content (`206`) are never compressed. With `mode = "upstream"`, a
  response whose body another plugin of the location reads is not compressed
  either: what [`sub_filter`](../pingap-plugin/docs/sub_filter.md) rewrites
  (by its `path` and `types`) and the claims `jwt` signs at its `auth_path`.
- **`redirect`**: only `http_to_https = true` changes the scheme. A plugin
  with just a `prefix` on a TLS listener used to send every request to
  `http://`.
- **Prometheus metrics by path** (`prometheus_metrics = "/metrics"`): the
  request plugins of the matching location run first, so a scraper behind a
  location with authentication needs credentials, or the path a location of
  its own.
- An option that takes a list and is written as one string (`ip_list =
  "1.2.3.4"`) is a list of one; it used to be empty.

### Health checks, timers, logs

- A check's period under one second used to run once and never again; it is
  now ten seconds, the tick of the timer every period is rounded up to.
- `expect_status`, `check_port` and `expect_body` in a `health_check` url are
  settings now; 0.15 sent them to the backend as query parameters.
- TCP keepalive is on as soon as one of `tcp_idle`, `tcp_interval`,
  `tcp_probe_count` is set; 0.15 needed all three (or `tcp_user_timeout`).
- **ACME**: a certificate that does not set `buffer_days` is renewed 14 days
  before it expires (it was 2; at most a third of its lifetime), so every one
  with less than that is ordered at the first check after the upgrade.
- **Log targets**: `--log stdout` and `access_log = "stdout ..."` are the
  streams; 0.15 wrote a file named `stdout.<date>`. `syslog://<host>` is a
  remote server now, where the host used to be ignored.
- **Compressed log archives** are named after the file they hold
  (`access.log.2026-10-05.zst`), and only the log's own rolled files are
  compressed and removed; 0.15 walked the whole directory.
- Text access logs escape quotes, backslashes and control characters in what
  a request supplies. Lines without those are unchanged.
- **Webhook**: `webhook_type = "ntfy"` is a type of its own, for a topic of
  [ntfy](https://ntfy.sh/). 0.15 read it like any name it did not know, as
  the generic JSON post to `webhook`. A configuration that happened to use
  that name now posts the JSON of ntfy, and posts it to the url without its
  last part (the topic); a `webhook` that is not the url of a topic is
  [refused](#configuration-that-is-now-refused).

### Reload, restart and the configuration files

- A reload is all or nothing: upstreams, locations and plugins are built
  first, and one that fails applies none of the change.
- `-t`, `--to-hcl`, `--to-kdl` and `--sync` no longer rewrite the layout of a
  configuration directory, and fail on a configuration that does not load
  where they used to go on with an empty one.
- `--sync`, and an import through the admin, into etcd or a directory with
  `?separation` **delete** entries of the destination that the source does
  not have.
- Configuration history keeps the 100 newest versions of each entry; the
  first save after the upgrade removes older ones.
- An entry that is defined in two files of a directory is an error that
  names both.
- With `--autoreload`, a change that only a restart applies (a server's
  `addr`, most of `[basic]`) is said: a warning in the log and a
  `reload_config_fail` notification. It used to be passed over in silence.
- A restart is refused, and the running process goes on, when the stored
  configuration listens on a new address that cannot be bound. It used to go
  ahead and end with no process serving.
- A changed `basic.upgrade_sock` applies after pingap is stopped and started.
  A restart keeps the path in use, where it used to take the service down.
- **A restart needs a daemon** (`-d`, on Linux). In the foreground - a
  container, a unit without `-d`, a terminal - the admin's restart and
  `--autorestart` used to hand the sockets to a daemon and let the process
  that was started exit: the end of the container, the replacement
  included, some minutes later. Now the admin refuses with the reason, and
  `--autorestart` reloads like `--autoreload` and reports what waits for a
  restart. Restart the container or the service to apply that.
- A build without `tracing` warns about `prometheus_metrics`, `otlp_exporter`
  and `basic.sentry`, and one without `pyro` about `basic.pyroscope`: it does
  nothing with them, as before. With `--strict` they are an error. Use a
  `-full` build for the first three.

### Admin

- **API paths without `/api`** (`/configs/...`, `/basic`, `/restart`) are
  `404`. `GET /api/certificates` no longer returns certificates and keys.
- **An admin without credentials** refuses API requests that arrive from the
  same machine under a host name other than `localhost` or an ip address,
  and writes that come from another site. Behind a reverse proxy on that
  machine that passes the public host, the page loads and every API call is
  `403`: give the admin credentials.
- A password in `--admin` is percent-decoded: `p%40ss` means `p@ss`.
- Saves are validated like `-t`, against the configuration as it would be
  stored, and answer `400` with the reason (they used to answer `500`, or
  store what could not be loaded again). Create an upstream before the
  location that names it.
- New: read-only accounts and API tokens (`readonly_authorizations`,
  `tokens`, `readonly_tokens`), and one audit line in the log for each change.

### Docker, packages and the unit

- The image is built on `debian:trixie-slim` (it was `ubuntu:24.04`);
  entrypoint, command and paths are the same. Every tag has a `-distroless`
  twin, which has no shell and no entrypoint script.
- `:latest`, `:full` and `:rustls-full` are pushed once the tests of the
  commit have passed; they used to be pushed alongside them.
- `pingap.service` is stopped by systemd's own `SIGTERM`.
- `pingap.service` is `Type=forking` (it was `Type=simple`, which does not
  fit a daemon started with `-d`: the service could be taken for ended while
  the pid file was not written yet). A unit that was installed earlier is not
  rewritten by a new binary: change the line, or install the unit again
  (`PINGAP_SERVICE=1` with `install.sh`), then `systemctl daemon-reload`.
- The Rust toolchain needed to build (1.96) and both TLS backends are
  unchanged.

### Going back

0.15 reads a 0.16 configuration with these differences, none of which it
reports as an error:

- Keys that are new in 0.16 are ignored, and with them what they did. Some
  of that is protection: without `tls_client_ca` a listener asks no client
  for a certificate, and without `proxy_protocol` the header of a load
  balancer that still sends one is a broken request. The others are
  `send_proxy_protocol`, `fail_open`, `client_cert`, the timeouts of a
  location, `acme_*`, `ocsp_stapling`, and the webhook's `webhook_min_level`,
  `webhook_headers`, `webhook_secret`, `webhook_template`, `webhook_retries`.
- **An admin whose only credentials are tokens** (`tokens`, `?token=` on
  `--admin`) runs **without authentication**: 0.15 does not know them.
- A location with a plugin that is new in 0.16 (`oidc`, `hmac_auth`,
  `uri_block`, `maintenance`, ...) is served **without** it. Take such
  locations out of service first.
- `discovery = "srv"` is taken for static addresses.
- `$ENV:` and `$FILE:` values are used as the literal text.
- The cache is cold again.

### For users of the crates

Public structs are not `#[non_exhaustive]`, so a struct literal breaks where a
field was added. The changes that are more than an added field:

- **pingap-core**: `get_cache_key` takes the `RequestHeader`, not the `Uri`;
  `RequestState.guard` is `guards: Vec<Guard>`; `LocationInstance::rewrite`
  returns `pingora::Result<bool>`; `HttpChunkResponse` has `status` and
  `pace`; `get_client_ip` picks the right-most untrusted address.
- **pingap-upstream**: `PeerAttempt` has `location`.
- **pingap-proxy**: `ServerServices.lb` is a `Box<dyn ServiceWithDependents>`,
  added with `add_boxed_service`.
- **pingap-logger**: `AsyncLoggerTask::get_dir()` is gone (`get_log_files()`);
  `LogCompressParams::new` takes `Vec<LogFiles>`; `logger_try_init` returns
  `Option<LogFiles>`.
- **pingap-plugin**: the `get_*_conf` helpers fail on a value of the wrong
  type, also for plugins of your own that use them.
- **pingap-health**: `HealthCheckConf` has `expect_status`, `check_port` and
  `expect_body`; `new_health_check_with_peer` takes what a check inherits
  from its upstream.
