# response_headers

Adds, sets, removes and renames response headers. Values support the same
dynamic substitutions as the rest of Pingap's header handling, so request
context can be surfaced to the client.

- **Step:** `response` (default) or `upstream_response` via `mode`
- **Registered as:** `response_headers`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `response_headers`. |
| `add_headers` | string[] | — | `Name: value` — appended, keeping existing values. |
| `set_headers` | string[] | — | `Name: value` — replaces any existing value. |
| `set_headers_not_exists` | string[] | — | `Name: value` — only set when the header is absent. |
| `remove_headers` | string[] | — | Header names to delete. |
| `rename_headers` | string[] | — | `Old-Name: New-Name` — moves every value of the header. |
| `preset` | string | — | `security` sets a group of headers where the response has none of the name. See [The security preset](#the-security-preset). |
| `always` | bool | `false` | Also apply the rules to what did not come from the upstream: the response another plugin of the location answers with, and the proxy's own error page. `mode = "response"` only. |
| `mode` | string | *(response)* | `upstream` to rewrite the upstream response header instead. Anything but `response` or `upstream` is a configuration error. |

An entry that is not `Name: value` (`Old-Name: New-Name` for
`rename_headers`) is a configuration error. One without its colon used to be
dropped without a word, and a misspelt `mode` was taken for `response`.

Operations always run in this order, regardless of declaration order:

1. `add_headers`
2. `remove_headers`
3. `set_headers`
4. `set_headers_not_exists`
5. `rename_headers`

So a header added in step 1 and named in `remove_headers` is gone; a header
renamed in step 5 sees the result of everything before it.

## The security preset

`preset = "security"` sets, where the response does not have the header
already:

| Header | Value |
| --- | --- |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Strict-Transport-Security` | `max-age=31536000`, only where the client came over https: on a TLS connection, or through a proxy listed in `basic.trusted_proxies` that says so in `X-Forwarded-Proto` |

What the upstream sends under one of these names stands, and so does a rule of
the plugin itself: `set_headers = ["X-Frame-Options: DENY"]` next to the
preset gives `DENY`. `includeSubDomains` and `preload` are commitments for a
whole domain and are not part of it; add them with `set_headers` when they are
meant. Keep the preset in `response` mode: in `upstream` mode the headers are
stored with a cached response, `Strict-Transport-Security` among them or not
according to the request that filled the cache.

## Every response of the location

The headers of this plugin are set on the response of the upstream. A `401`
from an authentication plugin, a `429`, a redirect, a file of
[`directory`](directory.md) and the error page Pingap sends when the upstream
is down do not come from there, and went out without them - which is where a
security header is missed most.

`always = true` applies the rules to those responses too. It works together
with `preset`, which is the usual reason to turn it on:

```toml
[plugins.securityHeaders]
category = "response_headers"
preset = "security"
always = true
```

An error page only gets them once the plugins of the location have run for
the request. A request no location matched has no plugins to ask, and neither
has one the location itself turned away before them (`client_max_body_size`,
`max_processing`).

With `always`, every rule applies to those responses, the ones that take
something off or put something in its place as well. `set_headers =
["Cache-Control: public, max-age=3600"]` then also replaces the `no-store` of
a `401` or of a maintenance notice: use `set_headers_not_exists` for a header
other responses have reasons of their own to set. The length and the type of
the proxy's own error page are not a rule's to change.

## Dynamic values

| Variable | Expands to |
| --- | --- |
| `$hostname` | The proxy's hostname |
| `$remote_addr` | Address of the peer the connection came from |
| `$client_ip` | Address of the client: what a proxy listed in `basic.trusted_proxies` says of it, and the peer's own otherwise |
| `$forwarded_proto` / `$forwarded_port` / `$forwarded_host` | The scheme, port and host the client used, as a trusted proxy says in `X-Forwarded-Proto` / `-Port` / `-Host`; those of this connection otherwise |
| `$remote_port` | Client port |
| `$upstream_addr` | Selected upstream address |
| `$ja4` | The client's JA4 TLS fingerprint, on a server with `ja4 = true` |
| `$tls_client_subject` / `$tls_client_fingerprint` / `$tls_client_serial` / `$tls_client_verified` | The certificate the client showed, on a server with [`tls_client_ca`](../../pingap-proxy/README.md#client-certificates-mutual-tls): its subject, SHA-256 and serial number, and `true` / `false` for whether there is one. Without a certificate the first three are empty, and the header is set all the same |
| `$proxy_add_x_forwarded_for` | Existing `X-Forwarded-For` plus the client address |
| `$http_<name>` | Value of request header `<name>`; underscores stand for dashes, so `$http_user_agent` reads `User-Agent` |
| `$<NAME>` | Environment variable `NAME` |
| `:<key>` | A value from the request context |

## Examples

Security headers plus a bit of debugging:

```toml
[plugins.respHeaders]
category = "response_headers"
set_headers = [
    "X-Frame-Options: DENY",
    "X-Content-Type-Options: nosniff",
    "Referrer-Policy: strict-origin-when-cross-origin",
]
set_headers_not_exists = ["Cache-Control: no-cache"]
add_headers = ["X-Served-By: $hostname"]
remove_headers = ["Server", "X-Powered-By"]
rename_headers = ["X-Internal-Trace: X-Trace-Id"]
```

Rewrite the upstream response before Pingap's own cache and response handling see
it:

```toml
[plugins.fixUpstream]
category = "response_headers"
mode = "upstream"
remove_headers = ["Set-Cookie"]
set_headers = ["Cache-Control: public, max-age=3600"]
```

## `mode`

| `mode` | Hook | When to use |
| --- | --- | --- |
| unset | `response` | Normal case: the client-facing response |
| `upstream` | `upstream_response` | To influence caching or other response plugins that run later |

An instance handles exactly one of the two — it is not both.

## Usage notes

- `remove_headers` and `rename_headers` names must be valid HTTP header names or
  startup fails, which `pingap -t` will report.
- `rename_headers` appends to the destination, so renaming onto an existing
  header produces two values rather than overwriting. A multi-valued header
  such as `Set-Cookie` moves with all of its values.
- A dynamic value that cannot be resolved falls back to the literal configured
  string, so a typo like `$hostnam` is emitted verbatim.
