# request_headers

Adds, sets, removes and renames headers of the request before it goes on to
the upstream. It is the counterpart of [`response_headers`](response_headers.md):
the same settings, applied to the other direction.

A location can set and append headers for its upstream with `proxy_set_headers`
and `proxy_add_headers`. This plugin is for what those cannot do - take a
header off, rename one, set one only when the client sent none - and for a set
of rules that several locations share.

- **Step:** `request` (default) or `proxy_upstream` — configurable
- **Registered as:** `request_headers`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `request_headers`. |
| `add_headers` | string[] | — | `Name: value` — appended, keeping what the request has. |
| `set_headers` | string[] | — | `Name: value` — replaces what the request has. |
| `set_headers_not_exists` | string[] | — | `Name: value` — only set when the request has no such header. |
| `remove_headers` | string[] | — | Header names to take off, every value of them. |
| `rename_headers` | string[] | — | `Old-Name: New-Name` — moves every value of the header. |
| `step` | string | `request` | `request` or `proxy_upstream`. Any other value is a configuration error. |

An entry that is not `Name: value` (`Old-Name: New-Name` for `rename_headers`),
or a name that is not a header name, is a configuration error and reported by
`pingap -t`. So is a rule for `Content-Length` or `Transfer-Encoding`: they say
how the body is framed, and with another value than the body has the upstream
reads a request that is not the one the client sent. And so is one for `Host`:
for a client on HTTP/2 served by an upstream on HTTP/1 it is set again from
the request's authority after this plugin has run, so the rule would hold for
some clients and not for others. Set it with the location's
`proxy_set_headers`, which holds for all of them.

Operations always run in this order, regardless of declaration order:

1. `add_headers`
2. `remove_headers`
3. `set_headers`
4. `set_headers_not_exists`
5. `rename_headers`

## Dynamic values

A value that is one of these, and nothing else, is replaced:

| Variable | Expands to |
| --- | --- |
| `$hostname` | The proxy's hostname |
| `$host` | The host the request is for |
| `$scheme` | `http` or `https`, as the client connected |
| `$remote_addr` | Client address |
| `$remote_port` | Client port |
| `$server_addr` / `$server_port` | The address and port the request arrived on |
| `$ja4` | The client's JA4 TLS fingerprint, on a server with `ja4 = true` |
| `$proxy_add_x_forwarded_for` | Existing `X-Forwarded-For` plus the client address |
| `$http_<name>` | Value of request header `<name>`; underscores stand for dashes, so `$http_user_agent` reads `User-Agent` |
| `$<NAME>` | Environment variable `NAME` |
| `:<key>` | A value from the request context |

The values are read from the request as it came, before any rule of the plugin
is applied: `X-From: $http_x_client` next to `set_headers = ["X-Client: ..."]`
copies what the client sent. A value that does not resolve is sent as it is
written.

## Examples

Keep the client's cookies and its `Authorization` from an upstream that has no
use for them, and pass on who is asking:

```toml
[plugins.cleanRequest]
category = "request_headers"
remove_headers = ["Cookie", "Authorization", "X-Internal-Key"]
set_headers = ["X-Real-IP: $remote_addr", "X-Forwarded-Proto: $scheme"]
set_headers_not_exists = ["Accept-Language: en"]
rename_headers = ["X-Api-Key: X-Internal-Key"]

[locations.assets]
upstream = "assets"
path = "/assets"
plugins = ["cleanRequest"]
```

## Usage notes

- The headers are changed on the request itself. The plugins listed after this
  one see the result, the ones before it the request as it came: put it after
  an authentication plugin that reads the header it removes.
- With `step = "proxy_upstream"` it runs after the cache was looked up, so a
  cache hit is answered without it, and the cache key (`headers` of the
  [`cache`](cache.md) plugin) is taken from the headers as they were.
- The location's own `proxy_set_headers` and `proxy_add_headers` are applied
  later, when the request is sent, and win over this plugin for a header both
  set.
- `rename_headers` appends to the destination, so renaming onto a header the
  request already has gives two values rather than replacing it. Where the
  destination is a name the upstream trusts, list it in `remove_headers` as
  the example does: the removal comes first, and takes off whatever the client
  sent under that name.
- A header this plugin adds, sets or renames to is the proxy's from then on.
  A client cannot have it dropped again by naming it in its `Connection`
  header, which is how a hop-by-hop header of the client's own is kept from
  the upstream.
- The access log reads the request after the plugin: a header that was removed
  is not there for `{>name}` to print.
