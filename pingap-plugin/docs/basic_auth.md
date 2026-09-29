# basic_auth

HTTP Basic authentication (RFC 7617). Useful for staging sites, internal
dashboards and anything behind a browser where a login page is overkill.

- **Step:** `request` (fixed)
- **Registered as:** `basic_auth`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `basic_auth`. |
| `authorizations` | string[] | — | **Required, non-empty.** Base64 of `user:password`, one entry per account. |
| `delay` | duration | none | Sleep this long before answering a failed attempt, to slow brute force. |
| `hide_credentials` | bool | `false` | Strip `Authorization` before proxying upstream. |
| `ip_fail_limit` | int | `0` | Wrong passwords per client IP before that IP is blocked with `403`. `0` turns it off. |
| `ip_fail_window` | duration | `5m` | How long failures are counted, which is also the longest an IP stays blocked. |

`authorizations` entries are validated as base64 at startup, so a typo fails
`pingap -t` instead of silently locking everyone out. Credentials are compared in
constant time; the `Basic` scheme is matched case-insensitively, as RFC 7235
requires.

## Generating an entry

```bash
echo -n "pingap:123123" | base64
# cGluZ2FwOjEyMzEyMw==
```

## Example

```toml
[plugins.staging]
category = "basic_auth"
authorizations = [
    "cGluZ2FwOjEyMzEyMw==",   # pingap:123123
    "YWRtaW46c2VjcmV0",       # admin:secret
]
delay = "1s"
hide_credentials = true
ip_fail_limit = 5
ip_fail_window = "10m"

[locations.staging]
upstream = "app"
path = "/"
plugins = ["staging"]
```

Verify:

```bash
curl -i http://127.0.0.1:6188/
# HTTP/1.1 401 Unauthorized
# www-authenticate: Basic realm="Access to the staging site"
# Authorization is missing

curl -i -u pingap:123123 http://127.0.0.1:6188/
# HTTP/1.1 200 OK
```

## Responses

| Situation | Status | Body |
| --- | --- | --- |
| No `Authorization` header | 401 + `WWW-Authenticate` | `Authorization is missing` |
| Wrong user or password | 401 + `WWW-Authenticate` (after `delay`) | `Invalid user or password` |
| Client IP blocked by `ip_fail_limit` | 403 | `Forbidden, too many failures` |

## Usage notes

- Basic auth sends the password on every request, base64 encoded, not encrypted.
  Only use it over TLS.
- `delay` blocks the request task for its duration. Keep it well under a second
  on a busy listener, or combine a short delay with [`limit`](limit.md) instead.
- `hide_credentials = true` is the safe default whenever the upstream does not
  itself need the credentials — it keeps them out of upstream logs.

## Blocking repeated failures

With `ip_fail_limit` set, each wrong password is counted against the client
IP. Once an IP reaches the limit it is answered `403 Forbidden, too many
failures`, even for correct credentials, until its window ends:

- The window starts at the IP's first counted failure and lasts
  `ip_fail_window`. With `5` and `10m`, five wrong passwords in the first
  minute block the IP for the remaining nine. Refused requests are not
  counted, so they do not extend the block.
- Only wrong credentials count. A request without an `Authorization` header is
  how every browser starts, before it shows the login prompt, so it never
  counts.
- A successful login does not clear earlier failures; they expire with the
  window.
- Up to 4096 client IPs are tracked at once. Beyond that the least used are
  forgotten, which can only let an IP off early.
- The count is per process, like the `limit` plugin's.

The client IP is pingap's usual client IP. Without `basic.trusted_proxies` it is
taken from `X-Forwarded-For` first, which any client can set: an attacker can
send a fresh address with every guess and never be blocked, or put someone
else's address in the header to get them blocked. Behind a proxy or CDN, list
it in `trusted_proxies`; when clients connect directly, set `trusted_proxies`
anyway (to any address that is not a client) so the header is ignored.
