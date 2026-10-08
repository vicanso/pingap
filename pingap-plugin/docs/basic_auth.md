# basic_auth

HTTP Basic authentication (RFC 7617). Useful for staging sites, internal
dashboards and anything behind a browser where a login page is overkill.

- **Step:** `request` (fixed)
- **Registered as:** `basic_auth`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `basic_auth`. |
| `authorizations` | string[] | — | Base64 of `user:password`, one entry per account. At least one account is required, here or in `htpasswd`. |
| `htpasswd` | string[] | — | `user:hash`, one entry per account, with the password as a bcrypt or argon2 hash. See [Hashed passwords](#hashed-passwords). |
| `realm` | string | `Access to the staging site` | The realm of the `WWW-Authenticate` challenge, which a browser shows in its login prompt. |
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

## Hashed passwords

An `authorizations` entry is the password itself, base64 being no more than a
spelling of it: whoever reads the configuration file, the etcd prefix or the
admin has every password. An `htpasswd` entry holds a hash the password can
not be read back from:

```bash
htpasswd -nbB pingap 123123
# pingap:$2y$05$k6jyd5p6IGayudQCa5NLHuOeIKLGQyn1F2tqUkslMvPI6ZMCmmtxC
```

```toml
[plugins.staging]
category = "basic_auth"
htpasswd = [
    'pingap:$2y$05$k6jyd5p6IGayudQCa5NLHuOeIKLGQyn1F2tqUkslMvPI6ZMCmmtxC',
]
realm = "Staging"
```

- bcrypt (`$2y$`, `$2a$`, `$2b$`, `$2x$`) and argon2 (`$argon2id$`, also `i` and `d`)
  are taken. What `htpasswd` writes without `-B` (`$apr1$`, MD5 based), SHA-1
  and a plain password are refused at startup: they are fast to try, which is
  what a hash is there to prevent. Write the entries in single quotes in TOML,
  so that `$` and `\` are taken as they are.
- Both lists can be used together. A user name can be in `htpasswd` once.
- These hashes take tens of milliseconds to compute, on purpose. Credentials
  that passed are therefore remembered for five minutes, by a keyed digest of
  them that only this process can make, and a request with them is not hashed
  again: an API client that sends its credentials with every call costs one
  hash every five minutes. A changed entry takes effect with the reload that
  brings it, which starts the memory anew.
- A request with credentials that are not known yet costs a hash whoever sends
  it, a wrong guess included. The hashes are computed off the threads that
  serve requests, a few at a time; set `ip_fail_limit` so that guessing stops
  being answered at all. The limit is looked at again when a request gets its
  turn to be hashed, so guesses that arrive together are not all computed
  before the first of them has failed: the ones that have their turn at the
  same moment are, which is as many as the machine has cores, so the limit
  can be passed by about that many.
- A user that does not exist takes as long to refuse as a wrong password of
  the first account, so the names of the accounts can not be told apart by
  timing - as long as the accounts use the same kind of hash at the same
  cost. Mixed, a name can be told by how long its refusal takes.
- The cost of a hash is the one written in it. A bcrypt cost in the
  twenties, or an argon2 hash made with gigabytes of memory, is paid by every
  login and by every guess: make the entries with the defaults of the tool.

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

Failures are counted by an address the client cannot choose:

| `basic.trusted_proxies` | The address counted |
| --- | --- |
| set | The client IP: through a listed proxy the right-most `X-Forwarded-For` entry that is not a listed proxy, otherwise the peer |
| not set | The address of the connection itself; `X-Forwarded-For` and `X-Real-IP` are not looked at |

So behind a proxy or CDN that is not listed in `trusted_proxies`, every client
shares the proxy's address and one count: a few wrong passwords from anyone
block them all until the window ends. List the proxy.

Up to 0.15.0 the count went by `X-Forwarded-For` whenever no trusted proxies
were set, which any client can write: a new address with every guess was never
blocked, and someone else's address got them blocked. The admin's own lockout
of failed logins is counted the same way.
