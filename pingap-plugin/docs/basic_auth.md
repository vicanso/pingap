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

`authorizations` entries are validated as base64 at startup, so a typo fails
`pingap -t` instead of silently locking everyone out. Credentials are compared in
constant time.

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

## Usage notes

- Basic auth sends the password on every request, base64 encoded, not encrypted.
  Only use it over TLS.
- `delay` blocks the request task for its duration. Keep it well under a second
  on a busy listener, or combine a short delay with [`limit`](limit.md) instead.
- `hide_credentials = true` is the safe default whenever the upstream does not
  itself need the credentials — it keeps them out of upstream logs.
