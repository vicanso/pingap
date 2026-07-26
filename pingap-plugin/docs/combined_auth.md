# combined_auth

Signed-request authentication for machine-to-machine APIs. A caller identifies
itself with an `app_id`, proves it holds the shared secret with an HMAC-style
digest, and the timestamp in the signature bounds how long a captured request
stays replayable. An optional IP allow-list can be attached per application.

- **Step:** `request` (fixed)
- **Registered as:** `combined_auth`

## Configuration

`authorizations` is an array of tables, one per application:

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `combined_auth`. |
| `authorizations` | table[] | — | **Required.** One entry per application. |
| `authorizations[].app_id` | string | — | Identifier the caller sends as `?app_id=`. Entries without it are skipped. |
| `authorizations[].secret` | string | — | Shared secret. The literal `*` disables **all** checks for this app. |
| `authorizations[].deviation` | int | — | **Required** (unless `secret = "*"`), greater than zero. Maximum allowed clock skew, in seconds. |
| `authorizations[].ip_list` | string[] | — | IPs / CIDRs allowed to use this app id. |

## Request format

The caller sends three query parameters:

| Parameter | Meaning |
| --- | --- |
| `app_id` | Which entry of `authorizations` to use |
| `ts` | Current Unix time, in seconds |
| `digest` | `hex(sha256("<secret>:<ts>"))`, case-insensitive |

Note that `digest` covers only the secret and the timestamp — it authenticates
the *caller*, not the request body or path.

## Example

```toml
[plugins.appAuth]
category = "combined_auth"

[[plugins.appAuth.authorizations]]
app_id = "pingap"
secret = "123123"
deviation = 60
ip_list = ["127.0.0.1", "192.168.1.0/24"]

[[plugins.appAuth.authorizations]]
app_id = "internal"
secret = "*"          # unrestricted, use with care
```

Client side:

```bash
APP_ID=pingap
SECRET=123123
TS=$(date +%s)
DIGEST=$(printf '%s:%s' "$SECRET" "$TS" | shasum -a 256 | cut -d' ' -f1)

curl "http://127.0.0.1:6188/api/orders?app_id=$APP_ID&ts=$TS&digest=$DIGEST"
```

## Validation order

1. `app_id` present and known — otherwise 401.
2. `secret == "*"` → allow immediately (skips IP, timestamp and digest checks).
3. `ip_list`, when configured, must match the client IP.
4. `ts` present, numeric, and `|now - ts| <= deviation`.
5. `digest` present and equal to the expected value, compared in constant time.

Any failure returns **401** with `cache-control: private, no-store` and the
reason in the body (e.g. `Plugin combined_auth invalid, message: digest is
invalid`).

## Usage notes

- `deviation` has no default and must be greater than zero, because it is what
  bounds the replay window. 30–120 seconds is a reasonable range; larger values
  widen the window.
- `secret = "*"` bypasses the IP allow-list too. If you want an unauthenticated
  but IP-restricted app, use [`ip_restriction`](ip_restriction.md) instead.
- Timestamp validation needs the proxy's clock to be in sync with clients; run
  NTP.
- Because the digest does not cover the URL, a captured signature works for any
  path within the `deviation` window. Keep the window short and stay on TLS.
