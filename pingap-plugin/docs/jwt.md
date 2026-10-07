# jwt

JWT authentication with three verification modes, plus an optional endpoint that
turns an upstream response into a signed token.

- **Step:** `request` for verification; also hooks `response` / `response_body`
  for token minting
- **Registered as:** `jwt`

## Verification modes

The mode is chosen by which keys are configured, and they are tried in this
order:

1. **Asymmetric with a static key** — `algorithm` is one of `RS256` `RS384`
   `RS512` `PS256` `PS384` `PS512` `ES256` `ES384` and `public_key` holds the
   PEM. The configured algorithm is pinned, so a token that claims a different
   `alg` is rejected (no algorithm-confusion downgrade).
2. **Remote JWKS** — `jwks_url` is set. The key is selected by the token's `kid`
   and pinned to the token's algorithm; only asymmetric algorithms are accepted.
   A token without a `kid` is tried against every key, and a key without one (a
   single-key JWKS, typically) is kept rather than dropped. Keys are cached for
   `jwks_ttl`, refreshed single-flight with a cooldown of `min(jwks_ttl, 10s)`,
   and a stale cache is reused if a refetch fails. The cooldown counts from
   the last attempt whether it succeeded or not, so while the endpoint is down
   it is asked once per cooldown and requests are answered from what is cached
   instead of waiting on it.
3. **HMAC** — otherwise `secret` is used with `HS256` or `HS512`.

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `jwt`. |
| `header` | string | — | Header holding the token; a `Bearer` scheme (any case) is stripped. |
| `cookie` | string | — | Cookie holding the token. |
| `query` | string | — | Query parameter holding the token. The value is percent-decoded before it is verified. |
| `secret` | string | — | HMAC shared secret. Required unless `public_key` or `jwks_url` is set. |
| `algorithm` | string | `HS256` | Signing algorithm; also the algorithm used when minting. |
| `public_key` | string | — | PEM public key, required for asymmetric `algorithm`. |
| `jwks_url` | string | — | JWKS endpoint URL. |
| `jwks_ttl` | duration | `1h` | How long fetched JWKS keys stay fresh. |
| `auth_path` | string | — | Path that mints tokens instead of consuming them. |
| `require_exp` | bool | `true` | Whether a token has to carry `exp`, in every verification mode, and whether the response at `auth_path` has to before it is signed. See [Expiry](#expiry). |
| `leeway` | duration | `60s` | How far the issuer's clock may be from the proxy's: `exp` and `nbf` are given this much in every verification mode. At most `1d`. See [Expiry](#expiry). |
| `delay` | duration | none | Sleep before answering an invalid token. |

Exactly one of `header` / `cookie` / `query` is used, checked in that order; at
least one must be set.

## Examples

### HMAC

```toml
[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
secret = "123123"
algorithm = "HS256"
auth_path = "/login"
delay = "1s"

[locations.api]
upstream = "api"
path = "/"
plugins = ["jwtAuth"]
```

```bash
# mint
curl -X POST http://127.0.0.1:6188/login -d '{"id":"u-1","exp":1893456000}'
# {"token": "eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiAiSldUIn0.…"}

# use
curl -H "Authorization: Bearer eyJ…" http://127.0.0.1:6188/api/me
```

### Remote JWKS (Auth0, Keycloak, Cognito…)

```toml
[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
jwks_url = "https://example.auth0.com/.well-known/jwks.json"
jwks_ttl = "1h"
```

### Static public key

```toml
[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
algorithm = "RS256"
public_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A…
-----END PUBLIC KEY-----
"""
```

## Token minting (`auth_path`)

Requests to `auth_path` skip verification entirely. On the way back, the plugin
replaces the upstream response body with

```json
{"token": "<header>.<upstream body base64url>.<signature>"}
```

sets `content-type: application/json` and switches to chunked encoding. The
upstream therefore returns the *claims* (`{"id":"u-1","exp":…}`), not a token.

The body is signed byte for byte, so the request to `auth_path` goes to the
upstream without the client's `Accept-Encoding`: the claims come back
uncompressed. An upstream that compresses them anyway is answered with a `502`
rather than a token whose payload is a gzip stream.

Minting only works with HMAC — the signature is always computed from `secret`
using `HS256` or `HS512`. Only a `2xx` upstream response is signed; an error
body is passed through untouched, so a failed login cannot be turned into a
token.

## Expiry

A token without `exp` is valid for as long as the key is, so by default one is
required everywhere:

- **Verification** — in all three modes a token whose payload has no `exp` (or
  a `null` one) is answered with `401`. The HMAC mode used to accept such a
  token; the two public key modes never did.
- **Minting** — the upstream's claims are signed as they are, nothing is added
  to them. If they are not a JSON object with a numeric `exp`, no token is
  issued and the request to `auth_path` fails: with a `502`, or, when the
  upstream's header had already been passed on before its body arrived, by
  closing the connection in the middle of the response.

`require_exp = false` restores the earlier behaviour for deployments that issue
tokens meant to never expire: a missing `exp` is accepted in every mode, and
`auth_path` signs whatever a `2xx` response holds. A token that does carry
`exp` is still rejected once it has passed.

The issuer's clock and the proxy's are never quite the same, so both time
claims are given `leeway` (`60s` unless set): a token is expired once `exp` is
more than that behind the proxy's clock, and not yet valid while `nbf` is more
than that ahead. It is the same in all three modes. The two public key modes
always had sixty seconds, from the library that verifies them, while the HMAC
mode had none: an issuer a second ahead had its tokens answered `Jwt
authorization is not yet valid`, now and then, by one configuration and never
by another. `leeway = "0s"` holds every mode to the second, which for the HMAC
mode is what it did before; with the default a token of that mode is taken for
up to a minute after its `exp`.

## Responses

| Situation | Status | Body |
| --- | --- | --- |
| No token found | 401 | `Jwt authorization is missing` |
| Not three dot-separated parts, or the payload is not a JSON object (HMAC mode) | 401 | `Jwt authorization format is invalid` |
| Bad signature, or unsupported `alg` | 401 (after `delay`) | `Jwt authorization is invalid` |
| `exp` more than `leeway` in the past (HMAC mode) | 401 | `Jwt authorization is expired` |
| No `exp` and `require_exp` is on (HMAC mode) | 401 | `Jwt authorization has no exp` |
| `nbf` more than `leeway` in the future (HMAC mode) | 401 | `Jwt authorization is not yet valid` |
| Claims at `auth_path` without `exp` and `require_exp` is on | 502, or the connection is closed | error page |

## Usage notes

- The asymmetric and JWKS paths verify the signature, `exp` and `nbf` together
  via `jsonwebtoken`; `aud` is not validated. The HMAC path checks the same two
  claims with the same `leeway`, accepts them as integers or floats, and does
  not require `typ` in the header. `delay` applies only to a bad signature, the one outcome a guess can
  produce.
- In HMAC mode an explicitly configured `algorithm` is enforced, so an `HS512`
  configuration rejects an `HS256` token and vice versa. Leaving `algorithm`
  unset accepts either. `none` and everything else are always rejected, and an
  `algorithm` the secret path cannot verify (`HS384`, or an asymmetric one with
  no `public_key` / `jwks_url`) is rejected at startup.
- `auth_path` is compared for exact equality against the request path.
- Anything reachable under `auth_path` is unauthenticated by design — keep it on
  its own location if the surrounding location is otherwise protected.
