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
   and pinned to that JWK's algorithm; only asymmetric algorithms are accepted.
   Keys are cached for `jwks_ttl`, refreshed single-flight with a cooldown of
   `min(jwks_ttl, 10s)`, and a stale cache is reused if a refetch fails.
3. **HMAC** — otherwise `secret` is used with `HS256` or `HS512`.

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `jwt`. |
| `header` | string | — | Header holding the token; a `Bearer ` prefix is stripped. |
| `cookie` | string | — | Cookie holding the token. |
| `query` | string | — | Query parameter holding the token. |
| `secret` | string | — | HMAC shared secret. Required unless `public_key` or `jwks_url` is set. |
| `algorithm` | string | `HS256` | Signing algorithm; also the algorithm used when minting. |
| `public_key` | string | — | PEM public key, required for asymmetric `algorithm`. |
| `jwks_url` | string | — | JWKS endpoint URL. |
| `jwks_ttl` | duration | `1h` | How long fetched JWKS keys stay fresh. |
| `auth_path` | string | — | Path that mints tokens instead of consuming them. |
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

Minting only works with HMAC — the signature is always computed from `secret`
using `HS256` or `HS512`. Only a `2xx` upstream response is signed; an error
body is passed through untouched, so a failed login cannot be turned into a
token that never expires.

## Responses

| Situation | Status | Body |
| --- | --- | --- |
| No token found | 401 | `Jwt authorization is missing` |
| Not three dot-separated parts (HMAC mode) | 401 | `Jwt authorization format is invalid` |
| Bad signature, or unsupported `alg` | 401 (after `delay`) | `Jwt authorization is invalid` |
| `exp` in the past (HMAC mode) | 401 | `Jwt authorization is expired` |

## Usage notes

- The asymmetric and JWKS paths verify the signature **and** `exp` together via
  `jsonwebtoken`; `aud` is not validated.
- In HMAC mode the algorithm is taken from the token header and both `HS256` and
  `HS512` are accepted, so setting `algorithm = "HS512"` does not by itself
  reject an `HS256` token. `none` and every other value are rejected.
- `auth_path` is compared for exact equality against the request path.
- Anything reachable under `auth_path` is unauthenticated by design — keep it on
  its own location if the surrounding location is otherwise protected.
