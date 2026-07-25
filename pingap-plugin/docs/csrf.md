# csrf

CSRF protection using the double-submit-cookie pattern. The client fetches a
signed token from `token_path`, which also lands in a cookie, and must then echo
it in a header on every state-changing request. A cross-site attacker can make
the browser send the cookie but cannot read it to set the header.

- **Step:** `request` (fixed)
- **Registered as:** `csrf`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `csrf`. |
| `token_path` | string | — | **Required.** Path that issues a new token. |
| `key` | string | — | **Required.** Secret used to sign tokens. Must be identical on every instance. |
| `name` | string | `x-csrf-token` | Name of both the header and the cookie. |
| `ttl` | duration | `0` (never expires) | Token lifetime; also becomes the cookie `Max-Age`. |

## Token format

```
<nanoid(12)>.<unix-seconds in hex>.<base64(sha256(id "." ts  ‖ key))>
```

The signature is verified in constant time, so tokens cannot be forged without
`key`.

## Example

```toml
[plugins.csrf]
category = "csrf"
token_path = "/csrf-token"
key = "WjrXUG47wu"
ttl = "1h"

[locations.app]
upstream = "app"
path = "/"
plugins = ["csrf"]
```

Browser side:

```js
// once per session / page load
await fetch("/csrf-token", { credentials: "same-origin" });
// -> 204 No Content, Set-Cookie: x-csrf-token=…; Path=/; Max-Age=3600

const token = document.cookie.match(/x-csrf-token=([^;]+)/)[1];

await fetch("/api/orders", {
  method: "POST",
  headers: { "x-csrf-token": token, "content-type": "application/json" },
  credentials: "same-origin",
  body: JSON.stringify({ sku: "abc" }),
});
```

## Behaviour

| Request | Result |
| --- | --- |
| `GET`/`HEAD`/`OPTIONS` on any path | Skipped, no token needed |
| Any method on `token_path` | `204` with `Set-Cookie` and `cache-control: private, no-store` |
| Other methods, header missing | `401`, `Csrf token is empty or invalid` |
| Other methods, header ≠ cookie | `401` |
| Other methods, signature bad or expired | `401` |

## Usage notes

- `token_path` is matched for exact equality and is checked **before** the safe
  method check, so it answers on any method.
- The cookie is issued with `Path=/` only. Pingap does not set `Secure`,
  `HttpOnly` or `SameSite` — `HttpOnly` would in fact break the pattern, since
  JavaScript has to read the cookie to build the header. Terminate TLS in front
  and consider a `SameSite` cookie policy at the application level.
- `key` must be shared by every Pingap instance behind the same load balancer,
  otherwise tokens minted by one node are rejected by another.
- `ttl = 0` means tokens never expire; prefer an explicit lifetime.
