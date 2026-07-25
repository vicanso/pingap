# ua_restriction

Allow- or deny-list requests by `User-Agent`, matched with regular expressions.

- **Step:** `request` (fixed)
- **Registered as:** `ua_restriction`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `ua_restriction`. |
| `ua_list` | string[] | `[]` | Regex patterns, compiled at startup. |
| `type` | string | `allow` | `deny` blocks matching agents; anything else allows **only** matching agents. |
| `message` | string | `Request is forbidden` | Body of the 403 response. |

Patterns use the [`regex`] crate's syntax and are **unanchored** — `go-http-client`
matches anywhere in the header. Anchor with `^…$` when you mean an exact value.
An invalid pattern is a startup error, so `pingap -t` catches it.

## Examples

Block scripted clients and a specific crawler:

```toml
[plugins.blockBots]
category = "ua_restriction"
type = "deny"
ua_list = [
    "go-http-client/1\\.1",
    "(Twitterspider)/(\\d+)\\.(\\d+)",
    "^python-requests/",
    "curl/",
]
message = "Automated access is not allowed"
```

Only let a known internal client through:

```toml
[plugins.internalClient]
category = "ua_restriction"
type = "allow"
ua_list = ["^my-service/\\d+\\.\\d+$"]
```

## Behaviour

| `User-Agent` | `type = "allow"` | `type = "deny"` |
| --- | --- | --- |
| Matches a pattern | allowed | **403** |
| Matches nothing | **403** | allowed |
| Header absent | **403** | allowed |

## Usage notes

- In allow mode a missing `User-Agent` is blocked. Many health checkers and
  monitoring probes send none — exclude those paths or add a pattern for them.
- `User-Agent` is trivially spoofed, so this stops naive scripts, not determined
  ones. For real gating use [`key_auth`](key_auth.md) or
  [`ip_restriction`](ip_restriction.md).
- TOML strings need the backslash escaped: write `"\\d+"`, or use a literal
  string `'\d+'`.

[`regex`]: https://docs.rs/regex/latest/regex/#syntax
