# ip_restriction

Allow- or deny-list access by client IP address or CIDR range.

- **Step:** `request` (fixed)
- **Registered as:** `ip_restriction`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `ip_restriction`. |
| `ip_list` | string[] | `[]` | IPv4/IPv6 addresses and CIDR ranges. |
| `type` | string | `allow` | `deny` blocks listed IPs; anything else (including unset) allows **only** listed IPs. |
| `message` | string | `Request is forbidden` | Body of the 403 response. |

`type` is compared literally against `"deny"`. Any other value — including an
empty one — is treated as allow-list mode, so an empty `ip_list` with no `type`
blocks every request. Set `type` explicitly.

## Examples

Allow-list an internal admin path:

```toml
[plugins.internalOnly]
category = "ip_restriction"
type = "allow"
ip_list = ["127.0.0.1", "10.0.0.0/8", "192.168.1.0/24", "::1"]
message = "Internal access only"

[locations.admin]
upstream = "admin"
path = "/admin"
plugins = ["internalOnly"]
```

Deny-list a few abusive ranges:

```toml
[plugins.blockList]
category = "ip_restriction"
type = "deny"
ip_list = ["1.2.3.4", "203.0.113.0/24"]
```

## Client IP resolution

The client IP comes from `pingap_core::get_client_ip`, which prefers
`X-Forwarded-For` / `X-Real-IP` and falls back to the peer address. Configure
`basic.trusted_proxies` so those headers are only honoured for connections coming
from your real load balancers — otherwise any client can spoof its IP and walk
straight past an allow-list.

```toml
[basic]
trusted_proxies = ["10.0.0.0/8"]
```

## Responses

| Situation | Status | Body |
| --- | --- | --- |
| Blocked by policy | 403 | `message` |
| Client IP is unparseable | 400 | Parse error text |

## Usage notes

- The result is a plain 403 with no `Retry-After` or challenge; use
  [`limit`](limit.md) if you want throttling rather than blocking.
- For country-level rules see [`geo_restriction`](geo_restriction.md).
