# ip_restriction

Allow- or deny-list access by client IP address or CIDR range.

- **Step:** `request` (fixed)
- **Registered as:** `ip_restriction`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `ip_restriction`. |
| `ip_list` | string[] | `[]` | IPv4/IPv6 addresses and CIDR ranges. An entry that is neither fails configuration validation. |
| `type` | string | `allow` | `allow` permits **only** listed IPs; `deny` blocks them. Case-insensitive; any other value is a configuration error. |
| `message` | string | `Request is forbidden` | Body of the 403 response. |

Leaving `type` unset means `allow`, so an empty `ip_list` blocks every request.
Set it explicitly.

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

With `trusted_proxies` set:

- A connection that does not come from a trusted proxy is identified by its
  peer address; its forwarded headers are ignored.
- Through a trusted proxy, `X-Forwarded-For` is read from the right. Each proxy
  appends the address it received the request from, so entries that are
  trusted proxies themselves are skipped and the first one that is not is the
  client. Whatever stands to the left of it was sent by that client and is not
  looked at: for `X-Forwarded-For: 6.6.6.6, 9.9.9.9` arriving from `10.0.0.2`
  the client is `9.9.9.9`. Several `X-Forwarded-For` lines are read as one
  list, and an entry may carry a port (`9.9.9.9:4321`, `[2001:db8::1]:4321`).
- Without `X-Forwarded-For` the address is `X-Real-IP`, then the peer.

Without `trusted_proxies` the first `X-Forwarded-For` entry is taken from
anyone, which is only safe when no client can reach pingap directly.

## Responses

| Situation | Status | Body |
| --- | --- | --- |
| Blocked by policy | 403 | `message` |
| Client IP is unparseable | 400 | Parse error text |

## Usage notes

- The result is a plain 403 with no `Retry-After` or challenge; use
  [`limit`](limit.md) if you want throttling rather than blocking.
- For country-level rules see [`geo_restriction`](geo_restriction.md).
