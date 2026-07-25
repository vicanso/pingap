# traffic_splitting

Redirects a share of the traffic that matched a location to a different upstream.
This is the building block for canary releases, blue/green cutovers and A/B
tests. Routing is unchanged — only the chosen backend pool differs.

- **Step:** `request` (fixed)
- **Registered as:** `traffic_splitting`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `traffic_splitting`. |
| `upstream` | string | — | **Required.** Upstream to switch to when the request is selected. |
| `weight` | int | `0` | 0–100. Percentage of traffic sent to `upstream`. |
| `stickiness` | bool | `false` | Make the decision deterministic per client instead of random. |
| `sticky_cookie` | string | — | Cookie whose value drives the sticky decision. |
| `sticky_header` | string | — | Header whose value drives the sticky decision. Only used when `sticky_cookie` is unset. |
| `matcher` | string | — | Regex on the sticky value. Matching values always go to `upstream`. |

When `stickiness = true`, at least one of `sticky_cookie` / `sticky_header` must
be set, or configuration fails.

## Selection logic

A roll in `0..100` is compared with `weight`; the request switches upstream when
`roll < weight`.

| Mode | Roll |
| --- | --- |
| `stickiness = false` | Uniform random |
| `stickiness = true`, no `matcher` | `crc32(sticky value) % 100` — same client, same result |
| `stickiness = true`, `matcher` set | `0` when the regex matches, `255` otherwise |
| Sticky value missing | `255` — never selected |

## Examples

Random 10% canary:

```toml
[plugins.canary]
category = "traffic_splitting"
upstream = "app-v2"
weight = 10

[locations.app]
upstream = "app-v1"
path = "/"
plugins = ["canary"]
```

Sticky 20% canary — a given `deviceId` always gets the same version, so a user
does not flip between builds between requests:

```toml
[plugins.canary]
category = "traffic_splitting"
upstream = "app-v2"
weight = 20
stickiness = true
sticky_cookie = "deviceId"
```

Explicit opt-in by header — only internal testers see v2:

```toml
[plugins.betaUsers]
category = "traffic_splitting"
upstream = "app-v2"
weight = 100
stickiness = true
sticky_header = "X-User-Group"
matcher = "^(beta|internal)$"
```

## Usage notes

- With `matcher`, `weight` must still be greater than `0` — a matched value only
  produces a roll of `0`, which still has to be below `weight`. Use `weight =
  100` for a pure opt-in rule.
- Clients without the sticky cookie/header are never selected. Make sure the
  value is set (for instance by an edge that assigns `deviceId`) before relying
  on sticky mode.
- The plugin only rewrites which upstream is used; the location's own `upstream`
  remains the default for everyone else.
- Several `traffic_splitting` plugins on one location run in order, and the last
  one that selects wins.
