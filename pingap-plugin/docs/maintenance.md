# maintenance

Answers every request of a location with the notice that the site is down for
maintenance, and lets through the people who are doing the maintenance.

A [`mock`](mock.md) plugin can answer `503` for everyone - those people
included, who then cannot look at the site they are working on.

- **Step:** `request` (fixed)
- **Registered as:** `maintenance`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `maintenance`. |
| `enabled` | bool | `true` | `false` turns the plugin off without taking it out of the location: the page and the lists stay in the configuration for the next time. |
| `status` | int | `503` | Status of the notice, `400` to `599`. |
| `retry_after` | duration | — | Sent as `Retry-After`, in seconds. |
| `message` | string | `Service is under maintenance` | Body of the notice, as `text/plain`. |
| `html` | string | — | Body of the notice, as `text/html`. Set this or `message`, not both. |
| `allow_ip_list` | string[] | — | IPs and CIDR ranges that are let through. |
| `allow_header` | string | — | `Name: value`: a request with this header and this value is let through. |

## Example

```toml
[plugins.maintenance]
category = "maintenance"
retry_after = "30m"
html = "<h1>Back at 03:00 UTC</h1><p>We are upgrading the database.</p>"
allow_ip_list = ["10.0.0.0/8", "203.0.113.7"]
allow_header = "X-Maintenance-Pass: 7c2f0e5a"

[locations.app]
upstream = "app"
plugins = ["maintenance", "auth"]
```

Everyone else:

```
HTTP/1.1 503 Service Unavailable
Retry-After: 1800
Content-Type: text/html; charset=utf-8
Cache-Control: private, no-store
```

## Behaviour

| Request | Result |
| --- | --- |
| `enabled = false` | Passes, as if the plugin were not listed |
| Carries the `allow_header` with its value | Passes |
| Client address is in `allow_ip_list` | Passes |
| Anything else | `status` with the notice |

## Usage notes

- List it first among the plugins of a location, so that a request that is
  turned away costs nothing of what follows.
- The address `allow_ip_list` goes by is the peer's own, or the client's
  through a proxy listed in `basic.trusted_proxies`. An `X-Forwarded-For` from
  anyone else is what the request claims and is not looked at.
- `allow_header` is a shared secret: the value is what lets a request through,
  and it is compared in constant time. A name without a value is a
  configuration error. Use it for the checks of a deployment pipeline, or with
  a browser extension that adds the header.
- The notice is marked `no-store`: kept by a cache, it would go on being served
  after the maintenance is over.
- Switching `enabled` is a change of the plugin and takes effect with the next
  reload, like any other.
