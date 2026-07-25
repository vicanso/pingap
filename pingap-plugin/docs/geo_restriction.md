# geo_restriction

Allow- or deny-list requests by the client's country, resolved from an embedded
GeoIP database. There is also a reporting mode that only logs the lookup, so you
can size the impact of a rule before enforcing it.

- **Step:** `request` (fixed)
- **Registered as:** `geo_restriction`
- **Requires the `geo` cargo feature** (not part of `full`)

```bash
cargo build --features=geo
```

`geo` is deliberately kept out of `full` because it embeds a GeoIP database in
the binary. `make lint` runs a separate clippy pass over it so the feature does
not rot unnoticed.

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `geo_restriction`. |
| `type` | string | — | **Required.** One of `allow`, `deny`, `reporting`. |
| `country_codes` | string[] | `[]` | ISO 3166-1 alpha-2 codes. Entries may also be space/comma separated inside one string. |
| `message` | string | `Access from your country is not allowed` | Body of the 403 response. |

Codes are upper-cased and validated to be exactly two ASCII letters, so a typo
fails at startup rather than silently never matching.

## Examples

Only serve a domestic market:

```toml
[plugins.geoAllow]
category = "geo_restriction"
type = "allow"
country_codes = ["CN", "HK", "MO", "TW"]
```

Block a few countries:

```toml
[plugins.geoDeny]
category = "geo_restriction"
type = "deny"
country_codes = ["XX, YY"]        # also accepted: one string, comma separated
message = "Service unavailable in your region"
```

Measure first, enforce later:

```toml
[plugins.geoReport]
category = "geo_restriction"
type = "reporting"
```

Reporting mode emits an `info` log line per request with the IP and resolved
country and always continues.

## Behaviour

| Situation | `allow` | `deny` |
| --- | --- | --- |
| Country in `country_codes` | allowed | **403** |
| Country not in the list, or unknown (`??`) | **403** | allowed |
| Client IP not parseable | allowed (plugin continues) | allowed |

## Usage notes

- The GeoIP database is embedded in the binary, so lookups need no network
  access — but the data ages with the release. Country assignments for a given IP
  can be wrong, especially for mobile carriers, VPNs and cloud ranges.
- Client IP resolution follows `basic.trusted_proxies`; without it, a forged
  `X-Forwarded-For` picks the country. See
  [`ip_restriction`](ip_restriction.md#client-ip-resolution).
- Run `type = "reporting"` in production for a while and check the logs before
  turning on `allow`, which blocks everything the database cannot classify.
