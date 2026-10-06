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

On a build without the feature the plugin can still be declared, which only
logs a warning, but a location that names it is a configuration error:
`--test`, startup and a reload reject it rather than serve the location with
no restriction.

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
| Client IP not parseable | **403** | allowed |

A client IP that is not an address has no country and is treated like any
address the database does not know. An IPv4 client of a dual-stack listener
(`[::]:80`), whose address is `::ffff:1.2.3.4`, is looked up as `1.2.3.4`.

## Usage notes

- The GeoIP data comes from [`tor-geoip`](https://crates.io/crates/tor-geoip)'s
  `embedded-db` feature and is compiled into the binary, so lookups need no
  network access — but the data ages with the crate version. Country assignments
  for a given IP can be wrong, especially for mobile carriers, VPNs and cloud
  ranges.
- The country is that of an address the client cannot choose: through a proxy
  listed in `basic.trusted_proxies` the forwarded address, otherwise the
  peer's own. Behind a proxy that is not listed, every request has the
  proxy's country. See
  [`ip_restriction`](ip_restriction.md#client-ip-resolution).
- Run `type = "reporting"` in production for a while and check the logs before
  turning on `allow`, which blocks everything the database cannot classify.
