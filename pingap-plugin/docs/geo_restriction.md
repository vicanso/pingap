# geo_restriction

Allow- or deny-list requests by the client's country, resolved from an embedded
GeoIP database or from a MaxMind DB file. There is also a reporting mode that
only logs the lookup, so you can size the impact of a rule before enforcing it,
and the country can be passed to the upstream in a request header.

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
| `database` | string | — | Path of a MaxMind DB file (`.mmdb`) to look countries up in, in place of the embedded data. |
| `database_refresh` | duration | `1m` | How often the file is looked at for a change. At least `1s`. |
| `header` | string | — | Request header the upstream is told the country in, e.g. `X-Geo-Country`. |

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

A database that is kept up to date, and the country for the upstream:

```toml
[plugins.geo]
category = "geo_restriction"
type = "reporting"
database = "/var/lib/GeoIP/GeoLite2-Country.mmdb"
header = "X-Geo-Country"
```

## Behaviour

| Situation | `allow` | `deny` |
| --- | --- | --- |
| Country in `country_codes` | allowed | **403** |
| Country not in the list, or unknown (`??`) | **403** | allowed |
| Client IP not parseable | **403** | allowed |

A client IP that is not an address has no country and is treated like any
address the database does not know. An IPv4 client of a dual-stack listener
(`[::]:80`), whose address is `::ffff:1.2.3.4`, is looked up as `1.2.3.4`.

### `database`

The embedded data is as old as the release it came with. A file is as new as
whoever provides it keeps it: `geoipupdate`, a cron job, a mounted volume.

- Any database of the MaxMind DB format that names a country works: GeoLite2
  and GeoIP2 Country or City, DB-IP, and others. The code is read from
  `country.iso_code`, or from a `country_code` or `country` field that holds
  the two letters.
- The file is read when the plugin is built: one that is missing or is no
  database is a configuration error. With `database` set the embedded data is
  not used at all, so an address the file does not know has no country.
- The file is looked at every `database_refresh`, and read again when its
  modification time has changed. A request is never held up for it: the
  reading happens beside the requests, which go by the database that is
  loaded until the new one is ready. A file that can not be read at that
  moment - one that is still being written, or is gone - leaves the loaded
  one in place, is reported in the log, and is tried again at the next look.
  Replace the file by renaming a complete one over it, as `geoipupdate` does.
- Plugins that name the same file share one copy of it in memory. Each
  looks at the file at its own `database_refresh`; a change that one of them
  finds is there for all.

### `header`

With `header` set, the request goes to the upstream with the country in that
header, in every mode: `X-Geo-Country: DE`. A header of that name that the
client sent is removed first, also when no country is known, in which case
the upstream gets none: what it reads there is always the proxy's word.

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
