# Pingap Config

Configuration model, storage backends and format conversion for
[Pingap](https://github.com/vicanso/pingap).

Everything Pingap can be told to do is expressed as a `PingapConfig`. This crate
owns that type, the code that loads it from somewhere, the validation that
rejects a bad configuration before the proxy starts, and the conversions between
the three supported input formats.

## The configuration model

```rust
pub struct PingapConfig {
    pub basic: BasicConf,
    pub upstreams: HashMap<String, UpstreamConf>,
    pub locations: HashMap<String, LocationConf>,
    pub servers: HashMap<String, ServerConf>,
    pub plugins: HashMap<String, PluginConf>,
    pub certificates: HashMap<String, CertificateConf>,
    pub storages: HashMap<String, StorageConf>,
}
```

| Section | Purpose |
| --- | --- |
| `basic` | Process-wide settings: threads, user/group, pid file, logging, webhooks, Sentry, Pyroscope, trusted proxies |
| `servers` | Listeners: address, TLS, HTTP/2, access log, metrics, which locations they serve |
| `locations` | Routing rules: host/path matching, rewrite, headers, plugins, limits |
| `upstreams` | Backend pools: addresses, discovery, load balancing, health checks, timeouts, circuit breaking |
| `plugins` | Plugin instances, keyed by name, with `category` selecting the implementation |
| `certificates` | TLS certificates, including ACME settings |
| `storages` | Reusable configuration fragments referenced by `includes`; also where ACME keeps its challenge state |

Every section implements `Validate`. `pingap -t` loads the configuration, runs
all validators and exits — run it in CI and before a reload.

## Storage backends

The backend is chosen from the value of `-c` / `PINGAP_CONF`:

| Value | Backend | Layout | Hot reload |
| --- | --- | --- | --- |
| `/opt/pingap/pingap.toml` | Single file | `Single` | Polled |
| `/opt/pingap/conf` (a directory) | Files per category | `MultiByType` | Polled |
| `/opt/pingap/conf?separation=true` | One file per item | `MultiByItem` | Polled |
| `etcd://127.0.0.1:2379/pingap` | etcd | `MultiByItem` | Pushed via a watch stream |
| *(in-process)* | `MemoryStorage` | `Single` | None |

```bash
pingap -c /opt/pingap/conf --autoreload
pingap -c "etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s" --autoreload
pingap -c "/opt/pingap/conf?separation=true&enable_history=true"
```

Query parameters for the file backend (directories only):

| Parameter | Meaning |
| --- | --- |
| `separation=true` | Write each item to its own file. Anything other than the literal `false` counts as true. |
| `enable_history=true` | Keep previous versions next to the config (`<dir>-history`) so the admin UI can restore them. Requires `separation`. |

`MemoryStorage` backs the config-file-less quick start
(`pingap --domain=… --upstream=…`): the configuration is synthesized from the
command line and held in memory, with writes optionally mirrored to a file so an
ACME-issued certificate survives a restart.

### The `Storage` trait

```rust
#[async_trait]
pub trait Storage: Send + Sync {
    async fn fetch(&self, key: &str) -> Result<String>;
    async fn save(&self, key: &str, value: &str) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    fn support_observer(&self) -> bool { false }
    fn support_history(&self) -> bool { false }
    // ...
}
```

In `Single` mode both updates and deletes are read-modify-write followed by one
`save`, so a backend that only implements `fetch` and `save` is enough.
`ConfigManager` serializes those read-modify-write cycles behind a mutex so
concurrent admin and ACME writes cannot clobber each other.

## Configuration formats

The same configuration can be written as TOML (canonical), HCL or KDL. When
loading a directory, `.toml` files win; if there are none, `.hcl` is tried, then
`.kdl`. HCL and KDL are converted to TOML in memory, so they are input formats
only — everything downstream sees TOML.

```toml
[upstreams.api]
addrs = ["api.github.com:443"]
discovery = "dns"
sni = "api.github.com"

[locations.github-api]
upstream = "api"
path = "/api"
rewrite = "^/api/(?<path>.+)$ /$1"

[servers.test]
addr = "127.0.0.1:6118"
locations = ["github-api"]
```

```hcl
server "test" {
  addr = "127.0.0.1:6118"

  location "github-api" {
    path    = "/api"
    rewrite = "^/api/(?<path>.+)$ /$1"

    upstream "api" {
      addrs     = ["api.github.com:443"]
      discovery = "dns"
      sni       = "api.github.com"
    }
  }
}
```

HCL supports `$ENV:NAME` interpolation, so secrets can come from the
environment instead of the file:

```hcl
upstream "api" {
  addrs     = ["$ENV:PINGAP_API_ADDR"]
  discovery = "dns"
}
```

Conversion and migration on the command line:

```bash
pingap -c /opt/pingap/conf --to-hcl ./conf.hcl        # dump as HCL
pingap -c /opt/pingap/conf --to-kdl ./conf.kdl        # dump as KDL
pingap -c /opt/pingap/conf --sync etcd://127.0.0.1:2379/pingap   # file -> etcd
pingap --template > pingap.toml                       # starter config
pingap -c /opt/pingap/conf -t                         # validate and exit
```

## Hot reload

`ConfigManager::support_observer()` decides how changes arrive:

- **etcd** returns `true` and pushes changes through an `etcd_client::WatchStream`.
- **File** returns `false` and is polled every `basic.auto_restart_check_interval`.

Both feed the same reload handle; the difference is only the delivery mechanism.
`--autoreload` swaps the configuration in place, which is what you want in
containers. `--autorestart` performs a zero-downtime graceful restart, which is
what listener-level changes need.

## Includes

`servers`, `locations` and `upstreams` accept an `includes` list naming entries
of `storages`, whose TOML content is merged into the section. This keeps shared
blocks — a set of timeouts, a common header list — defined once.

```toml
[storages.commonTimeouts]
category = "config"
value = """
connection_timeout = "5s"
read_timeout = "30s"
"""

[upstreams.api]
addrs = ["10.0.0.1:8080"]
includes = ["commonTimeouts"]
```

`to_pingap_config(replace_include)` controls whether includes are expanded; the
admin UI reads the unexpanded form so edits stay readable.

## Usage

```rust
use pingap_config::{new_config_manager, Validate};

let manager = new_config_manager("/opt/pingap/conf")?;
let config = manager.load_all().await?.to_pingap_config(true)?;
config.validate()?;
```

## License

Apache-2.0.
