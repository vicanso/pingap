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
all validators and exits — run it in CI and before a reload. On top of the
validators it builds every upstream, location and plugin the way startup does,
so an unknown `alpn`, a `ca` that does not load, a path or host regex that does
not compile, a malformed `rewrite` rule or an invalid plugin setting - a value
of the wrong type included - is reported there and not on the next start. A
certificate is loaded with its key, so a key that belongs to another
certificate is reported as well. The
validators also check what entries name of each other: a location's upstream
and plugins, a server's locations, and the upstream of a `traffic_splitting`
plugin. An `access_log` that is neither a format with a placeholder, a preset,
nor a file followed by one of the two is rejected. It only
reads: the configuration is left exactly as it is on disk.

A key or a section pingap does not know is left out when the document is read.
It is not an error, but it is reported: `--test`, a start and every reload of
a changed document log one warning per finding, with the name it was probably
meant to be.

```
config: unknown section [server], did you mean [servers]?
config: basic: unknown key "trusted_proxy", did you mean "trusted_proxies"?
config: location(api): unknown key "client_max_body_sizes", did you mean "client_max_body_size"?
```

The keys of an entry are checked with its `includes` put in, so a typo inside
a storage fragment is reported for the entry that includes it. Plugin settings
are not checked this way: which keys a plugin takes is for the plugin to say.

With `--strict` (or `PINGAP_STRICT` set to anything but empty) each of these findings is an error
instead: `pingap -t --strict` exits non-zero and names every one of them, a
start fails, a reload leaves the running configuration as it is and reports
the failure like any other, and the admin API refuses a change that brings an
unknown key in. A restart passes the flag on to the process that takes over.
Use it for `-t` in CI, where a misspelt key should stop the pipeline rather
than be read past.

## Storage backends

The backend is chosen from the value of `-c` / `PINGAP_CONF`:

| Value | Backend | Layout | Hot reload |
| --- | --- | --- | --- |
| `/opt/pingap/pingap.toml` | Single file | `Single` | Polled |
| `/opt/pingap/conf` (a directory) | Files per category | `MultiByType` | Polled |
| `/opt/pingap/conf?separation=true` | One file per item | `MultiByItem` | Polled |
| `etcd://127.0.0.1:2379/pingap` | etcd | `MultiByItem` | Pushed via a watch stream |
| *(in-process)* | `MemoryStorage` | `Single` | None |

A path that does not exist yet is classified by its extension: `.toml`, `.hcl`
and `.kdl` mean a single config file, anything else means a directory to be
created. Pingap has to commit to one or the other before the path exists — a
directory it guessed was a file would silently ignore `separation` and write
`pingap.toml` inside itself, leaving every later run reading a layout it would
never have written.

```bash
pingap -c /opt/pingap/conf --autoreload
pingap -c "etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s" --autoreload
pingap -c "/opt/pingap/conf?separation=true&enable_history=true"
```

An etcd URL is `etcd://host:2379[,host2:2379]/prefix[?params]`; the prefix
defaults to `/` when omitted, and a URL without a host is rejected. Parameters
are `timeout` (default `10s`), `connect_timeout` (default `5s`), `user`,
`password` and `enable_history`. The storage opens one client and reuses it
for every request; a request that fails is retried once on a fresh connection.

- A request and a connection attempt are bounded also when the URL gives no
  timeouts, and the connection of the watch is checked with an HTTP/2 ping
  every 30 seconds. Without either, a connection that had gone quiet held the
  poll waiting on it for good, and every save behind it.
- The keys of a prefix are read a page at a time (64 keys, fewer when their
  values are large; what it came down to is kept for the next read), all pages
  as of the same revision, so a configuration is not limited to what fits
  into one gRPC message (4 MiB).
- With `enable_history=true` the hundred newest versions of each key are kept
  under `<prefix>-history`; older ones are removed as new ones are written.
  A deleted key leaves no version behind.
- TLS to etcd is not supported.

A directory is loaded by reading every `*.toml` file in it (or, when there is
none, every `*.hcl`, then every `*.kdl`). Each file is parsed on its own and
its tables are merged into one document, so a syntax error names the file it
is in, and a file may use any TOML spelling (`upstreams.extra.addrs = [..]`
at the top level works like `[upstreams.extra]`). A category can be spread
over files, but an entry — and `[basic]` — is defined in one of them: the same
name in two files is an error that names both.

Each file is read once. In a directory mounted from a Kubernetes ConfigMap or
Secret every file is reachable three ways (the link at the top, `..data`, and
the timestamped directory behind it); whatever lies under a name starting with
`..` is left out, and two paths to the same file count once.

A file is written by putting the new content in a temporary file beside it and
renaming that over it, so a reader - the change check among them - finds the
old content or the new and never half a file. The mode and the owner of the
file are kept, and a symlink is followed to the file it points at. Where the
name cannot be taken over (a single config file mounted into a container) or
the owner cannot be kept, the file is written in place.

A file that is new is no more open than the directory it is created in, less
the right to execute: in a config directory that only its owner can enter
(`0700`), a new entry file is `0600`, and the directory of a category created
for it is `0700`. That is a ceiling, asked for when the file is created, so
the umask of the process still narrows it. The file is given to the owner of
the directory where the process may do that (it was started as root and the
directory belongs to the user it runs as). The history directory is created
like the config directory, and a copy kept there is no more open than the
file it copies. The temporary file a save goes through is private from the
moment it exists.

Importing a configuration (`POST /api/configs/import`, `--sync`) replaces what is
stored: an entry the imported configuration does not have is removed, in every
layout.

Sizes are written back exactly: `10MB` is saved as `10 MB`, in the largest unit
that divides it.

Query parameters for the file backend (directories only):

| Parameter | Meaning |
| --- | --- |
| `separation=true` | Write each item to its own file. Anything other than the literal `false` counts as true. |
| `enable_history=true` | Keep previous versions next to the config (`<dir>-history`) so the admin UI can restore them. Requires `separation`. |

### Layout normalization

Each layout writes different file names, and a config directory is loaded by
concatenating **every** toml file in it. Reads therefore accept any layout —
including a single hand-written file holding all sections — but every write
(`get`/`update`/`delete`, the admin panel, the ACME certificate save) only
addresses the canonical names. A non-canonical file is configuration the write
path cannot see: a lookup misses it (an ACME-issued certificate would be
silently lost, re-issued every cycle until the CA's rate limit — issue #213),
and a category write puts a second copy of its tables next to it, after which
the directory stops parsing with a `duplicate key` pointing at a line number no
individual file has.

`ConfigManager::migrate_layout` handles this. It runs once at startup, before
the first read, and rewrites the configuration in canonical form, then retires
every file the current layout would not have written itself — another layout's
leftovers (`pingap.toml` from a run before the directory existed,
`certificates.toml` in a separated directory) as well as combined or
arbitrarily named files:

- with `enable_history=true` the retired file is copied into the history
  directory and removed;
- otherwise it is renamed to `<name>.toml.bak`, which the loader ignores since
  it only globs `*.toml`.

Commands that only read the configuration — `--test`, `--to-hcl`, `--to-kdl`,
`--sync` and `--diff` — skip the migration and load whatever layout is there. They fail
when the configuration does not load, also with an admin address set
(`--admin` or `PINGAP_ADMIN_ADDR`): starting on an empty configuration so that
it can be repaired through the admin is for a server that is going to run, not
for a check or a copy.

Either way the retired path is printed at startup. A directory that is already
carrying two layouts cannot be migrated — which table should win is not
knowable — so startup reports the conflicting file names and leaves everything
in place for a manual merge.

The migration deliberately happens before anything writes: the admin panel
edits one entry at a time through `ConfigManager::update`, which holds only
that entry and so cannot clean up a file containing all the others. That single
write is what turns a directory carrying one old layout into a broken one.

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
`.kdl`. HCL and KDL are converted to TOML in memory, so everything downstream
sees TOML.

What a change made through pingap (the admin, a certificate renewed by ACME)
is written as depends on where the configuration is kept:

| Kept in | A change is written as |
| --- | --- |
| TOML, a single file or a directory | TOML |
| A single `.hcl` or `.kdl` file | That format again. The whole file is rewritten in pingap's own layout, so comments and nesting written by hand are not kept. What is about to be written is read back first, and a configuration that would not come back the same is refused and nothing is saved. |
| A directory of `.hcl` or `.kdl` files | Nothing: such a directory is read-only, and a change is refused with an error. Its files are laid out as their author saw fit, so there is no file one entry belongs in. Edit the files, or keep the configuration in TOML to manage it through pingap. ACME cannot work on such a directory either: it has nowhere to store its account, tokens and certificates. |

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

A block is written where it is first used: a location inside the first server
that lists it, an upstream inside the first location that names it. A location
shared by several servers — the same routes on port 80 and on 443 — is
therefore written once, and the other servers refer to it by name:

```hcl
server "http" {
  addr = "0.0.0.0:80"

  location "site" {
    upstream = "web"
  }
}

server "https" {
  addr      = "0.0.0.0:443"
  locations = ["site"]
}
```

In KDL a node with one value is that value and a node with several is a list.
The fields that are always lists (`addrs`, `locations`, `plugins`, `includes`,
`modules`, `proxy_set_headers`, `proxy_add_headers`, `match_headers`,
`match_query`, `match_cookies`, `trusted_proxies`, `webhook_notifications`)
are lists with one value too. For any other field, a plugin's for example, a
list of one is written with `item` children, which is also what `--to-kdl`
produces:

```text
plugin "blockList" {
    category "ip_restriction"
    type "deny"
    ip_list {
        item "1.2.3.4"
    }
}
```

A plugin setting that takes a list of strings also accepts a single string in
its place, so `ip_list "1.2.3.4"` works as well.

## Values from the environment and from files

A container gets its credentials through the environment or as mounted files.
A value of the configuration can name one of those instead of holding the
credential itself:

```toml
[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
secret = "$ENV:JWT_SECRET"

[plugins.apiKeys]
category = "key_auth"
header = "X-Api-Key"
keys = ["$FILE:/run/secrets/key_a", "$FILE:/run/secrets/key_b"]

[upstreams.api]
addrs = ["$ENV:API_ADDR"]

[basic]
webhook = "$ENV:PINGAP_WEBHOOK"
```

- `$ENV:NAME` is the value of the environment variable `NAME` (letters,
  digits and `_`).
- `$FILE:/path` is the content of that file, without the line ends at its
  end. The path is absolute (`~/` is the home directory), the file a regular
  one of at most 1 MB of UTF-8 text.

A variable that is set to nothing counts as one that is not set, and a file
with nothing in it as one that is not there: that is what an environment gets
from `NAME: ${NAME}` when the host has no such variable, and an empty
credential is one that some checks accept.

The rules are the same in TOML, HCL and KDL, and for a configuration in etcd:

- A reference is the **whole** of a string value, wherever that string is: a
  field of an entry, an item of a list, a setting of a plugin, a value that
  an entry takes from a storage it `includes`. `"Bearer $ENV:TOKEN"` is not
  one and stays the text it is. (Two places read more on their own: any query
  parameter of a certificate's `dns_service_url`, see
  [pingap-acme](../pingap-acme/README.md), and a header value that names a
  variable as `$NAME`, see `proxy_set_headers`.)
- It stands for text. A field of `basic`, a server, a location, an upstream
  or a certificate that is a duration, a size, a number or a boolean does not
  take one: that is a configuration error. A setting of a plugin that is
  written as text does, a duration included. The names of entries and keys
  are not looked at.
- A reference that names nothing - the variable is not set, the file can not
  be read - is a configuration error that says which entry and which key:
  `plugin(jwtAuth): secret: environment variable JWT_SECRET is not set`. A
  start fails on it, `pingap -t` reports it, a reload keeps the running
  configuration. It is never taken as the text it is, which would make
  `$ENV:JWT_SECRET` the secret.
- What a reference gives is the value. It is not looked at for further
  references.

References are replaced in the configuration a process runs with, and nowhere
else:

- The admin shows and saves the reference as it is written, and so do
  `--to-hcl`, `--to-kdl` and `--sync`. A change saved through the admin is
  checked with the references replaced, so a variable that is missing on that
  machine is reported before the change is stored. A control panel node
  (`--cp`) stores a configuration other machines run: there a reference it can
  not look up is left alone, and the entry it is in is not checked for the
  form of its values (an address written as a reference is no address). The
  same holds for the commands that only print, compare or copy.
- What a reference stood for is kept out of the difference a reload writes to
  the log and sends to the webhook, whatever its key is called: it is shown
  as a checksum, like the values of the keys that are known to be credentials,
  so a change still shows as a change.
- With `--autoreload` or `--autorestart` the files that are referred to are
  read each time the process looks whether its configuration has changed
  (every ten seconds, or `basic.auto_restart_check_interval` when that is
  shorter): a secret that is rotated in place is taken like a change of the
  configuration would be, without a restart where that kind of entry reloads
  hot. Replace such a file by renaming a new one over it, as a mounted secret
  is replaced: one that is written in place can be read half written. A file
  that has gone is reported like any reload that fails, and the running
  configuration stays. The environment of a process does not change while it
  runs, and a restart pingap performs itself (`--autorestart`, the admin)
  hands its own environment to the replacement: a new value of a variable is
  there once the process is started anew.

Whoever can change the configuration can have the process read a file or a
variable this way. That is not new - a `directory` plugin serves any path it
is given - but it is a reason to keep the admin and the storage behind the
same care as the secrets.

Conversion and migration on the command line:

```bash
pingap -c /opt/pingap/conf --to-hcl > conf.hcl        # dump as HCL
pingap -c /opt/pingap/conf --to-kdl > conf.kdl        # dump as KDL
pingap -c /opt/pingap/conf --sync etcd://127.0.0.1:2379/pingap   # file -> etcd
pingap --template > pingap.toml                       # starter config
pingap -c /opt/pingap/conf -t                         # validate and exit
pingap -c /opt/pingap/conf --diff /tmp/new-conf       # what would change
```

### Checking a configuration: `-t`

`-t` goes as far as a start does without serving: the document is read, its
includes and `$ENV:` / `$FILE:` references are replaced, every entry is
validated, and then every upstream, location, plugin, certificate and server
is built the way startup builds it. A server is built up to where its
listeners would open their sockets, which is where its TLS settings are made:
a `tls_min_version` that is no version or a cipher list the TLS library does
not take used to pass `-t` and fail the start. Nothing is bound, so the check
can run next to a process that is serving on the same addresses, and no access
log is opened. The admin runs the same checks on the configuration a change
would leave in the storage, before it stores it.

### Previewing a change: `--diff`

`pingap -c <running> --diff <candidate>` prints what would change if the
configuration at `<candidate>` (a file, a directory or an etcd address)
replaced the one of `-c`, and exits:

```text
++ [ADDED] upstream:u2

[MODIFIED] plugin:auth
- keys = ["crc32:983E2A19"]
+ keys = ["crc32:CD38375F"]

[MODIFIED] upstream:api
- addrs = ["127.0.0.1:5001"]
+ addrs = ["127.0.0.1:5002"]
```

It is the difference a reload writes to the log and sends to the webhook,
before anything is applied: `-` is what `-c` has, `+` what the candidate has,
each with its includes and references replaced. Credentials are shown as
checksums - the keys that are known to hold one, and everything a `$ENV:` or
`$FILE:` reference stood for - so a changed secret shows as a change and
nothing else. `no difference` is printed when there is none. Neither side is
written to, and neither is validated: run `-t` on the candidate for that. A
reference that names nothing on the machine the command runs on is compared as
the text it is written as. The exit status is `0` whether or not there is a
difference, and not `0` when one of the two does not load, or the candidate
does not exist or has no configuration in it (an etcd prefix with a slip in
it).

## Hot reload

`ConfigManager::support_observer()` decides how changes arrive:

- **etcd** returns `true` and pushes changes through an `etcd_client::WatchStream`.
  The watch runs on a connection of its own. When it breaks or the server ends
  it, it is started again, with a delay that grows from 500ms to a minute while
  etcd stays unreachable, and the configuration is compared once more as soon
  as it is back. The stored configuration is also re-read every
  `basic.auto_restart_check_interval`, watch or no watch. The watch is on the
  keys below the prefix and nothing else: `/pingap` no longer wakes for
  `/pingap2` or for its own `/pingap-history`.
- **File** returns `false` and is polled every `basic.auto_restart_check_interval`.

Both feed the same reload handle; the difference is only the delivery mechanism.
A poll fetches the raw document (`ConfigManager::load_all_raw`) and hashes it;
parsing, validation (which resolves every static upstream address) and the diff
only run when the document changed since the last pass, or when the last pass
was hot-reload-only and this one may restart.
A replacement process that cannot load its configuration, or whose plugins do
not build, exits and leaves the running one in place, `--admin` or not.

A hot reload is all or nothing for what has to be built. When upstreams,
locations or plugins changed, every one of them is built first as `pingap -t`
would (off the worker threads, without touching what is running), and a
failure there - a regex that does not compile, a plugin option of the wrong
type, an address that does not resolve - leaves the running configuration as
it is. It is reported once, in the log and as a `reload_config_fail`
notification, and the same document is tried again once a minute, in case what
stood in the way has passed (a name that did not resolve). Categories
used to be replaced one after the other, and a failure in one left the others
applied: locations routing to an upstream that was not there. Should a category
still fail while it is being replaced, it stays what it was in the running
configuration (and in what the admin reports), the routes of the servers are
not rebuilt from locations that could not be, and the next change to the
document tries it again. An upstream that a change removes is kept until the
locations that routed to it have been replaced.
A change that only touches `storages` never restarts the process: an entry
there has no effect of its own, and what another entry includes from it shows
up as a change of that entry.
A certificate given as a file path is watched on the same schedule: when the
document is unchanged, the files of such certificates are hashed, and one
whose file was replaced - by a renewal with certbot, say - is loaded again.
This needs `--autoreload` or `--autorestart` like any other reload. It also
works next to certificates managed by ACME: only the certificates that come
from files are touched.
What a reload changed is logged, and sent to the webhook, as the difference
between the two configurations. Credentials in it are replaced by a checksum
(`secret = "crc32:8D9A1B2C"`), so that a change still shows as one: values
under keys such as `secret`, `password`, `token`, `key`, `keys` and
`authorizations`, the user and password of any url, the query or path of the
urls that carry keys (`webhook`, `sentry`, `*_url`), the value of headers like
`Authorization`, and what a storage holds. The same goes for the settings a
plugin logs at debug level.
`--autoreload` swaps the configuration in place, which is what you want in
containers. A change to a location takes effect in routing as well: the hosts
and paths a server routes by are rebuilt whenever its locations change. `--autorestart` performs a zero-downtime graceful restart, which is
what listener-level changes need. That restart hands over on readiness: the
replacement reports over `<upgrade_sock>.ready` the moment it is ready to take
the listening sockets, and only then does the old process signal itself to
quit; `basic.restart_ready_timeout` (default 1m) bounds the wait, after which
the restart is abandoned. `basic.working_directory` sets where the daemon
`chdir`s.

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
`to_running_config(missing)` gives the configuration a process runs with:
includes expanded and every `$ENV:` / `$FILE:` reference replaced (see
[Values from the environment and from files](#values-from-the-environment-and-from-files)). `--to-hcl`,
`--to-kdl` and `--sync` write the unexpanded form too: the entry keeps its
`includes` and the fragment stays the one place its keys are defined. A fragment's keys
override the entry's own, and a later include overrides an earlier one. An
include that names no `storages` entry, or a storage whose value is not TOML,
is rejected when the configuration is loaded
(`upstream(api): include(commonTimeouts) is not found`) instead of being
silently dropped.

## Usage

```rust
use pingap_config::{new_config_manager, Validate};

let manager = new_config_manager("/opt/pingap/conf")?;
let config = manager.load_all().await?.to_pingap_config(true)?;
config.validate()?;
```

## License

Apache-2.0.
