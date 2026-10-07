# admin

Serves the embedded web admin UI and the configuration REST API. Lives in the
`pingap` binary (`src/plugin/admin.rs`) because it needs the configuration
manager, the certificate/upstream providers and the restart machinery.

- **Step:** `request` (fixed)
- **Registered as:** `admin`

Most people never declare this plugin by hand — the `--admin` command line flag
builds an equivalent configuration. Declaring it explicitly is what you do when
the admin UI should live on an existing server behind a path prefix.

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `admin`. |
| `path` | string | `""` | URL prefix the admin UI is mounted at. A trailing `/` is stripped. |
| `authorizations` | string[] | `[]` | Base64 of `user:password`, both non-empty; anything else is rejected. **Empty disables authentication entirely.** |
| `max_age` | duration | `2d` | Allowed clock skew for the signed token. |
| `ip_fail_limit` | int | `10` | Failed attempts per IP before that IP is blocked for 5 minutes. |

## Via the command line

```bash
pingap -c /opt/pingap/conf --admin=pingap:123123@127.0.0.1:3018

# or, mounted under a prefix on an existing listener
pingap -c /opt/pingap/conf --admin=pingap:123123@0.0.0.0:80/pingap
```

Equivalent environment variables: `PINGAP_ADMIN_ADDR`, `PINGAP_ADMIN_USER`,
`PINGAP_ADMIN_PASSWORD`. Prefer them where other users of the machine can
see the process list: the command line of a process is public, its
environment is not. A graceful restart keeps it that way - what came from the
environment (these three, and `PINGAP_CONF`) is inherited by the replacement
process and not written out as arguments.

The credentials are `user:password`, or the base64 of `user:password` in place
of the user. A user without a password that is not such a base64 value
(`--admin=root@127.0.0.1:3018`) is an error and the process does not start.
Characters with a meaning in a URL are percent-encoded (`p%40ss` for `p@ss`),
and the password is what they decode to.

## As a plugin

```toml
[plugins.admin]
category = "admin"
path = "/pingap"
authorizations = ["cGluZ2FwOjEyMzEyMw=="]   # pingap:123123
max_age = "1h"
ip_fail_limit = 5

[locations.admin]
path = "/pingap"
plugins = ["admin"]
weight = 2000

[servers.main]
addr = "0.0.0.0:80"
locations = ["admin", "app"]
```

## Authentication

The API does not use HTTP Basic. Each request carries

```
Authorization: <token>:<unix-seconds>
token = hex(sha256("<user>:<password>:<unix-seconds>"))
```

`<unix-seconds>` must be within `max_age` of the proxy's clock, and the token is
compared in constant time. The web UI computes this for you after login.

There are two kinds of path under the admin prefix. `/api` and everything
below it is the API and always requires the token. Every other path is a file
of the embedded UI, served without authentication so the login screen can
load, and answered `404` when there is no such file. An API route is only
reachable under `/api`: `/configs/...` without the prefix is not routed to it.

After `ip_fail_limit` failed logins an IP is refused with `403 Forbidden, too
many failures` for 5 minutes. A failed login is a request to the API whose
`Authorization` does not check out; a request without one is answered `401`
and not counted, so a page that keeps polling after its token ran out does not
lock its user out. The lock stands in front of the API only: the files of the
UI still load, and on a server shared with an application the paths outside
the admin prefix are not affected.

## Without credentials

`--admin=127.0.0.1:3018`, with no user and password, is a common way to run the
admin on a machine of one's own. The API then answers whatever reaches it, and
a browser on that machine reaches it for every page its user has open. Two
kinds of request are refused with `403`, and a warning at startup says that the
admin has no credentials:

- **A write from another site.** A page elsewhere can send a `POST` it is not
  allowed to read the answer of (a form, or `fetch` in `no-cors` mode), which
  is all that storing a configuration or asking for a restart takes. A request
  other than `GET`/`HEAD` is refused when the browser marks it as coming from
  another origin: `Sec-Fetch-Site` is anything but `same-origin` or `none`, or,
  where the browser does not send that header (plain http to anything but
  localhost), its `Origin` is not the `Host` the request was sent to. A client
  that sends neither header, such as `curl`, is not a browser and is served.
- **A name that is not this machine's.** A page under a name that its owner
  then points at `127.0.0.1` (DNS rebinding) is, to the browser, the admin's
  own page, and could read the configuration with its private keys. On a
  connection that came in on a loopback address the `Host` has to be an IP
  address, `localhost`, or a name under `.localhost`; any other name is
  refused for the whole API. The files of the UI are still served.

Neither applies once credentials are set: the token every request needs is a
header a page of another site cannot add, and a secret a rebound page does not
have. That is also the way out when a credential-less admin on loopback really
is reached under a name (a reverse proxy on the same machine that passes the
`Host` on, an entry in `/etc/hosts`): set a user and a password.

What this does not cover is an admin without credentials on an address of the
network. It is reached by whatever name that network gives it, so the name
cannot be checked, and anyone who can connect can use it. That includes an
admin in a container whose port is published on the host's `127.0.0.1`: inside
the container the connection arrives on the container's own address, not on
loopback, so the name check does not apply there. Set credentials.

## API

All routes are relative to `<path>/api`.

A request body is read up to 8 MiB; a larger one is answered `413`.

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/configs/{category}` | Read configuration for a category |
| `POST` | `/configs/{category}/{name}` | Create or update one entry |
| `POST` | `/configs/import` | Import a whole configuration |
| `DELETE` | `/configs/{category}/{name}` | Delete one entry |
| `GET` | `/config-history/{category}/{name}` | Previous versions, when the storage backend supports history |
| `GET` | `/basic` | Process info, enabled features (includes the TLS backend name `openssl` / `rustls`), supported plugins, upstream health |
| `GET` | `/certificates` | Parsed information about the loaded certificates |
| `POST` | `/aes` | AES encrypt/decrypt helper used by the UI for secrets |
| `POST` | `/restart` | Trigger a graceful restart |

`/basic` describes the process: its `user`, `group` and `config_hash` are
those of the configuration it is running, not of what is stored, and the UI,
which asks for it every few seconds, reads nothing from the storage. A control
panel node runs no configuration: there `user` and `group` are read from the
storage on each request, and `config_hash` is that of an empty configuration.

`{category}` is one of `basic`, `server`, `location`, `upstream`, `plugin`,
`certificate`, `storage`. A `POST` to any other category is answered `400`
(`pingap`, the name the UI posts the basic config under, is accepted as
`basic`).

### What a write is checked against

A `POST` is refused with `400` when the configuration it would leave in the
storage is one that `pingap -t` rejects. That is more than the entry on its
own: the references between entries (a location's upstream and plugins, a
server's locations), and whatever only building an entry finds — a path or
host regex that does not compile, a plugin option of the wrong type, a private
key that is not the certificate's. `POST /configs/import` is checked the same
way and has to be a valid configuration as a whole; an import that is empty, or
has a top level section pingap does not know (`[upstream.x]` for
`[upstreams.x]`), is refused, since it would replace what is stored with
nothing.

The check builds upstreams, locations, plugins and certificates the way a
start does, but nothing of it reaches the running proxy: in particular a
`cache` plugin is checked without creating its directory or touching the cache
backends in use. It runs off the worker threads, since it may resolve host
names and read files.

Two things follow from "the configuration it would leave":

- An entry has to exist before another one refers to it: create the upstream,
  then the location that names it.
- When the stored configuration is already invalid (edited by hand, or written
  by an older version), changes are accepted as long as the entry itself
  parses, so it can be repaired through the admin one entry at a time. The
  full check applies again from the moment the configuration is valid.

A `DELETE` is refused while another stored entry refers to the one being
removed: an upstream named by a location or a `traffic_splitting` plugin, a
location listed by a server, a plugin listed by a location, a storage named in
an `includes`. The check reads the storage, not the configuration the process
is running, so it holds on a control-panel node and on a node started without
`--autoreload` as well.

```bash
TS=$(date +%s)
TOKEN=$(printf 'pingap:123123:%s' "$TS" | shasum -a 256 | cut -d' ' -f1)
curl -H "Authorization: $TOKEN:$TS" http://127.0.0.1:3018/api/basic
```

## Control-panel mode

`pingap --cp --admin=user:pass@127.0.0.1:3018` runs only the admin node: it
manages configuration in the shared backend (typically etcd) without proxying
traffic itself. Data-plane instances watch the same backend and hot reload.

A control-panel node checks a write against the references between entries and
the location patterns only. Upstreams, plugins and certificates are not built
there, and which plugin categories its own build has is not held against the
configuration: building reads files (`ca`, a certificate given as a path) that
belong to the machines the configuration is for. When the stored configuration
names files that are not on the control-panel node at all, it does not pass
there as a whole, and writes are then only checked entry by entry.

## Usage notes

- **An empty `authorizations` disables authentication.** Never expose such an
  instance beyond localhost; see [Without credentials](#without-credentials)
  for what is and is not refused there.
- The API can change certificates, upstreams and servers and can restart the
  process. Bind it to a private interface, or put
  [`ip_restriction`](ip_restriction.md) in front of the admin location.
- Configuration written through the API goes to whatever backend `-c` points at.
  With `file://` storage, a proxy started with `--upstream` (the config-file-less
  quick start) has no editable backing store and the UI cannot be used to change
  it.
- The token embeds a timestamp but not the request; it is a bearer credential.
  Serve the admin UI over TLS.
- `/configs/{category}/{name}` and `/config-history/{category}/{name}` both
  require the name segment; omitting it returns an error rather than a result.
