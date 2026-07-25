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
| `authorizations` | string[] | `[]` | Base64 of `user:password`. **Empty disables authentication entirely.** |
| `max_age` | duration | `2d` | Allowed clock skew for the signed token. |
| `ip_fail_limit` | int | `10` | Failed attempts per IP before that IP is blocked for 5 minutes. |

## Via the command line

```bash
pingap -c /opt/pingap/conf --admin=pingap:123123@127.0.0.1:3018

# or, mounted under a prefix on an existing listener
pingap -c /opt/pingap/conf --admin=pingap:123123@0.0.0.0:80/pingap
```

Equivalent environment variables: `PINGAP_ADMIN_ADDR`, `PINGAP_ADMIN_USER`,
`PINGAP_ADMIN_PASSWORD`.

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

Static assets of the login page (`/`, `*.js`, `*.css`, `*.png`) are served
without authentication so the login screen can load. Anything under `/api` always
requires it, so an API route cannot be reached by dressing it up with a
static-looking suffix.

After `ip_fail_limit` failures an IP is refused with `403 Forbidden, too many
failures` for 5 minutes.

## API

All routes are relative to `<path>/api`.

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/configs/{category}` | Read configuration for a category |
| `POST` | `/configs/{category}/{name}` | Create or update one entry |
| `POST` | `/configs/import` | Import a whole configuration |
| `DELETE` | `/configs/{category}/{name}` | Delete one entry |
| `GET` | `/config-history/{category}/{name}` | Previous versions, when the storage backend supports history |
| `GET` | `/basic` | Process info, enabled features, supported plugins, upstream health |
| `GET` | `/certificates` | Parsed information about the loaded certificates |
| `POST` | `/aes` | AES encrypt/decrypt helper used by the UI for secrets |
| `POST` | `/restart` | Trigger a graceful restart |

`{category}` is one of `basic`, `server`, `location`, `upstream`, `plugin`,
`certificate`, `storage`.

```bash
TS=$(date +%s)
TOKEN=$(printf 'pingap:123123:%s' "$TS" | shasum -a 256 | cut -d' ' -f1)
curl -H "Authorization: $TOKEN:$TS" http://127.0.0.1:3018/api/basic
```

## Control-panel mode

`pingap --cp --admin=user:pass@127.0.0.1:3018` runs only the admin node: it
manages configuration in the shared backend (typically etcd) without proxying
traffic itself. Data-plane instances watch the same backend and hot reload.

## Usage notes

- **An empty `authorizations` disables authentication.** Never expose such an
  instance beyond localhost.
- The API can change certificates, upstreams and servers and can restart the
  process. Bind it to a private interface, or put
  [`ip_restriction`](ip_restriction.md) in front of the admin location.
- Configuration written through the API goes to whatever backend `-c` points at.
  With `file://` storage, a proxy started with `--upstream` (the config-file-less
  quick start) has no editable backing store and the UI cannot be used to change
  it.
- The token embeds a timestamp but not the request; it is a bearer credential.
  Serve the admin UI over TLS.
- `GET /api/config-history/{category}` without a `{name}` segment is not handled
  and will abort the request handler — always include the name.
