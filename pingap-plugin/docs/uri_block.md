# uri_block

Turns requests away by what they ask for: a path or a query that matches one
of a list of patterns, or a method that is not among those allowed.

It is for the requests no part of a site answers and every scanner sends -
`/.env`, `/.git/config`, `/wp-login.php`, a query with `../` in it - and that
would otherwise reach the upstream, or need a location with a
[`mock`](mock.md) plugin for each path.

- **Step:** `request` (fixed)
- **Registered as:** `uri_block`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `uri_block`. |
| `presets` | string[] | — | Built-in security rule packs (`sensitive_files`, `scanners`, `path_traversal`, `sqli_xss`, `common`, `all`). Merged with custom `paths` and `queries` into a single pass. See [Built-in presets](#built-in-presets). |
| `paths` | string[] | — | Regular expressions. A request whose path matches one of them is blocked. |
| `queries` | string[] | — | Regular expressions. A request whose query matches one of them is blocked. |
| `methods` | string[] | — | The methods that are let through, in any case (`GET`, `post`). Empty allows every method. |
| `status` | int | `403` | Status of the refusal, `400` to `599`. |
| `message` | string | `Request is blocked` | Body of the refusal. |
| `dry_run` | bool | `false` | Let a request that would be refused go on, and log the refusal as a warning instead: a new rule can be watched on real traffic before it turns anyone away. See [Dry run](limit.md#dry-run). |

At least one of `presets`, `paths`, `queries` and `methods` is required. A pattern that
does not compile, an unknown preset name, a method that is not one, or a `status`
outside the range is a configuration error and reported by `pingap -t`.

## Built-in presets

Instead of copying long regex lists into every location, you can enable one or
more built-in security rule packs and combine them with `dry_run = true` before
switching to enforcement:

| Preset | Scope | What it blocks |
| --- | --- | --- |
| `sensitive_files` | `paths` | `.env` / `.env.*`, `.git` / `.svn` / `.hg`, `.htaccess` / `.htpasswd`, `.npmrc` / `.netrc` / `.DS_Store`, `.aws` / `.ssh`, SSH private keys (`id_rsa`, `id_ed25519`), `wp-config.php`, `web.config`, backup/dump extensions (`.bak`, `.orig`, `.save`, `.swp`, `.swo`, `.sql`, `.dump`). Does not block `/.well-known/*` (ACME HTTP-01 / OIDC). |
| `scanners` | `paths` | WordPress scanner probes (`wp-login.php`, `wp-admin`, `xmlrpc.php`, `wlwmanifest.xml`), phpMyAdmin / Adminer / `phpinfo.php`, `cgi-bin`, `vendor/phpunit`, router probes (`boaform/admin`, `HNAP1`). |
| `path_traversal` | `paths` + `queries` | `../` / `..\\` / `..;/`, percent-encoded `%2e%2e` and double-encoded `%252e%252e`, NUL bytes (`%00`), and `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, `windows/win.ini`. |
| `sqli_xss` | `queries` | High-signal SQLi/XSS query payloads: `UNION [ALL] SELECT`, `' or 1=1`, `sleep()` / `benchmark()` / `pg_sleep()` / `waitfor delay`, `information_schema` / `load_file(` / `into outfile`, `<script`, `javascript:`, `onerror=` / `onload=` / `onclick=`. |
| `common` | Bundle | Shorthand for `sensitive_files` + `scanners` + `path_traversal` (low false-positive baseline). |
| `all` | Bundle | Shorthand for `common` + `sqli_xss`. |

## What is matched

- **The path** is matched twice: as it was sent, and the way a location is
  chosen - percent-decoded once, with `.` and `..` resolved, `//` as one
  slash, `\` as `/` and the `;parameters` of a segment taken off. `\.env$`
  therefore blocks `/%2eenv`, `/public/../.env` and `//.env` like `/.env`,
  and `^/admin` blocks `/admin/..;/x` as well as `/public/../admin`: what
  one upstream reads as one path another reads as the other, and a request
  is blocked when either form matches. It is the path after the location's
  `rewrite`: with `rewrite = "^/app/(.*)$ /$1"`, `^/\.git/` blocks
  `/app/.git/config`.
- **The query** is matched as it was sent, and again as it reads once decoded
  (`%2e%2e%2f` as `../`, `+` as a space), so one pattern covers both.
- A pattern matches anywhere in the text unless it is anchored with `^` and
  `$`, and case matters unless it starts with `(?i)`. The syntax is that of
  the [`regex`](https://docs.rs/regex) crate.
- All the patterns of a list are looked at in one pass, so a long list costs
  little more than a short one.

## Examples

```toml
[plugins.blockScanners]
category = "uri_block"
presets = ["common"]
paths = ['^/internal/']
queries = ['\bexec\s*\(']
methods = ["GET", "HEAD", "POST"]
status = 404
message = "Not Found"
dry_run = true

[locations.app]
upstream = "app"
plugins = ["blockScanners"]
```

Single quotes keep TOML from reading the backslashes of a pattern.

## Responses

| Situation | Result |
| --- | --- |
| Method not in `methods` | `status` with `message` |
| Path matches one of `paths` | `status` with `message` |
| Query matches one of `queries` | `status` with `message` |
| Otherwise | `Continue` |

The refusal is `text/plain` and marked `no-store`. Which rule a request ran
into is logged at `debug`.

## Usage notes

- List it first among the plugins of a location: a request that is blocked
  then costs nothing of what follows, no cache lookup and no authentication
  subrequest.
- `404` with a plain `Not Found` gives a scanner less to go on than `403`,
  which says there is something there.
- It is a filter for the obvious, not a web application firewall: it reads
  the path, the query and the method, and nothing of the headers or the body.
- `methods` is a list of what is allowed. To refuse a single method on some
  paths, use a location for those paths.
