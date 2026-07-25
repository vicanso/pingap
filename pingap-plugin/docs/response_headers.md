# response_headers

Adds, sets, removes and renames response headers. Values support the same
dynamic substitutions as the rest of Pingap's header handling, so request
context can be surfaced to the client.

- **Step:** `response` (default) or `upstream_response` via `mode`
- **Registered as:** `response_headers`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `response_headers`. |
| `add_headers` | string[] | — | `Name: value` — appended, keeping existing values. |
| `set_headers` | string[] | — | `Name: value` — replaces any existing value. |
| `set_headers_not_exists` | string[] | — | `Name: value` — only set when the header is absent. |
| `remove_headers` | string[] | — | Header names to delete. |
| `rename_headers` | string[] | — | `Old-Name: New-Name` — moves the value. |
| `mode` | string | *(response)* | `upstream` to rewrite the upstream response header instead. |

Operations always run in this order, regardless of declaration order:

1. `add_headers`
2. `remove_headers`
3. `set_headers`
4. `set_headers_not_exists`
5. `rename_headers`

So a header added in step 1 and named in `remove_headers` is gone; a header
renamed in step 5 sees the result of everything before it.

## Dynamic values

| Variable | Expands to |
| --- | --- |
| `$hostname` | The proxy's hostname |
| `$remote_addr` | Client address |
| `$remote_port` | Client port |
| `$upstream_addr` | Selected upstream address |
| `$proxy_add_x_forwarded_for` | Existing `X-Forwarded-For` plus the client address |
| `$http_<name>` | Value of request header `<name>` |
| `$<NAME>` | Environment variable `NAME` |
| `:<key>` | A value from the request context |

## Examples

Security headers plus a bit of debugging:

```toml
[plugins.respHeaders]
category = "response_headers"
set_headers = [
    "X-Frame-Options: DENY",
    "X-Content-Type-Options: nosniff",
    "Referrer-Policy: strict-origin-when-cross-origin",
]
set_headers_not_exists = ["Cache-Control: no-cache"]
add_headers = ["X-Served-By: $hostname"]
remove_headers = ["Server", "X-Powered-By"]
rename_headers = ["X-Internal-Trace: X-Trace-Id"]
```

Rewrite the upstream response before Pingap's own cache and response handling see
it:

```toml
[plugins.fixUpstream]
category = "response_headers"
mode = "upstream"
remove_headers = ["Set-Cookie"]
set_headers = ["Cache-Control: public, max-age=3600"]
```

## `mode`

| `mode` | Hook | When to use |
| --- | --- | --- |
| unset | `response` | Normal case: the client-facing response |
| `upstream` | `upstream_response` | To influence caching or other response plugins that run later |

An instance handles exactly one of the two — it is not both.

## Usage notes

- `remove_headers` and `rename_headers` names must be valid HTTP header names or
  startup fails, which `pingap -t` will report.
- `rename_headers` appends to the destination, so renaming onto an existing
  header produces two values rather than overwriting.
- A dynamic value that cannot be resolved falls back to the literal configured
  string, so a typo like `$hostnam` is emitted verbatim.
