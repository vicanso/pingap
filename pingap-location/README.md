# Pingap Location Module

This module provides an intelligent and flexible request routing system for reverse proxies and API gateways. It enables routing decisions based on request hostnames and URL paths, with support for powerful matching options, URL rewriting, and other essential proxying features.

## Features

- **Dynamic Host Matching**: Match requests based on the `Host` header using:
  - **Exact Match**: e.g., `example.com` (case-insensitive)
  - **Wildcard / suffix**: e.g., `*.example.com` (subdomains only, not the apex)
  - **Regex Match**: e.g., `~(?<subdomain>.+)\.example\.com`, with support for named captures.
- **Host-bucket routing index**: per-server weight-ordered locations are indexed by exact host, suffix, regex, and “any host” so matching skips unrelated hosts when hostnames are diverse (see `LocationHostIndex`).
- **Flexible Path Matching**: Match requests based on the URL path with different strategies:
  - **Exact Match**: e.g., `=/api/login`
  - **Prefix Match**: e.g., `/static`
  - **Regex Match**: e.g., `~/users/(?<id>\d+)`, with support for named captures.
- **URL Rewriting**: Dynamically modify the request path before proxying, including substituting variables from named captures.
  - `rewrite = "<regex> <replacement>"`; `$1` and `$name` in the replacement refer to the regex's groups. A `$name` that is a **request variable** - a named capture of the host pattern, or a variable a plugin set - is substituted with that variable first, so `host = "~(?<tenant>.+)\.example\.com"` with `rewrite = "^/users/(.*)$ /$tenant/$1"` sends `acme.example.com/users/me` to `/acme/me`. A lone replacement holding `$` (`"/$1"`) rewrites the whole path. The request's query string is kept: appended with `?`, or with `&` when the replacement has a query of its own (`rewrite = "^/old/(.*) /search?from=old&q=$1"` turns `/old/a?page=2` into `/search?from=old&q=a&page=2`). A rule whose regex does not compile, or that has more than two parts, is an error when the location is built rather than a silently ignored rule.
- **Request Throttling**: Limit the maximum number of concurrent requests a location will process.
- **Body Size Limiting**: Enforce a maximum size for the client request body to prevent abuse.
- **Header Modification**: Add or set custom HTTP headers before forwarding a request to an upstream service.
- **gRPC-Web Support**: Enable seamless proxying of gRPC-Web requests, translating them to standard gRPC.
- **Extensible Plugins**: Attach custom processing logic through a plugin system.

## Core Concepts

### `Location`

The `Location` is the central struct that encapsulates a complete set of routing rules. It is created from a `LocationConf` and contains all the logic to determine if an incoming request is a match and how it should be handled.

### `HostSelector`

How the request `Host` header is matched:

| Pattern | Meaning |
| --- | --- |
| `example.com` | Exact match (case-insensitive) |
| `*.example.com` | Any subdomain of `example.com` (not the apex itself) |
| `~regex` | Regex with optional named captures |

Example: `~(?<name>.+)\.npmtrend\.com` matches `charts.npmtrend.com` and captures `charts` as `name`.

A host with its root label written out names the same host: a request for `Host: example.com.` is matched as `example.com`, and a trailing dot in a configured pattern is dropped as well. Matched as it came, such a request missed the locations of the host and fell through to the catch-all, past the plugins that guard the host.

Exact and wildcard patterns are stored lowercased and compared to the request host in place, so a request with `Host: API.Example.COM` matches `api.example.com` without a lowercased copy being made per pattern. A regex pattern (host or path) that declares no named groups is tested with a plain match, which lets the regex engine skip tracking group positions; only a pattern with `(?<name>...)` groups pays for extracting them.

### `LocationHostIndex` / `ServerLocationRoute`

Built when server locations are (re)loaded. For each request host the index returns a **weight-ordered** candidate list (exact + matching suffixes + all regex-host locations + any-host locations). Full path/condition matching still runs only on those candidates, so the first hit is the same as a linear scan of the full weight-sorted list. The lookup costs one small `Vec` per request: the host is lowercased only when it contains upper-case letters, and the buckets are merged by sorting the handful of indices.

### `PathSelector`

This enum determines how to match the request's URL path. The matching strategy is determined by a special prefix in the configuration string:

- **`=` (Exact Match)**: The path must be an exact match. e.g., `=/api/v1/status`.
- **`~` (Regex Match)**: The path is matched against a regular expression. e.g., `~/api/users/(\d+)`.
  A rewrite rule runs its regex once per request: the leftmost match builds the new path and, when the pattern has named groups, those become request variables from the same match.
- **(Prefix Match)**: If no prefix is provided, the request path must start with the given string. e.g., `/api/`.

A request is matched by its **normalized** path: percent-encoding decoded (once), path parameters left out, a backslash taken for a slash, `.` and `..` segments resolved, repeated slashes merged. `/%61dmin/users`, `//admin/users` and `/public/../admin/users` all match a location for `/admin`, as the upstream that receives them would read them, so the plugins of that location cannot be sidestepped by spelling the path differently. A request no `rewrite` rule changes is forwarded exactly as it came.

`rewrite` holds for this form too, so a rule that adds or strips a prefix cannot be sidestepped by the spelling: with `path = "/users"` and `rewrite = "^/users/(.*)$ /acme/$1"`, `/%75sers/x` is sent on as `/acme/x` and `/users/a/../../users/y` as `/acme/y`, where they used to pass the rule unmatched, or leave the prefix again one segment later. The rule is applied to the path as it was sent whenever that is safe, and that is nearly always: `/users/group%2Fproject` goes on as `/acme/group%2Fproject`, a `;jsessionid=...` and a `//` inside the path stay. It is applied to the normalized path instead, with the bytes a URI cannot carry percent-encoded again, when the path as sent does not match the rule but the normalized one does, when it holds a `.` or `..` segment under any reading (`%2e%2e`, `..;x`, `a%2F..%2Fb`), or when the two would give different paths; only those requests lose what the normalization takes for syntax. A rule that produces something that is not a path fails the request with a `500` instead of forwarding the original.

Two of these are what only some backends read, and the request is matched
the way they read it:

- **Path parameters.** A servlet container (Tomcat, Jetty) drops the
  `;name=value` of a segment before it looks at the path, so
  `/public/..;/admin` is `/admin` to it, `/api;v=1/admin` is `/api/admin`, and
  `/login;jsessionid=A1` is `/login`. Everything from a `;` to the end of its
  segment is left out of the match.
- **Backslashes.** IIS takes `\` for `/`, so `/public\..\admin` is `/admin`.

A backend that does neither has nothing at such a path, so nothing is lost by
it. Up to 0.15.0 neither was covered, and in front of such a backend these
spellings reached a path past the location meant to guard it.

Exact and prefix paths in the configuration are kept in the same form, so `/%E6%96%87%E6%A1%A3` and `/文档` name the same location. A regex is taken as written and is applied to the normalized path: write `/a b`, not `/a%20b`, in a pattern, and a pattern cannot match a path parameter or a backslash, which are gone by then. A `;` in an exact or prefix path of the configuration cuts it there, like in a request.
- **(Any)**: An empty path string matches any request path.
