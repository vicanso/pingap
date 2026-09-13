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
  - `rewrite = "<regex> <replacement>"`; `$1` and `$name` in the replacement refer to the regex's groups. A `$name` that is a **request variable** - a named capture of the host pattern, or a variable a plugin set - is substituted with that variable first, so `host = "~(?<tenant>.+)\.example\.com"` with `rewrite = "^/users/(.*)$ /$tenant/$1"` sends `acme.example.com/users/me` to `/acme/me`. A lone replacement holding `$` (`"/$1"`) rewrites the whole path. A rule whose regex does not compile, or that has more than two parts, is an error when the location is built rather than a silently ignored rule.
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

Exact and wildcard patterns are stored lowercased and compared to the request host in place, so a request with `Host: API.Example.COM` matches `api.example.com` without a lowercased copy being made per pattern.

### `LocationHostIndex` / `ServerLocationRoute`

Built when server locations are (re)loaded. For each request host the index returns a **weight-ordered** candidate list (exact + matching suffixes + all regex-host locations + any-host locations). Full path/condition matching still runs only on those candidates, so the first hit is the same as a linear scan of the full weight-sorted list. The lookup costs one small `Vec` per request: the host is lowercased only when it contains upper-case letters, and the buckets are merged by sorting the handful of indices.

### `PathSelector`

This enum determines how to match the request's URL path. The matching strategy is determined by a special prefix in the configuration string:

- **`=` (Exact Match)**: The path must be an exact match. e.g., `=/api/v1/status`.
- **`~` (Regex Match)**: The path is matched against a regular expression. e.g., `~/api/users/(\d+)`.
- **(Prefix Match)**: If no prefix is provided, the request path must start with the given string. e.g., `/api/`.
- **(Any)**: An empty path string matches any request path.
