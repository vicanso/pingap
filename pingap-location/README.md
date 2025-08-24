# Pingap Location Module

This module provides an intelligent and flexible request routing system for reverse proxies and API gateways. It enables routing decisions based on request hostnames and URL paths, with support for powerful matching options, URL rewriting, and other essential proxying features.

## Features

- **Dynamic Host Matching**: Match requests based on the `Host` header using:
  - **Exact Match**: e.g., `example.com`
  - **Regex Match**: e.g., `~(?<subdomain>.+)\.example\.com`, with support for named captures.
- **Flexible Path Matching**: Match requests based on the URL path with different strategies:
  - **Exact Match**: e.g., `=/api/login`
  - **Prefix Match**: e.g., `/static`
  - **Regex Match**: e.g., `~/users/(?<id>\d+)`, with support for named captures.
- **URL Rewriting**: Dynamically modify the request path before proxying, including substituting variables from named captures.
- **Request Throttling**: Limit the maximum number of concurrent requests a location will process.
- **Body Size Limiting**: Enforce a maximum size for the client request body to prevent abuse.
- **Header Modification**: Add or set custom HTTP headers before forwarding a request to an upstream service.
- **gRPC-Web Support**: Enable seamless proxying of gRPC-Web requests, translating them to standard gRPC.
- **Extensible Plugins**: Attach custom processing logic through a plugin system.

## Core Concepts

### `Location`

The `Location` is the central struct that encapsulates a complete set of routing rules. It is created from a `LocationConf` and contains all the logic to determine if an incoming request is a match and how it should be handled.

### `HostSelector`

This enum determines how to match the request's `Host` header. It can be an exact string match or a regular expression. When using a regex, named capture groups (e.g., `(?<name>...)`) can be used to extract variables from the hostname for use in rewriting or other logic.

For example, a `HostSelector` with the pattern `~(?<name>.+).npmtrend.com` will match `charts.npmtrend.com` and capture `charts` into the `name` variable.

### `PathSelector`

This enum determines how to match the request's URL path. The matching strategy is determined by a special prefix in the configuration string:

- **`=` (Exact Match)**: The path must be an exact match. e.g., `=/api/v1/status`.
- **`~` (Regex Match)**: The path is matched against a regular expression. e.g., `~/api/users/(\d+)`.
- **(Prefix Match)**: If no prefix is provided, the request path must start with the given string. e.g., `/api/`.
- **(Any)**: An empty path string matches any request path.
