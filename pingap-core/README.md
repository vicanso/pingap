# Pingap Core

Pingap Core is the foundational library for the Pingap project, providing a robust set of core components and utilities for building high-performance, extensible proxy and networking applications in Rust.

## Overview

This library offers a modular toolkit designed to handle the entire lifecycle of HTTP requests and responses. It includes a powerful request context system, flexible plugin architecture, efficient HTTP header and response manipulation, background task management, and more. It is built on top of the `pingora` framework, extending its capabilities with specialized features.

## Core Features

- **Request Context (`Ctx`)**: A central struct that tracks the state of each request, including timing metrics, connection details, upstream information, caching status, and custom variables. It also provides utilities for generating detailed logs and `Server-Timing` headers.
- **Plugin System**: An extensible plugin architecture that allows developers to hook into various stages of the request/response lifecycle (`PluginStep`). This enables custom logic for authentication, rate-limiting, header modification, and more.
- **HTTP Helpers**: A rich set of utilities for working with HTTP headers and responses:
    - **Header Manipulation**: Parse, create, and modify HTTP headers, with support for dynamic value substitution (e.g., `$hostname`, `$remote_addr`, `$http_user_agent`).
    - **Response Builders**: Fluent builders (`HttpResponseBuilder`) for easily constructing complete HTTP responses, with helpers for common types like JSON, HTML, text, and redirects.
    - **Streaming Responses**: Support for chunked responses (`HttpChunkResponse`) to efficiently stream large bodies of data.
- **Background Task Service**: A generic service (`BackgroundTaskService`) for running periodic tasks in the background, such as health checks, data synchronization, or cleanup routines.
- **Rate Limiting**: An efficient, TTL-based LRU cache (`TtlLruLimit`) for implementing rate-limiting logic based on a maximum number of requests within a given time window.
- **Notification Service**: A simple, extensible trait (`Notification`) for sending alerts and notifications through various channels.
- **High-Performance Utilities**: Includes utilities like a coarse-grained time cache to reduce system calls and improve performance in hot code paths.

## Modules

- `ctx`: Provides the central `Ctx` struct for request lifecycle state management.
- `http_header`: Contains helpers for parsing and manipulating HTTP request headers.
- `http_response`: Provides builders and structs for creating HTTP responses.
- `plugin`: Defines the `Plugin` trait and `PluginStep` enum for building custom plugins.
- `service`: Includes the `BackgroundTaskService` for running background tasks.
- `ttl_lru_limit`: Implements a TTL-based LRU rate limiter.
- `notification`: Defines the trait for sending notifications.
- `util`: Contains miscellaneous utilities, including time caching and hostname retrieval.

## License

This project is licensed under the Apache-2.0 License.
