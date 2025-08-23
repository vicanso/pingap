# pingap-logger

[![Crates.io](https://img.shields.io/crates/v/pingap-logger.svg)](https://crates.io/crates/pingap-logger)
[![Docs.rs](https://docs.rs/pingap-logger/badge.svg)](https://docs.rs/pingap-logger)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

A flexible and powerful logging library for the Pingap project, built on the `tracing` ecosystem.

## Overview

`pingap-logger` provides a robust logging solution with a focus on performance and flexibility. It offers various features, including customizable access logging, multiple log writers (file, syslog, stdout/stderr), automatic log rotation, and log compression.

## Features

- **Customizable Access Logs:** Easily create custom access log formats using a wide range of tags.
- **Multiple Log Writers:** Write logs to files, syslog, or standard output/error.
- **Log Rotation:** Automatically rotate log files on a daily, hourly, or minutely basis.
- **Log Compression:** Compress rotated log files using `gzip` or `zstd` to save disk space.
- **Structured Logging:** Output logs in JSON format for easy parsing and analysis.
- **Performance-Oriented:** Designed for high-performance applications, with features like buffered writing.

## Installation

Add `pingap-logger` to your `Cargo.toml`:

```toml
[dependencies]
pingap-logger = "0.12.0"
```

## Usage

### Initializing the Logger

To initialize the logger, use the `logger_try_init` function with the desired `LoggerParams`.

```rust
use pingap_logger::{logger_try_init, LoggerParams};

fn main() {
    let params = LoggerParams {
        log: "/tmp/pingap-test.log?rolling=daily&compression=gzip".to_string(),
        level: "info".to_string(),
        capacity: 4096,
        json: true,
    };
    let _ = logger_try_init(params);
}
```

### Access Logging

The access logger can be configured with a format string. There are several predefined formats: `combined`, `common`, `short`, and `tiny`.

You can also create your own custom format.

```rust
use pingap_logger::Parser;
use pingora::proxy::Session;
use pingap_core::Ctx;

// Example of a custom format
let format = "{client_ip} - {method} {uri} {proto} {status} {latency_human}";
let parser = Parser::from(format);

// In your request handling logic
// let log_line = parser.format(&session, &ctx);
// println!("{}", log_line);
```

#### Available Tags

The following tags are available for access logging:

| Tag                    | Description                                            |
| ---------------------- | ------------------------------------------------------ |
| `{host}`               | Server hostname.                                       |
| `{method}`             | HTTP method (e.g., GET, POST).                         |
| `{path}`               | Request path.                                          |
| `{proto}`              | Protocol version (e.g., HTTP/1.1).                     |
| `{query}`              | Query parameters.                                      |
| `{remote}`             | Remote address.                                        |
| `{client_ip}`          | Client IP address.                                     |
| `{scheme}`             | URL scheme (http or https).                            |
| `{uri}`                | Request URI.                                           |
| `{referer}`            | Referer header.                                        |
| `{user_agent}`         | User-Agent header.                                     |
| `{when}`               | Request time in RFC3339 format.                        |
| `{when_utc_iso}`       | Request time in UTC ISO format.                        |
| `{when_unix}`          | Request time in Unix timestamp (milliseconds).         |
| `{size}`               | Response size in bytes.                                |
| `{size_human}`         | Response size in human-readable format (e.g., 1.2 KB). |
| `{status}`             | Response status code.                                  |
| `{latency}`            | Request latency in milliseconds.                       |
| `{latency_human}`      | Request latency in human-readable format (e.g., 1.2s). |
| `{payload_size}`       | Payload size in bytes.                                 |
| `{payload_size_human}` | Payload size in human-readable format.                 |
| `{request_id}`         | Request ID.                                            |
| `{~<cookie_name>}`     | Value of a cookie.                                     |
| `{><header_name>}`     | Value of a request header.                             |
| `{<<header_name>}`     | Value of a response header.                            |
| `{:<context_key>}`     | Value from the context.                                |

## Configuration

The logger is configured via a URI-like string in the `log` field of `LoggerParams`.

- **File Logging:** `"/path/to/file.log?rolling=daily&compression=gzip"`
  - `rolling`: `daily` (default), `hourly`, `minutely`, `never`.
  - `compression`: `gzip` or `zstd`.
  - `level`: Compression level.
  - `days_ago`: Number of days to keep compressed logs.
  - `time_point_hour`: The hour of the day to run the compression job.

- **Syslog (Unix-only):** `"syslog:///?format=3164"`
  - `format`: `3164` (default) or `5424`.
  - `process`: The process name to use in syslog messages.
  - `facility`: The syslog facility.

- **Standard I/O:** `""` (empty string) for stderr.

## Benchmarks

This library is designed for high performance. For detailed benchmark results, please see the `benches` directory in the source code.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the Apache-2.0 License.