# pingap-logger

[![Crates.io](https://img.shields.io/crates/v/pingap-logger.svg)](https://crates.io/crates/pingap-logger)
[![Docs.rs](https://docs.rs/pingap-logger/badge.svg)](https://docs.rs/pingap-logger)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

A flexible and powerful logging library for the Pingap project, built on the `tracing` ecosystem.

## Overview

`pingap-logger` provides a robust logging solution with a focus on performance and flexibility. It offers various features, including customizable access logging, multiple log writers (file, syslog, stdout/stderr), automatic log rotation, and log compression.

## Features

- **Customizable Access Logs:** Easily create custom access log formats using a wide range of tags.
- **Multiple Log Writers:** Write logs to files, standard output/error, or syslog, local or a remote server over UDP/TCP.
- **Log Rotation:** Automatically rotate log files on a daily, hourly, or minutely basis.
- **Log Compression:** Compress rotated log files using `gzip` or `zstd` to save disk space.
- **Structured Logging:** JSON application logs, and a JSON access log format with escaped, typed values.
- **Performance-Oriented:** Designed for high-performance applications, with features like buffered writing.
- **`log` Crate Bridge:** Records emitted through the `log` crate are captured too, so nothing is silently dropped.

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
        log: "/tmp/pingap-test.log?rolling=daily".to_string(),
        level: "info".to_string(),
        capacity: 4096,
        json: true,
    };
    let _ = logger_try_init(params);
}
```

### Records From the `log` Crate

`logger_try_init` also installs a `tracing-log` bridge, so records emitted
through the `log` crate reach the same subscriber as `tracing` events. This
matters because Pingora logs through `log`: without the bridge nothing installs
a `log::Log` implementation and its diagnostics — including the bootstrap
failure that explains why a hot upgrade did not take over the listening
sockets — are discarded.

Two consequences worth knowing:

- `log::max_level` stays at `Trace`, leaving `EnvFilter` as the single
  filtering point. A level changed at runtime through the reload handle
  therefore applies to bridged records immediately.
- As far as `EnvFilter` directives are concerned, the target of a bridged
  record is `log`, not the emitting module. Use `log=debug` to raise the level
  for all of them; the rendered output still carries the original target
  (`pingora_core::server`, ...).

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
| `{status}`             | Response status code, the one the client was sent. When the response comes from the cache that is not the upstream's: a revalidation the upstream answers with `304` is logged as the `200` the client got (`upstream_status` has the other). |
| `{latency}`            | Request latency in milliseconds.                       |
| `{latency_human}`      | Request latency in human-readable format (e.g., 1.2s). |
| `{payload_size}`       | Payload size in bytes.                                 |
| `{payload_size_human}` | Payload size in human-readable format.                 |
| `{request_id}`         | Request ID.                                            |
| `{~<cookie_name>}`     | Value of a cookie.                                     |
| `{><header_name>}`     | Value of a request header.                             |
| `{<<header_name>}`     | Value of a response header.                            |
| `{:<context_key>}`     | Value from the context.                                |

A placeholder is `{`, a name made of letters, digits and `_ - < > ~ : $`, and
`}`; a `{` not followed by that is literal text. A missing value - an absent
header or cookie, no status yet - is rendered as `-`; a context field with no
value writes nothing. A placeholder that names no tag is dropped.

In a text format a value that comes from the request or a response header is
escaped: `"` becomes `\"`, `\` becomes `\\`, and a control character `\xXX`.
A format usually quotes such fields (`"{referer}" "{user_agent}"`), and a
user agent of `" 200 "-` would otherwise write fields of its own into the
line. Everything else, non-ASCII text included, is written as it came.

An `access_log` has to log something of the request: a format with at least
one placeholder, a preset, or a file followed by either. `access_log =
"stdout"` or a file path on its own is rejected by configuration validation -
it used to be taken for a format and printed that word once per request.

#### Context keys

`{:<context_key>}` prints a value pingap recorded while serving the request.
The same keys work in header values as `:<context_key>`, for example
`proxy_set_headers = ["X-Upstream: :upstream_addr"]`.

| Key | Value |
| --- | --- |
| `connection_id` | Id of the downstream connection |
| `connection_reused` | `true` when the downstream connection already served an earlier request |
| `connection_time` | Age of the downstream connection |
| `processing` | Requests the server was processing when this one arrived, itself included |
| `location` | Name of the matched location |
| `tls_version` | Downstream TLS version: `TLSv1.3` on an OpenSSL build, `TLSv1_3` on a rustls build |
| `tls_cipher` | Downstream TLS cipher |
| `tls_client_subject`, `tls_client_fingerprint`, `tls_client_serial`, `tls_client_verified` | The certificate the client showed on a server with [`tls_client_ca`](../pingap-proxy/README.md#client-certificates-mutual-tls): its subject, SHA-256 and serial number, and `true` / `false` for whether there is one |
| `tls_handshake_time` | Downstream TLS handshake, on the first request of a connection |
| `ja4` | The client's [JA4 fingerprint](../pingap-proxy/README.md#ja4-fingerprint), e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`; needs `ja4 = true` on the server |
| `ja4_r` | `JA4_r`: the sorted cipher and extension lists instead of their hashes |
| `ja4_o` | `JA4_o`: hashed over the lists in the order the client sent them |
| `ja4_ro` | `JA4_ro`: the lists in the order sent, unhashed; every other form can be computed from it |
| `upstream_addr` | Address of the upstream backend |
| `upstream_status` | Status the upstream answered with, `-` when there was none |
| `upstream_reused` | `true` when the upstream connection came from the keep-alive pool |
| `upstream_connected` | Open connections to the upstream; needs `enable_tracer` on it |
| `upstream_connect_time` | Getting an upstream connection, pooled or new |
| `upstream_tcp_connect_time` | TCP connect to the upstream |
| `upstream_tls_handshake_time` | TLS handshake with the upstream |
| `upstream_connect_offload_wait_time` | Wait for an offload thread before connecting; only with `basic.upstream_connect_offload_*` |
| `upstream_connection_time` | Age of the upstream connection |
| `upstream_processing_time` | From the upstream connection to the upstream's response header |
| `upstream_response_time` | From the upstream's response header to the end of its body |
| `compression_time` | Time spent compressing the response |
| `compression_ratio` | Input bytes over output bytes, one decimal |
| `cache_lookup_time` | Cache lookup |
| `cache_lock_time` | Waiting for a cache lock |
| `service_time` | From the start of the request to the log line |

Times are milliseconds. Every key ending in `_time` has a `_human` twin that
prints the same time readably, for example `{:upstream_response_time_human}`
gives `12ms` or `1.2s`. A key whose value was never recorded, such as a
cache time on an uncached request or `ja4` on a plain HTTP connection, prints
nothing.

#### Configuring a server

A server's `access_log` is a format, optionally preceded by a destination and
a space:

| Value | Meaning |
| --- | --- |
| `tiny` | A predefined format, written to the application log |
| `{client_ip} {status} {:ja4}` | A custom format, written to the application log; it starts with `{` |
| `/var/log/pingap/access.log {client_ip} {status}` | A file, then a predefined name or a custom format |
| `stdout json` | Standard output; `stderr` for standard error |
| `syslog://10.0.0.5?protocol=tcp combined` | A syslog server, one message per line |

Whatever the destination, the line is handed to a task that writes it; the
thread a request ends on does not write. That holds for an access log in the
application log as well: its lines used to be written where the request ended,
a lock shared by every thread and, with the log on stderr, a write for each
request. Lines for a file, a standard stream or syslog are dropped, and
counted, when the task falls behind by more than `channel_buffer`. Lines for
the application log are then written by the request itself instead of being
dropped: such a line carries the time it was written and may come before lines
of earlier requests that are still waiting. From the moment the process is
told to stop gracefully (SIGTERM, a restart), requests write their lines
themselves again and the task writes out what it still holds. A fast stop
(SIGINT) ends the task where it is: lines it had not written yet are lost, as
they are for the other destinations.

The predefined formats are:

```text
combined  {remote} "{method} {uri} {proto}" {status} {size_human} "{referer}" "{user_agent}"
common    {remote} "{method} {uri} {proto}" {status} {size_human}
short     {remote} {method} {uri} {proto} {status} {size_human} - {latency}ms
tiny      {method} {uri} {status} {size_human} - {latency}ms
json      {"when":{when},"remote":{remote},"client_ip":{client_ip},"host":{host},
          "method":{method},"uri":{uri},"proto":{proto},"status":{status},
          "size":{size},"latency":{latency},"referer":{referer},
          "user_agent":{user_agent},"request_id":{request_id}}
```

(`json` is a single line; it is wrapped here to fit.)

A destination is one of:

- **A file**, which takes the parameters of file logging described below,
  such as `rolling`:
  `/var/log/pingap/access.log?rolling=hourly {client_ip} {status}`.
- **`stdout` or `stderr`**, for containers that collect the standard streams.
  `/dev/stdout` and `/dev/stderr` mean the same; as file paths they would get
  a rotation suffix appended.
- **A `syslog://` URL**, local or remote, with the parameters in
  [Configuration](#configuration). Each line is one message, so a JSON format
  arrives as one object per message.

All of them also take `channel_buffer` (lines queued before new ones are
dropped, default 1000) and `flush_timeout` (default `10s`): lines are written
by a background task, and a file is flushed on that timer while standard
output and error are flushed after every batch, so they can be followed live.

A first word followed by a format is always read as the destination:
`ACCESS {status}` writes to a file called `ACCESS`. Start a custom format with
a tag to log to the application log instead.

### Which requests are logged

Every request gets a line unless the destination says otherwise, with
parameters that go where `rolling` and `channel_buffer` go:

```toml
[servers.web]
# no line for the probes, every error and every slow request, and one
# in ten of the rest
access_log = "/var/log/pingap/access.log?skip=^/health$&min_status=400&min_latency=500ms&sample=0.1 combined"
```

| Parameter | Effect |
| --- | --- |
| `skip` | A regular expression; a request whose path and query match (`/health`, `/api/users?page=2`) is not logged. The path is the one the client sent, before a location's `rewrite`. |
| `min_status` | A request answered with this status or a higher one is always logged: `min_status=400` for every error, `500` for the server's own. |
| `min_latency` | A request that took this long or longer is always logged: `min_latency=500ms`. |
| `sample` | The share, `0` to `1`, of the other requests that is logged, taken evenly: `sample=0.1` is every tenth. |

- `min_status` and `min_latency` say what is wanted for certain, and either is
  enough. With one of them set and no `sample`, nothing else is logged; with
  `sample` next to them, that share of the rest is logged as well.
- `sample` alone is a share of all requests.
- `skip` comes first: what it matches is not logged whatever its status.
- A request that is left out is left out before its line is formatted, so not
  logging it is cheaper than logging it.
- The value of a parameter is the value of a url parameter: `&`, `+`, `%`, `#`
  and a space in a regular expression are written `%26`, `%2B`, `%25`, `%23`
  and `%20` (the destination also ends at the first space).
- The conditions belong to a destination. An access log that names none
  (`access_log = "combined"`, which goes to the application log) has no place
  for them: write `stderr?min_status=400 combined`.
- A condition that does not parse (`sample=2`, `min_status=abc`, a `skip` that
  is no regular expression) is an error at startup and for `pingap -t`.

### Rotating with logrotate

A file access log is opened again when the process receives `SIGUSR1`: what is
buffered is written to the file as it is, and the next line goes to a new file
under the configured name. That is what `logrotate` needs with
`rolling=never`:

```text
/var/log/pingap/access.log {
    daily
    rotate 14
    compress
    delaycompress
    postrotate
        kill -USR1 "$(cat /run/pingap.pid)"
    endscript
}
```

- The file is the one the configuration named when the server started. A
  relative path is resolved against the directory the process started in,
  once, so a later change of directory does not move the log.
- A file that can not be opened again (its directory is no longer writable,
  for one) is an error in the application log, and the log goes on writing
  to the file it had: nothing is lost, and the next `SIGUSR1` tries again. A
  directory that is missing is made again.
- Only file access logs listen for the signal. The application log is not
  opened again by it, and a process without a file access log does not handle
  the signal at all: there it ends the process, which is what a signal nobody
  handles does.

What is not there yet: rotating by size, and a bound on the length of a field
or a line.

#### JSON format

A format that starts with `{"` is a JSON object, and every value is made safe
for it. A placeholder inside a string is escaped into that string; one that
stands alone becomes a JSON value of its own:

```toml
[servers.main]
addr = "0.0.0.0:80"
locations = ["api"]
access_log = 'stdout {"time":{when},"request":"{method} {uri}","status":{status},"latency":{latency},"ua":{user_agent},"upstream":{:upstream_addr},"ja4":{:ja4}}'
```

```json
{"time":"2026-10-02T10:04:05.006+08:00","request":"GET /api/items?page=2","status":200,"latency":12,"ua":"curl/8.7.1","upstream":"10.0.0.7:8080","ja4":null}
```

| Placeholder | Becomes |
| --- | --- |
| Inside quotes, `"{method} {uri}"` | The text, escaped: `"` and `\` are backslashed, control characters written as `\u00XX`, invalid UTF-8 replaced with U+FFFD. A missing value is empty. |
| Alone, a numeric tag: `{status}`, `{size}`, `{payload_size}`, `{latency}`, `{when_unix}`, and the context keys `connection_id`, `processing`, `upstream_connected`, `upstream_status`, `compression_ratio` and every `_time` key (milliseconds; the `_human` twins are strings) | A number |
| Alone, `{:upstream_reused}` or `{:connection_reused}` | `true` or `false` |
| Alone, any other tag | A quoted, escaped string |
| Alone, with no value | `null`, as is a number that is not one, such as the `-` of a missing upstream status |

The type of a field depends on the tag, never on the value, so a field keeps
one type from line to line: a location named `404` is still the string
`"404"`. A placeholder that names no tag is dropped as in any format, which
would leave the JSON without a value, so check the names.

A JSON format written to the application log is embedded in the application
log line (and escaped again when `log_format_json` is on); send it to its own
destination to get one object per line.

#### Logging the JA4 fingerprint

Enable `ja4` on a TLS server and add `{:ja4}` to its format:

```toml
[servers.main]
addr = "0.0.0.0:443"
global_certificates = true
ja4 = true
access_log = "/var/log/pingap/access.log {client_ip} {method} {uri} {status} {latency}ms {:tls_version} {:ja4}"
```

Each line then ends with the client's fingerprint:

```text
203.0.113.7 GET /api/items 200 12ms TLSv1.3 t13d1516h2_8daaf6152771_e5627efa2ab1
```

`{:ja4}` is the form to group and match on. Add `{:ja4_ro}` as well to keep
the raw values for later analysis, since the hashes cannot be reversed. A
connection without a fingerprint, plain HTTP or a ClientHello that could not
be read, leaves the field empty. The same value can be sent upstream with
`proxy_set_headers = ["X-JA4: $ja4"]`; see
[pingap-proxy](../pingap-proxy/README.md#ja4-fingerprint).

`format` writes straight into one pre-sized buffer: the timestamps are
rendered digit by digit rather than through an intermediate `String`, and the
per-line cost is the fields themselves.

## Configuration

The logger is configured via a URI-like string in the `log` field of `LoggerParams`.

- **File Logging:** `"/path/to/file.log?rolling=daily"`
  - `rolling`: `daily` (default), `hourly`, `minutely`, `never`; any other value is rejected. Rotation boundaries and the file name suffix (`file.log.YYYY-MM-DD[-HH[-MM]]`) use **UTC**, not the machine's local time zone: on a UTC+8 host a daily file switches at 08:00 local time and an entry written at 18:00 local lands in the `-10` hourly file. This comes from `tracing-appender`, which has no time zone option; the timestamps inside the log lines are local time.
  - An access log also takes `channel_buffer` (lines held for the writer, default 1000) and `flush_timeout` (default `10s`). The application log does not: there they are reported like any other unknown parameter.
  - `keep` (access log): how long the files the log rotated are kept, `keep=14d`. Older ones are removed when the server starts and then every hour, compressed (`.gz`, `.zst`) or not, by when they were last written. Only the files this log rotated itself, as for the compression; the file being written is never removed. Without it they are kept for good, as before. A log written to one file with `rolling=never` has no rotated files, see [Rotating with logrotate](#rotating-with-logrotate) for that. A `keep`, `rolling`, `flush_timeout` or `channel_buffer` that does not parse, or is zero, is an error at startup and for `pingap -t`; a file that can not be opened is an error at startup (`-t` opens no log).
  - These are all the parameters of the path. One that is not among them is reported with a warning when the log is opened and has no effect; this README used to list the settings of the compression here as if they were parameters.

  Rotated files are compressed by the task from `new_log_compress_service()`, which is set up with `LogCompressParams` and not through the path. In pingap that is `basic.log_compress_algorithm`, `basic.log_compress_level`, `basic.log_compress_days_ago` and `basic.log_compress_time_point_hour`:
  - algorithm: `gzip` or `zstd`.
  - level: compression level.
  - days ago: compress a rotated file once it has not been **modified** for this many days (default 7); the original is removed afterwards. The archive is the file's whole name with the extension added, `file.log.2026-10-05.zst` (or `.gz`). Only the files this log rotated itself are touched, the ones named `file.log.YYYY-MM-DD[-HH[-MM]]` in the log's own directory: other files there, subdirectories and a log with `rolling=never` are left alone.
  - time point hour: the hour of the day to run the compression job. The job runs on the blocking thread pool, so compressing a large file does not hold up the other background tasks.
  - `capacity` (`LoggerParams`, `basic.log_buffered_size` in pingap): with 4096 bytes or more the file is written through a buffer of that size. A buffered log is flushed by the task from `new_log_flush_service()` (once a minute in pingap) and by `flush_application_log()`, which pingap calls right before it exits; without those a quiet server's last lines would sit in the buffer, and the lines before an exit would be lost.

  Parameters that do not parse (`rolling=monthly`, `flush_timeout=soon` on the access log, an unknown syslog `facility`) are errors at startup rather than silently the defaults.

- **Syslog (Unix-only):** a `syslog://` URL. Each event or access log line is
  one message, at severity info.

  | URL | Server |
  | --- | --- |
  | `syslog://` or `syslog:///` | The local daemon, at `/dev/log`, `/var/run/syslog` or `/var/run/log` |
  | `syslog:///run/rsyslog/dev.sock` | The local daemon at that socket path |
  | `syslog://10.0.0.5` | A remote server over UDP, port 514 |
  | `syslog://logs.example.com:1514?protocol=tcp` | A remote server over TCP; IPv6 in brackets, `syslog://[fd00::5]` |

  - `format`: `3164` (default) or `5424`.
  - `process`: The process name to use in syslog messages (default `pingap`).
  - `facility`: The syslog facility, e.g. `LOG_LOCAL0` (default `LOG_USER`).
  - `protocol`: `udp` (default) or `tcp`, remote servers only.

  A remote host is resolved at startup, so a typo fails there. Over UDP each
  message is a datagram, sent without waiting for anything. Over TCP messages
  are framed by a newline (RFC 6587; a newline inside a message becomes a
  space). The connection is made on the first message, so a server that is
  down does not stop pingap from starting. Connecting and writing time out
  after one second; after a failure messages are dropped for five seconds
  before the next attempt, and each failure is reported on stderr.

  The local socket is connected at startup, so a path that is not there fails
  then. When the syslog daemon is restarted the socket is connected again on
  the next message, which is then sent; while there is no daemon, messages are
  dropped and a reconnect is tried every five seconds.

- **Standard I/O:** `stdout` or `stderr`; `""` (empty string) is stderr.

## Benchmarks

This library is designed for high performance. For detailed benchmark results, please see the `benches` directory in the source code.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the Apache-2.0 License.