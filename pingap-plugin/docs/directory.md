# directory

Serves static files from a directory: MIME detection, ETags, `Cache-Control`,
HTTP range requests, chunked streaming for large files, forced downloads and an
optional HTML directory index.

- **Step:** `request` (default) or `proxy_upstream` — configurable
- **Registered as:** `directory`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `directory`. |
| `path` | string | — | **Required.** Root directory. `~` is expanded and the path is made absolute. |
| `index` | string | `index.html` | File served for `/`. A leading `/` is added if missing. |
| `autoindex` | bool | `false` | Generate an HTML listing for directories. |
| `chunk_size` | bytesize | `4kb` | Streaming chunk size; also the threshold above which streaming is used. Floored at 4 KB. |
| `max_age` | duration | — | `Cache-Control: max-age=…`. Not applied to `text/html`. |
| `private` | bool | `false` | Add `private` to `Cache-Control`. |
| `charset` | string | — | Appended to `Content-Type` for `text/*`. |
| `download` | bool | `false` | Add `Content-Disposition: attachment`. |
| `headers` | string[] | — | Extra response headers as `Name: value`. |
| `step` | string | `request` | `request` or `proxy_upstream`. |

## Examples

Serve a built SPA:

```toml
[plugins.web]
category = "directory"
path = "/var/www/app"
index = "index.html"
chunk_size = "64kb"
max_age = "1h"
charset = "utf-8"
headers = ["X-Content-Type-Options: nosniff"]

[locations.web]
path = "/"
plugins = ["web"]
```

A browsable download area:

```toml
[plugins.files]
category = "directory"
path = "~/Downloads"
autoindex = true
download = true
chunk_size = "1mb"
```

Range request:

```bash
curl -r 0-1023 -i http://127.0.0.1:6188/big.iso
# HTTP/1.1 206 Partial Content
# content-range: bytes 0-1023/734003200
# accept-ranges: bytes
```

## Behaviour

- Every response carries `Accept-Ranges: bytes` and a weak ETag derived from size
  and mtime (`W/"<size hex>-<mtime hex>"`).
- `text/html` responses are treated as non-cacheable, so `max_age` is not applied
  to them — the SPA shell stays fresh while hashed assets are cached.
- `bytes=start-end`, `bytes=start-` and `bytes=-suffix` are supported; only the
  first range of a multi-range request is honoured. An unsatisfiable range gets
  `416` with `Content-Range: bytes */<size>`.
- Files at or below `chunk_size` are read into memory and sent in one response;
  larger ones are streamed.
- `autoindex` listings skip dotfiles.

## Responses

| Situation | Status |
| --- | --- |
| File found | `200`, or `206` for a range request |
| Path escapes `path` after normalisation | `403` |
| File missing | `404 Not Found` |
| Other IO error | `500 File access error` |
| Bad range | `416 Range Not Satisfiable` |

## Usage notes

- `index` is only substituted for the root path `/`, and only when `autoindex`
  is off. A request for a subdirectory such as `/docs/` returns `404` unless
  `autoindex` is enabled.
- Traversal protection is lexical: the joined path is normalised and must still
  start with `path`. A **symlink inside the served directory that points
  outside** is not caught by that check, so do not serve a tree containing
  untrusted symlinks.
- `autoindex` reveals file names, sizes and timestamps. Combine with
  [`basic_auth`](basic_auth.md) or [`ip_restriction`](ip_restriction.md) for
  anything non-public.
- Set `chunk_size` well above 4 KB when serving large media; it directly controls
  the syscall rate while streaming.
