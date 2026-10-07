# directory

Serves static files from a directory: MIME detection, ETags and
`Last-Modified`, `Cache-Control`, HTTP range requests, chunked streaming for
large files, files kept precompressed, a fallback page for single page
applications, forced downloads and an optional HTML directory index.

- **Step:** `request` (default) or `proxy_upstream` — configurable
- **Registered as:** `directory`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `directory`. |
| `path` | string | — | **Required**; a plugin without it is a configuration error. Root directory. `~` is expanded and the path is made absolute. |
| `index` | string | `index.html` | File served for a directory, `/` or any deeper one. A leading `/` is added if missing. |
| `autoindex` | bool | `false` | Generate an HTML listing for directories. |
| `chunk_size` | bytesize | `4kb` | Streaming chunk size; also the threshold above which streaming is used. A size string or a byte count; floored at 4 KB. A value that does not parse is a configuration error. |
| `max_age` | duration | — | `Cache-Control: max-age=…`. Not applied to `text/html`. A duration that does not parse is a configuration error. |
| `private` | bool | `false` | Add `private` to `Cache-Control`. |
| `charset` | string | — | Appended to `Content-Type` for `text/*`. |
| `download` | bool | `false` | Add `Content-Disposition: attachment`. |
| `follow_symlinks` | bool | `true` | When `false`, a file must still be under `path` once symlinks are resolved. The `index` file of a directory is checked the same way. |
| `fallback` | string | — | A file of the directory, named from its root (`/index.html`), sent with `200` for a path that does not exist. Only for a path whose last segment has no extension. See [Single page applications](#single-page-applications). |
| `precompressed` | string[] | — | Codings a file may be kept in next to itself, in order of preference: `br` (`app.js.br`), `gzip` (`app.js.gz`), `zstd` (`app.js.zst`). See [Precompressed files](#precompressed-files). |
| `hidden` | bool | `false` | Serve what begins with a dot. When `false`, a path with such a segment (`/.env`, `/.git/config`) is answered `404`; `.well-known` is served either way. |
| `headers` | string[] | — | Extra response headers as `Name: value`. |
| `step` | string | `request` | `request` or `proxy_upstream`. |

## Examples

Serve a built SPA:

```toml
[plugins.web]
category = "directory"
path = "/var/www/app"
index = "index.html"
fallback = "/index.html"
precompressed = ["br", "gzip"]
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

## Single page applications

A page with routes of its own (`/users/1`) is one file on disk, and a reload
or a link straight to such a route asks the server for a path that is not
there. `fallback = "/index.html"` answers it with that file and a `200`.

Only a path whose last segment has no extension is answered this way:
`/users/1` and `/v1.2/users/` are routes, while `/assets/main.js` or
`/logo.png` that do not exist are files that are missing and stay `404` -
answered with the page they would be parsed as script or shown as a broken
image. A path that ends in a slash is a route whatever its last segment looks
like (`/v1.2/`), and a directory that exists and has no `index` file is
answered with the fallback as well. The file has to be inside `path`; one that
is not there leaves the `404`.

## Precompressed files

With `precompressed = ["br", "gzip"]`, a request for `app.js` from a client
whose `Accept-Encoding` takes `br` is answered with `app.js.br` as it is, when
that file exists: `Content-Encoding: br`, the `Content-Type` of `app.js`, the
`Content-Length` of the coded file. The list is the order of preference; a
coding the client does not accept, weights it `q=0`, or that there is no file
for is passed over, and without any the file itself is sent.

- Every response for a file carries `Vary: Accept-Encoding` once the setting
  is on, the uncoded ones included, so a cache keeps them apart. A `Vary` set
  through `headers` is kept and has `Accept-Encoding` added to it.
- The ETag of a coded file ends in the coding (`W/"<size>-<mtime>-br"`).
- A request with a `Range` is answered from the file itself, and a coded
  response does not carry `Accept-Ranges`.
- The coded file is only a second form of one that exists: `app.js.br` without
  `app.js` is not served for `/app.js`.
- Nothing is compressed here. Build the files with the bundler, or leave the
  setting off and use the [`compression`](compression.md) plugin.

## Behaviour

- A request whose `If-None-Match` names the file's ETag is answered `304 Not
  Modified` with no body (the comparison is weak, so `W/` prefixes do not
  matter, and `*` always matches). Without an `If-None-Match`, an
  `If-Modified-Since` no older than the file gets the same answer.
- Every response carries a weak ETag derived from size and mtime
  (`W/"<size hex>-<mtime hex>"`), the mtime as `Last-Modified`, and
  `Accept-Ranges: bytes` unless it is a [precompressed](#precompressed-files)
  file.
- A path with a segment that begins with a dot is answered `404` unless
  `hidden = true`: `/.env`, `/.git/config`, `/a/.cache/x`, in whatever way the
  dot is written (`/%2eenv`). `.well-known` is the exception. This is new
  behaviour: such files used to be served like any other.
- `text/html` responses are treated as non-cacheable, so `max_age` is not applied
  to them — the SPA shell stays fresh while hashed assets are cached.
- Only `GET` and `HEAD` are served. An `OPTIONS` is answered `204` with
  `Allow: GET, HEAD, OPTIONS` (so a [`cors`](cors.md) plugin listed after this
  one can still complete a preflight); any other method gets `405 Method Not
  Allowed` with the same `Allow`.
- A directory asked for without its closing slash (`/docs`) is redirected to
  the address with it (`301`, `Location: ./docs/`, query kept), so the relative
  links of its index page or listing resolve inside the directory. The redirect
  goes by the path and query the client sent, not by what the location's
  `rewrite` made of them, and its target is relative, so it is also right
  behind a proxy that strips a prefix.
- `bytes=start-end`, `bytes=start-` and `bytes=-suffix` are supported; only the
  first range of a multi-range request is honoured. A suffix longer than the
  file is the whole file (`206`). A well formed range that lies outside the
  file gets `416` with `Content-Range: bytes */<size>`. A `Range` that is not a
  byte range (`bytes=5-2`, another unit) is ignored and the whole file is sent
  with `200`, as RFC 9110 asks.
- `If-Range` is honoured: the range applies only when its value is the ETag the
  file currently has, or its `Last-Modified` to the letter; otherwise the whole
  file is sent.
- A `206` carries the same cache headers (`max_age`, `private`) as the whole
  file, whatever the size of the range.
- A `HEAD` is answered from the file's metadata, with the headers and the
  `Content-Length` of the `GET`; the file is not read.
- Files at or below `chunk_size` are read into memory and sent in one response;
  larger ones are streamed. Either way the response has a `Content-Length` and
  the status of the request: `206` with `Content-Range` for a range, whatever
  its size.
- `autoindex` listings are sorted by name and skip dotfiles (unless `hidden`
  is on); names are
  HTML-escaped and links percent-encoded, so a file called `<script>` or
  `a b.txt` is listed and linked correctly.

## Responses

| Situation | Status |
| --- | --- |
| File found | `200`, or `206` for a range request |
| Path escapes `path` after normalisation | `403` |
| File missing | `404 Not Found`, or the `fallback` file with `200` |
| A path segment begins with a dot and `hidden` is off | `404 Not Found` |
| Other IO error | `500 File access error` |
| Range outside the file | `416 Range Not Satisfiable` |
| `OPTIONS` | `204 No Content` with `Allow` |
| Any other method than `GET`/`HEAD` | `405 Method Not Allowed` |
| Directory without the closing slash | `301` to the same path with it |

## Usage notes

- A directory request serves its `index` file at any depth when `autoindex` is
  off (`/docs/` finds `docs/index.html`), and the listing when it is on.
- Traversal protection is lexical by default: the joined path is normalised and
  must still start with `path`, which catches `../` but not a **symlink inside
  the served directory that points outside it**. Set `follow_symlinks = false`
  to also compare the resolved real path, at the cost of one extra `realpath`
  per request. The check covers the file that is actually served, so a
  directory whose `index` file links out of the tree is refused through `/dir/`
  as it is through `/dir/index.html`. The default stays `true` so that
  deployments which link content into the tree keep working; turn it off
  whenever the directory can contain symlinks you did not create. A symlinked
  *root* works either way, since the root is resolved once at startup.
- `autoindex` reveals file names, sizes and timestamps. Combine with
  [`basic_auth`](basic_auth.md) or [`ip_restriction`](ip_restriction.md) for
  anything non-public.
- Set `chunk_size` well above 4 KB when serving large media; it directly controls
  the syscall rate while streaming.
