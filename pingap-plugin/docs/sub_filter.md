# sub_filter

Search-and-replace inside the response body, in the spirit of nginx's
`sub_filter` and the `subs_filter` module. Useful for rewriting absolute URLs,
injecting a script tag, or patching an upstream you cannot change.

- **Step:** `response` and `response_body` (default), or `upstream_response` and `upstream_response_body` when `step = "upstream_response"`; also runs at `request`
- **Registered as:** `sub_filter`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `sub_filter`. |
| `step` | string | `response` | `response` (rewrite on the way to the client) or `upstream_response` (rewrite the upstream response before [`cache`](cache.md) stores it, so cache hits serve the rewritten body directly). Any other value is a configuration error. |
| `filters` | string[] | `[]` | Substitution rules; see the syntax below. |
| `path` | string | — | Regex on the request path. Unset means every path. |
| `status_codes` | string | — | Comma-separated status codes to apply to, e.g. `"200,201"`. Unset means all; an entry that is not a number is a configuration error. |
| `types` | string[] | — | Content types to rewrite, as prefixes: `["text/html", "application/json"]`, `["text/"]`. Unset means every response, whatever its type. |
| `max_size` | size | — | The largest body that is rewritten, e.g. `"1mb"`. A larger one is passed on as it came. Unset means no limit. Setting `max_size` switches the plugin into full-body buffering mode. |
| `max_buffer_size` | size | `64 MiB` | Shared concurrent memory budget across all in-flight buffered responses of this plugin instance, e.g. `"64mb"`. Applies only in buffered mode (when a `subs_filter` regex rule or `max_size` is configured); when exceeded, the response fails open and streams unmodified. Must be greater than `0`. |

## Rule syntax

```
sub_filter  '<literal>' '<replacement>' [flags]
subs_filter '<regex>'   '<replacement>' [flags]
```

Either of the two texts is in single or in double quotes, so one that has a
quote of the one kind in it is written in the other (`sub_filter "it's" 'it
is'`). The replacement may be empty, which takes what is found out
(`sub_filter '<script src="/old.js"></script>' ''`).

| Flag | Meaning |
| --- | --- |
| `g` | Replace every occurrence instead of only the first |
| `i` | Case-insensitive (`subs_filter` only) |

`subs_filter` replacements use the [`regex`] crate's syntax, so capture groups
are referenced as `$1`, `$2` or `${name}`.

## Examples

```toml
[plugins.rewriteLinks]
category = "sub_filter"
path = "^/docs"
status_codes = "200"
filters = [
    "sub_filter  'http://old.example.com' 'https://new.example.com' g",
    "subs_filter '<title>(.*?)</title>' '<title>$1 — Docs</title>' i",
    "sub_filter  '</head>' '<script src=\"/analytics.js\"></script></head>'",
]

[locations.docs]
upstream = "docs"
path = "/docs"
plugins = ["rewriteLinks"]
```

Filters run in the order they are listed, each operating on the output of the
previous one.

## Behaviour

When the plugin applies, it removes `Content-Length` and switches the response to
`Transfer-Encoding: chunked`. How the body is processed depends on the rules and
`max_size`:

- **Streaming mode (literal `sub_filter` rules only, `max_size` unset):** uses a
  sliding-window streaming replacer that coalesces small incoming chunks up to
  `8 KiB` and holds only `pattern.len() - 1` overlap bytes per rule across
  flushes, emitting rewritten output mid-stream without buffering the entire
  body in memory. `max_buffer_size` does not apply in this mode.
- **Buffered mode (any `subs_filter` regex rule, or `max_size` set):** buffers
  the response body in memory, applies all filters at end of stream, and emits
  the result. A rule that matches nothing costs no copy. If a body without a
  known `Content-Length` exceeds `max_size` or would push concurrent in-flight
  buffered bytes for the plugin instance past `max_buffer_size` (`64 MiB` by
  default), it fails open: what was buffered so far is released as it came and
  the rest streams through unmodified.

It leaves alone responses that have no body to rewrite: HEAD answers, `1xx`,
`204`, `304`, and anything with a `Content-Encoding` other than `identity`,
whose bytes are compressed and would never match. A part of a body, a `206` or
anything with a `Content-Range`, is left alone too: rewritten, it would be no
part of the original any more while its header still said which.

So that a client cannot choose to get a part, the plugin removes `Range` and
`If-Range` from every request it applies to (by `path`), at the `request` step:
the upstream is asked for the whole body, and so is the cache, which would
otherwise cut the range out of the stored response itself. The client gets a
`200` with the rewritten body, which is a valid answer to a range request.

A response that is rewritten loses its `Accept-Ranges`, and a strong `ETag`
becomes a weak one (`W/"v1"`): both described the body the upstream sent.

## Usage notes

- **Step selection (`step = "upstream_response"`):** by default (`step = "response"`),
  `sub_filter` rewrites the body on the way to the client, after [`cache`](cache.md),
  so every cache hit runs the filters again. Setting `step = "upstream_response"`
  moves rewriting into the upstream response hook before `cache` stores the
  object, so cache hits serve the already-rewritten body directly; downstream
  [`compression`](compression.md) (default mode) still compresses cached responses
  on the way to the client. `Range` stripping and plain-body signalling still
  run at the `request` step in both modes.
- **Only buffered mode holds the full response body in memory** (when any rule
  is a regex `subs_filter`, or when `max_size` is set). Literal-only
  `sub_filter` rules without `max_size` stream in `8 KiB` chunks with bounded
  overlap memory. In buffered mode, scope the plugin with `path` and
  `status_codes` and keep it away from large files or streaming endpoints, or
  bound it explicitly:
  - **`types`** leaves every response of another type alone: streamed, with
    its `Content-Length`, and not held in memory. A response that names no
    type is left alone as well. Without `types` an image or a download on
    the same location is processed like a page (and buffered to its end in
    buffered mode).
  - **`max_size`** leaves a body alone that is larger. One that says so in
    its `Content-Length` is not touched at all. One that gives no length is
    held up to the limit and then let go as it came, what was held first:
    no part of it is rewritten. Because `max_size` needs to hold up to the
    limit before deciding, setting it disables streaming mode even for
    literal-only rules.
  - **`max_buffer_size`** caps the total memory held simultaneously across all
    in-flight responses on a plugin instance in buffered mode (default
    `64 MiB`). A response that would exceed this shared budget fails open and
    passes through unmodified so concurrent large bodies cannot exhaust memory.
  `types` and `max_size` are off unless they are set, as the plugin has always
  worked. nginx's `sub_filter_types` defaults to `text/html`;
  `types = ["text/html"]` is that.
  Neither `types` nor `max_size` brings range requests back: `Range` and
  `If-Range` are taken off every request the plugin applies to by `path`, before
  the type or the size of the response is known. A download next to the pages,
  on the same `path`, is passed on untouched but cannot be resumed; give the
  plugin a `path` that leaves it out.
- Compressed upstream responses are skipped, not rewritten: if the upstream
  returns gzip, the filters would never match. Either ask the upstream not to
  compress, or compress in Pingap with [`compression`](compression.md) in its
  default mode, which compresses after the rewrite. With `mode = "upstream"`
  the responses this plugin applies to (by its `path`) are not compressed at
  all: that mode codes a body before any plugin of the response step sees it,
  whatever their order in the list, and used to leave nothing here to rewrite
  for a client that takes a coding.
- A rule that fails to parse is a startup error, so `pingap -t` catches quoting
  mistakes. A text in single quotes can not contain a single quote, and one in
  double quotes no double quote; there is no escaping.
- Replacement happens on raw bytes, so a match that straddles a multi-byte UTF-8
  boundary in a regex pattern is handled by the regex engine, but literal
  patterns must be given exactly as they appear in the body.

[`regex`]: https://docs.rs/regex/latest/regex/#syntax
