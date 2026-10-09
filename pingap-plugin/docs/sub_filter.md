# sub_filter

Search-and-replace inside the response body, in the spirit of nginx's
`sub_filter` and the `subs_filter` module. Useful for rewriting absolute URLs,
injecting a script tag, or patching an upstream you cannot change.

- **Step:** `response` and `response_body`
- **Registered as:** `sub_filter`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `sub_filter`. |
| `filters` | string[] | `[]` | Substitution rules; see the syntax below. |
| `path` | string | — | Regex on the request path. Unset means every path. |
| `status_codes` | string | — | Comma-separated status codes to apply to, e.g. `"200,201"`. Unset means all; an entry that is not a number is a configuration error. |
| `types` | string[] | — | Content types to rewrite, as prefixes: `["text/html", "application/json"]`, `["text/"]`. Unset means every response, whatever its type. |
| `max_size` | size | — | The largest body that is rewritten, e.g. `"1mb"`. A larger one is passed on as it came. Unset means no limit. |

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

When the plugin applies, it removes `Content-Length`, switches the response to
`Transfer-Encoding: chunked`, buffers the whole body, applies the filters at end
of stream and emits the result. A rule that matches nothing costs no copy.

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

- **The entire response body is buffered in memory** before substitution. Scope
  the plugin with `path` and `status_codes` and keep it away from large files or
  streaming endpoints, or say what it is for:
  - **`types`** leaves every response of another type alone: streamed, with
    its `Content-Length`, and not held in memory. A response that names no
    type is left alone as well. Without `types` an image or a download on
    the same location is buffered to its end and searched like a page.
  - **`max_size`** leaves a body alone that is larger. One that says so in
    its `Content-Length` is not touched at all. One that gives no length is
    held up to the limit and then let go as it came, what was held first:
    no part of it is rewritten.
  Both are off unless they are set, as the plugin has always worked. nginx's
  `sub_filter_types` defaults to `text/html`; `types = ["text/html"]` is that.
  Neither brings range requests back: `Range` and `If-Range` are taken off
  every request the plugin applies to by `path`, before the type or the size
  of the response is known. A download next to the pages, on the same
  `path`, is passed on untouched but cannot be resumed; give the plugin a
  `path` that leaves it out.
- Compressed upstream responses are skipped, not rewritten: if the upstream
  returns gzip, the filters would never match. Either ask the upstream not to
  compress, or compress in Pingap with [`compression`](compression.md) after
  this plugin.
- A rule that fails to parse is a startup error, so `pingap -t` catches quoting
  mistakes. A text in single quotes can not contain a single quote, and one in
  double quotes no double quote; there is no escaping.
- Replacement happens on raw bytes, so a match that straddles a multi-byte UTF-8
  boundary in a regex pattern is handled by the regex engine, but literal
  patterns must be given exactly as they appear in the body.

[`regex`]: https://docs.rs/regex/latest/regex/#syntax
