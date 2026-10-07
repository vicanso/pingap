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

## Rule syntax

```
sub_filter  '<literal>' '<replacement>' [flags]
subs_filter '<regex>'   '<replacement>' [flags]
```

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
  streaming endpoints.
- Compressed upstream responses are skipped, not rewritten: if the upstream
  returns gzip, the filters would never match. Either ask the upstream not to
  compress, or compress in Pingap with [`compression`](compression.md) after
  this plugin.
- A rule that fails to parse is a startup error, so `pingap -t` catches quoting
  mistakes. Patterns and replacements must be wrapped in single quotes and cannot
  themselves contain a single quote.
- Replacement happens on raw bytes, so a match that straddles a multi-byte UTF-8
  boundary in a regex pattern is handled by the regex engine, but literal
  patterns must be given exactly as they appear in the body.

[`regex`]: https://docs.rs/regex/latest/regex/#syntax
