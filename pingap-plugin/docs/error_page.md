# error_page

The pages of a location for the errors the proxy answers itself - no upstream
to be had, a request refused by a limit - in place of the one page of the
whole server (`basic.error_template`). An API wants its errors as JSON and a
site as a page of its own, and one process serves both.

- **Step:** none of its own: it is asked when an error is answered, and, with
  `intercept`, looks at the status of every response of the upstream
- **Registered as:** `error_page`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `error_page`. |
| `pages` | string[] | `[]` | `status:page` entries. The status is one from `400` to `599`, or `4xx` / `5xx` for all of them; the page is the path of a file or the text itself. |
| `json` | bool | `false` | A request that asks for JSON gets the error as `{"status":502,"message":"Bad Gateway"}`, whatever pages there are. |
| `intercept` | bool | `false` | The pages also take the place of what the **upstream** sends with the statuses of `pages`. Needs `pages`. |

One of `pages` and `json` has to be set.

## Examples

```toml
# a site: its own pages
[plugins.sitePages]
category = "error_page"
pages = [
    "404:/etc/pingap/pages/404.html",
    "5xx:/etc/pingap/pages/down.html",
]

# an API: JSON for whoever asks for it, a line of text for the rest
[plugins.apiErrors]
category = "error_page"
json = true
pages = ["5xx:service unavailable ({{status}})"]

[locations.site]
upstream = "site"
plugins = ["sitePages"]

[locations.api]
upstream = "api"
path = "/api"
plugins = ["apiErrors"]
```

## Pages

- **A file or the text.** A page that starts with `/`, `~/`, `./` or `../` is
  the path of a file, read when the plugin is built: a file that is not there
  is a configuration error (`pingap -t`). The file is not watched. An edited
  page is served once the plugin is built again, which is when its own
  configuration changes or the process restarts - a reload that leaves the
  plugin as it was keeps the page it has read. Anything else is the page
  itself.
- **Its type** is that of the file's extension - `.json` is
  `application/json`, `.txt` is `text/plain`, anything else `text/html` - and
  for a text in the configuration what it starts with: `<` is HTML, `{` or `[`
  JSON, anything else plain text. A text that starts with a placeholder
  (`{{status}} {{message}}`) is plain text.
- **`{{status}}` and `{{message}}`** in a page are replaced by the status code
  and by what the proxy has to say of the error: the reason phrase of the
  status, or, for a `4xx` the proxy or a plugin raised, the message written
  for the client (which limit, which route). The message is escaped for the
  kind of page it goes into, HTML or a JSON string: a part of it may come from
  the request. That covers the places a text belongs in: the text of an
  element or a quoted attribute value in HTML, a string in JSON
  (`"error":"{{message}}"`). Do not put it into a `<script>`, a URL or an
  unquoted attribute, nor outside the quotes in JSON.
- **The page of one status** is taken ahead of the page of its hundred, in
  whatever order they are listed. A status no page is for gets the server's
  own page, as without the plugin.

## Behaviour

- **`json`**: a request asks for JSON when its `Accept` names
  `application/json` (or a `+json` type) and not `text/html`. A browser asks
  for `text/html` first and gets the page; `curl` asks for `*/*` and gets the
  page too.
- The pages are for every error of the location that the proxy answers,
  whichever plugin of the location stopped the request and wherever
  `error_page` stands in the list. The status, the headers the location's
  plugins set on responses (`cors`, `response_headers` with `always`) and the
  `X-Pingap-EType` header are as on the server's own page.
- The errors of the location include the ones that refuse a request before
  any plugin runs: the `413` of `client_max_body_size` and the `429` of
  `max_processing`.
- **Without `intercept`** a response of the upstream is the upstream's, with
  whatever status and body it has. **With it**, an upstream response whose
  status has a page in `pages` is dropped, header and body, and the proxy
  answers that status itself, as it does its own errors: with the page - or,
  with `json`, as JSON for a request that asks for it -, `{{message}}` being
  the reason phrase of the status. A `HEAD` gets the header of the page.
  `json` alone takes nothing from the upstream: an API's own `422` keeps the
  body that says what was wrong, unless a page is listed for it.
- What goes with an intercepted response:
  - The headers of the upstream are gone with its body: a `Retry-After`, a
    `Set-Cookie`, the `WWW-Authenticate` of a `401`. Do not list a status
    whose headers the client needs.
  - It is not stored in the cache, also when the upstream allows it: every
    such request reaches the upstream.
  - The rest of the upstream's response is not read, so that connection to
    the upstream is closed and not reused, and over HTTP/1.1 the client's
    connection is closed after the page (`Connection: close`), as after any
    error of a request that was being proxied. An HTTP/2 client keeps its
    connection.
  - A `5xx` with a stale response in the cache and `stale-if-error` is
    answered from the cache, as without the plugin.
  - The status counts for the backend as it would have (health statistics,
    circuit breaker), and the access log has it like any other; the error
    log has no line for it.
- What a plugin answers itself - the `401` of an authentication plugin, a
  `mock` - is that plugin's response and is not replaced.
- An error on a request that matched no location has no plugins to ask and
  gets the server's page.
