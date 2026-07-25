# key_auth

API key authentication. The key is read from either a request header **or** a
query parameter and compared, in constant time, against a configured list.

- **Step:** `request` (fixed)
- **Registered as:** `key_auth`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `key_auth`. |
| `header` | string | — | Header name carrying the key, e.g. `X-API-Key`. |
| `query` | string | — | Query parameter name carrying the key, e.g. `api_key`. |
| `keys` | string[] | — | **Required, non-empty.** The accepted keys, compared byte for byte. |
| `delay` | duration | none | Sleep this long before answering a failed attempt. |
| `hide_credentials` | bool | `false` | Remove the key from the request before proxying. |

At least one of `header` / `query` must be set. **If both are set, `query`
wins** and `header` is ignored — the plugin reads a single location, never both.

## Examples

Header-based:

```toml
[plugins.apiKey]
category = "key_auth"
header = "X-API-Key"
keys = ["KOXQaw", "GKvXY2"]
hide_credentials = true
delay = "500ms"
```

```bash
curl -H 'X-API-Key: KOXQaw' http://127.0.0.1:6188/api/users
```

Query-based (handy for `<img>` / `<script>` URLs that cannot set headers):

```toml
[plugins.apiKey]
category = "key_auth"
query = "api_key"
keys = ["KOXQaw"]
hide_credentials = true
```

```bash
curl 'http://127.0.0.1:6188/api/users?api_key=KOXQaw'
```

With `hide_credentials = true` the upstream receives `/api/users` with the
`api_key` parameter rewritten out of the URI, so keys never reach upstream access
logs.

## Responses

| Situation | Status | Body |
| --- | --- | --- |
| Key absent or empty | 401 | `Key missing` |
| Key present but unknown | 401 (after `delay`) | `Key auth fail` |

## Usage notes

- Keys in query strings end up in browser history, `Referer` headers and any
  intermediate proxy log. Prefer `header` when you control the client.
- `step` is **not** honoured — the plugin always runs at `request`, whatever the
  configuration says.
- For per-key quotas, put [`limit`](limit.md) with `tag = "header"` (or
  `"query"`) and the same key name after this plugin.
