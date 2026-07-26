# referer_restriction

Allow- or deny-list requests by the host in the `Referer` header. The classic use
is hot-link protection for images and downloads.

- **Step:** `request` (fixed)
- **Registered as:** `referer_restriction`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `referer_restriction`. |
| `referer_list` | string[] | `[]` | Hosts to match. An entry starting with `*` matches by suffix. |
| `type` | string | `allow` | `allow` permits **only** listed hosts; `deny` blocks them. Case-insensitive; any other value is a configuration error. |
| `message` | string | `Request is forbidden` | Body of the 403 response. |

Entries are matched against the **host** of the parsed `Referer` URL, not the
full URL. `*.example.com` is stored as the suffix `.example.com`, so it matches
`a.example.com` but not `example.com` itself — list both if you need both.

## Examples

Hot-link protection:

```toml
[plugins.hotlink]
category = "referer_restriction"
type = "allow"
referer_list = ["example.com", "*.example.com"]
message = "Hotlinking is not allowed"

[locations.images]
path = "/images"
plugins = ["hotlink"]
```

Block a few known scrapers:

```toml
[plugins.blockReferers]
category = "referer_restriction"
type = "deny"
referer_list = ["spam.example", "*.scraper.example"]
```

## Behaviour

| `Referer` | `type = "allow"` | `type = "deny"` |
| --- | --- | --- |
| Host in the list | allowed | **403** |
| Host not in the list | **403** | allowed |
| Header absent | **403** | allowed |
| Header unparseable as a URL | **403** | allowed |

## Usage notes

- In allow mode, requests **without** a `Referer` are blocked. That breaks direct
  navigation, bookmarks and clients with a strict `Referrer-Policy`. For
  hot-link protection you usually want to permit the empty case — either use
  deny mode, or scope the plugin to embed-only paths.
- `Referer` is client-controlled and trivially forged; treat this as a
  convenience measure, not a security control. Use [`key_auth`](key_auth.md) or
  signed URLs when it must actually hold.
