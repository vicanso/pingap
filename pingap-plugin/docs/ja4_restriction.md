# ja4_restriction

Allow- or deny-list requests by the [JA4 fingerprint](../../pingap-proxy/README.md#ja4-fingerprint)
of their TLS connection: what the client's TLS stack is, whatever its
`User-Agent` says. A script that calls itself Chrome still shakes hands the
way its library does.

- **Step:** `request` (fixed)
- **Registered as:** `ja4_restriction`
- **Needs `ja4 = true` on the server** the request comes in on

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `ja4_restriction`. |
| `ja4_list` | string[] | — | **Required.** Regex patterns matched against the `ja4` form of the fingerprint, compiled at startup into one set. A fingerprint written out in full is a pattern that matches itself. |
| `type` | string | `allow` | `allow` permits **only** matching fingerprints; `deny` blocks them. Case-insensitive; any other value is a configuration error. |
| `message` | string | `Request is forbidden` | Body of the 403 response. |
| `dry_run` | bool | `false` | Let a request that would be refused go on, and log the refusal as a warning instead: a new rule can be watched on real traffic before it turns anyone away. See [Dry run](limit.md#dry-run). |

A fingerprint reads `t13d1516h2_8daaf6152771_e5627efa2ab1`: the protocol and
TLS version, whether there was an SNI, the counts of ciphers and extensions,
and the first and last character of the first ALPN value (`h2`, `h1` for
`http/1.1`, `00` for none); then a hash of the ciphers, and one of the
extensions (without SNI and ALPN) together with the signature algorithms.
Patterns use the [`regex`] crate's syntax and are **unanchored**:
`^t13d` is every TLS 1.3 client that
sent an SNI, `_8daaf6152771_` one list of ciphers. An invalid pattern is a
startup error, so `pingap -t` catches it.

## Examples

Turn away clients that offer TLS 1.2 at most, on a site for browsers: every
current browser offers 1.3, old libraries and tools do not. Watch first what
would be refused:

```toml
[plugins.noOldTls]
category = "ja4_restriction"
type = "deny"
ja4_list = ["^t1[0-2]"]
message = "Please use a current browser"
dry_run = true
```

To turn away particular TLS stacks, copy their fingerprints from the access
log (`{:ja4}`) into `ja4_list`, each written out in full.

Only TLS 1.3 clients on an internal API:

```toml
[plugins.modernTls]
category = "ja4_restriction"
type = "allow"
ja4_list = ["^t13"]
```

## Behaviour

| Fingerprint | `type = "allow"` | `type = "deny"` |
| --- | --- | --- |
| Matches a pattern | allowed | **403** |
| Matches nothing | **403** | allowed |
| None (plain http, or `ja4` off on the server) | **403** | allowed |

## Usage notes

- Turn on `ja4 = true` on the server first. Without it no request has a
  fingerprint, and an allow list turns every one of them away.
- Find the fingerprints to list in the access log: `{:ja4}` prints the one of
  each request, next to `{user_agent}` to see which claim does not fit.
- A fingerprint names a TLS stack, not a client: every user of one browser
  version shares it, and an update of a browser or a library changes it. Keep
  deny lists to the stacks of tools, and prefer `dry_run` before an allow
  list goes live.
- Behind a proxy or a CDN that terminates TLS, the fingerprint is the proxy's.
- To slow a kind of client down instead of turning it away, count by the
  fingerprint in [`limit`](limit.md#by-tls-fingerprint).

[`regex`]: https://docs.rs/regex/latest/regex/#syntax
