# hmac_auth

Requests signed with a shared secret, in the form of HTTP Signatures
(`draft-cavage-http-signatures`). The signature is made for one request: it
covers the method, the path and the query, the headers the configuration asks
for, and with `validate_body` the body. Taken off the wire, it is of no use
for another path or another body.

[`combined_auth`](combined_auth.md) signs the secret and a time, and that
signature is good for any request while the time holds. Use `hmac_auth` where
that is not enough.

- **Step:** `request` (fixed)
- **Registered as:** `hmac_auth`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `hmac_auth`. |
| `keys` | string[] | — | **Required.** `key_id:secret` entries. The secret is everything after the first colon. |
| `signed_headers` | string[] | `["host", "date"]` | Headers a signature has to cover. The request target is always covered. `date` is satisfied by `x-date` as well. |
| `clock_skew` | duration | `5m` | How far the signed `Date` (or `X-Date`) may be from the time of the proxy. At least `1s`. |
| `validate_body` | bool | `false` | The body has to match a signed `Content-Digest` or `Digest` header, and the request has to say how long it is. |
| `hide_credentials` | bool | `false` | Remove `Authorization` before the request goes to the upstream. |

## Example

```toml
[plugins.signed]
category = "hmac_auth"
keys = ["app1:6f2aaf3c66424c1a", "app2:0d5f0a9be7b14c55"]
signed_headers = ["host", "date"]
validate_body = true
hide_credentials = true

[locations.api]
upstream = "api"
path = "/api"
plugins = ["signed"]
```

## Signing a request

The client sends:

```http
POST /api/orders?dry_run=1 HTTP/1.1
Host: api.example.com
Date: Fri, 09 Oct 2026 08:00:00 GMT
Content-Length: 8
Content-Digest: sha-256=:A3ySFO73TMOIfzpPCFtOF9digNr9JzsO4WDAnEuhz9Q=:
Authorization: Signature keyId="app1",algorithm="hmac-sha256",headers="(request-target) host date content-digest",signature="<base64>"

{"id":1}
```

`headers` lists what is signed, in order. The text that is signed has one line
for each entry, joined by a line feed (`\n`), with no line feed at the end:

```text
(request-target): post /api/orders?dry_run=1
host: api.example.com
date: Fri, 09 Oct 2026 08:00:00 GMT
content-digest: sha-256=:A3ySFO73TMOIfzpPCFtOF9digNr9JzsO4WDAnEuhz9Q=:
```

- `(request-target)` is the method in lower case, a space, and the path with
  its query as the client sent them.
- A header is its name in lower case, a colon, a space, and its value without
  the blanks around it. A header that is sent more than once has its values
  joined by `, `.
- `signature` is the HMAC of that text under the secret of `keyId`, in
  base64. `algorithm` is `hmac-sha256` (also when it is left out) or
  `hmac-sha512`.

With `curl` and `openssl`:

```bash
date=$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S GMT')
text=$(printf '(request-target): get /api/users?page=2\nhost: api.example.com\ndate: %s' "$date")
signature=$(printf '%s' "$text" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64)
curl https://api.example.com/api/users?page=2 -H "Date: $date" \
  -H "Authorization: Signature keyId=\"app1\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date\",signature=\"$signature\""
```

## Behaviour

- **What has to be signed.** `(request-target)` always, and every header of
  `signed_headers`. A signature that covers less is refused, whatever it is
  worth otherwise. It may cover more.
- **Time.** When `date` or `x-date` is signed, it has to be within
  `clock_skew` of the proxy's clock: that is what limits how long a request
  that was seen on the wire can be sent again. `x-date` is taken where both
  are signed, since a browser cannot set `Date`. It is an HTTP date, or the
  seconds since 1970. Taking `date` out of `signed_headers` takes this limit
  away for the clients that then do not sign one.
- **The path that is signed is the client's.** A `rewrite` of the location
  does not change what the signature is checked against.
- **`validate_body`.** A request with a body has to name its digest in
  `Content-Digest` (`sha-256=:<base64>:`, RFC 9530) or `Digest`
  (`SHA-256=<base64>`), and sign that header; `sha-512` is taken as well.
  - It also has to say how long the body is, with `Content-Length`. A body of
    unknown length - a chunked upload, an HTTP/2 stream without a length - is
    refused with `411`: there is no telling which of its pieces is the last
    until the upstream has had all of them. (That includes an HTTP/2 request
    without a body that ends its stream in a frame of its own instead of
    with its header; clients do not.)
  - The body is checked as it is passed to the upstream, and the digest is
    compared with the piece that completes the declared length, before that
    piece is passed on. When it is not the body that was signed, the request
    ends with a `401` there: the upstream has the header of the request and
    less than the body it announces, never the whole request. What it makes
    of a request that breaks off is its own affair. A body that is shorter
    or longer than it said is refused the same way.
  - A request without a body needs no digest, and one it does sign is checked
    at once.
- A request a later plugin answers by itself, or one answered from the cache,
  has its body read by nobody, and so not checked. List `hmac_auth` ahead of
  [`cache`](cache.md), as every plugin that says who may ask.
- **With `cache`.** The response to a request with `Authorization` is the
  requester's own: it is stored only when the origin says it may be shared
  (`public`, `s-maxage`, `must-revalidate`). That is judged by the request as
  the upstream gets it. With `hide_credentials` the upstream can not tell
  who signed, and the response is stored and served to every client whose
  signature holds, as with [`basic_auth`](basic_auth.md). Where the upstream
  tells the callers apart by something else - a header they sign - put that
  header into the `headers` of the cache plugin, or leave the cache off.
- A signed header with a value that is not text (bytes outside visible ASCII)
  is refused, not passed over.
- **Refusals.** A request that is refused when it comes in gets a `401` with
  `WWW-Authenticate: Signature realm="pingap",headers="..."`, which names
  what has to be signed. The body says what is wrong with the request - no
  signature, a header that is not covered, a date too far off - and
  `Signature invalid` for a key that is not known or a signature that does
  not match, without telling the two apart. A body without a length is a
  `411`. A body that turns out not to be the one that was signed ends the
  request with the proxy's error page for `401`, without the challenge.

## Usage notes

- The secrets are in the configuration as text, and the admin shows them as
  they are. The log, and the configuration differences that are logged and
  sent to the webhook, show `keys` as a checksum.
- HTTP/2 has no `Host` header; the host of the request is signed as `host`
  all the same.
- Nothing is kept of the requests that were seen: within `clock_skew` a
  request can be sent a second time as it is. What it cannot be is changed.
- Nothing is added to the request for the upstream to know who called. It
  can read the `keyId` from `Authorization`, unless `hide_credentials` takes
  the header off; or have the client send its name in a header of its own,
  and list that header in `signed_headers`.
