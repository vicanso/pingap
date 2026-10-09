# mirror

Sends a copy of the requests of a location to a second address and throws the
answer away. For trying a new version of a service with the traffic the
current one gets: what the mirror answers, how long it takes and whether it is
there at all make no difference to the client, whose request goes to the
upstream as ever.

[`traffic_splitting`](traffic_splitting.md) divides the requests between two
upstreams. `mirror` sends them to both.

- **Step:** `request` (default) or `proxy_upstream`
- **Registered as:** `mirror`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `mirror`. |
| `target` | string | — | **Required.** Where the copies go: `http://10.0.0.2:8080`, or with a path that is put in front of the request's, `https://shadow.internal/v2`. No query. |
| `percentage` | int | `100` | The share of the requests that are copied, `0` to `100`. |
| `methods` | string[] | `["GET", "HEAD"]` | The methods that are copied. |
| `max_body_size` | size | `0` | The largest request body that is copied, e.g. `"64kb"`. `0`: a request with a body is not mirrored. |
| `timeout` | duration | `5s` | How long a copy may take, the answer included. |
| `max_inflight` | int | `100` | Copies that may be under way at one time. A copy that would be one more is not sent. |
| `host` | string | — | The `Host` of the copy. Unset: the one of the request. |
| `step` | string | `request` | `request`, or `proxy_upstream` to copy only what is on its way to the upstream. |

## Examples

```toml
# every read of the API goes to the new version as well
[plugins.shadow]
category = "mirror"
target = "http://10.0.0.2:8080"

# one write in ten too, bodies up to 64 kB
[plugins.shadowWrites]
category = "mirror"
target = "http://10.0.0.2:8080"
methods = ["GET", "HEAD", "POST", "PUT"]
max_body_size = "64kb"
percentage = 10

[locations.api]
upstream = "api"
path = "/api"
plugins = ["shadow"]
```

## Behaviour

- **The copy** has the method, the path and the query of the request as the
  upstream gets them - after a `rewrite` of the location - and its headers,
  less those of the client's connection (`Connection`, `Transfer-Encoding`
  and the like). `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto` are
  set for the client the proxy sees. The answer is read and dropped as it
  comes, none of it kept, and a redirect is not followed.
- The address of the copy is made as a URL, which normalises it: `..`
  segments are resolved (also written as `%2e%2e`), and a few characters are
  percent-encoded. The upstream gets the path as the client sent it; for a
  path of that kind the two can differ.
- **It is sent from a task of its own.** The request does not wait for it,
  and a target that is slow, refuses the connection or answers `500` changes
  nothing for the client.
- **`X-Pingap-Mirror: 1`** marks a copy. A request that comes with the header
  is not mirrored again: two proxies that mirror to each other would
  otherwise pass one request round for ever. The mirror can also tell by it
  that a request is a copy.
- **Bodies.** A request without a body is copied as soon as the plugin runs.
  One with a body is copied when its body is through, from what was kept of
  it as it passed to the upstream: at most `max_body_size` for each request
  that is being uploaded, in memory. No body is kept while as many copies
  as `max_inflight` allows are under way. A
  request whose body is larger - by its `Content-Length`, or as it turns out -
  is not mirrored at all, and neither is one that fails before its body is
  complete.
- **`max_inflight`** bounds what a target that does not answer can hold up:
  each of its copies is waited for until `timeout`, and no more than this many
  are waited for at a time. A copy counts from the moment it is sent, which
  for a request with a body is when the body is through. The requests beyond
  that are served and not mirrored.
- A copy that fails is counted, and reported in the log for the first, the
  second, the fourth, the eighth... of them, so that a target that is down
  does not write a line for every request.

## Usage notes

- The default is the methods that change nothing at the target. A `POST` that
  is mirrored is carried out twice: once by the upstream and once by the
  mirror. Point the mirror at something that may do that - its own database,
  a service in a dry-run mode.
- Credentials are copied with the other headers: `Authorization`, cookies.
  The mirror is to be trusted as the upstream is.
- A client can keep its requests from the mirror by sending
  `X-Pingap-Mirror` itself. That is the price of the loop protection; do not
  rely on the mirror seeing every request.
- A request that is answered before the plugin's turn - by a plugin listed
  ahead of it - is not mirrored. With `step = "proxy_upstream"` a request
  answered from the cache is not either.
- The body is copied when the upstream is asked for the request. A request a
  later plugin answers itself is not passed to the upstream, and if it has a
  body it is not mirrored.
- List it behind the plugins that say who may ask (`key_auth`, `jwt`): a
  request they refuse then never reaches the mirror.
