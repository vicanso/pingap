# bandwidth_limit

Sends the body of a response no faster than so many bytes a second. For a site
that hands out large files: without a limit, one client on a fast line takes
all the bandwidth there is for as long as its download lasts.

- **Step:** `request` (fixed)
- **Registered as:** `bandwidth_limit`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `bandwidth_limit`. |
| `rate` | size | — | Bytes a second, e.g. `"1mb"`, `"200kb"`. Required, more than `0`. |
| `after` | size | `0` | So many bytes of each response go out as fast as they can; the limit holds for what follows. |
| `path` | string | — | Regex on the request path. Unset means every request of the location. |

## Examples

```toml
# downloads at 1 MB/s each, after the first megabyte
[plugins.downloads]
category = "bandwidth_limit"
rate = "1mb"
after = "1mb"

[plugins.files]
category = "directory"
path = "/var/www/downloads"

[locations.downloads]
path = "/downloads"
plugins = ["downloads", "files"]
```

```toml
# only the video files of an upstream
[plugins.video]
category = "bandwidth_limit"
rate = "500kb"
path = "\\.(mp4|webm)$"
```

## Behaviour

The plugin only says how fast; the pace is kept where a body is written:

- for a response from the upstream or from the cache, by the proxy, on the
  body as it passes it on: after the plugins that rewrite it (`sub_filter`),
  and before it is compressed for the client, where the
  [`compression`](compression.md) plugin does that in its default mode. A
  text that is compressed on its way out crosses the wire slower than the
  rate by as much as it shrinks; a download is as large on the wire as it is
  counted. With `mode = "upstream"` the plugin compresses first, and what is
  counted is the compressed body;
- for a file the [`directory`](directory.md) plugin streams, by that plugin.
  List `bandwidth_limit` **before** `directory`: a plugin that answers ends
  the list, and one behind it never runs.

The first piece of a body goes out at once, and each further piece waits until
what was sent before it has taken its time at the rate. The header of the
response is never held back. A body is through once all but its last piece
have taken their time: 300 kB at 100 kB a second, in pieces of 64 KiB, take
about 2.6 seconds.

The pace goes by what has been sent and how long that has taken, so the time
the client itself takes to read counts toward it: a slow client is not slowed
down a second time. Time that was not used is not saved up either - a
download that stood still for a minute does not get a minute's worth at once
afterwards.

## Usage notes

- The limit is **per response**, not per client. Whoever opens four
  connections gets four times the rate; limit those with
  [`limit`](limit.md) (`type = "inflight"`).
- A body that is written in one piece is not held back, there being nothing
  before it to wait for:
  - what a plugin answers at once: a mock, an error page, a file of the
    `directory` plugin that is no larger than its `chunk_size`;
  - a response [`sub_filter`](sub_filter.md) has rewritten, which it holds
    until it is complete and passes on whole;
  - what the proxy has read from the upstream by the time it writes the
    first of the body, which from an upstream faster than the limit is up
    to a few hundred kilobytes. What follows waits for it.

  The limit is for downloads, which are many times that. `after` says the
  same on purpose, for more.
- `after` is for a location that serves pages and downloads alike: a page is
  through before the limit begins.
- The pieces are those the body comes in: 64 KiB for a response from the
  cache, `chunk_size` for a file of `directory`, and for a response from the
  upstream what the proxy has read while it waited, up to four reads of
  64 KiB at a time. With a rate far below the size of a piece the client
  sees steps, not a steady stream: a piece at once, then a pause for as long
  as that piece takes at the rate - a minute, with `rate = "1kb"` and pieces
  of 64 KiB. A client with a read timeout shorter than the pause gives up.
- With [`cache`](cache.md) on the same location, a response that is not in
  the cache yet is stored as it is passed on, at the pace of the client that
  asked first. For as long as that download takes, the other requests for the
  same object wait for it - up to the `lock` of the cache plugin - and then
  ask the upstream themselves. Once it is stored, every hit is served from
  the cache at its own pace.
- An upgraded connection (a websocket) is not a body and is not limited.
- Neither is the proxy's own fetch of a cached response in the background
  (`stale-while-revalidate`): nobody is waiting for those bytes, and the
  client was served from the cache at its pace.
