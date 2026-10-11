# Pingap Webhook

Outbound notifications for [Pingap](https://github.com/vicanso/pingap).

Pingap emits a notification whenever something operationally interesting
happens — a certificate is about to expire, an upstream goes unhealthy, a
configuration reload succeeds or fails. This crate delivers those notifications
to a chat room, to a phone through [ntfy](https://ntfy.sh/), or to an HTTP
endpoint, so nobody has to be watching the log.

It implements `pingap_core::Notification`, so the rest of the workspace only
depends on the trait.

## Configuration

```toml
[basic]
webhook = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxx"
webhook_type = "wecom"
webhook_notifications = [
    "backend_status",
    "lets_encrypt",
    "reload_config_fail",
    "restart_fail",
    "service_discover_fail",
    "tls_validity",
]
```

| Key | Description |
| --- | --- |
| `webhook` | Destination URL. Empty disables notifications. |
| `webhook_type` | `wecom`, `dingtalk`, `ntfy`, or anything else for a generic JSON POST. |
| `webhook_notifications` | Categories to deliver, or `["*"]` for all of them. **A category not listed here is dropped.** |
| `webhook_batch_window` | Notifications no more than this far apart are merged into one post (default `10s`, `0s` disables merging). |
| `webhook_batch_max_events` | Notifications per post at most (default `5`, `1` disables merging). |
| `webhook_min_level` | Notifications below this level are not sent: `info` (default), `warn` or `error`. |
| `webhook_headers` | Headers of the request, each `Name: value`: the token a receiver asks for. |
| `webhook_secret` | What a post is signed with, see [Signing](#signing). |
| `webhook_template` | The text of the message in place of the built-in one, see [Templates](#templates). |
| `webhook_retries` | How many times a post that failed is sent again (default `0`, at most `10`). |

## Categories

| Category | Raised when |
| --- | --- |
| `backend_status` | A backend's health status changes |
| `upstream_status` | An upstream's overall health changes |
| `service_discover_fail` | DNS or Docker discovery fails |
| `tls_validity` | A certificate is approaching expiry |
| `parse_certificate_fail` | A configured certificate cannot be parsed |
| `lets_encrypt` | An ACME order succeeds or fails |
| `diff_config` | A configuration change is detected |
| `reload_config` / `reload_config_fail` | Hot reload outcome. `reload_config_fail` is also sent when the stored configuration does not validate, when the storage can not be read at all (an etcd that is away, a file that lost its permissions): once when it starts, not at every pass; and, with level `warn`, when `--autoreload` is given a certificate to order with the HTTP-01 challenge and the process has no server on port 80, or any other change that only a restart applies (the `addr` of a server, most of `[basic]`): the message lists what is waiting, once for the same set of changes |
| `restart` / `restart_fail` | Graceful restart outcome |

Each notification carries a category, a level (`Info`, `Warn`, `Error`), a title
and a message. The payload also includes the hostname and the local IP list, so
in a multi-instance deployment you can tell which node reported.

## Batching

Bursts are merged so a flapping upstream or a reload that touches several
entries produces one message instead of five:

- notifications no more than `webhook_batch_window` (default **10 seconds**)
  apart go into the same post, and each one extends the wait, so a batch goes
  out once it has been quiet for that long;
- a batch holds at most `webhook_batch_max_events` (default **5**)
  notifications and goes out as soon as it is full.

A notification that arrives on its own is posted exactly as before, after the
10 second wait. A merged post carries the highest level in the batch, the
categories it contains (`backend_status,upstream_status`), the shared title or
`N notifications` when the titles differ, and one numbered line per
notification:

```
1. [error] backend_status: upstream api(10.0.0.1:8080) becomes unhealthy
2. [error] backend_status: upstream api(10.0.0.2:8080) becomes unhealthy
3. [info] reload_config: Upstream(api) is modified
```

The allow-list is applied per notification before batching, so a dropped
category never takes up a slot. Batched posts are sent from a background task,
so `notify` returns before delivery. A batch still collecting when pingap is
stopped is posted on the way out: at the start of a graceful shutdown
(SIGTERM, SIGQUIT), or right before exit on a fast one (SIGINT), the latter
giving the post at most 5 seconds. Both settings are hot reloaded like the other `webhook*`
keys; `webhook_batch_window = "0s"` (or `webhook_batch_max_events = 1`) posts
every notification immediately. Embedders set the same policy with
`WebhookNotificationSender::with_batch(window, max_events)`.

## Formats

| `webhook_type` | Payload |
| --- | --- |
| `wecom` | WeCom (企业微信) markdown message, colour-coded by level |
| `dingtalk` | DingTalk (钉钉) markdown message |
| `ntfy` | A message of [ntfy](https://ntfy.sh/), with a priority and a sign by level, see [ntfy](#ntfy) |
| anything else | Generic JSON POST: an object with `name` (`pingap`), `title`, `level` (`info`, `warn`, `error`), `category`, `message`, `hostname` and `ip` (the local addresses, `;` separated). `title` used to be missing from it. |

`Warn` and `Error` render in warning colour; `Info` renders as a comment.

## ntfy

[ntfy](https://ntfy.sh/) pushes messages to phones and browsers that have
subscribed to a topic, on ntfy.sh or on a server of your own. `webhook` is the
url of the topic:

```toml
[basic]
webhook = "https://ntfy.sh/my-pingap-alerts"
webhook_type = "ntfy"
webhook_notifications = ["backend_status", "tls_validity", "reload_config_fail"]
```

On ntfy.sh anybody who knows the name of a topic can read it and write to it:
pick one that cannot be guessed, or use a topic that is protected.

| Of the notification | In ntfy |
| --- | --- |
| level `info` / `warn` / `error` | priority `3` (default) / `4` (high) / `5` (max), and the first tag, which ntfy shows as a sign in front of the title: ℹ️ / ⚠️ / 🚨 |
| title | the title; the category where the notification has no title of its own, which is most of them |
| category | a tag, one for each category of a post that merges several, so a subscription can be told to show some of them |
| message | the text, followed by the hostname and the addresses of the machine |

- **A topic that is protected**: give the token in `webhook_headers`
  (`"Authorization: Bearer tk_..."`), or the user and the password in the url
  (`https://user:password@ntfy.example.com/alerts`, with what is no letter or
  digit percent-encoded: `p%40ss` for `p@ss`).
- **What else ntfy takes as a header** can be set the same way, for every
  message: `"X-Markdown: yes"` with a `webhook_template` written in markdown,
  `"X-Click: https://..."`, `"X-Icon: ..."`, `"X-Email: ..."`. Title, priority
  and tags are the ones above, whatever the headers say.
- The text is cut at 4000 bytes, with a `…` where it was cut, and shorter
  where it is mostly quotes and line feeds. ntfy takes 4096 and makes an
  attachment of anything longer, or refuses it; the difference of a reloaded
  configuration (`diff_config`) is easily longer.
- The message is posted as JSON to the server (the url without the topic),
  which is where ntfy takes that form. What the url has after a `?` goes
  along, and ntfy reads it the way it reads headers: `?auth=...`,
  `?delay=30m`.
- A url that is not one of a topic is refused when the configuration is
  checked: one without a topic (`https://ntfy.sh`), one that ends with a name
  ntfy does not take for a topic or keeps for itself (`app`, `docs`, `v1`...),
  the url of a subscription (`.../mytopic/json`), one with a `#`.
- A post counts as delivered when ntfy answers it with the message it made
  of it. A `200` with anything else is a failure in the log: the page of
  another server, or what comes back when the url is redirected (to `https`,
  say), in which case the message never arrives.

## Filtering

A notification is posted when its category is in `webhook_notifications`
**and** its level is at least `webhook_min_level`. `"*"` in the list stands
for every category, the ones a later version adds included: a list that names
each of them is complete until the next one comes, which is then dropped
without a word. It is an entry of its own, not a pattern: `"reload_*"` names
no category. In the admin, all categories selected is saved as `"*"`. Both are applied to each
notification before it is merged with others, so one that is filtered out
takes no place in a batch.

```toml
[basic]
webhook_notifications = ["backend_status", "tls_validity", "reload_config_fail"]
webhook_min_level = "warn"      # a backend that is healthy again is `info`
```

```toml
[basic]
webhook_notifications = ["*"]   # everything...
webhook_min_level = "warn"      # ...that is a warning or worse
```

## Templates

`webhook_template` replaces the text that is built in. These are filled in:
`{{title}}`, `{{message}}`, `{{level}}`, `{{category}}`, `{{hostname}}`,
`{{ip}}`, `{{name}}` (`pingap`) and `{{count}}` (how many notifications the
post merges).

- For `wecom` and `dingtalk` the template is the markdown that is shown:

  ```toml
  webhook_template = "**{{title}}** ({{level}})\n\n{{message}}\n\n{{hostname}}"
  ```

- For `ntfy` the template is the text of the message, shown as it is written.
  Title, priority and tags stay the built-in ones.

- For any other type the template is the **whole body** of the post, and what
  is filled in is escaped as the text of a JSON string - put each placeholder
  between quotes (a number like `{{count}}` may stand without). This is how
  the post is given the shape a receiver expects, Slack for one:

  ```toml
  webhook_template = '{"text":"[{{level}}] {{title}}: {{message}}","username":"{{name}}@{{hostname}}"}'
  ```

  The body is sent as `application/json` unless `webhook_headers` names
  another `Content-Type`.

## Signing

- **`dingtalk`**: `webhook_secret` is the secret of a robot that has signing
  ("加签") switched on. Each post then carries `timestamp` and `sign` in its
  url, as DingTalk describes it: the HMAC-SHA256 of `<timestamp>\n<secret>`
  under the secret, in base64.
- **A receiver of your own** (any type but `wecom`, `dingtalk` and `ntfy`):
  the body is signed, and the post carries `X-Pingap-Signature: sha256=<hex>`, the
  HMAC-SHA256 of the body under the secret. The receiver computes the same
  over the bytes it got and compares.
- **`wecom`** and **`ntfy`** have no signing; the secret is not used there.

## Delivery

- A post that is answered with a status below `400` counts as delivered. For
  `wecom` and `dingtalk` the answer is read as well: both answer `200`
  whatever they made of the post and say in the body whether they took it
  (`{"errcode":310000,"errmsg":"sign not match"}`). An `errcode` other than
  `0` is logged as a failure, with the code and the message. It used to be
  logged as a success. `ntfy` answers with a status, and says why in the
  body, which is logged with it: `status 403 Forbidden: forbidden`.
- With `webhook_retries`, a post that was not answered, or was answered with
  a `5xx` or a `429`, is sent again that many times: after a second, then
  two, four... and no longer than five minutes apart. What the receiver
  refuses - another `4xx`, an `errcode` - is not sent again. That includes
  an `errcode` that says there were too many messages: the two chats answer
  `200` for that as well, and the codes are not told apart. The retries are
  made in the background: what raised the notification does not wait for
  them, and neither does the next post, so a post that is being retried can
  arrive after one that was raised later. Each failed post has a task of its
  own until it is delivered or given up.

## Usage

```rust
use pingap_webhook::WebhookNotificationSender;

let sender = WebhookNotificationSender::new(
    "https://example.com/hook".to_string(),
    "wecom".to_string(),
    vec!["backend_status".to_string(), "tls_validity".to_string()],
);
```

## Notes

- `webhook_notifications` is an allow-list. Leaving it empty silences everything
  even when `webhook` is set — a common cause of "why am I not getting alerts".
  `["*"]` allows everything.
- Every `webhook*` key is hot reloaded under `--autoreload` /
  `--autorestart`: a change applies without a restart, also to notifications
  from upstreams, discovery and certificate checks that were already running. A
  batch still collecting at that moment goes out with the settings it was
  collected under.
- Certificate expiry warnings (`tls_validity`) are for certificates somebody
  has to replace by hand: `certificates.<name>.buffer_days` is how many days
  ahead they start (7 when unset). A certificate with `acme` set is renewed by
  the ACME task, and what goes wrong there is a `lets_encrypt` notification;
  it only gets this warning when it is still not renewed a week before its
  end. See [pingap-acme](../pingap-acme/README.md).
- Delivery is best-effort: failures are logged, and retried only as often as
  `webhook_retries` says, which is not at all by default. A notification that
  is still being retried when pingap stops is lost. Treat webhooks as a
  convenience on top of metrics and logs, not as the only alerting path.
- `webhook_secret` and `webhook_headers` are shown as checksums in the log
  and in the configuration differences that are logged and sent to the
  webhook, like the key in the url of `webhook`. The admin shows them as
  they are.
- One webhook is what there is: several targets, each with a type and a
  filter of its own, are not supported.

## License

Apache-2.0.
