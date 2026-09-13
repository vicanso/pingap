# Pingap Webhook

Outbound notifications for [Pingap](https://github.com/vicanso/pingap).

Pingap emits a notification whenever something operationally interesting
happens — a certificate is about to expire, an upstream goes unhealthy, a
configuration reload succeeds or fails. This crate delivers those notifications
to a chat room or an HTTP endpoint so nobody has to be watching the log.

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
| `webhook_type` | `wecom`, `dingtalk`, or anything else for a generic JSON POST. |
| `webhook_notifications` | Categories to deliver. **A category not listed here is dropped.** |
| `webhook_batch_window` | Notifications no more than this far apart are merged into one post (default `10s`, `0s` disables merging). |
| `webhook_batch_max_events` | Notifications per post at most (default `5`, `1` disables merging). |

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
| `reload_config` / `reload_config_fail` | Hot reload outcome |
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
| anything else | Generic JSON POST |

`Warn` and `Error` render in warning colour; `Info` renders as a comment.

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
- `webhook`, `webhook_type` and `webhook_notifications` are hot reloaded under
  `--autoreload` / `--autorestart`: a change applies without a restart, also to
  notifications from upstreams, discovery and certificate checks that were
  already running. A batch still collecting at that moment goes out with the
  settings it was collected under.
- Certificate expiry warnings pair with `certificates.<name>.buffer_days`, which
  controls how far ahead ACME renews; see
  [pingap-acme](../pingap-acme/README.md).
- Delivery is best-effort and failures are logged, not retried. Treat webhooks
  as a convenience on top of metrics and logs, not as the only alerting path.

## License

Apache-2.0.
