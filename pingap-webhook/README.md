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
- Certificate expiry warnings pair with `certificates.<name>.buffer_days`, which
  controls how far ahead ACME renews; see
  [pingap-acme](../pingap-acme/README.md).
- Delivery is best-effort and failures are logged, not retried. Treat webhooks
  as a convenience on top of metrics and logs, not as the only alerting path.

## License

Apache-2.0.
