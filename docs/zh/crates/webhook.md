# Pingap Webhook

[Pingap](https://github.com/vicanso/pingap) 的出站通知。

当发生有运维意义的事件时——证书即将过期、上游变不健康、配置重载成功或失败——Pingap 发出通知。本 crate 把这些通知投递到聊天室或 HTTP 端点，无需一直盯着日志。

它实现 `pingap_core::Notification`，因此工作区其余部分只依赖该 trait。

## 配置

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
| `webhook` | 目标 URL。空则禁用通知。 |
| `webhook_type` | `wecom`、`dingtalk`，或其他值表示通用 JSON POST。 |
| `webhook_notifications` | 要投递的类别。**未列出的类别会被丢弃。** |

## 类别

| Category | Raised when |
| --- | --- |
| `backend_status` | 后端健康状态变化 |
| `upstream_status` | 上游整体健康变化 |
| `service_discover_fail` | DNS 或 Docker 发现失败 |
| `tls_validity` | 证书接近过期 |
| `parse_certificate_fail` | 配置的证书无法解析 |
| `lets_encrypt` | ACME 下单成功或失败 |
| `diff_config` | 检测到配置变更 |
| `reload_config` / `reload_config_fail` | 热更新结果 |
| `restart` / `restart_fail` | 优雅重启结果 |

每条通知带类别、级别（`Info`、`Warn`、`Error`）、标题与消息。载荷还含主机名与本地 IP 列表，多实例部署时可区分报告节点。

## 格式

| `webhook_type` | Payload |
| --- | --- |
| `wecom` | 企业微信 markdown 消息，按级别着色 |
| `dingtalk` | 钉钉 markdown 消息 |
| 其他 | 通用 JSON POST |

`Warn` 与 `Error` 用警告色；`Info` 以评论样式渲染。

## 用法

```rust
use pingap_webhook::WebhookNotificationSender;

let sender = WebhookNotificationSender::new(
    "https://example.com/hook".to_string(),
    "wecom".to_string(),
    vec!["backend_status".to_string(), "tls_validity".to_string()],
);
```

## 说明

- `webhook_notifications` 是允许列表。留空会静默一切，即使设了 `webhook`——这是“为什么收不到告警”的常见原因。
- 证书过期警告与 `certificates.<name>.buffer_days` 配合，后者控制 ACME 提前多久续期；见 [pingap-acme](acme.md)。
- 投递是尽力而为，失败记日志不重试。把 webhook 当作指标与日志之上的便利，而非唯一告警路径。

## 许可证

Apache-2.0。
