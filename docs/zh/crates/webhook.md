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
| `webhook_batch_window` | 间隔不超过该时长的通知合并为一条（默认 `10s`，`0s` 关闭合并）。 |
| `webhook_batch_max_events` | 一条消息最多合并的通知数（默认 `5`，`1` 关闭合并）。 |

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

## 合并发送

短时间内的多条通知会合并成一条，上游抖动或一次改动多个条目的重载只会收到一条消息而不是五条：

- 相邻两条通知间隔不超过 `webhook_batch_window`（默认 **10 秒**）就进入同一批；每来一条都会重新计时，所以一批在安静这么久之后发出；
- 一批最多 `webhook_batch_max_events`（默认 **5**）条，凑满立即发出。

单独到达的通知在等待 10 秒后按原来的格式发出，内容不变。合并后的消息取批内最高级别，类别列出批内所有类别（如 `backend_status,upstream_status`），标题相同时沿用，不同时写为 `N notifications`，正文每条通知一行并编号：

```
1. [error] backend_status: upstream api(10.0.0.1:8080) becomes unhealthy
2. [error] backend_status: upstream api(10.0.0.2:8080) becomes unhealthy
3. [info] reload_config: Upstream(api) is modified
```

允许列表在合并之前逐条生效，被丢弃的类别不占名额。合并后的发送在后台任务里完成，`notify` 返回时不代表已投递。停止 pingap 时尚在收集的一批会在退出前发出：优雅退出（SIGTERM、SIGQUIT）在开始退出时立即发送，快速退出（SIGINT）在进程结束前发送，后者最多等待 5 秒。这两个键和其他 `webhook*` 键一样支持热更新；`webhook_batch_window = "0s"`（或 `webhook_batch_max_events = 1`）表示每条立即发送。以库方式使用时用 `WebhookNotificationSender::with_batch(window, max_events)` 设置同样的策略。

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
- `webhook`、`webhook_type` 与 `webhook_notifications` 支持热更新（`--autoreload` / `--autorestart`）：修改后无需重启即生效，已在运行的上游、服务发现与证书检查发出的通知也按新配置投递。此时尚在收集的一批仍按收集时的配置发出。
- 证书过期警告与 `certificates.<name>.buffer_days` 配合，后者控制 ACME 提前多久续期；见 [pingap-acme](acme.md)。
- 投递是尽力而为，失败记日志不重试。把 webhook 当作指标与日志之上的便利，而非唯一告警路径。

## 许可证

Apache-2.0。
