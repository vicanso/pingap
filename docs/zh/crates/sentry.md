# Pingap Sentry

通过 [Sentry](https://sentry.io/) 为 [Pingap](https://github.com/vicanso/pingap) 上报错误。

刻意做薄：把 DSN 解析为 `sentry_core::ClientOptions`。Sentry 客户端本身由 pingora 安装，Pingap 通过 pingora 的 `sentry` feature 启用，因此代理运行时内的 panic 与错误会带堆栈被捕获，而不是只出现在日志里。

## 构建

需要 `tracing` cargo feature（包含在 `full` 中）：

```bash
cargo build --features=tracing
```

## 配置

```toml
[basic]
sentry = "https://<key>@o0.ingest.sentry.io/0"
```

缺失或无法解析的 DSN 会禁用上报；错误记入日志，启动继续。

## 用法

```rust
use pingap_sentry::new_sentry_options;

let options = new_sentry_options("https://key@o0.ingest.sentry.io/0")?;
// handed to pingora's server configuration
```

## 说明

- 此处仅可配置 DSN。采样率、环境与 release 标签保持 Sentry 客户端默认；在 Sentry 项目侧设置，或通过客户端读取的标准 `SENTRY_*` 环境变量。
- 繁忙代理可能产生大量相似事件。在 Sentry 项目中配置限流与分组，而不是指望体量天然很低。
- 与 [pingap-webhook](webhook.md) 互补：Sentry 捕获意外失败，webhook 报告证书过期等预期运维事件。

## 许可证

Apache-2.0。
