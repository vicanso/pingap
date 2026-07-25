# Pingap Pyroscope

通过 [Pyroscope](https://pyroscope.io/) 为 [Pingap](https://github.com/vicanso/pingap) 提供持续 CPU 剖析。

Agent 在运行中的代理采样栈并发送到 Pyroscope 服务器，从而把 CPU 回归归因到具体函数——哪个插件、哪个压缩级别、哪条正则——而不是靠猜。

## 构建

剖析在 cargo feature 之后，并配有保留调试符号的 profile（strip 过的二进制火焰图无用）：

```bash
cargo build --features=pyro
make release-perf          # features = perf (pyro + full), profile = release-perf
```

## 配置

```toml
[basic]
pyroscope = "http://pyroscope:4040?app=pingap&sample_rate=100&tag:region=$REGION&tag:env=prod"
```

URL 是 Pyroscope 服务器；其余来自查询参数：

| Parameter | Default | Description |
| --- | --- | --- |
| `app` | `pingap` | Pyroscope 中显示的应用名 |
| `user` / `password` | — | 服务器 Basic 认证凭据 |
| `sample_rate` | `100` | 每秒采样数 |
| `tag:<name>` | — | 任意标签。以 `$` 开头的值从环境读取。 |

环境插值便于按实例打标签：

```toml
pyroscope = "http://pyroscope:4040?app=pingap&tag:host=$HOSTNAME&tag:region=$AWS_REGION"
```

## 运行

Agent 是 pingora `BackgroundService`：随进程启动，在优雅关闭时干净关闭，使剖析数据刷出而非截断。

```rust
use pingap_pyroscope::new_agent_service;

let service = new_agent_service("http://pyroscope:4040?app=pingap");
```

## 说明

- 采样消耗 CPU。`100` Hz 是合理的生产默认；仅在调查具体问题时提高。
- 无调试信息时火焰图是地址墙——使用 `release-perf` profile（`make release-perf`），其禁用 strip。
- 标签用于在 Pyroscope UI 中区分实例、区域与版本。至少设置主机标签。

## 许可证

Apache-2.0。
