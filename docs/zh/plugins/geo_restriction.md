# geo_restriction

按客户端国家做允许/拒绝列表，国家由内嵌 GeoIP 数据库解析。另有仅记录查找结果的上报模式，便于在强制执行前评估影响。

- **步骤：** `request`（固定）
- **注册名：** `geo_restriction`
- **需要 cargo feature `geo`**（不包含在 `full` 中）

```bash
cargo build --features=geo
```

`geo` 刻意不纳入 `full`，因为会内嵌 GeoIP 数据库。`make lint` 会单独对该 feature 跑 clippy，避免静默腐烂。

没有这个 feature 的构建上仍然可以声明该插件，只会在日志里告警；但引用它的 location 属于配置错误，`--test`、启动和热更新都会拒绝，而不是在没有限制的情况下提供服务。

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `geo_restriction`。 |
| `type` | string | — | **必填。** 为 `allow`、`deny`、`reporting` 之一。 |
| `country_codes` | string[] | `[]` | ISO 3166-1 alpha-2 代码。单条字符串内也可用空格/逗号分隔。 |
| `message` | string | `Access from your country is not allowed` | 403 响应正文。 |

代码会转为大写并校验为恰好两个 ASCII 字母，拼写错误在启动时失败，而不是静默永不匹配。

## 示例

仅服务国内市场：

```toml
[plugins.geoAllow]
category = "geo_restriction"
type = "allow"
country_codes = ["CN", "HK", "MO", "TW"]
```

拦截若干国家：

```toml
[plugins.geoDeny]
category = "geo_restriction"
type = "deny"
country_codes = ["XX, YY"]        # also accepted: one string, comma separated
message = "Service unavailable in your region"
```

先观测再强制：

```toml
[plugins.geoReport]
category = "geo_restriction"
type = "reporting"
```

上报模式对每个请求打 `info` 日志（含 IP 与解析到的国家），并始终继续。

## 行为

| Situation | `allow` | `deny` |
| --- | --- | --- |
| 国家在 `country_codes` 中 | 允许 | **403** |
| 国家不在列表中，或未知（`??`） | **403** | 允许 |
| 客户端 IP 无法解析 | **403** | 允许 |

不是合法地址的客户端 IP 没有国家归属，和数据库里查不到的地址同样对待。通过双栈监听（`[::]:80`）接入的 IPv4 客户端，地址是 `::ffff:1.2.3.4`，按 `1.2.3.4` 查找。

## 使用说明

- GeoIP 数据来自 [`tor-geoip`](https://crates.io/crates/tor-geoip) 的 `embedded-db` feature，随二进制一起编译，查找无需网络——但数据随 crate 版本老化。特定 IP 的国家归属可能不准，尤其是移动运营商、VPN 与云网段。
- 按客户端无法自行指定的地址判断国家：经过 `basic.trusted_proxies` 里的代理时用转发头里的地址，否则用对端地址。前面有代理而没有列入时，所有请求都算作代理所在的国家。见 [`ip_restriction`](ip_restriction.md#客户端-ip-解析)。
- 建议先在生产用 `type = "reporting"` 观察日志，再开启会拦截数据库无法分类国家的 `allow`。
