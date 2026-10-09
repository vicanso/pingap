# geo_restriction

按客户端国家做允许/拒绝列表，国家由内嵌 GeoIP 数据库或 MaxMind DB 文件解析。另有仅记录查找结果的上报模式，便于在强制执行前评估影响；还可以把国家码通过请求头传给上游。

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
| `database` | string | — | MaxMind DB 文件（`.mmdb`）的路径，用它代替内嵌数据来查询国家。 |
| `database_refresh` | duration | `1m` | 每隔多久检查一次文件是否有变化。至少 `1s`。 |
| `header` | string | — | 用哪个请求头把国家码告诉上游，如 `X-Geo-Country`。 |

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

使用保持更新的数据库，并把国家码传给上游：

```toml
[plugins.geo]
category = "geo_restriction"
type = "reporting"
database = "/var/lib/GeoIP/GeoLite2-Country.mmdb"
header = "X-Geo-Country"
```

## 行为

| Situation | `allow` | `deny` |
| --- | --- | --- |
| 国家在 `country_codes` 中 | 允许 | **403** |
| 国家不在列表中，或未知（`??`） | **403** | 允许 |
| 客户端 IP 无法解析 | **403** | 允许 |

不是合法地址的客户端 IP 没有国家归属，和数据库里查不到的地址同样对待。通过双栈监听（`[::]:80`）接入的 IPv4 客户端，地址是 `::ffff:1.2.3.4`，按 `1.2.3.4` 查找。

### `database`

内嵌数据和发布版本一样旧。文件则由提供它的一方保持更新：`geoipupdate`、定时任务、挂载的卷。

- 任何给出国家的 MaxMind DB 格式数据库都可以：GeoLite2 和 GeoIP2 的 Country 或 City、DB-IP 等。国家码从 `country.iso_code` 读取，或者从存放两个字母的 `country_code`、`country` 字段读取。
- 文件在构建插件时读取：文件不存在或者不是数据库属于配置错误。设置了 `database` 之后完全不使用内嵌数据，文件里查不到的地址就没有国家。
- 每隔 `database_refresh` 检查一次文件，修改时间变了就重新读取。请求不会因此被阻塞：读取在请求之外进行，新数据库就绪之前请求继续使用已加载的那份。当时读不了的文件（比如还在写入中，或者被删掉了）不会替换已加载的数据库，会在日志里报告，下次检查时再试。替换文件时请把完整的新文件重命名覆盖上去，`geoipupdate` 就是这么做的。
- 引用同一个文件的多个插件在内存里共用一份。每个插件按自己的 `database_refresh` 检查文件；其中一个发现文件变了并重新读取之后，所有插件都用上新的。

### `header`

设置了 `header` 之后，在任何模式下请求都会带着这个头发往上游：`X-Geo-Country: DE`。客户端自己发来的同名请求头会先被去掉，查不到国家时也一样（这时上游收不到这个头）：上游在这里读到的永远是代理给出的结果。

## 使用说明

- GeoIP 数据来自 [`tor-geoip`](https://crates.io/crates/tor-geoip) 的 `embedded-db` feature，随二进制一起编译，查找无需网络——但数据随 crate 版本老化。特定 IP 的国家归属可能不准，尤其是移动运营商、VPN 与云网段。
- 按客户端无法自行指定的地址判断国家：经过 `basic.trusted_proxies` 里的代理时用转发头里的地址，否则用对端地址。前面有代理而没有列入时，所有请求都算作代理所在的国家。见 [`ip_restriction`](ip_restriction.md#客户端-ip-解析)。
- 建议先在生产用 `type = "reporting"` 观察日志，再开启会拦截数据库无法分类国家的 `allow`。
