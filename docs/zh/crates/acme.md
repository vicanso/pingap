# Pingap ACME

为 [Pingap](https://github.com/vicanso/pingap) 从 Let's Encrypt 自动获取 TLS 证书。

Pingap 可自行申请与续期证书：声明域名后，后台服务下单、校验并安装证书，并在过期前续期。支持 HTTP-01 与 DNS-01；DNS-01 使通配符证书成为可能。

## HTTP-01

最简单的方式。Pingap 必须可从公网在 80 端口访问，且域名解析到本机。

```toml
[certificates.pingap]
domains = "pingap.io,www.pingap.io"
acme = "lets_encrypt"
buffer_days = 30

[servers.https]
addr = "0.0.0.0:443"
locations = ["app"]
global_certificates = true
enabled_h2 = true
```

Pingap 在 `/.well-known/acme-challenge/<token>` 自行提供 challenge。若配置中没有任何 server 监听 80，会自动添加名为 `lets encrypt` 的监听器——无需手写。

一条命令快速启动在无配置文件时做同样的事：

```bash
pingap --domain=pingap.io --upstream=192.168.1.1:3000
```

## DNS-01

通配符所需，以及 80 端口公网不可达的主机。

```toml
[certificates.wildcard]
domains = "*.pingap.io,pingap.io"
acme = "lets_encrypt"
dns_challenge = true
dns_provider = "cf"
dns_service_url = "https://api.cloudflare.com?token=$ENV:CF_TOKEN"
buffer_days = 30
```

| `dns_provider` | Service | `dns_service_url` |
| --- | --- | --- |
| `ali` | 阿里云 DNS | `https://alidns.aliyuncs.com?access_key_id=xxx&access_key_secret=xxx` |
| `cf` | Cloudflare | `https://api.cloudflare.com?token=xxx` |
| `huawei` | 华为云 DNS | `https://dns.{region}.myhuaweicloud.com?access_key_id=xxx&access_key_secret=xxx` |
| `tencent` | DNSPod / 腾讯云 | `https://dnspod.tencentcloudapi.com?access_key_id=xxx&access_key_secret=xxx` |
| `manual` 或未设 | — | 无 API。TXT 记录记入日志，需自行添加。 |

名称正是 `ali` 与 `cf`，不是 `aliyun` / `cloudflare`。**任何未识别值会静默回退到 manual 任务**，拼写错误不会大声失败——只是等待没人会添加的 TXT。请对照上表仔细核对拼写。

`dns_service_url` 中任意值可写成 `$ENV:NAME` 并从环境读取，密钥不必进配置文件。

提供商添加 `_acme-challenge` TXT、等待校验后删除。`manual`（或空提供商）时 challenge 每个进程启动只尝试一次，因为没有可轮询的对象。

## 证书配置

| Key | Type | Description |
| --- | --- | --- |
| `domains` | string | 逗号分隔的域名列表 |
| `acme` | string | `lets_encrypt` 以启用 ACME |
| `dns_challenge` | bool | 使用 DNS-01 而非 HTTP-01 |
| `dns_provider` | string | `ali`、`cf`、`huawei`、`tencent`、`manual` |
| `dns_service_url` | string | 提供商端点与凭据 |
| `buffer_days` | int | 过期前多少天续期 |
| `is_default` | bool | SNI 无匹配时使用该证书 |

`buffer_days` 是续期余量：`30` 时，90 天的 Let's Encrypt 证书在第 60 天续期。

## 证书存哪里

签发的证书经配置存储写回，因此：

- **etcd**：共享后端的每个实例自动拿到新证书。只需其中一个实例下单。
- **文件** 存储：证书落在配置目录。
- **快速启动**：证书持久化到 `~/.pingap/acme/<domains>.toml`（仅属主可读），下次启动恢复。

HTTP-01 challenge 令牌也经配置存储往返，因此 ACME 需要可写后端。

## 环境变量

| Variable | Effect |
| --- | --- |
| `PINGAP_DISABLE_ACME` | 跳过 ACME 后台任务。80 端口 challenge 监听器仍会创建。 |

适合预发或测试：其余配置行为一致，但不联系 Let's Encrypt。

## 速率限制

Let's Encrypt 对同一域名集合允许**每周 5 张重复证书**。切勿在重启或部署脚本中删除已持久化证书；临时容器若丢失配置目录要特别小心——崩溃循环可在几分钟内耗尽周配额。

## 添加 DNS 提供商

实现 `AcmeDnsTask`：

```rust
#[async_trait]
pub trait AcmeDnsTask: Sync + Send {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()>;
    /// Called when the challenge is over; removes the record added above.
    async fn done(&self) -> Result<()>;
}
```

然后在 `lets_encrypt.rs` 的 match 中接入提供商名。最小现有示例见 `dns_cf.rs`。

## 许可证

Apache-2.0。
