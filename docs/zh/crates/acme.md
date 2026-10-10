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

Pingap 在 `/.well-known/acme-challenge/<token>` 自行提供 challenge。若配置中没有任何 server 监听 80，进程启动时会自动添加名为 `lets encrypt` 的监听器——无需手写。`addr` 里写了多个地址的 server，只要其中一个是 80 端口就算（`0.0.0.0:80,[::]:8080`）；以前只看最后一个地址，结果在已经被占用的地址上又加了一次监听。这个路径只回答正在进行的验证所用的 token；其他名字一律返回 `404`，包括同一存储里其他条目的名字（ACME 账号、includes）。

只有运行中的配置里有用这种验证方式申请的证书时，这个路径才归 Pingap 处理。没有这样的证书时，发到这个路径的请求和其他请求一样交给 location，所以 Pingap 后面的服务可以运行自己的 ACME 客户端。

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

规范名称是 `ali` 与 `cf`；早期文档用过 `aliyun`、`cloudflare`，作为别名仍可接受。其他任何值会被 `pingap -t` 拒绝，而不是静默回退到 manual 任务、等待没人会添加的 TXT。

`dns_service_url` 中任意查询参数的值，或者整个值，可写成 `$ENV:NAME` 并从环境读取，密钥不必进配置文件。写在查询参数里时，变量未设置则保持原文。整个值写成引用时，遵循配置里其他所有值的规则（见 [pingap-config](config.md)，那里还有 `$FILE:/path`）：变量未设置是配置错误，而以前是把这段原文传给服务商。

提供商添加 `_acme-challenge` TXT、等待校验后删除。zone 取记录名的可注册域名，按公共后缀列表解析（`example.co.uk`，而不是 `co.uk`）。`manual`（或空提供商）时 challenge 每个进程启动只尝试一次，条目有变化时再尝试一次，因为没有可轮询的对象；TXT 值记入日志，同时写入 storage 类别，一天后由每小时的清扫删除。

## 证书配置

| Key | Type | Description |
| --- | --- | --- |
| `domains` | string | 逗号分隔的域名列表 |
| `acme` | string | `lets_encrypt` 以启用 ACME |
| `dns_challenge` | bool | 使用 DNS-01 而非 HTTP-01 |
| `dns_provider` | string | `ali`、`cf`、`huawei`、`tencent`、`manual` |
| `dns_service_url` | string | 提供商端点与凭据 |
| `buffer_days` | int | 过期前多少天续期。默认 `14`，证书有效期的三分之一比它短时取后者 |
| `acme_directory` | string | CA 的 directory 地址。默认 Let's Encrypt 的生产环境 |
| `acme_ca` | string | 用来校验 CA 自身证书的根证书（PEM 文件），用于自建 CA。默认使用系统的根证书 |
| `acme_eab_kid`、`acme_eab_hmac` | string | 外部账号绑定：CA 给出的 key id 和对应的 HMAC key |
| `acme_contact` | string | 账号的联系邮箱，逗号分隔 |
| `acme_key_type` | string | 证书的密钥：`ecdsa`（P-256，默认）或 `rsa`（2048 位） |
| `is_default` | bool | SNI 无匹配时使用该证书 |

`buffer_days` 是续期余量：`30` 时，90 天的 Let's Encrypt 证书在第 60 天续期。不设置时余量是 14 天（以前是 2 天，订单一直失败时几乎没有发现和处理的时间），并且不超过证书有效期的三分之一：有效期 6 天的证书在到期前 2 天续期。

设置了 `acme` 的证书由本任务续期，所以在续期还没有逾期之前，每天的过期告警（`tls_validity`，给需要人工更换的证书用的）不会提到它。续期余量过半仍未续上时同样会告警，最晚在到期前一周：这时续期已经失败了一段时间，或者根本不会发生（设置了 `PINGAP_DISABLE_ACME`，或者用的是手工 DNS 验证，它只在进程启动或条目有变化时执行一次）。续期出问题时会即时通知，见[订单没有成功时](#订单没有成功时)。

## 使用其他 CA

证书默认向 Let's Encrypt 申请，条目里指定了别的 ACME 服务时向它申请：

```toml
# Let's Encrypt 的 staging 环境：试验用，不占正式环境的配额。它签的证书不被信任。
[certificates.trial]
domains = "example.com"
acme = "lets_encrypt"
acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"

# 要求账号绑定的 CA（ZeroSSL、Google Trust Services）：key id 和 key 在它的控制台里取。
[certificates.site]
domains = "example.com,*.example.com"
acme = "lets_encrypt"
acme_directory = "https://acme.zerossl.com/v2/DV90"
acme_eab_kid = "$ENV:EAB_KID"
acme_eab_hmac = "$ENV:EAB_HMAC"
acme_contact = "ops@example.com"
dns_challenge = true
dns_provider = "cf"
dns_service_url = "https://api.cloudflare.com?token=$ENV:CF_TOKEN"

# 自建的 CA（step-ca）：它的 directory，以及签发它自身证书的根证书。
[certificates.internal]
domains = "app.internal.example"
acme = "lets_encrypt"
acme_directory = "https://ca.internal.example/acme/acme/directory"
acme_ca = "/etc/pingap/internal-root.pem"
```

- `acme` 仍然写 `lets_encrypt`：它的作用是给这个条目开启 ACME，不论 CA 是谁。
- **`acme_directory`** 必须是 `https` 地址。订单的其余部分和 Let's Encrypt 一样：验证方式、续期余量、证书存放的位置。
- **`acme_ca`** 是文件路径，每次下单时读取。不配时 CA 的证书必须是系统信任的，公共 CA 都满足。
- **外部账号绑定**：`acme_eab_kid` 和 `acme_eab_hmac` 要同时配置。key 按 CA 展示的 base64 原样填写（规范里是 URL 字母表、不带填充；带填充的和标准字母表的也接受）。它是凭据：配置变更的日志里会被遮蔽，也可以写成 `$ENV:NAME` 或 `$FILE:/path`。
- **`acme_contact`** 在创建账号时写入。已经存在的账号保留它原有的联系方式。
- **`acme_key_type = "rsa"`** 申请 2048 位 RSA 密钥的证书，给不支持 ECDSA 的客户端用。默认的 `ecdsa` 是 P-256 密钥。两种都要时，给这个域名写两个 `domains` 相同的条目，其中一个设置 `acme_key_type = "rsa"`：两张证书各自申请、各自续期，握手时用客户端能验证的那一张签名（见 `pingap-certificate` 的说明）。
- **`domains` 一律按小写申请**，不论配置里怎么写。以前写成 `Example.com` 时，签回来的证书（`example.com`）永远和条目里的域名对不上，每次检查都会重新申请。
- **每个 CA 一个账号。** 账号凭据保存在配置存储里：Let's Encrypt 的两个环境是 `lets_encrypt_account` 和 `lets_encrypt_staging_account`，其他 directory（以及要求绑定的 CA 上的每个绑定）是 `acme_account_<hash>`，所以同一个 CA 的证书共用一个账号。directory 或绑定改了就是另一个账号，下一次下单时创建。
- 已有且未到续期时间的证书不会被动：改了 `acme_directory` 或 `acme_key_type` 的条目，要到下一次续期才会从新的 CA、用新的密钥类型签发。
- `acme_directory`、`acme_ca`、绑定和密钥类型随配置一起校验（`pingap -t`）：不是 `https` 的地址、只配了一半的绑定、不是 base64 的 key、不存在的密钥类型，都在这时报错，而不是几周后下单时才发现。

还没有的：TLS-ALPN-01 验证、按 CA 建议的时间续期（ARI）、内置四家之外的 DNS 服务商。

## 证书存哪里

签发的证书经配置存储写回，因此：

- **etcd**：共享后端的每个实例自动拿到新证书。只需其中一个实例下单。
- **文件** 存储：证书落在配置目录。
- 共用存储的实例共用证书：下单之前先读存储里的条目，如果里面已经有同样域名、余量充足的证书（另一个实例已经续期），就直接安装，不再下单。以前每个实例只看自己运行中的配置，各自申请一张，实例多了会碰到 CA 的重复签发限制。两个实例恰好同时检查时仍可能各下一单，实例之间没有协调。新增或修改的条目，各实例会在同一分钟内检查，所以验证耗时超过一分钟时（DNS-01）每个实例都会下单。
- **快速启动**：证书持久化到 `~/.pingap/acme/<domains>.toml`（仅属主可读），下次启动恢复。

验证路径（`/.well-known/acme-challenge/<token>`）在插件之前处理（`early_request` 阶段的插件除外），对任何人开放，80 端口上的每个 server 都会处理——这个 server 还监听了别的地址时，那些地址上也一样。是否处理取决于请求到达时运行中的配置，而不是进程启动时的配置：热更新加进来的证书在现有的 server 上完成验证，热更新去掉之后这个路径交还给 location。没有证书需要这种验证时也不会为它去读存储，所以存储不可用不会拖住别人的验证请求。

本进程发起的订单的 token 直接从内存应答；其他 token 可能属于共用存储的另一个实例的订单，或者重启前上一个进程的订单，所以要到存储里的 token 中去找。存储里的 token 一秒内不管多少请求只读一次，读取期间到达的请求等这一次读取的结果：大量伪造 token 的请求每秒只换来一次读取，也挡不住真实 token 被找到。订单把 token 写入存储之后，等 1.5 秒才通知 CA 来验证，保证没有实例还在用比 token 更早的读取结果应答。以前每个请求都会读一次存储：重新解析整份配置文件，或者向 etcd 发一次请求，谁都可以这样做。

HTTP-01 challenge 令牌也经配置存储往返，因此 ACME 需要可写后端。令牌保存时带 `created_at` 时间戳并每小时清扫一次：超过一天的（远超共享存储的任何实例仍可能向 CA 提供它的时间窗口）会被删除，令牌不再在存储类别里无限堆积。

ACME 账号也存在那里：storage 类别的 `lets_encrypt_account` 条目（对 staging CA 是 `lets_encrypt_staging_account`），之后每次下单、共享后端的任一实例都复用它。原来每次下单都注册一个新账号，而 Let's Encrypt 对此按 IP 限流；存下的账号不再可用时会换新的。该条目保存账号私钥，和证书条目保存 `tls_key` 一样。

## 环境变量

| Variable | Effect |
| --- | --- |
| `PINGAP_DISABLE_ACME` | 跳过 ACME 后台任务。80 端口 challenge 监听器仍会创建。这时本进程不会申请也不会保存证书，所以热更新把 `acme` 条目当作普通条目处理：用存储里它现有的证书。 |

适合预发或测试：其余配置行为一致，但不联系 Let's Encrypt。

## 不重启就新增和修改条目

使用 `--autoreload` 或 `--autorestart` 时，配置里新增的 `acme` 条目，或者设置有变化的条目（`domains`、验证方式、CA、`buffer_days`），由热更新交给 ACME 任务。任务在下一次运行时就检查这个条目，不用等十分钟一次的检查：热更新之后一分钟之内，或者等它手上正在进行的订单结束。之前下单失败攒下的等待时间作废，因为那是针对旧设置的。原本不是 ACME、现在加上了 `acme` 的条目，如果已经有证书，证书的域名和条目写的完全一致、并且还没进入续期余量时继续用；否则立即重新申请。

新证书到位之前，条目用现有的证书为它现在写的域名提供服务。已经归 ACME 任务管理的条目，热更新不会从存储里取它的证书和私钥：这两项由任务自己保存、自己启用。

下单至少要几秒，等 DNS 记录生效时要几分钟。这期间对条目的修改会保留：新证书写进下单结束时存储里的那个条目，改过的设置在下一次运行时再下单。这期间被删除的条目不会被写回来，这期间不再归 ACME 的条目（去掉了 `acme`、换上了自己的证书）保持你给它的内容；申请到的证书丢弃，日志里有记录。任务正忙于另一个条目的订单时被修改的条目，不会按修改前的设置下单，同样等到下一次运行。

多个实例共用存储时，各实例各自热更新，前后相差片刻。还没拿到新配置、又没有别的 HTTP-01 证书的实例，会把另一个实例那笔订单的验证请求交给 location；那笔订单失败，按通常的等待时间重试。

热更新加不了的是监听端口。HTTP-01 验证需要 80 端口上的 server，而 `lets encrypt` 这个监听器只在进程启动时添加（设置了 `PINGAP_DISABLE_ACME` 的进程也一样：它要替下单的实例应答验证）。进程启动时既没有 80 端口的 server、也没有 HTTP-01 的条目，那么之后新增的这类条目要等重启：`--autorestart` 会执行重启；`--autoreload` 打一条警告日志并发出一条 `warn` 级别的 `reload_config_fail` 通知，证书在重启之前不会去申请。在配置里写一个 80 端口的 server，或者改用 DNS-01，可以避免这种情况。

手工应答的验证（`dns_provider = "manual"`）只发起一次：进程启动时，或者条目是新增的、有变化的时候。

## 订单没有成功时

每十分钟检查一次证书，缺失、进入续期余量，或者不再覆盖配置的域名时下单。下单失败会连同出错的步骤写入日志，并发出一条 `error` 级别的 `lets_encrypt` 通知，之后等一段时间再试，连续失败时等待时间逐次翻倍：十分钟、二十分钟、四十分钟，最长六小时。以前是每次检查都重试，比 CA 允许的“每个域名每小时 5 次验证失败”还频繁。下单成功，或者存储里出现了可用的证书，等待就结束；重启、或者修改条目的设置也会清掉等待。

下单成功但拿到的证书对这个条目来说不能用，同样算失败并进入等待：`buffer_days` 不小于 CA 签发的证书有效期，或者 `domains` 和证书里的域名不一致（重复、大写）。证书照常安装，但要等到等待结束才会再次申请，而不是每十分钟一次。

配置里其他证书加载失败不再有影响：新证书照常安装并记录，其他证书的问题以 `parse_certificate_fail` 通知。（以前新证书已经在用，却没有被记录，于是每十分钟重新申请一次。）

- 与 CA、与 DNS 服务商的每一次交互都有时限：一分钟内没有应答的请求会让本次尝试失败；订单的验证超过额度（每个域名两分半钟，另加三分钟）也一样。已经添加的 TXT 记录无论如何都会删除。不会在一条不再有数据的连接上一直等下去。
- CA 会把一次成功的验证记住一段时间。在这段时间里创建的订单直接是 `ready` 状态，不需要再验证，直接进入签发。
- 存储必须可写：账号、验证 token 和证书都要保存进去。配置是由 `.hcl` 或 `.kdl` 文件组成的目录时存储是只读的，这种情况下不会向 CA 发出任何请求。存储里的条目已经不归 ACME、而进程仍按旧配置运行时（没有开热更新，或者热更新一直失败）也一样；配置目录里有布局以外的文件、或者有表放错了文件，使得证书、账号或 token 的写入会被拒绝时也一样：存不进去的就不申请。
- 使用 `--autorestart` 时，ACME 任务中途写入的内容（账号、token）不会触发进程重启，新证书就地生效。修改 `acme` 条目同样不会触发重启，除非需要新的监听端口（见上文）。存储里的证书和运行中的不一样时（另一个实例续期了，或者被手工改过）仍然会重启，和以前一样。

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
