# Pingap Certificate

`pingap-certificate` 是为 Pingap 设计的稳健 TLS 证书管理库。为基于 Pingora 的 TLS 服务器提供动态、基于 SNI 的证书加载与选择。使单机实例可无缝更新与管理多域名 TLS 证书。

## 关键特性

- **动态证书加载**：证书与私钥可在运行时更新，无需重启，保证高可用。
- **基于 SNI 的证书选择**：TLS 握手时根据客户端提供的主机名自动选择正确证书。适合单 IP 托管多个 TLS 站点。
- **通配符证书支持**：原生处理通配符证书（如 `*.example.com`），保护多个子域。
- **同一域名的 RSA 和 ECDSA 双证书**：一个域名可以有两张证书，一张 RSA 密钥、一张 ECDSA 密钥。每次握手用客户端能验证的那一张签名，老客户端照常可用，其余客户端用更小、更省 CPU 的 ECDSA 签名。
- **即时自签证书生成**：可作为本地 CA 动态生成自签证书。适合开发环境或为任意域名终止 TLS 的服务。同一时间最多缓存 2048 张签发的证书；超过之后仍会为握手签发证书，但不再缓存，所以客户端发来的域名不会让缓存无限增长。缓存同时按 CA 的名字和内容区分，同名的 CA 换了证书后会重新签发，不再沿用旧 CA 签出的证书；已过期的签发证书会重新签发，每日检查会清掉两天内到期的条目。
- **OCSP Stapling**：证书设置 `ocsp_stapling` 后，后台向 CA 的 OCSP 响应服务获取应答，握手时随证书一起发送，客户端不必再去向 CA 查询证书是否被吊销。
- **证书有效期监控**：后台服务周期性检查即将过期的证书，可配置发送通知，避免意外中断。每张证书只检查一次，按配置名上报（日志附带其域名），不论它服务多少个域名。
- **Let's Encrypt 链支持**：捆绑常见 Let's Encrypt 中间证书，确保 Let's Encrypt 签发证书的信任链完整。
- **灵活配置**：通过 `CertificateConf` 结构体轻松配置，可从多种配置源加载。

## TLS 后端

本 crate 只针对 pingora 的一种 TLS 后端构建，由 workspace 的 `openssl`（默认）或 `tls-rustls` 特性选择。证书选择逻辑（SNI 精确 / 通配 / 默认匹配、CA 即时签发）两者共用，只有交给 pingora 的方式不同：

| | `openssl` | `tls-rustls` |
| --- | --- | --- |
| 选择入口 | `TlsAccept::certificate_callback`，握手时装入 `X509`/`PKey` | `ResolvesServerCert`，返回预先构建的 `CertifiedKey` |
| OCSP stapling | 状态回调（`SSL_CTX_set_tlsext_status_cb`）给出 OpenSSL 选定的那张证书的应答 | 应答是 resolver 返回的 `CertifiedKey` 的一部分 |
| 同一域名的两张证书 | 两张都装上，各带各的证书链；OpenSSL 按客户端的签名算法选择，TLS 1.3 以下还要看协商出的加密套件 | 按 ClientHello 选择：客户端只给出了适用于 RSA 那张的签名算法和加密套件时用 RSA 的，其余情况用 ECDSA 的 |
| `tls_min_version` / `tls_max_version` | 生效 | 配置校验拒绝（固定 TLS 1.2 + 1.3） |
| `tls_cipher_list` / `tls_ciphersuites` | 生效 | 配置校验拒绝（rustls 默认套件） |
| 密码学库 | OpenSSL | aws-lc-rs，由 `install_default_crypto_provider()` 在 `main` 早期安装 |

`LoadedCertificate` 以当前后端的形式保存证书，`TLS_BACKEND` 在运行时给出后端名称（`--version` 长格式、启动日志、admin `/basic` features）。rustls 下若任一不支持的 per-server TLS 字段被设置，`validate_servers_tls_for_backend` 会让启动 / `--test` / auto-restart 失败。

## 工作原理

crate 核心是 `GlobalCertificate`：SNI 选择逻辑（精确 → 通配 → 默认，CA 条目即时签发）两边共用，交给 pingora 的方式按后端分支——OpenSSL 实现 `TlsAccept::certificate_callback`，rustls 实现 `ResolvesServerCert`。

证书存储用 `arc_swap::ArcSwap` 包装哈希表，可对整套证书做原子、无锁更新。配置变更时创建新映射并与旧映射交换，确保入站请求始终看到一致的证书视图。`update_certificates(configs, previous)` 在构建新映射时沿用配置（含文件路径所指文件内容）未变的证书，因此重载只解析、加载有变化的证书，并只上报这些名字；`parse_certificates` 是不复用任何旧证书的同一过程。

### 同一域名的两张证书

一个域名由一张证书提供服务，或者由两张密钥类型不同的证书提供服务：一张 RSA，一张不是 RSA（ECDSA 或 Ed25519）。没有专门的配置项，两个条目写同一个域名即可：

```toml
[certificates.site-ecdsa]
domains = "example.com,*.example.com"
tls_cert = "/opt/certs/ecdsa/fullchain.pem"
tls_key = "/opt/certs/ecdsa/privkey.pem"

[certificates.site-rsa]
domains = "example.com,*.example.com"
tls_cert = "/opt/certs/rsa/fullchain.pem"
tls_key = "/opt/certs/rsa/privkey.pem"
```

只能验证其中一种的客户端拿到那一种，带着它自己的证书链。两种都能验证的客户端，rustls 后端下拿到 ECDSA 的那张，OpenSSL 后端下拿到它排在前面的那种——对现在在用的浏览器和库来说就是 ECDSA。通配符证书和默认证书（每种类型各一个条目设置 `is_default`）同样如此。使用 ACME 时，第二个条目写相同的 `domains` 并设置 `acme_key_type = "rsa"`。

- 选择的三个步骤不混用：某个域名自己只有一张 RSA 证书时就用这一张，不会再从它的通配符证书那里补一张 ECDSA 的。
- 两个条目用同一种密钥写了同一个域名，就多了一个：只有其中一个提供服务，日志里有一条警告指出两者（`serving`、`ignored`）。用哪一个是确定的：没有设置 `acme` 的条目排在设置了的前面，其余按名字取第一个。以前取决于哈希表的遍历顺序，每个进程、每次重载都可能不同；两个条目都是文件路径时，文件重载的每一轮还会换成另一个。没有提供服务的那个条目仍然会被加载：照常检查有效期，admin 里也能看到。
- 设置了 `is_ca` 的条目不论 CA 自己的密钥是什么都算 ECDSA：它签发的证书是 ECDSA 密钥。
- OpenSSL 后端下选择结果受监听器的 `tls_cipher_list` 影响：列表里没有任何 ECDHE-ECDSA 套件时，TLS 1.2 的客户端只会拿到 RSA 证书。两者之间的先后由客户端决定——TLS 1.3 以下看它的加密套件顺序，TLS 1.3 看它的签名算法顺序：pingora 的监听器没有设置 OpenSSL 的服务端优先。

域名的比较不区分大小写，和 DNS 一样：`domains = "Example.com"` 为 `example.com` 提供服务，客户端把名字写成大写也能匹配。以前这样写的条目是一个任何握手都不会请求的名字；设置了 `acme` 时，CA 签回的证书里的名字和配置里写的永远不一致，每次检查都会重新申请。

### OCSP stapling

```toml
[certificates.site]
domains = "example.com"
tls_cert = "/opt/certs/fullchain.pem"
tls_key = "/opt/certs/privkey.pem"
ocsp_stapling = true
```

设置 `ocsp_stapling = true` 后，Pingap 向证书里（authority information access 扩展）写明的 OCSP 响应服务查询这张证书，并在客户端要求时把应答放进握手。客户端不用自己去问 CA，就拿到了 CA 对“证书没有被吊销”的说明。默认关闭。

- **会被装订的应答。** 只有同时满足以下条件的应答：状态是 good；由证书的签发者签名，或者由签发者授权签 OCSP 应答的响应服务证书签名；并且在有效期内（生成时间不在将来，也没有过期）——应答必须写明有效到什么时候（`nextUpdate`；私有 CA 的响应服务可能不写，这时什么都不装订）。不满足的应答只记日志、不使用——会校验的客户端会因为它拒绝握手。这里无法校验的签名类型（比如 P-521 的 ECDSA）按没有签名处理，日志里是 `not signed by the issuer`。
- **放进握手的内容** 不是响应服务发来的原始字节，而是用 CA 签名的那部分、签名本身、以及响应服务的证书（它不是 CA 自己时）重新组装的，最大 12 KiB，签名算法的写法也统一成唯一的一种（因此不接受 RSA-PSS 签名的应答）。签名只覆盖声明本身，不覆盖它外面的部分，而响应服务是通过明文 HTTP 访问的：否则路径上的人可以往一份能通过所有检查的应答里加东西，让解析严格的客户端因此中断握手。出于同样的原因，应答里必须按查询时的方式（签发者的 SHA-1 哈希）标识证书，查询请求也不跟随重定向。
- **前提。** `tls_cert` 里叶子证书后面要有签发者的证书：应答的签名用它来校验。证书里还要写有 `http` 地址的响应服务。缺任何一项，证书照常提供服务，日志里有一条警告说明缺的是哪一项（`ocsp stapling is not possible for this certificate`）。CA 条目（`is_ca`）和它签发的证书不做装订。Let's Encrypt 已经停止提供 OCSP 响应服务，它的证书里不再写这个地址。
- **什么时候去查询。** 由后台任务查询，握手过程中不会去查：启动后（或带来这张证书的重载之后）一分钟之内，在此之前握手不带应答；拿到应答一小时后；应答快过期时提前五分钟。每次查询最多等 10 秒，是从 Pingap 所在的机器发出的普通 HTTP `POST`（遵守常用的代理环境变量）。同时最多查询 8 张证书。
- **查询不到时。** 已有的应答继续使用到它过期；之后握手不带应答，但不会失败。一分钟后重试，之后间隔依次为两分钟、四分钟……最长一小时；连续失败的第 1、2、4、8……次写日志（`no ocsp answer to staple`）。响应服务表示证书已被吊销时，立即撤掉已有的应答，并记一条 error 日志。
- **同一域名的两张证书** 各有各的应答，发送的是握手所用那张证书的应答。
- 应答只保存在内存里：重启之后重新查询。
- 带 must-staple 扩展的证书没有特殊处理：第一份应答到来之前，以及响应服务不可用的时间超过上一份应答的有效期时，握手不带应答，坚持要求装订的客户端会连接失败。

证书与私钥是一起加载的，私钥与证书不配对在两种 TLS 后端下都是错误，`pingap -t` 和 admin 保存时都会报告。（OpenSSL 自身只在握手时安装这一对的时候才会报错，以前的结果是受影响域名的每次握手都在运行时失败。）热更新时某个条目构建失败会被上报，它原本要替换的证书继续为原来的域名提供服务；失败条目里新的 `domains` 和 `is_default` 不会生效。

`tls_cert` / `tls_key` 以文件路径给出的证书，在文件内容变化时会重新加载，不需要改配置：重载服务每一轮都会对这些文件计算 hash（`CertificateConf::reads_files`、`hash_key`）。原地替换 `fullchain.pem` 和 `privkey.pem` 的续期，几秒之内生效。和其他重载一样，需要进程带 `--autoreload` 或 `--autorestart` 运行。同一份配置里由 ACME 管理的证书仍由 ACME 服务负责，不受影响。

配置变更时证书按条目逐个热更新。不是 ACME 的条目原地新增、替换或删除，配置里同时有 ACME 条目时也一样；以前只要配置里有一个 `acme` 条目，所有证书都要等到重启才更新。新配置里设置了 `acme` 的条目保持原样，新增的这类条目也不会加入：它的证书由 ACME 服务申请和保存，对其设置（`domains`、验证方式）的修改需要重启才生效——`--autorestart` 会执行重启，`--autoreload` 只打一条警告日志。去掉了 `acme` 的条目或被删除的条目和其他条目一样热更新，ACME 服务不再为它续期。两个条目写了同一个域名时，正在为该域名提供服务的那个被删除后，域名交给另一个。

OpenSSL 后端下，被 OpenSSL 拒绝的 `tls_cipher_list`、`tls_ciphersuites`、`tls_min_version`、`tls_max_version`（或 `tlsv1.1`/`tlsv1.2`/`tlsv1.3` 以外的版本名；大小写不敏感）在构建监听器时报错，服务器不会带着与配置不同的设置启动。

## 模块

crate 按职责分为多个模块：

- `lib.rs`：crate 入口。定义主 `Certificate` 数据结构与解析 PEM 证书/密钥的工具函数。
- `dynamic_certificate.rs`：动态证书管理与基于 SNI 选择的核心逻辑。定义 `GlobalCertificate` 并管理全局证书存储。
- `tls_backend.rs`：`TLS_BACKEND`、`install_default_crypto_provider` 与 `validate_servers_tls_for_backend`。
- `tls_certificate.rs`：定义封装证书、私钥与元数据的 `TlsCertificate`，以及由 CA 签发新证书的逻辑。
- `ocsp.rs`：OCSP stapling：构造查询请求、校验响应服务的应答，以及定期刷新应答的后台任务。
- `self_signed.rs`：管理动态生成自签证书的生命周期，含创建、缓存与陈旧证书清理。
- `validity_checker.rs`：周期性检查即将过期证书并发送警告的后台任务。
- `chain.rs`：访问捆绑 Let's Encrypt 中间证书的辅助函数。

## 许可证

本项目采用 [Apache 2.0 许可证](https://github.com/vicanso/pingap/blob/main/LICENSE)。
