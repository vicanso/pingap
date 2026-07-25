# Pingap Certificate

`pingap-certificate` 是为 Pingap 设计的稳健 TLS 证书管理库。为基于 Pingora 的 TLS 服务器提供动态、基于 SNI 的证书加载与选择。使单机实例可无缝更新与管理多域名 TLS 证书。

## 关键特性

- **动态证书加载**：证书与私钥可在运行时更新，无需重启，保证高可用。
- **基于 SNI 的证书选择**：TLS 握手时根据客户端提供的主机名自动选择正确证书。适合单 IP 托管多个 TLS 站点。
- **通配符证书支持**：原生处理通配符证书（如 `*.example.com`），保护多个子域。
- **即时自签证书生成**：可作为本地 CA 动态生成自签证书。适合开发环境或为任意域名终止 TLS 的服务。
- **证书有效期监控**：后台服务周期性检查即将过期的证书，可配置发送通知，避免意外中断。
- **Let's Encrypt 链支持**：捆绑常见 Let's Encrypt 中间证书，确保 Let's Encrypt 签发证书的信任链完整。
- **灵活配置**：通过 `CertificateConf` 结构体轻松配置，可从多种配置源加载。

## 工作原理

crate 核心是实现 `pingora::listeners::TlsAccept` 的 `GlobalCertificate`。TLS 握手时调用其 `certificate_callback`。该方法检查客户端 hello 中的 SNI 主机名，并在全局、线程安全的证书存储中查找对应证书。

存储用 `arc_swap::ArcSwap` 包装哈希表实现，可对整套证书做原子、无锁更新。配置变更时创建新证书映射并与旧映射交换，确保入站请求始终看到一致的证书视图。

查找逻辑优先精确域名匹配，再回退通配符匹配，最后使用已配置的默认证书。

## 模块

crate 按职责分为多个模块：

- `lib.rs`：crate 入口。定义主 `Certificate` 数据结构与解析 PEM 证书/密钥的工具函数。
- `dynamic_certificate.rs`：动态证书管理与基于 SNI 选择的核心逻辑。定义 `GlobalCertificate` 并管理全局证书存储。
- `tls_certificate.rs`：定义封装证书、私钥与元数据的 `TlsCertificate`，以及由 CA 签发新证书的逻辑。
- `self_signed.rs`：管理动态生成自签证书的生命周期，含创建、缓存与陈旧证书清理。
- `validity_checker.rs`：周期性检查即将过期证书并发送警告的后台任务。
- `chain.rs`：访问捆绑 Let's Encrypt 中间证书的辅助函数。

## 许可证

本项目采用 [Apache 2.0 许可证](https://github.com/vicanso/pingap/blob/main/LICENSE)。
