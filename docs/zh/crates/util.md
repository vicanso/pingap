# Pingap Util

Pingap 项目的工具集合。

## 功能

- **加解密**：AES-256-GCM-SIV 加密与解密。
- **格式化**：时长与字节大小的可读格式化。
- **IP 规则**：判断 IP 是否匹配一组规则（IP 与 CIDR）。
- **路径处理**：解析含 `~` 的路径并拼接 URL 路径。
- **PEM 处理**：从字符串、文件或 base64 转换 PEM 证书/密钥。
- **TOML 处理**：从 TOML 字符串移除空表。
- **版本信息**：获取包版本与 rustc 版本。
- **Base64**：编解码 base64 字符串。

## 安装

在 `Cargo.toml` 中加入：

```toml
[dependencies]
pingap-util = "0.12.0"
```

## 用法

### 加解密

```rust
use pingap_util::{aes_encrypt, aes_decrypt};

let key = "a-very-secret-key-that-is-32-bytes";
let data = "hello world";

let encrypted = aes_encrypt(key, data).unwrap();
let decrypted = aes_decrypt(key, &encrypted).unwrap();

assert_eq!(data, decrypted);
```

### 格式化

```rust
use pingap_util::{format_byte_size};

let mut buf = String::new();
format_byte_size(&mut buf, 1024 * 1024);
assert_eq!(buf, "1MB");
```

### IP 规则

```rust
use pingap_util::IpRules;

let rules = IpRules::new(&[
    "192.168.1.0/24",
    "10.0.0.1",
]);

assert!(rules.is_match("192.168.1.100").unwrap());
assert!(rules.is_match("10.0.0.1").unwrap());
assert!(!rules.is_match("172.16.0.1").unwrap());
```

### 路径处理

```rust
use pingap_util::{resolve_path, path_join};

// Note: This test depends on the user's home directory
// let home_path = dirs::home_dir().unwrap().to_string_lossy().to_string();
// assert_eq!(resolve_path("~/some/path"), format!("{}/some/path", home_path));

assert_eq!(path_join("/foo/", "/bar"), "/foo/bar");
```

### PEM 处理

```rust
use pingap_util::convert_pem;
use std::fs;
use base64::{engine::general_purpose::STANDARD, Engine};

// Example with a PEM string
let pem_str = "-----BEGIN CERTIFICATE-----
...";
let cert_bytes = convert_pem(pem_str).unwrap();

// Example with a file path
// fs::write("cert.pem", pem_str).unwrap();
// let cert_bytes_from_file = convert_pem("cert.pem").unwrap();

// Example with base64
// let pem_base64 = STANDARD.encode(pem_str);
// let cert_bytes_from_base64 = convert_pem(&pem_base64).unwrap();
```

### TOML 处理

```rust
use pingap_util::toml_omit_empty_value;

let toml_str = r#"
[a]
foo = "bar"
[b]
"#;

let cleaned_toml = toml_omit_empty_value(toml_str).unwrap();
assert_eq!(cleaned_toml.trim(), "[a]
foo = "bar"");
```

## 许可证

本项目采用 Apache-2.0 许可证。
