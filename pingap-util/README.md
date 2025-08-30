# Pingap Util

A collection of utilities for the Pingap project.

## Features

- **Cryptography**: AES-256-GCM-SIV encryption and decryption.
- **Formatting**: Human-readable formatting for durations and byte sizes.
- **IP Rules**: Check if an IP address matches a set of rules (IPs and CIDR networks).
- **Path Manipulation**: Resolve paths containing `~` and join URL paths.
- **PEM Handling**: Convert PEM-formatted certificates/keys from strings, files, or base64.
- **TOML Manipulation**: Remove empty tables from a TOML string.
- **Version Information**: Get package and rustc versions.
- **Base64**: Encode and decode base64 strings.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
pingap-util = "0.12.0"
```

## Usage

### Cryptography

```rust
use pingap_util::{aes_encrypt, aes_decrypt};

let key = "a-very-secret-key-that-is-32-bytes";
let data = "hello world";

let encrypted = aes_encrypt(key, data).unwrap();
let decrypted = aes_decrypt(key, &encrypted).unwrap();

assert_eq!(data, decrypted);
```

### Formatting

```rust
use pingap_util::{format_byte_size};

let mut buf = String::new();
format_byte_size(&mut buf, 1024 * 1024);
assert_eq!(buf, "1MB");
```

### IP Rules

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

### Path Manipulation

```rust
use pingap_util::{resolve_path, path_join};

// Note: This test depends on the user's home directory
// let home_path = dirs::home_dir().unwrap().to_string_lossy().to_string();
// assert_eq!(resolve_path("~/some/path"), format!("{}/some/path", home_path));

assert_eq!(path_join("/foo/", "/bar"), "/foo/bar");
```

### PEM Handling

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

### TOML Manipulation

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

## License

This project is licensed under the Apache-2.0 License.
