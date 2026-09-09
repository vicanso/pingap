# Pingap Certificate

The `pingap-certificate` crate is a robust TLS certificate management library designed for the Pingap project. It provides dynamic, Server Name Indication (SNI)-based certificate loading and selection for TLS servers built on the Pingora framework. This allows for seamless updates and management of TLS certificates for multiple domains on a single server instance.

## Key Features

- **Dynamic Certificate Loading**: Certificates and their private keys can be updated at runtime without requiring a server restart, ensuring high availability.
- **SNI-Based Certificate Selection**: Automatically selects the correct certificate during the TLS handshake based on the hostname provided by the client. This is essential for hosting multiple TLS-secured websites on a single IP address.
- **Wildcard Certificate Support**: Natively handles wildcard certificates (e.g., `*.example.com`) for securing multiple subdomains.
- **On-the-Fly Self-Signed Certificate Generation**: Includes a feature to act as a local Certificate Authority (CA) to generate self-signed certificates dynamically. This is particularly useful for development environments or for services that terminate TLS for arbitrary domains.
- **Certificate Validity Monitoring**: A background service periodically checks for certificates that are nearing their expiration date and can be configured to send notifications, preventing unexpected outages.
- **Let's Encrypt Chain Support**: Bundles common Let's Encrypt intermediate certificates to ensure proper chain of trust for certificates issued by Let's Encrypt.
- **Flexible Configuration**: Easily configured through `CertificateConf` structs, which can be loaded from various configuration sources.

## TLS backends

The crate is built for exactly one of pingora's TLS backends, chosen by the workspace's `openssl` (default) or `tls-rustls` feature. Certificate selection (exact, wildcard and default SNI matches, on-the-fly CA issuance) is shared; only the hand-over to pingora differs:

| | `openssl` | `tls-rustls` |
| --- | --- | --- |
| Selection hook | `TlsAccept::certificate_callback`, installing `X509`/`PKey` on the handshake | `ResolvesServerCert`, returning a prepared `CertifiedKey` |
| `tls_min_version` / `tls_max_version` | honoured | rejected at config validation (always TLS 1.2 + 1.3) |
| `tls_cipher_list` / `tls_ciphersuites` | honoured | rejected at config validation (rustls defaults) |
| Crypto provider | OpenSSL | aws-lc-rs via `install_default_crypto_provider()` early in `main` |

`LoadedCertificate` holds a certificate in the active backend's form, and `TLS_BACKEND` names the backend at runtime (`--version` long form, startup log, admin `/basic` features). Under rustls, `validate_servers_tls_for_backend` fails startup / `--test` / auto-restart when any of the unsupported per-server TLS fields are set.

## How it Works

The core of the crate is `GlobalCertificate`: SNI selection (exact → wildcard →
default, with on-the-fly CA issuance) is shared; only the hand-over to pingora
branches by backend — OpenSSL implements `TlsAccept::certificate_callback`,
rustls implements `ResolvesServerCert`.

The certificate store is an `arc_swap::ArcSwap` around a hash map, so the whole
set can be updated atomically without locks. A config change builds a new map
and swaps it in, so inbound requests always see a consistent view.

## Modules

The crate is organized into several modules, each with a specific responsibility:

- `lib.rs`: The main entry point of the crate. It defines the primary `Certificate` data structure and utility functions for parsing PEM-encoded certificates and keys.
- `dynamic_certificate.rs`: Contains the core logic for dynamic certificate management and SNI-based selection. It defines the `GlobalCertificate` struct and manages the global certificate store.
- `tls_backend.rs`: `TLS_BACKEND`, `install_default_crypto_provider`, and `validate_servers_tls_for_backend`.
- `tls_certificate.rs`: Defines the `TlsCertificate` struct, which encapsulates a certificate, private key, and associated metadata. It also contains the logic for generating new certificates signed by a CA.
- `self_signed.rs`: Manages the lifecycle of dynamically generated self-signed certificates, including their creation, caching, and periodic cleanup of stale certificates.
- `validity_checker.rs`: Implements the background task that periodically checks for expiring certificates and sends warnings.
- `chain.rs`: Provides helper functions to access bundled Let's Encrypt intermediate certificates.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).