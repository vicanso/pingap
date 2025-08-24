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

## How it Works

The core of the crate is the `GlobalCertificate` struct, which implements the `pingora::listeners::TlsAccept` trait. During the TLS handshake, its `certificate_callback` method is invoked. This method inspects the SNI hostname from the client hello message and looks up the corresponding certificate in a globally managed, thread-safe certificate store.

This store is implemented using an `arc_swap::ArcSwap` containing a hash map, which allows for atomic, lock-free updates to the entire set of certificates. When a configuration change occurs, a new certificate map is created and swapped with the old one, ensuring that incoming requests always see a consistent view of the certificates.

The lookup logic prioritizes exact domain matches, then falls back to wildcard matches, and finally to a default certificate if one is configured.

## Modules

The crate is organized into several modules, each with a specific responsibility:

- `lib.rs`: The main entry point of the crate. It defines the primary `Certificate` data structure and utility functions for parsing PEM-encoded certificates and keys.
- `dynamic_certificate.rs`: Contains the core logic for dynamic certificate management and SNI-based selection. It defines the `GlobalCertificate` struct and manages the global certificate store.
- `tls_certificate.rs`: Defines the `TlsCertificate` struct, which encapsulates a certificate, private key, and associated metadata. It also contains the logic for generating new certificates signed by a CA.
- `self_signed.rs`: Manages the lifecycle of dynamically generated self-signed certificates, including their creation, caching, and periodic cleanup of stale certificates.
- `validity_checker.rs`: Implements the background task that periodically checks for expiring certificates and sends warnings.
- `chain.rs`: Provides helper functions to access bundled Let's Encrypt intermediate certificates.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).