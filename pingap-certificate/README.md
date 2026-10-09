# Pingap Certificate

The `pingap-certificate` crate is a robust TLS certificate management library designed for the Pingap project. It provides dynamic, Server Name Indication (SNI)-based certificate loading and selection for TLS servers built on the Pingora framework. This allows for seamless updates and management of TLS certificates for multiple domains on a single server instance.

## Key Features

- **Dynamic Certificate Loading**: Certificates and their private keys can be updated at runtime without requiring a server restart, ensuring high availability.
- **SNI-Based Certificate Selection**: Automatically selects the correct certificate during the TLS handshake based on the hostname provided by the client. This is essential for hosting multiple TLS-secured websites on a single IP address.
- **Wildcard Certificate Support**: Natively handles wildcard certificates (e.g., `*.example.com`) for securing multiple subdomains.
- **RSA and ECDSA for One Domain**: A domain can have two certificates, one with an RSA key and one with an ECDSA key. Each handshake is signed with the one its client can verify, so old clients keep working while the rest get the smaller and cheaper ECDSA signature.
- **On-the-Fly Self-Signed Certificate Generation**: Includes a feature to act as a local Certificate Authority (CA) to generate self-signed certificates dynamically. This is particularly useful for development environments or for services that terminate TLS for arbitrary domains. At most 2048 issued certificates are kept at a time; past that a certificate is still issued for the handshake but not cached, so the server names clients send cannot grow the cache without bound. The cache goes by the CA's content as well as its name, so a CA replaced under the same name signs anew instead of handing out what the old one issued; an issued certificate that has expired is issued again, and the daily check drops what expires within two days.
- **OCSP Stapling**: With `ocsp_stapling` on a certificate, the answer of the CA's OCSP responder is fetched in the background and sent along in the handshake, so clients do not have to ask the CA whether the certificate was revoked.
- **Certificate Validity Monitoring**: A background service periodically checks for certificates that are nearing their expiration date and can be configured to send notifications, preventing unexpected outages. Each certificate is checked once and reported by its configured name (with its domains in the log), however many domains it serves.
- **Let's Encrypt Chain Support**: Bundles common Let's Encrypt intermediate certificates to ensure proper chain of trust for certificates issued by Let's Encrypt.
- **Flexible Configuration**: Easily configured through `CertificateConf` structs, which can be loaded from various configuration sources.

## TLS backends

The crate is built for exactly one of pingora's TLS backends, chosen by the workspace's `openssl` (default) or `tls-rustls` feature. Certificate selection (exact, wildcard and default SNI matches, on-the-fly CA issuance) is shared; only the hand-over to pingora differs:

| | `openssl` | `tls-rustls` |
| --- | --- | --- |
| Selection hook | `TlsAccept::certificate_callback`, installing `X509`/`PKey` on the handshake | `ResolvesServerCert`, returning a prepared `CertifiedKey` |
| OCSP stapling | a status callback (`SSL_CTX_set_tlsext_status_cb`) hands over the answer of the certificate OpenSSL went on with | the answer is part of the `CertifiedKey` the resolver returns |
| Two certificates for a name | both installed, each with its chain; OpenSSL picks by the client's signature algorithms and, below TLS 1.3, by the cipher suite it settles on | picked from the ClientHello: the RSA one when the client offers a signature scheme and a cipher suite for it and none for the other, else the ECDSA one |
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
`update_certificates(configs, previous)` builds that map while carrying over
every certificate whose configuration (and, for file paths, file content) is
unchanged, so a reload parses and loads only what changed and reports exactly
those names; `parse_certificates` is the same with nothing to reuse.

### Two certificates for one domain

A domain is served with one certificate, or with two whose keys are of
different kinds: one RSA, one that is not (ECDSA, or Ed25519). There is no
setting for it; two entries name the same domain:

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

A client that can verify only one kind gets that one, with its own chain. A
client that can verify both gets the ECDSA one under rustls, and the one it
asks for first under OpenSSL - which is the ECDSA one for the browsers and
libraries in use today. The same goes for a wildcard and for the default
certificate (`is_default` on one entry of each kind). With ACME the second
entry has the same `domains` and `acme_key_type = "rsa"`.

- The three steps of the selection are not mixed. A name that has only an RSA
  certificate of its own is served with that, and is not given the ECDSA one
  of its wildcard as well.
- Two entries that name a domain with keys of the same kind are one too many.
  One of them is served and a warning in the log names both (`serving`,
  `ignored`). Which one is fixed: an entry without `acme` comes before one
  with it, and among the rest the first by name. It used to be whichever came
  last out of a hash map: another one in every process, and after any reload -
  and with both given as files, the other one at every pass of the file
  reloader. The entry that is not served is still loaded: its expiry is
  checked and the admin lists it.
- An entry with `is_ca` counts as ECDSA whatever the key of the CA is: the
  certificates it issues have ECDSA keys.
- Under OpenSSL the choice follows the listener's `tls_cipher_list`: a list
  without any ECDHE-ECDSA suite leaves TLS 1.2 clients with the RSA
  certificate. Between the two the order is the client's, of its cipher
  suites below TLS 1.3 and of its signature algorithms from there on:
  pingora's listener does not set OpenSSL's server preference.

Domains are compared without regard to case, as DNS does:
`domains = "Example.com"` serves `example.com`, and so does a client that
writes the name in capitals. Such an entry used to be a name no handshake
asked for, and with `acme` its certificate was ordered again at every check,
since the names in what the CA issued were never the ones written.

### OCSP stapling

```toml
[certificates.site]
domains = "example.com"
tls_cert = "/opt/certs/fullchain.pem"
tls_key = "/opt/certs/privkey.pem"
ocsp_stapling = true
```

With `ocsp_stapling = true` the OCSP responder the certificate names (in its
authority information access) is asked about the certificate, and its answer
is sent in every handshake whose client asks for it. The client then has the
CA's word that the certificate is not revoked without asking the CA itself.
Off by default.

- **What is stapled.** Only an answer that says the certificate is good, is
  signed by the issuer of the certificate - or by a responder the issuer has
  given a certificate for signing OCSP answers - and is current: not from the
  future, and not past the time it holds until, which it has to say
  (`nextUpdate`; the responder of a private CA may leave it out, and then
  nothing is stapled). Anything else is logged and left out; a client that
  checks would refuse the handshake over it. A signature of a kind that can
  not be checked here (ECDSA with P-521, for one) counts as none, and the log
  says `not signed by the issuer`.
- **What goes into the handshake** is not the bytes the responder sent. It is
  what the CA signed, the signature, and the certificate of the responder
  when that is not the CA itself, put together anew - 12 KiB at most, and
  with the algorithm of a signature written the one way there is (which
  leaves out RSA-PSS: such an answer is not taken). The
  signature covers the statement and not what is around it, and the responder
  is reached over plain HTTP: whoever sits on that way could otherwise add to
  an answer that passes every check, and have clients that read strictly end
  their handshakes over it. For the same reason the certificate has to be
  named in the answer the way it was asked about (SHA-1 hashes of the issuer),
  and a redirect of the request is not followed.
- **What it needs.** The certificate of the issuer has to come after the leaf
  in `tls_cert`: the signature of the answer is checked with it. And the
  certificate has to name a responder with an `http` address. Without either,
  the certificate is served as it was and a warning says which is missing
  (`ocsp stapling is not possible for this certificate`). A CA entry
  (`is_ca`) and what it issues are never stapled. Let's Encrypt has stopped
  running OCSP responders, and its certificates name none.
- **When the responder is asked.** By a background task, never by a
  handshake: within a minute of the start, or of the reload that brought the
  certificate (handshakes go without until then); an hour after an answer was
  taken; and five minutes before the answer runs out when that is sooner. A
  request is given ten seconds, and goes out as a plain HTTP `POST` from the
  machine pingap runs on (the usual proxy environment variables apply). Up to
  eight certificates are asked about at a time.
- **When no answer comes.** The one there is goes on being stapled until it
  runs out; after that handshakes go without one - they do not fail. The
  responder is asked again after a minute, then two, four, up to an hour, and
  the failure is logged at the 1st, 2nd, 4th, 8th time in a row (`no ocsp
  answer to staple`). A responder that says the certificate is revoked takes
  the answer away at once, with an error in the log.
- **Two certificates for a domain** each have their own answer, and the one
  that is sent is that of the certificate the handshake is signed with.
- The answers are kept in memory: after a restart they are asked for again.
- A certificate with the must-staple extension is not treated differently.
  Until its first answer is in, and when the responder has been away for
  longer than the last answer holds, its handshakes have nothing stapled and
  a client that insists on it will not connect.

A certificate is loaded together with its private key, and a key that is not
the certificate's is an error under both backends — reported by `pingap -t`
and by the admin when it is saved. (OpenSSL on its own only objects when the
pair is put on a handshake, which used to mean every handshake of the affected
domains failed at runtime.) An entry that fails to build on a reload is
reported and the certificate it was to replace goes on serving the domains it
had; the `domains` and `is_default` of the entry that failed are not applied.

A certificate whose `tls_cert` / `tls_key` are file paths is loaded again when
the files change, without a change to the configuration: the reload service
hashes them on every pass (`CertificateConf::reads_files`, `hash_key`). A
renewal that replaces `fullchain.pem` and `privkey.pem` in place is picked up
within a few seconds. Like every reload this needs the process to run with
`--autoreload` or `--autorestart`. Certificates managed by ACME in the same
configuration are left to their own service and are not affected.

A change to the configuration is hot reloaded entry by entry. An entry that is
not one of ACME is added, replaced or removed in place, also when other entries
are; with a single `acme` entry in the configuration no certificate at all used
to be reloaded until a restart. An entry that has `acme` set in the new
configuration stays as it is, and a new one stays out: the ACME service orders
and stores its certificate, and a change to its settings (`domains`, the
challenge) takes a restart, which `--autorestart` performs and `--autoreload`
only logs a warning about. An entry that no longer has `acme`, or is removed,
is reloaded like any other, and the ACME service stops renewing it. When two
entries name the same domain and the one serving it is removed, the domain goes
to the other.

Under OpenSSL, a `tls_cipher_list`, `tls_ciphersuites`, `tls_min_version` or
`tls_max_version` that OpenSSL rejects (or a version name other than
`tlsv1.1`/`tlsv1.2`/`tlsv1.3`, case-insensitive) is an error when the listener
is built, so the server does not come up with other settings than the
configured ones.

## Modules

The crate is organized into several modules, each with a specific responsibility:

- `lib.rs`: The main entry point of the crate. It defines the primary `Certificate` data structure and utility functions for parsing PEM-encoded certificates and keys.
- `dynamic_certificate.rs`: Contains the core logic for dynamic certificate management and SNI-based selection. It defines the `GlobalCertificate` struct and manages the global certificate store.
- `tls_backend.rs`: `TLS_BACKEND`, `install_default_crypto_provider`, and `validate_servers_tls_for_backend`.
- `tls_certificate.rs`: Defines the `TlsCertificate` struct, which encapsulates a certificate, private key, and associated metadata. It also contains the logic for generating new certificates signed by a CA.
- `ocsp.rs`: OCSP stapling: the request for a certificate, the check of a responder's answer, and the background task that keeps the answers current.
- `self_signed.rs`: Manages the lifecycle of dynamically generated self-signed certificates, including their creation, caching, and periodic cleanup of stale certificates.
- `validity_checker.rs`: Implements the background task that periodically checks for expiring certificates and sends warnings.
- `chain.rs`: Provides helper functions to access bundled Let's Encrypt intermediate certificates.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).