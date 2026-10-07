# Pingap ACME

Automatic TLS certificates for [Pingap](https://github.com/vicanso/pingap) from
Let's Encrypt.

Pingap can obtain and renew certificates on its own: you declare the domains, and
a background service orders, validates and installs the certificate, then renews
it before expiry. Both HTTP-01 and DNS-01 challenges are supported; DNS-01 is
what makes wildcard certificates possible.

## HTTP-01

The simplest setup. Pingap must be reachable on port 80 from the internet, and
the domain must resolve to it.

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

Pingap serves the challenge on `/.well-known/acme-challenge/<token>` itself. If
no server in the configuration listens on port 80, one named `lets encrypt` is
added automatically for the duration — you do not need to declare it. Only the
tokens of a running validation are answered there; any other name is a `404`,
including the names of the other entries kept in the same storage (the ACME
account, includes).

The one-command quick start does the same thing with no config file at all:

```bash
pingap --domain=pingap.io --upstream=192.168.1.1:3000
```

## DNS-01

Needed for wildcards, and for hosts that are not publicly reachable on port 80.

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
| `ali` | Alibaba Cloud DNS | `https://alidns.aliyuncs.com?access_key_id=xxx&access_key_secret=xxx` |
| `cf` | Cloudflare | `https://api.cloudflare.com?token=xxx` |
| `huawei` | Huawei Cloud DNS | `https://dns.{region}.myhuaweicloud.com?access_key_id=xxx&access_key_secret=xxx` |
| `tencent` | DNSPod / Tencent Cloud | `https://dnspod.tencentcloudapi.com?access_key_id=xxx&access_key_secret=xxx` |
| `manual` or unset | — | No API. The TXT record is logged and you add it yourself. |

The canonical names are `ali` and `cf`; `aliyun` and `cloudflare` are accepted
as aliases because earlier documentation used those spellings. Anything else is
rejected by `pingap -t` rather than quietly falling back to the manual task and
waiting for a TXT record nobody is going to add.

Any value in `dns_service_url` may be written as `$ENV:NAME` and is read from the
environment, so credentials stay out of the configuration file.

The provider adds the `_acme-challenge` TXT record, waits for validation, and
removes it afterwards. The zone is the registrable domain of the record name,
resolved against the public suffix list (`example.co.uk`, not `co.uk`). With
`manual` (or an empty provider) the challenge is attempted only once per
process start, since there is nothing to poll; the TXT value is logged and
also written to the storage category, from where the hourly sweep removes it
a day later.

## Certificate configuration

| Key | Type | Description |
| --- | --- | --- |
| `domains` | string | Comma-separated domain list |
| `acme` | string | `lets_encrypt` to enable ACME for this certificate |
| `dns_challenge` | bool | Use DNS-01 instead of HTTP-01 |
| `dns_provider` | string | `ali`, `cf`, `huawei`, `tencent`, `manual` |
| `dns_service_url` | string | Provider endpoint and credentials |
| `buffer_days` | int | Renew this many days before expiry. Default: `14`, or a third of the certificate's lifetime when that is less |
| `is_default` | bool | Serve this certificate when SNI matches nothing |

`buffer_days` is the renewal margin: with `30`, a 90-day Let's Encrypt
certificate is renewed at day 60. Left out, the margin is fourteen days (it
used to be two, which left no time to notice an order that kept failing), and
never more than a third of what the certificate lasts: one good for six days
is renewed two days before its end.

A certificate with `acme` set is renewed by this task, so the daily expiry
warning (`tls_validity`), which is for certificates somebody has to replace by
hand, leaves it alone while its renewal is not overdue. It is warned about once
half of its renewal margin is gone as well, a week before its end at the
latest: by then the renewal has been failing for a while, or was never going to
happen (`PINGAP_DISABLE_ACME`, or a DNS challenge answered by hand, which is
only asked for when the process starts). What goes wrong with a renewal is
reported as it happens, see
[When an order does not go through](#when-an-order-does-not-go-through).

## Where certificates are stored

Issued certificates are written back through the configuration storage, which
means:

- With **etcd**, every instance sharing the backend picks up the new certificate
  automatically. Only one of them needs to do the ordering.
- With **file** storage, the certificate lands in the configuration directory.
- Instances that share a storage share the certificate: before ordering, an
  instance reads the stored entry, and when that already holds a certificate
  for the same domains with its margin left - another instance renewed it - it
  installs that one and orders nothing. Each instance used to go by its own
  running configuration and order its own, and half a dozen of them ran into
  the CA's limit on duplicate certificates. Two instances that reach the check
  at the same moment can still both order; nothing coordinates them.
- With the **quick start**, the certificate is persisted to
  `~/.pingap/acme/<domains>.toml` (owner-readable only) and restored on the next
  start.

The HTTP-01 challenge token also round-trips through configuration storage, which
is why ACME needs a writable backend. Tokens are stored with a `created_at`
timestamp and swept hourly: anything older than a day (far outside the window in
which any instance sharing the storage could still be serving it to the CA) is
deleted, so tokens no longer accumulate in the storage category forever.

The ACME account is stored there too, as the `lets_encrypt_account` entry of the
storage category (`lets_encrypt_staging_account` against the staging CA), and
reused by every later order on any instance sharing the backend. An account was
registered per order before, which Let's Encrypt rate-limits per IP; a stored
account that no longer works is replaced by a new one. The entry holds the
account's private key, like a certificate entry holds its `tls_key`.

## Environment

| Variable | Effect |
| --- | --- |
| `PINGAP_DISABLE_ACME` | Skips the ACME background task. The port-80 challenge listener is still created. |

Useful in staging or in tests, where you want the rest of the configuration to
behave identically without contacting Let's Encrypt.

## When an order does not go through

A certificate is checked every ten minutes, and ordered when it is missing,
within its renewal margin or no longer covers its domains. A failed order is
logged with the step it failed at, sent as a `lets_encrypt` notification of
level `error`, and tried again after a wait that doubles with every failure in
a row: ten minutes, twenty, forty, up to six hours. It used to be tried again
at every check, which is more often than the five failed validations an hour a
CA allows a name. A success, or a usable certificate turning up in the storage,
ends the wait; so does a restart.

An order that goes through and gives a certificate the entry cannot go on with
counts as a failure too, with the same wait: `buffer_days` not less than what
the CA's certificates last, or `domains` that is not what the certificate
names (a name twice, or in upper case). The certificate is installed, and
ordered again only after the wait instead of every ten minutes.

A certificate elsewhere in the configuration that does not load no longer gets
in the way: the new certificate is installed and recorded whatever the others
do, and what is wrong with them is reported as `parse_certificate_fail`.
(Before, the new certificate was served but not recorded, and ordered again
every ten minutes.)

- Every exchange with the CA and with the DNS provider is bounded: a request
  that gets no answer within a minute fails the attempt, and so does an order
  whose validations take longer than their allowance (two and a half minutes
  per domain, plus three). The TXT records that were added are removed either
  way. Nothing waits on a connection that has gone quiet.
- The CA remembers a successful validation for a while. An order made in that
  time comes back `ready`, with nothing left to prove, and is finalized
  directly.
- The storage has to take writes: the account, the challenge token and the
  certificate are all saved to it. On a configuration directory of `.hcl` or
  `.kdl` files, which is read-only, the attempt stops before the CA is asked
  for anything.
- With `--autorestart`, what the ACME task writes on the way (its account, the
  tokens) does not restart the process. The new certificate is installed in
  place.

## Rate limits

Let's Encrypt allows **5 duplicate certificates per week** for the same set of
domains. Never delete the persisted certificate as part of a restart or deploy
script, and be careful with ephemeral containers that lose their config
directory — a crash loop can burn the weekly quota in minutes.

## Adding a DNS provider

Implement `AcmeDnsTask`:

```rust
#[async_trait]
pub trait AcmeDnsTask: Sync + Send {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()>;
    /// Called when the challenge is over; removes the record added above.
    async fn done(&self) -> Result<()>;
}
```

then wire the provider name into the match in `lets_encrypt.rs`. See
`dns_cf.rs` for the smallest existing example.

## License

Apache-2.0.
