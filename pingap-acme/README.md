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
added automatically for the duration — you do not need to declare it.

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
removes it afterwards. With `manual` (or an empty provider) the challenge is
attempted only once per process start, since there is nothing to poll.

## Certificate configuration

| Key | Type | Description |
| --- | --- | --- |
| `domains` | string | Comma-separated domain list |
| `acme` | string | `lets_encrypt` to enable ACME for this certificate |
| `dns_challenge` | bool | Use DNS-01 instead of HTTP-01 |
| `dns_provider` | string | `ali`, `cf`, `huawei`, `tencent`, `manual` |
| `dns_service_url` | string | Provider endpoint and credentials |
| `buffer_days` | int | Renew this many days before expiry |
| `is_default` | bool | Serve this certificate when SNI matches nothing |

`buffer_days` is the renewal margin: with `30`, a 90-day Let's Encrypt
certificate is renewed at day 60.

## Where certificates are stored

Issued certificates are written back through the configuration storage, which
means:

- With **etcd**, every instance sharing the backend picks up the new certificate
  automatically. Only one of them needs to do the ordering.
- With **file** storage, the certificate lands in the configuration directory.
- With the **quick start**, the certificate is persisted to
  `~/.pingap/acme/<domains>.toml` (owner-readable only) and restored on the next
  start.

The HTTP-01 challenge token also round-trips through configuration storage, which
is why ACME needs a writable backend. Tokens are stored with a `created_at`
timestamp and swept hourly: anything older than a day (far outside the window in
which any instance sharing the storage could still be serving it to the CA) is
deleted, so tokens no longer accumulate in the storage category forever.

## Environment

| Variable | Effect |
| --- | --- |
| `PINGAP_DISABLE_ACME` | Skips the ACME background task. The port-80 challenge listener is still created. |

Useful in staging or in tests, where you want the rest of the configuration to
behave identically without contacting Let's Encrypt.

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
