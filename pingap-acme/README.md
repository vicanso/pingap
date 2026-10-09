# Pingap ACME

Automatic TLS certificates for [Pingap](https://github.com/vicanso/pingap) from
Let's Encrypt, or from any other CA that speaks ACME.

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

The value of any query parameter of `dns_service_url`, or the whole of it, may
be written as `$ENV:NAME` and is read from the environment, so credentials stay
out of the configuration file. In a query parameter, a variable that is not
set leaves the text as it is. The whole value written as a reference follows
the rule of every other value of the configuration (see
[pingap-config](../pingap-config/README.md), which also has `$FILE:/path`): a
variable that is not set is a configuration error, where it used to reach the
provider as that text.

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
| `acme_directory` | string | The directory url of the CA. Default: Let's Encrypt's production environment |
| `acme_ca` | string | A PEM file with the root the CA's own certificate is verified with, for a CA of one's own. Default: the roots of the system |
| `acme_eab_kid`, `acme_eab_hmac` | string | External account binding: the key id and its HMAC key, as the CA gives them |
| `acme_contact` | string | The e-mail addresses of the account, comma separated |
| `acme_key_type` | string | The key of the certificate: `ecdsa` (P-256, the default) or `rsa` (2048 bits) |
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

## Another CA

A certificate is ordered from Let's Encrypt unless its entry names another
ACME server:

```toml
# Let's Encrypt's staging environment: for trying things out without
# touching the limits of the real one. Its certificates are not trusted.
[certificates.trial]
domains = "example.com"
acme = "lets_encrypt"
acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"

# A CA that binds its accounts to one of its own (ZeroSSL, Google Trust
# Services): the key id and the key from its console.
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

# A CA of one's own (step-ca): its directory, and the root its own
# certificate is signed by.
[certificates.internal]
domains = "app.internal.example"
acme = "lets_encrypt"
acme_directory = "https://ca.internal.example/acme/acme/directory"
acme_ca = "/etc/pingap/internal-root.pem"
```

- `acme` stays `lets_encrypt`: it is what turns ACME on for the entry, whoever
  the CA is.
- **`acme_directory`** has to be an `https` url. Everything else of an order is
  as with Let's Encrypt: the challenges, the renewal margin, where the
  certificate is stored.
- **`acme_ca`** is a file, read each time an order is made. Without it the CA's
  certificate has to be one the system trusts, which that of a public CA is.
- **External account binding**: `acme_eab_kid` and `acme_eab_hmac` are set
  together. The key is base64 as the CA shows it (the url alphabet without
  padding by the specification; padding and the standard alphabet are taken
  as well). It is a credential: it is masked in what is logged of a change of
  the configuration, and can be written `$ENV:NAME` or `$FILE:/path`.
- **`acme_contact`** goes into the account when it is made. An account that
  exists keeps the contacts it has.
- **`acme_key_type = "rsa"`** orders a certificate with an RSA key of 2048
  bits, for clients that can not do ECDSA. The default, `ecdsa`, is a P-256
  key.
- **One account per CA.** The credentials of an account are kept in the
  configuration storage: `lets_encrypt_account` and
  `lets_encrypt_staging_account` for Let's Encrypt's two environments, and
  `acme_account_<hash>` for every other directory - and for every binding at a
  CA that binds accounts - so certificates of the same CA share an account. A
  changed directory or binding is another account, made with the next order.
- A certificate that is there and not due is left alone: an entry whose
  `acme_directory` or `acme_key_type` is changed gets its certificate from the
  new CA, or with the new kind of key, at its next renewal.
- `acme_directory`, `acme_ca`, the binding and the key type are checked with
  the configuration (`pingap -t`): a url that is not `https`, a binding with
  one half missing, a key that is not base64 and a key type there is none of
  are errors there, not weeks later when the order is made.

What is not there: the TLS-ALPN-01 challenge, renewal by the CA's suggestion
(ARI), and DNS providers other than the four built in.

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

The challenge path (`/.well-known/acme-challenge/<token>`) is answered ahead of
every plugin, to anyone. A token of an order this process made is answered
from memory. Any other may belong to an order of another instance on the same
storage, or of the process this one took over from in a restart, so it is
looked for among the tokens in the storage. Those are read once for everyone
who asks within a second, and requests that arrive during the read wait for
it: a flood of made-up tokens costs one read a second and cannot keep a real
one from being found. An order waits a second and a half between storing a
token and telling the CA to validate it, so that no instance still answers
from a read older than the token. Every request used to read the storage: the
whole configuration file parsed again, or a request to etcd, for anyone who
cared to ask.

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
