# Pingap Discovery

Backend discovery for [Pingap](https://github.com/vicanso/pingap) upstreams.

An upstream needs a set of backend addresses. This crate produces that set —
either from a static list, from DNS, or from Docker container labels — and keeps
it up to date so that scaling a backend up or down does not require a
configuration change.

The result is a pingora `Backends` object, which
[pingap-upstream](../pingap-upstream/README.md) wraps in a load balancer and
[pingap-health](../pingap-health/README.md) probes.

## Mechanisms

Selected with `discovery` in `UpstreamConf`:

| Value | Behaviour |
| --- | --- |
| `static` *(default)* | Resolve `addrs` once at startup and keep the result |
| `dns` | Re-resolve `addrs` periodically, so DNS changes take effect |
| `docker` | Look up containers by label through the Docker API |
| `transparent` | No discovery — forward to the address from the request itself |

`update_frequency` controls how often `dns` and `docker` refresh.

### Static

```toml
[upstreams.api]
addrs = ["10.0.0.1:8080", "10.0.0.2:8080 5"]
```

An address may carry a trailing weight (`host:port weight`), which the load
balancer honours. Hostnames are resolved once, at startup: use `dns` if the
address behind the name changes.

### DNS

```toml
[upstreams.api]
addrs = ["api.internal:8080"]
discovery = "dns"
update_frequency = "30s"
dns_server = "10.0.0.53:53"
dns_domain = "svc.cluster.local"
dns_search = "default.svc.cluster.local"
ipv4_only = true
```

| Key | Description |
| --- | --- |
| `dns_server` | Resolver to query. Unset uses the system resolver. |
| `dns_domain` | Domain appended to unqualified names |
| `dns_search` | Search list for unqualified names |
| `ipv4_only` | Ignore AAAA records |

Every resolved A/AAAA record becomes a backend, so this covers headless
Kubernetes services and round-robin DNS.

### Docker

```toml
[upstreams.api]
addrs = ["pingap-api:8080"]
discovery = "docker"
update_frequency = "10s"
```

Each entry is `label[:port] [weight]`. Containers are matched by Docker label
and their published address becomes a backend, so `docker compose up --scale
api=5` is picked up on the next refresh. The Docker daemon is reached through
`DOCKER_HOST`, falling back to the default socket.

### Transparent

```toml
[upstreams.passthrough]
addrs = []
discovery = "transparent"
```

No backend list at all: the request's own destination is used. This is how the
`transparent-proxy` example forwards arbitrary hosts — see
[examples/transparent-proxy](../examples/transparent-proxy).

## Notifications

`Discovery::with_sender` attaches a notification sender, so a discovery failure
(a DNS server that stops answering, a Docker socket that disappears) can raise a
webhook alert through [pingap-webhook](../pingap-webhook/README.md) instead of
only landing in the log.

## Usage

```rust
use pingap_discovery::{Discovery, DNS_DISCOVERY};

let discovery = Discovery::new(vec!["api.internal:8080".to_string()])
    .with_ipv4_only(true)
    .with_dns_server("10.0.0.53:53".to_string());

let backends = pingap_discovery::new_dns_discover_backends(&discovery)?;
```

## License

Apache-2.0.
