// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{Addr, Error, Result, format_addrs};
use super::{DNS_DISCOVERY, Discovery, LOG_TARGET, SRV_DISCOVERY};
use async_trait::async_trait;
use futures::future::join_all;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts,
};
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RData};
use hickory_resolver::system_conf::read_system_conf;
use http::Extensions;
use pingap_core::NotificationSender;
use pingap_core::{NotificationData, NotificationLevel};
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr as StdSocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// How long a built `Resolver` may be reused before re-reading system conf.
const RESOLVER_REFRESH: Duration = Duration::from_secs(60);
/// Floor / ceiling for DNS-TTL-based result caching.
const DISCOVERY_CACHE_MIN: Duration = Duration::from_secs(5);
const DISCOVERY_CACHE_MAX: Duration = Duration::from_secs(300);

struct CachedResolver {
    resolver: Arc<TokioResolver>,
    built_at: Instant,
}

struct DiscoveryCache {
    backends: BTreeSet<Backend>,
    /// The backends of each host, in the order of the hosts, and when
    /// they were last resolved: what a host whose lookup fails goes on
    /// with, for a while.
    host_backends: Vec<HostBackends>,
    failed_hosts: Vec<String>,
    valid_until: Instant,
}

#[derive(Clone, Default)]
struct HostBackends {
    backends: BTreeSet<Backend>,
    /// `None` for a host that has none to keep.
    resolved_at: Option<Instant>,
}

/// How long a host whose lookups fail keeps the backends it last had.
const KEEP_FAILED_FOR: Duration = Duration::from_secs(600);

/// What one host came to in a round.
enum Resolved {
    /// Its addresses, and until when they hold.
    Addrs(Vec<std::net::IpAddr>, Instant),
    /// What its `SRV` records lead to: each an address with the port and
    /// the weight its record gives it.
    Targets(Vec<(std::net::IpAddr, u16, usize)>, Instant),
    /// The answer was that there is no such name, or no address for it.
    Gone,
    /// No answer: a timeout, a server that could not be reached.
    Failed,
}

/// The backends after a round of lookups, and for how long they are good.
///
/// A host that got no answer keeps the backends it had: one lookup that
/// fails says nothing about the servers behind the name, and the health
/// check takes them out if they are gone. It used to lose them, and the
/// set without them was kept for as long as the other names' records
/// were good for - five minutes of an upstream at half strength over one
/// dropped packet. Not for ever: after ten minutes without an answer
/// they go. A host that was answered "no such name" loses them at once.
///
/// With a failure in it a round is only good for the shortest time, so
/// the name is asked for again soon.
fn merge_round(
    hosts: &[Addr],
    ipv4_only: bool,
    resolved: &[Resolved],
    previous: Option<&DiscoveryCache>,
    now: Instant,
) -> (Vec<HostBackends>, Instant) {
    let mut valid_until = now + DISCOVERY_CACHE_MAX;
    let mut any_failed = false;
    let mut host_backends = Vec::with_capacity(hosts.len());
    for (index, ((_, port, weight), lookup)) in
        hosts.iter().zip(resolved.iter()).enumerate()
    {
        let (ips, until) = match lookup {
            Resolved::Addrs(ips, until) => (ips, until),
            // The port and the weight are the record's, not the entry's.
            Resolved::Targets(targets, until) => {
                valid_until = valid_until.min(*until);
                host_backends.push(HostBackends {
                    backends: targets
                        .iter()
                        .filter(|(ip, _, _)| !ipv4_only || ip.is_ipv4())
                        .map(|(ip, port, weight)| Backend {
                            addr: SocketAddr::Inet(StdSocketAddr::new(
                                *ip, *port,
                            )),
                            weight: *weight,
                            ext: Extensions::new(),
                        })
                        .collect(),
                    resolved_at: Some(now),
                });
                continue;
            },
            Resolved::Gone => {
                any_failed = true;
                host_backends.push(HostBackends::default());
                continue;
            },
            Resolved::Failed => {
                any_failed = true;
                host_backends.push(
                    previous
                        .and_then(|cache| cache.host_backends.get(index))
                        .filter(|host| {
                            host.resolved_at.is_some_and(|at| {
                                now.saturating_duration_since(at)
                                    < KEEP_FAILED_FOR
                            })
                        })
                        .cloned()
                        .unwrap_or_default(),
                );
                continue;
            },
        };
        valid_until = valid_until.min(*until);
        host_backends.push(HostBackends {
            backends: ips
                .iter()
                .filter(|ip| !ipv4_only || ip.is_ipv4())
                .map(|ip| Backend {
                    addr: SocketAddr::Inet(StdSocketAddr::new(*ip, *port)),
                    weight: *weight,
                    ext: Extensions::new(),
                })
                .collect(),
            resolved_at: Some(now),
        });
    }
    let valid_until = if any_failed {
        now + DISCOVERY_CACHE_MIN
    } else {
        valid_until.clamp(now + DISCOVERY_CACHE_MIN, now + DISCOVERY_CACHE_MAX)
    };
    (host_backends, valid_until)
}

/// One discovery round.
struct Discovered {
    backends: BTreeSet<Backend>,
    /// Hosts that did not resolve this round.
    failed_hosts: Vec<String>,
    /// Served from the TTL cache rather than resolved just now. A cached
    /// round is not news: it is neither logged at info nor notified about.
    from_cache: bool,
    /// The backend set differs from the previous round's.
    changed: bool,
    /// The hosts that failed are not the ones of the previous round.
    new_failures: bool,
}

/// The `SRV` records that are gone by, of all a name has: their target,
/// port and weight.
///
/// Those of the lowest priority, which is the one a client is to use
/// while it can be reached (RFC 2782). The others are for when it can
/// not, and an upstream has no place for backends that are only spares:
/// taken along, they would get their share of the requests. A weight of
/// nothing is the least there is, not none. A target of `.` says the
/// service is not to be had at this name.
///
/// The weights are what they are to one another, see
/// [`normalize_weights`].
fn pick_srv_targets(
    records: &[(u16, u16, u16, String)],
) -> Vec<(String, u16, usize)> {
    let Some(lowest) = records
        .iter()
        .filter(|(_, _, _, target)| target != ".")
        .map(|(priority, _, _, _)| *priority)
        .min()
    else {
        return vec![];
    };
    let mut targets: Vec<(String, u16, usize)> = records
        .iter()
        .filter(|(priority, _, _, target)| *priority == lowest && target != ".")
        .map(|(_, weight, port, target)| {
            (target.clone(), *port, (*weight).max(1) as usize)
        })
        .collect();
    let mut weights: Vec<usize> =
        targets.iter().map(|(_, _, weight)| *weight).collect();
    normalize_weights(&mut weights);
    for (target, weight) in targets.iter_mut().zip(weights) {
        target.2 = weight;
    }
    targets
}

/// The most the weight of an `SRV` record comes to.
const SRV_WEIGHT_MAX: usize = 256;

/// Brings the weights of a set of `SRV` records down to what they are to
/// one another: divided by what they have in common, and with the
/// largest no more than [`SRV_WEIGHT_MAX`].
///
/// A weight is part of what a backend is known by, its health included:
/// one that changes makes a new backend of an address, healthy until it
/// is checked again. And a registry changes them without anything being
/// different about the servers - CoreDNS gives each of `n` pods
/// `100 / n`, so every weight changes when one pod is added. Divided,
/// equal weights are `1` whatever the registry writes.
///
/// The number also comes from outside, and is what the tables of the
/// load balancer are sized by: 160 points of a hash ring for each unit.
/// A record with the largest weight there is, 65535, would be 80 MB of
/// it. With the largest at 256 the shares are right to less than half a
/// percent.
fn normalize_weights(weights: &mut [usize]) {
    fn gcd(a: usize, b: usize) -> usize {
        if b == 0 { a } else { gcd(b, a % b) }
    }
    let common = weights
        .iter()
        .fold(0, |common, weight| gcd(common, *weight));
    if common > 1 {
        for weight in weights.iter_mut() {
            *weight /= common;
        }
    }
    let largest = weights.iter().copied().max().unwrap_or_default();
    if largest > SRV_WEIGHT_MAX {
        for weight in weights.iter_mut() {
            *weight =
                ((*weight * SRV_WEIGHT_MAX + largest / 2) / largest).max(1);
        }
    }
}

/// What the lookup of one target of an `SRV` record came to: its
/// addresses with the time they hold until, or, for a lookup that
/// failed, whether the answer was that there is no such name.
type TargetLookup = std::result::Result<(Vec<std::net::IpAddr>, Instant), bool>;

/// What the targets of a name's `SRV` records came to, from the port,
/// the weight and the lookup of each.
///
/// A target that does not resolve is left out and the others serve on.
/// A lookup that got no answer says nothing about the server behind the
/// name: the round is then good for the shortest time only, and the name
/// is asked again in a few seconds. It used to be good for as long as the
/// records of the others, up to five minutes without that backend over
/// one lost packet. With none of them resolved the name has no answer as
/// far as its backends go, and keeps for a while the ones it had.
fn srv_targets(
    lookups: Vec<(u16, usize, TargetLookup)>,
    records_valid_until: Instant,
    now: Instant,
) -> Resolved {
    if lookups.is_empty() {
        return Resolved::Gone;
    }
    let mut valid_until = records_valid_until;
    let mut targets = vec![];
    let mut resolved = false;
    let mut unanswered = false;
    for (port, weight, lookup) in lookups {
        match lookup {
            Ok((ips, until)) => {
                resolved = true;
                valid_until = valid_until.min(until);
                targets.extend(ips.into_iter().map(|ip| (ip, port, weight)));
            },
            Err(no_such_name) => unanswered |= !no_such_name,
        }
    }
    if !resolved {
        return Resolved::Failed;
    }
    if unanswered {
        valid_until = valid_until.min(now + DISCOVERY_CACHE_MIN);
    }
    Resolved::Targets(targets, valid_until)
}

/// DNS service discovery implementation
struct Dns {
    /// The names are looked up for their `SRV` records, and those for
    /// the addresses.
    srv: bool,
    ipv4_only: bool,
    hosts: Vec<Addr>,
    sender: Option<Arc<NotificationSender>>,
    name_server: Option<String>,
    domain: Option<String>,
    search: Option<String>,
    /// Reused across discovery ticks; rebuilt when system DNS conf may have changed.
    resolver: Mutex<Option<CachedResolver>>,
    /// Successful (or partial) discovery result held until the shortest DNS TTL.
    discovery_cache: Mutex<Option<DiscoveryCache>>,
}

/// Checks if the discovery type is DNS
/// The name servers of a `dns_server` setting: addresses separated by
/// commas, each with or without a port (`10.0.0.53`, `10.0.0.53:5353`,
/// `[fd00::53]:53`).
///
/// Only a bare address used to be understood, and whatever was not one was
/// dropped without a word. `10.0.0.53:53`, the form the documentation
/// shows, left the resolver with no server at all: every lookup failed and
/// the upstream had no backends.
fn parse_name_servers(value: &str) -> Result<Vec<NameServerConfig>> {
    let mut name_servers = vec![];
    for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (ip, port) = if let Ok(ip) = item.parse::<IpAddr>() {
            (ip, None)
        } else if let Ok(addr) = item.parse::<StdSocketAddr>() {
            (addr.ip(), Some(addr.port()))
        } else {
            return Err(Error::Invalid {
                message: format!(
                    "dns server {item} is invalid, expected an ip address with an optional port"
                ),
            });
        };
        let mut server = NameServerConfig::udp_and_tcp(ip);
        if let Some(port) = port {
            for connection in server.connections.iter_mut() {
                connection.port = port;
            }
        }
        name_servers.push(server);
    }
    Ok(name_servers)
}

pub fn is_dns_discovery(value: &str) -> bool {
    value == DNS_DISCOVERY
}

pub fn is_srv_discovery(value: &str) -> bool {
    value == SRV_DISCOVERY
}

impl Dns {
    /// Creates a new DNS discovery instance
    ///
    /// # Arguments
    /// * `addrs` - List of addresses to resolve
    /// * `tls` - Whether to use TLS
    /// * `ipv4_only` - Whether to only use IPv4 addresses
    ///
    /// # Returns
    /// * `Result<Self>` - New DNS discovery instance
    fn new(addrs: &[String], tls: bool, ipv4_only: bool) -> Result<Self> {
        let hosts = format_addrs(addrs, tls)?;
        Ok(Self {
            srv: false,
            hosts,
            ipv4_only,
            sender: None,
            name_server: None,
            domain: None,
            search: None,
            resolver: Mutex::new(None),
            discovery_cache: Mutex::new(None),
        })
    }

    /// Returns a shared resolver, rebuilding at most every `RESOLVER_REFRESH`
    /// so `/etc/resolv.conf` changes are still picked up without paying the
    /// rebuild cost on every discovery tick.
    async fn get_resolver(&self) -> Result<Arc<TokioResolver>> {
        let mut slot = self.resolver.lock().await;
        if let Some(cached) = slot.as_ref()
            && cached.built_at.elapsed() < RESOLVER_REFRESH
        {
            return Ok(cached.resolver.clone());
        }
        let provider = TokioRuntimeProvider::default();
        let (config, options) = self.read_system_conf()?;
        let mut builder = TokioResolver::builder_with_config(config, provider);
        *builder.options_mut() = options;
        let resolver =
            builder.build().map_err(|e| Error::Resolve { source: e })?;
        let resolver = Arc::new(resolver);
        *slot = Some(CachedResolver {
            resolver: resolver.clone(),
            built_at: Instant::now(),
        });
        Ok(resolver)
    }
    /// Sets the name server
    ///
    /// # Arguments
    /// * `name_server` - The name server
    ///
    /// # Returns
    /// * `Self` - The DNS discovery instance
    pub fn with_name_server(mut self, name_server: String) -> Self {
        if name_server.is_empty() {
            return self;
        }
        self.name_server = Some(name_server);
        self
    }

    /// Sets the domain
    ///
    /// # Arguments
    /// * `domain` - The domain
    ///
    /// # Returns
    /// * `Self` - The DNS discovery instance
    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain).filter(|domain| !domain.is_empty());
        self
    }

    /// Sets the search
    ///
    /// # Arguments
    /// * `search` - The search
    ///
    /// # Returns
    /// * `Self` - The DNS discovery instance
    pub fn with_search(mut self, search: String) -> Self {
        self.search = Some(search).filter(|search| !search.is_empty());
        self
    }

    /// Sets the notification sender
    ///
    /// # Arguments
    /// * `sender` - The notification sender
    ///
    /// # Returns
    /// * `Self` - The DNS discovery instance
    pub fn with_sender(
        mut self,
        sender: Option<Arc<NotificationSender>>,
    ) -> Self {
        self.sender = sender;
        self
    }

    /// Reads system DNS resolver configuration
    ///
    /// # Returns
    /// * `Result<(ResolverConfig, ResolverOpts)>` - Resolver configuration and options
    fn read_system_conf(&self) -> Result<(ResolverConfig, ResolverOpts)> {
        // read_system_conf returns ProtoError on macOS and NetError on other
        // unix targets — `.into()` is required on macOS and a no-op elsewhere.
        #[allow(clippy::useless_conversion)]
        let (mut config, mut options) = read_system_conf()
            .map_err(|e| Error::Resolve { source: e.into() })?;

        if let Some(domain) = &self.domain
            && let Ok(name) = Name::from_str(domain)
        {
            config.set_domain(name);
        }

        if let Some(search) = &self.search {
            search
                .split(',')
                .filter_map(|s| Name::from_str(s).ok())
                .for_each(|item| config.add_search(item));
        }

        if let Some(name_server) = &self.name_server {
            let name_servers = parse_name_servers(name_server)?;
            // Nothing given after all (an empty setting): the system's
            // servers stay.
            if !name_servers.is_empty() {
                config = ResolverConfig::from_parts(
                    config.domain().cloned(),
                    config.search().to_vec(),
                    name_servers,
                );
            }
        }

        options.ip_strategy = if self.ipv4_only {
            LookupIpStrategy::Ipv4Only
        } else {
            LookupIpStrategy::Ipv4AndIpv6
        };

        Ok((config, options))
    }

    /// Performs DNS lookups for configured hosts using tokio runtime
    ///
    /// # Returns
    /// Per-host DNS lookup results, index-aligned with `self.hosts`, plus
    /// the failed host names. A failed lookup is `Err`, of `true` when
    /// the answer was that the name has no address and of `false` when
    /// there was no answer.
    async fn tokio_lookup_ip(
        &self,
    ) -> Result<(Vec<std::result::Result<LookupIp, bool>>, Vec<String>)> {
        let resolver = self.get_resolver().await?;

        // One slot per host, in host order. The caller pairs each result with
        // that host's port and weight by position, so a failed lookup MUST
        // keep its slot: compacting the list would shift every later result
        // onto the wrong host, sending one domain's traffic to another
        // domain's port and weight.
        let mut lookup_ips = Vec::with_capacity(self.hosts.len());
        let mut failed_hosts = Vec::new();

        let lookup_futures = self
            .hosts
            .iter()
            .map(|(host, _, _)| resolver.lookup_ip(host.as_str()));

        let results = join_all(lookup_futures).await;

        for (index, result) in results.into_iter().enumerate() {
            match result {
                Ok(lookup) => {
                    lookup_ips.push(Ok(lookup));
                },
                Err(e) => {
                    let host = self
                        .hosts
                        .get(index)
                        .map(|item| item.0.clone())
                        .unwrap_or_default();
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        host,
                        "dns lookup failed"
                    );
                    failed_hosts.push(host);
                    lookup_ips.push(Err(e.is_no_records_found()));
                },
            }
        }
        if lookup_ips.iter().all(|lookup| lookup.is_err()) {
            return Err(Error::Invalid {
                message: "resolve dns failed".to_string(),
            });
        }
        Ok((lookup_ips, failed_hosts))
    }

    /// What the `SRV` records of each host lead to, index-aligned with
    /// `self.hosts`, plus the names that failed.
    async fn lookup_srv(&self) -> Result<(Vec<Resolved>, Vec<String>)> {
        let resolver = self.get_resolver().await?;
        let lookups = self.hosts.iter().map(|(host, _, _)| {
            let resolver = resolver.clone();
            async move {
                let lookup = resolver.srv_lookup(host.as_str()).await?;
                let records: Vec<(u16, u16, u16, String)> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::SRV(srv) => Some((
                            srv.priority,
                            srv.weight,
                            srv.port,
                            srv.target.to_utf8(),
                        )),
                        _ => None,
                    })
                    .collect();
                let picked = pick_srv_targets(&records);
                let mut lookups = Vec::with_capacity(picked.len());
                for (target, port, weight) in picked {
                    let addrs = match resolver.lookup_ip(target.as_str()).await
                    {
                        Ok(ips) => Ok((
                            ips.iter().collect::<Vec<_>>(),
                            ips.valid_until(),
                        )),
                        Err(e) => {
                            warn!(
                                target: LOG_TARGET,
                                error = %e,
                                host,
                                srv_target = target,
                                "srv target lookup failed"
                            );
                            Err(e.is_no_records_found())
                        },
                    };
                    lookups.push((port, weight, addrs));
                }
                Ok::<Resolved, hickory_resolver::net::NetError>(srv_targets(
                    lookups,
                    lookup.valid_until(),
                    Instant::now(),
                ))
            }
        });
        let mut resolved = Vec::with_capacity(self.hosts.len());
        let mut failed_hosts = vec![];
        for (index, result) in join_all(lookups).await.into_iter().enumerate() {
            let host = self
                .hosts
                .get(index)
                .map(|item| item.0.clone())
                .unwrap_or_default();
            let item = match result {
                Ok(item) => item,
                Err(e) => {
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        host,
                        "srv lookup failed"
                    );
                    if e.is_no_records_found() {
                        Resolved::Gone
                    } else {
                        Resolved::Failed
                    }
                },
            };
            if !matches!(item, Resolved::Targets(..)) {
                failed_hosts.push(host);
            }
            resolved.push(item);
        }
        if resolved
            .iter()
            .all(|item| !matches!(item, Resolved::Targets(..)))
        {
            return Err(Error::Invalid {
                message: "resolve dns srv failed".to_string(),
            });
        }
        Ok((resolved, failed_hosts))
    }

    /// Discovers backend services by resolving DNS
    async fn run_discover(&self) -> Result<Discovered> {
        // Honour DNS TTLs: health-check / update loops may call us more often
        // than records change; reuse the last set until the shortest TTL
        // expires (clamped to [MIN, MAX]).
        {
            let cache = self.discovery_cache.lock().await;
            if let Some(cached) = cache.as_ref()
                && Instant::now() < cached.valid_until
            {
                debug!(
                    hosts = ?self.hosts,
                    remaining_ms = cached
                        .valid_until
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                    "dns discover cache hit"
                );
                return Ok(Discovered {
                    backends: cached.backends.clone(),
                    failed_hosts: cached.failed_hosts.clone(),
                    from_cache: true,
                    changed: false,
                    new_failures: false,
                });
            }
        }

        debug!(
            hosts = ?self.hosts,
            "dns discover is running"
        );

        let (resolved, failed_hosts) = if self.srv {
            self.lookup_srv().await?
        } else {
            let (lookup_ips, failed_hosts) = self.tokio_lookup_ip().await?;
            let resolved: Vec<Resolved> = lookup_ips
                .iter()
                .map(|lookup| match lookup {
                    Ok(lookup) => Resolved::Addrs(
                        lookup.iter().collect(),
                        lookup.valid_until(),
                    ),
                    Err(true) => Resolved::Gone,
                    Err(false) => Resolved::Failed,
                })
                .collect();
            (resolved, failed_hosts)
        };

        let (upstreams, changed, new_failures) = {
            let mut cache = self.discovery_cache.lock().await;
            let (host_backends, valid_until) = merge_round(
                &self.hosts,
                self.ipv4_only,
                &resolved,
                cache.as_ref(),
                Instant::now(),
            );
            let upstreams: BTreeSet<Backend> = host_backends
                .iter()
                .flat_map(|host| host.backends.iter())
                .cloned()
                .collect();
            let changed = cache
                .as_ref()
                .is_none_or(|cached| cached.backends != upstreams);
            // A round with a failure in it is asked for again within
            // seconds: the same hosts failing again is not news.
            let new_failures = cache
                .as_ref()
                .is_none_or(|cached| cached.failed_hosts != failed_hosts);
            *cache = Some(DiscoveryCache {
                backends: upstreams.clone(),
                host_backends,
                failed_hosts: failed_hosts.clone(),
                valid_until,
            });
            (upstreams, changed, new_failures)
        };

        Ok(Discovered {
            backends: upstreams,
            failed_hosts,
            from_cache: false,
            changed,
            new_failures,
        })
    }
}

#[async_trait]
impl ServiceDiscovery for Dns {
    async fn discover(
        &self,
    ) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let start_time = Instant::now();
        let hosts: Vec<String> =
            self.hosts.iter().map(|item| item.0.clone()).collect();
        match self.run_discover().await {
            Ok(discovered) => {
                let Discovered {
                    backends,
                    failed_hosts,
                    from_cache,
                    changed,
                    new_failures,
                } = discovered;
                // A cached or unchanged round is routine; only a new
                // backend set is worth an info line, and only a fresh
                // resolution is worth a notification - the cache would
                // otherwise repeat the same failure every tick.
                if from_cache || !changed {
                    debug!(
                        target: LOG_TARGET,
                        hosts = hosts.join(","),
                        from_cache,
                        elapsed = format!("{}ms", start_time.elapsed().as_millis()),
                        "dns discover unchanged"
                    );
                } else {
                    let addrs: Vec<String> = backends
                        .iter()
                        .map(|item| item.addr.to_string())
                        .collect();
                    info!(
                        target: LOG_TARGET,
                        hosts = hosts.join(","),
                        addrs = addrs.join(","),
                        elapsed = format!("{}ms", start_time.elapsed().as_millis()),
                        "dns discover success"
                    );
                }
                if backends.is_empty() {
                    warn!(
                        target: LOG_TARGET,
                        hosts = hosts.join(","),
                        "dns discover resolved no backend"
                    );
                }
                if !from_cache
                    && new_failures
                    && !failed_hosts.is_empty()
                    && let Some(sender) = &self.sender
                {
                    sender
                        .notify(NotificationData {
                            category: "service_discover_fail".to_string(),
                            level: NotificationLevel::Warn,
                            message: format!(
                                "dns discovery resolve failed: {failed_hosts:?}"
                            ),
                            ..Default::default()
                        })
                        .await;
                }
                return Ok((backends, HashMap::new()));
            },
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    hosts = hosts.join(","),
                    elapsed = format!(
                        "{}ms",
                        start_time.elapsed().as_millis()
                    ),
                    "dns discover fail"
                );
                if let Some(sender) = &self.sender {
                    sender
                        .notify(NotificationData {
                            category: "service_discover_fail".to_string(),
                            level: NotificationLevel::Warn,
                            message: format!(
                                "dns discovery {:?}, error: {e}",
                                self.hosts
                            ),
                            ..Default::default()
                        })
                        .await;
                }
                Err(e.into())
            },
        }
    }
}

/// Creates a new DNS-based service discovery backend
///
/// # Arguments
/// * `discovery` - The discovery configuration
///
/// # Returns
/// * `Result<Backends>` - Configured service discovery backend
pub fn new_dns_discover_backends(discovery: &Discovery) -> Result<Backends> {
    new_backends(discovery, false)
}

/// Creates a service discovery backend that goes by the `SRV` records of
/// the names in `addrs`: `_http._tcp.api.internal`. The records give the
/// hosts, their ports and their weights; a port or a weight written
/// after a name is not used.
pub fn new_srv_discover_backends(discovery: &Discovery) -> Result<Backends> {
    new_backends(discovery, true)
}

fn new_backends(discovery: &Discovery, srv: bool) -> Result<Backends> {
    let mut dns =
        Dns::new(&discovery.addr, discovery.tls, discovery.ipv4_only)?;
    dns.srv = srv;
    if let Some(dns_server) = &discovery.dns_server {
        // Checked when the upstream is built, so a setting that is no
        // address fails the config check and not the first lookup.
        parse_name_servers(dns_server)?;
        dns = dns.with_name_server(dns_server.clone());
    }
    if let Some(domain) = &discovery.dns_domain {
        dns = dns.with_domain(domain.clone());
    }
    if let Some(search) = &discovery.dns_search {
        dns = dns.with_search(search.clone());
    }
    let backends =
        Backends::new(Box::new(dns.with_sender(discovery.sender.clone())));
    Ok(backends)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Discovery;
    use pretty_assertions::assert_eq;

    /// The `SRV` records that are gone by: those of the lowest priority,
    /// with their ports and weights.
    #[test]
    fn test_pick_srv_targets() {
        let record = |priority: u16, weight: u16, port: u16, target: &str| {
            (priority, weight, port, target.to_string())
        };
        let target = |host: &str, port: u16, weight: usize| {
            (host.to_string(), port, weight)
        };
        // The weights as they are to one another: 10 and 30 are 1 and 3.
        assert_eq!(
            vec![
                target("a.internal.", 8080, 1),
                target("b.internal.", 8081, 3)
            ],
            pick_srv_targets(&[
                record(20, 5, 9000, "spare.internal."),
                record(10, 10, 8080, "a.internal."),
                record(10, 30, 8081, "b.internal."),
            ])
        );
        // What CoreDNS writes for three pods, and for four: the same
        // backends, with nothing about them changed.
        for weight in [33, 25] {
            assert_eq!(
                vec![
                    target("a.internal.", 80, 1),
                    target("b.internal.", 80, 1)
                ],
                pick_srv_targets(&[
                    record(0, weight, 80, "a.internal."),
                    record(0, weight, 80, "b.internal."),
                ])
            );
        }
        // a weight of nothing is the least there is
        assert_eq!(
            vec![target("a.internal.", 80, 1)],
            pick_srv_targets(&[record(0, 0, 80, "a.internal.")])
        );
        // `.`: the service is not to be had here. With other records
        // beside it, those are gone by.
        assert_eq!(true, pick_srv_targets(&[record(0, 0, 0, ".")]).is_empty());
        assert_eq!(
            vec![target("a.internal.", 80, 1)],
            pick_srv_targets(&[
                record(0, 0, 0, "."),
                record(5, 1, 80, "a.internal.")
            ])
        );
        assert_eq!(true, pick_srv_targets(&[]).is_empty());
    }

    #[test]
    fn test_normalize_weights() {
        let normalized = |weights: &[usize]| {
            let mut weights = weights.to_vec();
            normalize_weights(&mut weights);
            weights
        };
        assert_eq!(vec![1, 3], normalized(&[10, 30]));
        assert_eq!(vec![1, 1, 1], normalized(&[100, 100, 100]));
        assert_eq!(vec![1], normalized(&[65535]));
        assert_eq!(vec![2, 3], normalized(&[2, 3]));
        // The largest there is beside the least: 256 to 1, not 65535.
        assert_eq!(vec![256, 1], normalized(&[65535, 1]));
        assert_eq!(vec![256, 128, 1], normalized(&[1000, 499, 3]));
        // As good as equal.
        assert_eq!(vec![256, 256], normalized(&[65535, 65534]));
        assert_eq!(Vec::<usize>::new(), normalized(&[]));
    }

    /// What the targets of a name came to: the ones that resolved, and a
    /// round that is short when one of the others got no answer.
    #[test]
    fn test_srv_targets() {
        let now = Instant::now();
        let hour = now + Duration::from_secs(3600);
        let minute = now + Duration::from_secs(60);
        let ip = |last: u8| IpAddr::from([10, 0, 0, last]);
        let targets = |resolved: Resolved| match resolved {
            Resolved::Targets(targets, until) => Some((targets, until)),
            _ => None,
        };

        // All of them: good for as long as the shortest of the records.
        let resolved = srv_targets(
            vec![
                (8080, 1, Ok((vec![ip(1), ip(2)], hour))),
                (8081, 3, Ok((vec![ip(3)], minute))),
            ],
            hour,
            now,
        );
        assert_eq!(
            Some((
                vec![(ip(1), 8080, 1), (ip(2), 8080, 1), (ip(3), 8081, 3)],
                minute
            )),
            targets(resolved)
        );

        // One that got no answer is left out, and asked for again soon.
        let resolved = srv_targets(
            vec![(8080, 1, Ok((vec![ip(1)], hour))), (8081, 3, Err(false))],
            hour,
            now,
        );
        assert_eq!(
            Some((vec![(ip(1), 8080, 1)], now + DISCOVERY_CACHE_MIN)),
            targets(resolved)
        );
        // One that is not there is left out for as long as the records
        // hold.
        let resolved = srv_targets(
            vec![(8080, 1, Ok((vec![ip(1)], hour))), (8081, 3, Err(true))],
            hour,
            now,
        );
        assert_eq!(Some((vec![(ip(1), 8080, 1)], hour)), targets(resolved));

        // None of them: no answer, the backends the name had stay.
        for no_such_name in [true, false] {
            let resolved =
                srv_targets(vec![(80, 1, Err(no_such_name))], hour, now);
            assert_eq!(true, matches!(resolved, Resolved::Failed));
        }
        // No record at all: the name has no backends.
        assert_eq!(
            true,
            matches!(srv_targets(vec![], hour, now), Resolved::Gone)
        );
    }

    /// What `SRV` records lead to is a backend for each address, with the
    /// port and the weight of its record and not those of the entry.
    #[test]
    fn test_merge_round_with_srv_targets() {
        let now = Instant::now();
        let hour = now + Duration::from_secs(3600);
        let ip = |last: u8| IpAddr::from([10, 0, 0, last]);
        let hosts = vec![
            ("_http._tcp.api.internal".to_string(), 80, 1),
            ("web.internal".to_string(), 8000, 2),
        ];
        let v6: IpAddr = "fd00::1".parse().unwrap();
        let resolved = [
            Resolved::Targets(
                vec![(ip(1), 8080, 10), (ip(2), 8081, 30), (v6, 8080, 10)],
                now + Duration::from_secs(30),
            ),
            Resolved::Addrs(vec![ip(9)], hour),
        ];
        let backends = |ipv4_only: bool| -> Vec<(String, usize)> {
            let (host_backends, valid_until) =
                merge_round(&hosts, ipv4_only, &resolved, None, now);
            // good for as long as the shortest of the records
            assert_eq!(now + Duration::from_secs(30), valid_until);
            host_backends
                .iter()
                .flat_map(|host| host.backends.iter())
                .map(|backend| (backend.addr.to_string(), backend.weight))
                .collect()
        };
        assert_eq!(
            vec![
                ("10.0.0.1:8080".to_string(), 10),
                ("10.0.0.2:8081".to_string(), 30),
                ("[fd00::1]:8080".to_string(), 10),
                ("10.0.0.9:8000".to_string(), 2),
            ],
            backends(false)
        );
        assert_eq!(3, backends(true).len());
    }

    /// Regression: an address with a port was dropped, leaving no server.
    #[test]
    fn test_parse_name_servers() {
        let servers = |value: &str| -> Vec<(String, Vec<u16>)> {
            parse_name_servers(value)
                .unwrap()
                .iter()
                .map(|server| {
                    (
                        server.ip.to_string(),
                        server.connections.iter().map(|c| c.port).collect(),
                    )
                })
                .collect()
        };
        let server = |ip: &str, port: u16| (ip.to_string(), vec![port, port]);

        assert_eq!(vec![server("10.0.0.53", 53)], servers("10.0.0.53"));
        assert_eq!(vec![server("10.0.0.53", 53)], servers("10.0.0.53:53"));
        assert_eq!(vec![server("10.0.0.53", 5353)], servers("10.0.0.53:5353"));
        assert_eq!(vec![server("fd00::53", 53)], servers("fd00::53"));
        assert_eq!(vec![server("fd00::53", 5353)], servers("[fd00::53]:5353"));
        assert_eq!(
            vec![server("10.0.0.53", 53), server("10.0.0.54", 1053)],
            servers("10.0.0.53, 10.0.0.54:1053,")
        );
        assert_eq!(true, servers("").is_empty());

        // Not an address: said so, not skipped.
        for value in ["dns.example.com", "10.0.0.53:port", "10.0.0.53,nope"] {
            let err = parse_name_servers(value).unwrap_err().to_string();
            assert_eq!(true, err.contains("is invalid"), "{value}: {err}");
        }
    }

    #[tokio::test]
    async fn test_async_dns_discover() {
        assert_eq!(true, is_dns_discovery("dns"));
        let dns = Dns::new(&["api".to_string()], true, true)
            .unwrap()
            .with_name_server("8.8.8.8".to_string())
            .with_domain("github.com".to_string());
        let (ip_list, _) = dns.tokio_lookup_ip().await.unwrap();
        assert_eq!(true, !ip_list.is_empty());

        let discovered = dns.run_discover().await.unwrap();
        assert_eq!(true, !discovered.backends.is_empty());
        assert_eq!(false, discovered.from_cache);
        assert_eq!(true, discovered.changed);
        // Within the TTL the same set comes back from the cache, and is
        // not reported as a change.
        let again = dns.run_discover().await.unwrap();
        assert_eq!(discovered.backends, again.backends);
        assert_eq!(true, again.from_cache);
        assert_eq!(false, again.changed);

        // new dns discover backends
        let result = new_dns_discover_backends(&Discovery {
            addr: vec!["api".to_string()],
            tls: true,
            ipv4_only: true,
            dns_server: Some("8.8.8.8".to_string()),
            dns_domain: Some("github.com".to_string()),
            dns_search: Some("local".to_string()),
            sender: None,
        });
        assert_eq!(true, result.is_ok());
    }

    /// Regression: a host whose lookup failed lost its backends, and the
    /// set without them was kept for as long as the records of the other
    /// hosts were good for, up to five minutes.
    #[test]
    fn test_a_failed_lookup_keeps_the_backends_it_had() {
        let hosts: Vec<Addr> = vec![
            ("a.test".to_string(), 8080, 1),
            ("b.test".to_string(), 443, 2),
        ];
        let now = Instant::now();
        let ip = |last: u8| std::net::IpAddr::from([10, 0, 0, last]);
        let addrs = |host: &HostBackends| {
            host.backends
                .iter()
                .map(|backend| backend.addr.to_string())
                .collect::<Vec<_>>()
        };
        let cache_of =
            |host_backends: Vec<HostBackends>, valid_until| DiscoveryCache {
                backends: host_backends
                    .iter()
                    .flat_map(|host| host.backends.iter())
                    .cloned()
                    .collect(),
                host_backends,
                failed_hosts: vec![],
                valid_until,
            };

        // Both resolve: good for as long as the shorter of the two.
        let long = now + Duration::from_secs(200);
        let (first, valid_until) = merge_round(
            &hosts,
            false,
            &[
                Resolved::Addrs(vec![ip(1), ip(2)], long),
                Resolved::Addrs(vec![ip(3)], now + Duration::from_secs(60)),
            ],
            None,
            now,
        );
        assert_eq!(vec!["10.0.0.1:8080", "10.0.0.2:8080"], addrs(&first[0]));
        assert_eq!(vec!["10.0.0.3:443"], addrs(&first[1]));
        assert_eq!(now + Duration::from_secs(60), valid_until);
        let previous = cache_of(first, valid_until);

        // The second one gets no answer: it keeps what it had, the first
        // takes its new address, and the round is asked for again soon.
        let (second, valid_until) = merge_round(
            &hosts,
            false,
            &[Resolved::Addrs(vec![ip(9)], long), Resolved::Failed],
            Some(&previous),
            now + Duration::from_secs(30),
        );
        assert_eq!(vec!["10.0.0.9:8080"], addrs(&second[0]));
        assert_eq!(vec!["10.0.0.3:443"], addrs(&second[1]));
        assert_eq!(
            now + Duration::from_secs(30) + DISCOVERY_CACHE_MIN,
            valid_until
        );
        // When it resolved stays what it was, so that the keeping ends.
        assert_eq!(Some(now), second[1].resolved_at);
        let previous = cache_of(second, valid_until);

        // Still no answer ten minutes on: it has gone on long enough.
        let (late, _) = merge_round(
            &hosts,
            false,
            &[Resolved::Addrs(vec![ip(9)], long), Resolved::Failed],
            Some(&previous),
            now + KEEP_FAILED_FOR,
        );
        assert_eq!(true, late[1].backends.is_empty());

        // The answer is that there is no such name: gone at once.
        let (gone, valid_until) = merge_round(
            &hosts,
            false,
            &[Resolved::Addrs(vec![ip(9)], long), Resolved::Gone],
            Some(&previous),
            now,
        );
        assert_eq!(true, gone[1].backends.is_empty());
        assert_eq!(now + DISCOVERY_CACHE_MIN, valid_until);

        // Never resolved: nothing to keep, and nothing of the other host
        // under its port.
        let (none, _) = merge_round(
            &hosts,
            false,
            &[Resolved::Failed, Resolved::Addrs(vec![ip(3)], long)],
            None,
            now,
        );
        assert_eq!(true, none[0].backends.is_empty());
        assert_eq!(vec!["10.0.0.3:443"], addrs(&none[1]));

        // The time a round is good for stays within its bounds.
        let hour = now + Duration::from_secs(3600);
        let (_, valid_until) = merge_round(
            &hosts,
            true,
            &[
                Resolved::Addrs(vec![ip(1)], hour),
                Resolved::Addrs(vec![ip(3)], hour),
            ],
            None,
            now,
        );
        assert_eq!(now + DISCOVERY_CACHE_MAX, valid_until);
    }

    #[tokio::test]
    async fn test_dns_discover_partial_failure_keeps_alignment() {
        // The first host cannot resolve, the second can, and they declare
        // different ports. Results are paired with hosts by position, so the
        // failed lookup must keep its slot: compacting used to shift the
        // second host's IPs onto the first host's port.
        let dns = Dns::new(
            &[
                "no-such-host-pingap-test:8080".to_string(),
                "api:443".to_string(),
            ],
            true,
            true,
        )
        .unwrap()
        .with_name_server("8.8.8.8".to_string())
        .with_domain("github.com".to_string());

        let (ip_list, failed_hosts) = dns.tokio_lookup_ip().await.unwrap();
        assert_eq!(2, ip_list.len());
        assert_eq!(true, ip_list[0].is_err());
        assert_eq!(true, ip_list[1].is_ok());
        assert_eq!(vec!["no-such-host-pingap-test".to_string()], failed_hosts);

        let discovered = dns.run_discover().await.unwrap();
        let backends = discovered.backends;
        assert_eq!(true, !backends.is_empty());
        assert_eq!(1, discovered.failed_hosts.len());
        // Every backend belongs to the host that resolved - none may carry
        // the failed host's port.
        for backend in backends.iter() {
            assert_eq!(
                true,
                backend.addr.to_string().ends_with(":443"),
                "{} must not be on the failed host's port",
                backend.addr
            );
        }
    }
}
