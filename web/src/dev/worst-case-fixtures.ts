import type useBasicState from "@/states/basic";
import type useConfigState from "@/states/config";
import type { CertificateInfo } from "@/states/config";
import type { TrafficSnapshot } from "@/states/traffic";

export type BreakUiMode = "live" | "worst" | "empty" | "one";

type BasicData = ReturnType<typeof useBasicState.getState>["data"];
type ConfigData = ReturnType<typeof useConfigState.getState>["data"];

export interface BreakUiDataset {
  basic: BasicData;
  config: ConfigData;
  certificateInfos: Record<string, CertificateInfo>;
  traffic: TrafficSnapshot | null;
  originalToml?: string;
  fullToml?: string;
  hcl?: string;
  kdl?: string;
}

const LONG_UNBREAKABLE_PRIMARY =
  "customer-feedback-enterprise-onboarding-eu-west-1-canary+v2&blue#1";
const LONG_UNBREAKABLE_SECONDARY =
  "grpc_internal_mesh_telemetry_collector_primary_pool_2026_q4_edge_gw";
const CJK_BILINGUAL_NAME = "网关路由-华东生产集群-双活容灾备份节点-01";
const SHORT_SINGLE_CHAR = "a";

function buildWorstCaseDataset(): BreakUiDataset {
  const nowSec = Math.floor(Date.now() / 1000);

  const serverNames = [
    LONG_UNBREAKABLE_PRIMARY,
    LONG_UNBREAKABLE_SECONDARY,
    CJK_BILINGUAL_NAME,
    SHORT_SINGLE_CHAR,
    ...Array.from(
      { length: 14 },
      (_, idx) => `edge-ingress-zone-${String(idx + 1).padStart(2, "0")}`,
    ),
  ];

  const locationNames = [
    LONG_UNBREAKABLE_PRIMARY,
    LONG_UNBREAKABLE_SECONDARY,
    CJK_BILINGUAL_NAME,
    SHORT_SINGLE_CHAR,
    ...Array.from({ length: 16 }, (_, idx) => `route-api-v${idx + 1}-dispatch`),
  ];

  const upstreamNames = [
    LONG_UNBREAKABLE_PRIMARY,
    "payments-ledger-settlement-critical-failover-pool",
    LONG_UNBREAKABLE_SECONDARY,
    CJK_BILINGUAL_NAME,
    SHORT_SINGLE_CHAR,
    ...Array.from(
      { length: 14 },
      (_, idx) => `backend-cluster-shard-${String(idx + 1).padStart(2, "0")}`,
    ),
  ];

  const streamNames = [
    LONG_UNBREAKABLE_PRIMARY,
    "postgres-primary-mtls-passthrough-eu-central-1",
    CJK_BILINGUAL_NAME,
    ...Array.from({ length: 5 }, (_, idx) => `tcp-relay-${idx + 1}`),
  ];

  const pluginNames = [
    LONG_UNBREAKABLE_PRIMARY,
    "oauth2-oidc-enterprise-sso-token-exchange",
    CJK_BILINGUAL_NAME,
    SHORT_SINGLE_CHAR,
    ...Array.from({ length: 14 }, (_, idx) => `policy-guard-${idx + 1}`),
  ];

  const certNames = [
    "wildcard-expired-legacy-edge+2024#old",
    "checkout-expiring-today&urgent",
    LONG_UNBREAKABLE_PRIMARY,
    CJK_BILINGUAL_NAME,
    ...Array.from({ length: 12 }, (_, idx) => `tenant-cert-${idx + 1}`),
  ];

  const storageNames = [
    LONG_UNBREAKABLE_PRIMARY,
    CJK_BILINGUAL_NAME,
    ...Array.from({ length: 8 }, (_, idx) => `shared-profile-${idx + 1}`),
  ];

  const servers: NonNullable<ConfigData["servers"]> = {};
  serverNames.forEach((name, idx) => {
    servers[name] = {
      addr:
        idx === 0
          ? "[2001:db8:85a3::8a2e:370:7334]:8443, [::1]:8080, unix:/var/run/pingap-admin.sock"
          : idx === 1
            ? "0.0.0.0:443, 0.0.0.0:8443, [::]:443"
            : `10.24.0.${10 + idx}:${8000 + idx}`,
      locations: locationNames.slice(0, idx === 0 ? 12 : 3),
      threads: idx % 2 === 0 ? 16 : undefined,
      enabled_h2: true,
      global_certificates: true,
      remark:
        idx === 0
          ? "Primary ingress serving multi-region & 华东生产流量 with Unicode diacritics café / naïve"
          : undefined,
    };
  });

  const locations: NonNullable<ConfigData["locations"]> = {};
  locationNames.forEach((name, idx) => {
    locations[name] = {
      host:
        idx === 0
          ? "portal.very-long-enterprise-subdomain.eu-west-1.internal.example.com, *.staging-canary.example.org"
          : idx === 1
            ? "api-gateway-v2.prod.internal"
            : `svc-${idx}.example.com`,
      path:
        idx === 0
          ? "~/api/v2/customers/[0-9a-f-]+/onboarding/webhooks/deliveries"
          : idx === 3
            ? "/"
            : `/v${idx}/dispatch`,
      upstream: upstreamNames[idx % upstreamNames.length],
      plugins: pluginNames.slice(0, idx === 0 ? 10 : 3),
      weight: idx === 0 ? 2048 : 512 - idx,
    };
  });

  const upstreams: NonNullable<ConfigData["upstreams"]> = {};
  upstreamNames.forEach((name, idx) => {
    upstreams[name] = {
      addrs:
        idx === 0
          ? [
              "[2001:db8:85a3::8a2e:370:7334]:9443 10",
              "10.120.14.201:8443 5",
              "10.120.14.202:8443 5",
              "10.120.14.203:8443 5",
            ]
          : [`10.88.${idx}.10:8080`, `10.88.${idx}.11:8080`],
      algo: idx % 2 === 0 ? "least_connections" : "round_robin",
      discovery: idx === 0 ? "dns" : undefined,
      health_check: idx < 2 ? "http://127.0.0.1/healthz" : undefined,
    };
  });

  const streams: NonNullable<ConfigData["streams"]> = {};
  streamNames.forEach((name, idx) => {
    streams[name] = {
      addr:
        idx === 0
          ? "[2001:db8::1]:5432, 0.0.0.0:15432"
          : `0.0.0.0:${16000 + idx}`,
      upstream: upstreamNames[idx % upstreamNames.length],
      sni_routes:
        idx === 0
          ? {
              "primary.db.internal.example.com": LONG_UNBREAKABLE_PRIMARY,
              "replica.db.internal.example.com": LONG_UNBREAKABLE_SECONDARY,
            }
          : undefined,
      threads: idx === 0 ? 8 : undefined,
    };
  });

  const plugins: NonNullable<ConfigData["plugins"]> = {};
  pluginNames.forEach((name, idx) => {
    plugins[name] = {
      category:
        idx % 4 === 0
          ? "jwt"
          : idx % 4 === 1
            ? "limit"
            : idx % 4 === 2
              ? "compression"
              : "response_headers",
      step: idx % 2 === 0 ? "request" : "response",
      remark:
        idx === 0
          ? "Enforce strict JWT + CORS & 签名校验 — production critical policy 🚀"
          : "Automated policy baseline",
    };
  });

  const certificates: NonNullable<ConfigData["certificates"]> = {};
  const certificateInfos: Record<string, CertificateInfo> = {};
  certNames.forEach((name, idx) => {
    certificates[name] = {
      domains:
        idx === 0
          ? "*.expired.enterprise-onboarding.eu-west-1.example.com, *.legacy.example.org"
          : `*.tenant-${idx}.example.com`,
      acme: idx % 3 === 0 ? "lets_encrypt" : undefined,
      is_default: idx === 2,
      ocsp_stapling: idx === 2,
    };
    const offsetDays =
      idx === 0 ? -42 : idx === 1 ? 0 : idx === 2 ? 5 : 45 + idx * 10;
    certificateInfos[name] = {
      domains: [
        `*.tenant-${idx}.eu-west-1.example.com`,
        `api-${idx}.internal.example.org`,
        `edge-${idx}.global-cdn.example.net`,
        `fallback-${idx}.apac.example.com`,
      ],
      not_before: nowSec - 90 * 86400,
      not_after: idx === 1 ? nowSec + 3600 : nowSec + offsetDays * 86400,
      issuer:
        "CN=Sectigo Public Server Authentication CA OV R36, O=Sectigo Limited, L=Salford, ST=Greater Manchester, C=GB",
      issuer_cn:
        idx === 2
          ? "Sectigo Public Server Authentication CA OV R36"
          : "Let's Encrypt R11",
      ocsp_stapling: true,
      ocsp_stapled: idx === 2,
      chain_count: 3,
    };
  });

  const storages: NonNullable<ConfigData["storages"]> = {};
  storageNames.forEach((name, idx) => {
    storages[name] = {
      category: idx % 2 === 0 ? "config" : "secret",
      value: 'read_timeout = "15s"\nconnection_timeout = "3s"',
      remark:
        idx === 0
          ? "Shared timeouts & TLS defaults for 华东-多可用区 clusters"
          : "Shared config fragment",
    };
  });

  // Total 26 ticks (17/20 + 0/6 <= MAX_TICKS=28) so mobile width overflows unless
  // HealthStrip switches cleanly at < sm, while desktop renders full ticks.
  const upstreamHealthyStatus: BasicData["upstream_healthy_status"] = {
    [LONG_UNBREAKABLE_PRIMARY]: {
      healthy: 17,
      total: 20,
      unhealthy_backends: [
        "[2001:db8:85a3::18]:9443",
        "[2001:db8:85a3::19]:9443",
        "[2001:db8:85a3::20]:9443",
      ],
    },
    "payments-ledger-settlement-critical-failover-pool": {
      healthy: 0,
      total: 6,
      unhealthy_backends: ["10.88.1.10:8080", "10.88.1.11:8080"],
    },
  };

  const buckets = 91;
  const times = Array.from(
    { length: buckets },
    (_, i) => nowSec - (buckets - i) * 10,
  );
  const requests = times.map((_, i) =>
    Math.round(180_000 + Math.sin(i / 6) * 95_000 + (i % 7) * 18_000),
  );
  const status4xx = requests.map((r) => Math.round(r * 0.032));
  const status5xx = requests.map((r, i) =>
    i > buckets - 10 ? Math.round(r * 0.018) : Math.round(r * 0.002),
  );
  const status3xx = requests.map((r) => Math.round(r * 0.08));
  const status2xx = requests.map(
    (r, i) => r - status3xx[i] - status4xx[i] - status5xx[i],
  );
  const latencyAvg = times.map((_, i) =>
    Math.round(42 + Math.cos(i / 5) * 28 + (i % 9) * 12),
  );
  const latencyP95 = latencyAvg.map((v, i) => Math.round(v * 6.5 + i * 2));
  const latencyMax = latencyP95.map((v) => Math.round(v * 2.1));

  const trafficUpstreams: TrafficSnapshot["upstreams"] = {};
  upstreamNames.slice(0, 12).forEach((name, idx) => {
    const scale = Math.max(0.05, 1 - idx * 0.075);
    trafficUpstreams[name] = {
      requests: requests.map((r) => Math.round(r * scale * 0.2)),
      errors: requests.map((r, bi) =>
        idx < 2 && bi > buckets - 10 ? Math.round(r * 0.012) : 0,
      ),
      latency_count: requests.map((r) => Math.round(r * scale * 0.2)),
      latency_avg: latencyAvg.map((v) => Math.round(v * (1 + idx * 0.15))),
      latency_max: latencyMax.map((v) => Math.round(v * (1 + idx * 0.2))),
    };
  });

  const trafficStreams: NonNullable<TrafficSnapshot["streams"]> = {};
  streamNames.slice(0, 6).forEach((name, idx) => {
    trafficStreams[name] = {
      active_connections: 4_820 - idx * 610,
      connections_total: 12_480_920 - idx * 910_000,
      rx_bytes: 94_812_340_120 * (6 - idx),
      tx_bytes: 285_114_920_440 * (6 - idx),
    };
  });

  const sampleToml = serverNames
    .slice(0, 4)
    .map(
      (name) =>
        `[servers."${name}"]\naddr = "${servers[name].addr}"\nthreads = 16`,
    )
    .join("\n\n");

  return {
    basic: {
      start_time: nowSec - 1_248_910,
      version: "0.17.0-rc.12+20261128.abcdef0",
      rustc_version: "1.96.0-nightly (2026-10-15 a1b2c3d4)",
      git_hash: "7ebc56820494fdd63898faa38050282a5846303a",
      memory: "428.6 MiB",
      arch: "x86_64",
      kernel: "6.8.0-49-generic #49~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC",
      config_hash:
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      pid: "148204",
      user: "pingap-daemon",
      group: "pingap-proxy",
      threads: 64,
      accepted: 98_765_432_109,
      processing: 14_820,
      cpus: 64,
      physical_cpus: 32,
      used_memory: "14.8 GiB",
      total_memory: "64.0 GiB",
      features: ["openssl", "tracing", "full", "imageoptim"],
      fd_count: 262_144,
      tcp_count: 131_072,
      tcp6_count: 65_536,
      supported_plugins: [
        "basic_auth",
        "cache",
        "compression",
        "cors",
        "csrf",
        "directory",
        "ip_restriction",
        "jwt",
        "key_auth",
        "limit",
        "mock",
        "ping",
        "redirect",
        "request_headers",
        "response_headers",
      ],
      support_history: true,
      read_only: false,
      restart_unsupported: "",
      upstream_healthy_status: upstreamHealthyStatus,
      abnormal_exit: {
        pid: 147910,
        started: nowSec - 3_720,
        panic:
          "thread 'pingora-worker-07' panicked at pingap-proxy/src/server.rs:412:18: called Option::unwrap() on a None value while draining upstream connection pool for eu-west-1",
      },
    },
    config: {
      basic: {
        name: "pingap-edge-prod-eu-west-1-primary-ingress-cluster-01 — Staging & 生产双活节点",
        threads: 16,
        log_level: "info,pingap_proxy=debug",
      },
      servers,
      streams,
      locations,
      upstreams,
      plugins,
      certificates,
      storages,
    },
    certificateInfos,
    traffic: {
      interval: 10,
      time: times,
      requests,
      status_2xx: status2xx,
      status_3xx: status3xx,
      status_4xx: status4xx,
      status_5xx: status5xx,
      latency_count: requests,
      latency_avg: latencyAvg,
      latency_p95: latencyP95,
      latency_max: latencyMax,
      upstreams: trafficUpstreams,
      streams: trafficStreams,
      cache_memory_evictions: 1_420_891,
    },
    originalToml: sampleToml,
    fullToml: `${sampleToml}\n\n# expanded defaults\n[basic]\nthreads = 16`,
    hcl: `server "${LONG_UNBREAKABLE_PRIMARY}" {\n  addr = "${servers[LONG_UNBREAKABLE_PRIMARY].addr}"\n}`,
    kdl: `server "${LONG_UNBREAKABLE_PRIMARY}" {\n  addr "${servers[LONG_UNBREAKABLE_PRIMARY].addr}"\n}`,
  };
}

function buildEmptyDataset(): BreakUiDataset {
  return {
    basic: {
      start_time: 0,
      version: "0.17.0",
      rustc_version: "",
      git_hash: "",
      memory: "",
      arch: "",
      kernel: "",
      config_hash: "",
      pid: "",
      user: "",
      group: "",
      threads: -1,
      accepted: 0,
      processing: 0,
      cpus: 0,
      physical_cpus: 0,
      used_memory: "",
      total_memory: "",
      features: [],
      fd_count: 0,
      tcp_count: 0,
      tcp6_count: 0,
      supported_plugins: ["ping", "compression"],
      support_history: false,
      read_only: false,
      restart_unsupported: "foreground",
      upstream_healthy_status: {},
      abnormal_exit: null,
    },
    config: {
      basic: {},
      servers: {},
      streams: {},
      locations: {},
      upstreams: {},
      plugins: {},
      certificates: {},
      storages: {},
    },
    certificateInfos: {},
    traffic: null,
    originalToml: "",
    fullToml: "",
    hcl: "",
    kdl: "",
  };
}

function buildOneDataset(): BreakUiDataset {
  const nowSec = Math.floor(Date.now() / 1000);
  return {
    basic: {
      start_time: nowSec - 48,
      version: "0.17.0",
      rustc_version: "1.96.0",
      git_hash: "7ebc568",
      memory: "18.2 MiB",
      arch: "arm64",
      kernel: "6.8.0",
      config_hash: "a1b2c3d",
      pid: "1",
      user: "pingap",
      group: "pingap",
      threads: 1,
      accepted: 1,
      processing: 1,
      cpus: 2,
      physical_cpus: 2,
      used_memory: "1.2 GiB",
      total_memory: "8.0 GiB",
      features: ["openssl"],
      fd_count: 1,
      tcp_count: 1,
      tcp6_count: 0,
      supported_plugins: ["ping"],
      support_history: true,
      read_only: false,
      restart_unsupported: "container",
      upstream_healthy_status: {
        a: {
          healthy: 1,
          total: 1,
          unhealthy_backends: [],
        },
      },
      abnormal_exit: null,
    },
    config: {
      basic: { name: "a" },
      servers: { a: { addr: "0.0.0.0:80", locations: ["a"] } },
      streams: { a: { addr: "0.0.0.0:5432", upstream: "a" } },
      locations: { a: { path: "/", upstream: "a", plugins: ["a"] } },
      upstreams: { a: { addrs: ["127.0.0.1:8080"] } },
      plugins: { a: { category: "ping" } },
      certificates: { a: { domains: "a.test" } },
      storages: { a: { category: "config", value: "threads = 1" } },
    },
    certificateInfos: {
      a: {
        domains: ["a.test"],
        not_before: nowSec - 86400,
        not_after: nowSec + 90 * 86400,
        issuer_cn: "CA",
      },
    },
    traffic: {
      interval: 10,
      time: [nowSec - 10],
      requests: [1],
      status_2xx: [1],
      status_3xx: [0],
      status_4xx: [0],
      status_5xx: [0],
      latency_count: [1],
      latency_avg: [1],
      latency_p95: [1],
      latency_max: [1],
      upstreams: {},
      streams: {},
    },
    originalToml: '[servers.a]\naddr = "0.0.0.0:80"',
    fullToml: '[servers.a]\naddr = "0.0.0.0:80"',
    hcl: 'server "a" { addr = "0.0.0.0:80" }',
    kdl: 'server "a" { addr "0.0.0.0:80" }',
  };
}

export function createBreakUiDataset(
  mode: Exclude<BreakUiMode, "live">,
): BreakUiDataset {
  switch (mode) {
    case "worst":
      return buildWorstCaseDataset();
    case "empty":
      return buildEmptyDataset();
    case "one":
      return buildOneDataset();
  }
}
