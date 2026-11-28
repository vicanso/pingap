import useConfigState, { getLocationWeight } from "@/states/config";
import { CheckCircle2, ChevronRight, Plus } from "lucide-react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  CERTIFICATES,
  HOME,
  LOCATIONS,
  PLUGINS,
  SERVERS,
  STORAGES,
  STREAMS,
  UPSTREAMS,
} from "@/routers";
import { LoadingPage } from "@/components/loading";
import useBasicState from "@/states/basic";
import { useI18n } from "@/i18n";
import { listify } from "radash";
import { useAsync } from "react-async-hook";
import React from "react";
import { useShallow } from "zustand/react/shallow";
import { PageShell } from "@/components/page-shell";
import { getLoginToken } from "@/states/token";
import { goToLogin } from "@/routers";
import { daysUntil, formatUptime } from "@/helpers/util";
import {
  TrafficPath,
  type PathHealth,
  type PathStage,
} from "@/components/traffic-path";
import { TrafficPanel } from "@/components/traffic-panel";
import { QuickSiteWizard } from "@/components/quick-site-wizard";

interface Summary {
  name: string;
  value: string;
  link: string;
  nameClass?: string;
  /**
   * Marks the value itself as a health state. A certificate row shows an
   * expiry date, and a bare date says nothing about whether it has passed —
   * reading it correctly means knowing today's date. The tone says it.
   */
  valueTone?: "warn" | "down";
  /** Spelled out, because a colour on its own is not a message. */
  valueTitle?: string;
}

interface EntityCard {
  title: string;
  path: string;
  count: number;
  unit: string;
  summary: Summary[];
}

interface Alert {
  key: string;
  tone: "warn" | "down";
  name: string;
  message: string;
  to: string;
  /** The whole of a message that may be longer than the line shows. */
  title?: string;
}

export default function Home() {
  const homeI18n = useI18n("home");
  const [config, initialized, certificateInfos, getCertificateInfos] =
    useConfigState(
      useShallow((state) => [
        state.data,
        state.initialized,
        state.certificateInfos,
        state.getCertificateInfos,
      ]),
    );
  const [basicInfo, fetchBasicInfo] = useBasicState(
    useShallow((state) => [state.data, state.fetch]),
  );

  // /basic was only fetched once when the app mounted, so every counter on this
  // page froze the moment it opened. Refresh while the dashboard is on screen —
  // scoped to this component, so no other page pays for it — and skip ticks for
  // a hidden tab, where nobody is reading the numbers.
  // Also skip when there is no login token: unauthenticated polls only spam
  // the admin log with "missing authorization header".
  React.useEffect(() => {
    let stopped = false;
    const refresh = () => {
      if (stopped || document.hidden || !getLoginToken()) {
        return;
      }
      fetchBasicInfo().catch((err: { status?: number }) => {
        if (err?.status === 401) {
          stopped = true;
          goToLogin();
        }
      });
    };
    const timer = setInterval(refresh, 5000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      stopped = true;
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [fetchBasicInfo]);

  useAsync(async () => {
    try {
      await getCertificateInfos();
    } catch {
      // Validity dates are supporting detail: without them the certificate
      // card simply omits the range and no expiry warning is raised. Not worth
      // a toast on every visit to the dashboard.
    }
  }, []);
  if (!initialized) {
    return <LoadingPage />;
  }

  const formatDate = (value: number) => {
    const date = new Date(value * 1000);
    const pad = (n: number) => n.toString().padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  };

  const serverSummary: Summary[] = [];
  if (config.servers) {
    listify(config.servers, (name, value) => {
      serverSummary.push({
        name,
        link: `${SERVERS}?name=${encodeURIComponent(name)}`,
        value: value.addr,
      });
    });
  }
  serverSummary.sort((a, b) => a.name.localeCompare(b.name));

  const streamSummary: Summary[] = [];
  if (config.streams) {
    listify(config.streams, (name, value) => {
      streamSummary.push({
        name,
        link: `${STREAMS}?name=${encodeURIComponent(name)}`,
        value: value?.addr || "—",
      });
    });
  }
  streamSummary.sort((a, b) => a.name.localeCompare(b.name));

  const locationSummary: Summary[] = [];
  const locationSummaryWeight: Record<string, number> = {};
  if (config.locations) {
    listify(config.locations, (name, value) => {
      locationSummaryWeight[name] = getLocationWeight(value);
      const match = [value.host, value.path || "/"].filter(Boolean).join(" ");
      locationSummary.push({
        name,
        link: `${LOCATIONS}?name=${encodeURIComponent(name)}`,
        value: match,
      });
    });
    locationSummary.sort(
      (a, b) =>
        (locationSummaryWeight[b.name] || 0) -
        (locationSummaryWeight[a.name] || 0),
    );
  }

  const upstreamSummary: Summary[] = [];
  if (config.upstreams) {
    listify(config.upstreams, (name, value) => {
      const status = basicInfo.upstream_healthy_status[name];
      let nameClass = "";
      if (status) {
        if (status.healthy === 0) {
          nameClass = "text-down";
        } else if (status.healthy < status.total) {
          nameClass = "text-warn";
        }
      }
      upstreamSummary.push({
        name,
        nameClass,
        link: `${UPSTREAMS}?name=${encodeURIComponent(name)}`,
        value: value.addrs.map((addr) => addr.split(" ")[0]).join(" "),
      });
    });
  }
  upstreamSummary.sort((a, b) => a.name.localeCompare(b.name));

  const pluginSummary: Summary[] = [];
  if (config.plugins) {
    listify(config.plugins, (name, value) => {
      pluginSummary.push({
        name,
        link: `${PLUGINS}?name=${encodeURIComponent(name)}`,
        value: value.category as string,
      });
    });
  }
  pluginSummary.sort((a, b) => a.name.localeCompare(b.name));

  // Single source of truth for what a certificate's remaining validity means,
  // so the alert list and the entity card can never disagree about it.
  const certificateState = (notAfter: number) => {
    const days = daysUntil(notAfter);
    if (days > 30) {
      return undefined;
    }
    return {
      tone: (days <= 7 ? "down" : "warn") as "down" | "warn",
      message:
        days < 0
          ? homeI18n("certExpired", { days: Math.abs(days) })
          : days === 0
            ? homeI18n("certExpiresToday")
            : homeI18n("certExpiring", { days }),
    };
  };

  const certificateSummary: Summary[] = [];
  if (config.certificates) {
    listify(config.certificates, (name, value) => {
      const info = certificateInfos[name];
      const hasExpiry = Boolean(info?.not_after);
      const state = hasExpiry ? certificateState(info.not_after) : undefined;
      certificateSummary.push({
        name,
        link: `${CERTIFICATES}?name=${encodeURIComponent(name)}`,
        value: hasExpiry
          ? homeI18n("expiresOn", { date: formatDate(info.not_after) })
          : value.domains || info?.domains?.join(", ") || "",
        valueTone: state?.tone,
        valueTitle: state?.message,
      });
    });
  }
  certificateSummary.sort((a, b) => a.name.localeCompare(b.name));

  const storageSummary: Summary[] = [];
  if (config.storages) {
    listify(config.storages, (name, value) => {
      storageSummary.push({
        name,
        link: `${STORAGES}?name=${encodeURIComponent(name)}`,
        value: value.category,
      });
    });
  }
  storageSummary.sort((a, b) => a.name.localeCompare(b.name));

  // Health is reported per upstream, and only for upstreams that actually run a
  // check. Anything not reported stays out of the ratio rather than being
  // counted as up — a green bar that means "nobody asked" is worse than none.
  const statuses = Object.entries(basicInfo.upstream_healthy_status || {}).sort(
    ([a], [b]) => a.localeCompare(b),
  );
  const health: PathHealth = { up: 0, total: 0, ticks: [] };
  let degradedPools = 0;
  statuses.forEach(([, status]) => {
    health.up += status.healthy;
    health.total += status.total;
    for (let i = 0; i < status.total; i++) {
      health.ticks.push(i < status.healthy);
    }
    if (status.healthy < status.total) {
      degradedPools += 1;
    }
  });
  const hasHealthChecks = statuses.length > 0;
  const backendsDown = health.total - health.up;
  const configuredBackends = upstreamSummary.length
    ? Object.values(config.upstreams || {}).reduce(
        (total, upstream) => total + upstream.addrs.length,
        0,
      )
    : 0;

  // Every port the process is bound to, in listen order — the first concrete
  // fact anyone checks when a request is not arriving.
  const ports = Array.from(
    new Set(
      [...serverSummary, ...streamSummary].flatMap((listener) =>
        listener.value
          .split(",")
          .map((addr) => addr.trim())
          .filter((addr) => addr && addr !== "—")
          .map((addr) =>
            addr.startsWith("unix:")
              ? "unix"
              : `:${addr.slice(addr.lastIndexOf(":") + 1)}`,
          ),
      ),
    ),
  );

  // Every distinct host the routes answer for. Falls back to the
  // highest-weight matcher when no location pins a host, since that is then
  // the first rule an incoming request is tested against.
  const hosts = Array.from(
    new Set(
      Object.values(config.locations || {}).flatMap((location) =>
        (location.host || "")
          .split(",")
          .map((host) => host.trim())
          .filter(Boolean),
      ),
    ),
  );
  const routeDetail = hosts.length
    ? hosts.slice(0, 2).join("  ") +
      (hosts.length > 2 ? `  +${hosts.length - 2}` : "")
    : locationSummary[0]?.value || homeI18n("stageEmpty");

  const stages: PathStage[] = [
    {
      key: "listen",
      label: homeI18n("stageListen"),
      value: (serverSummary.length + streamSummary.length).toString(),
      unit:
        streamSummary.length > 0
          ? homeI18n("stageListenWithStreams", {
              servers: serverSummary.length,
              streams: streamSummary.length,
            })
          : homeI18n("stageListenUnit"),
      detail: ports.length ? ports.join(" ") : homeI18n("stageEmpty"),
      to:
        serverSummary.length === 0 && streamSummary.length > 0
          ? STREAMS
          : SERVERS,
    },
    {
      key: "route",
      label: homeI18n("stageRoute"),
      value: locationSummary.length.toString(),
      unit: homeI18n("stageRouteUnit"),
      detail: routeDetail,
      to: LOCATIONS,
    },
    {
      key: "pool",
      label: homeI18n("stagePool"),
      value: upstreamSummary.length.toString(),
      unit: homeI18n("stagePoolUnit"),
      detail: !upstreamSummary.length
        ? homeI18n("stageEmpty")
        : degradedPools > 0
          ? homeI18n("poolsDegraded", { count: degradedPools })
          : hasHealthChecks
            ? homeI18n("poolsHealthy")
            : homeI18n("noHealthChecks"),
      detailTone: degradedPools > 0 ? "warn" : "muted",
      to: UPSTREAMS,
    },
    {
      key: "origin",
      label: homeI18n("stageOrigin"),
      value: hasHealthChecks
        ? `${health.up}/${health.total}`
        : configuredBackends.toString(),
      unit: hasHealthChecks
        ? homeI18n("stageOriginUnit")
        : homeI18n("stageOriginUnitPlain"),
      detail: !hasHealthChecks
        ? homeI18n("noHealthChecks")
        : backendsDown > 0
          ? homeI18n("backendsDown", { count: backendsDown })
          : homeI18n("stageOriginAllUp"),
      detailTone: backendsDown > 0 ? "down" : "muted",
      to: UPSTREAMS,
    },
  ];

  const meters = [
    {
      label: homeI18n("processing"),
      value: basicInfo.processing.toLocaleString(),
    },
    {
      label: homeI18n("accepted"),
      value: basicInfo.accepted.toLocaleString(),
    },
    {
      label: homeI18n("memory"),
      value: basicInfo.memory || "—",
      muted: !basicInfo.memory,
    },
    {
      label: homeI18n("threads"),
      // Thread count comes from the OS; -1 means unavailable (e.g. non-Linux).
      value:
        basicInfo.threads == null || basicInfo.threads < 0
          ? "—"
          : basicInfo.threads.toLocaleString(),
      muted: basicInfo.threads == null || basicInfo.threads < 0,
      title:
        basicInfo.threads == null || basicInfo.threads < 0
          ? homeI18n("threadsUnavailable")
          : undefined,
    },
  ];

  // Anything an operator would want to act on today, in one list, ordered by
  // how bad it is. Both of these were previously only visible as small print
  // inside a card that is mostly about counting things.
  const alerts: Alert[] = [];
  statuses.forEach(([name, status]) => {
    if (status.healthy >= status.total) {
      return;
    }
    alerts.push({
      key: `upstream-${name}`,
      tone: status.healthy === 0 ? "down" : "warn",
      name,
      message:
        status.healthy === 0
          ? homeI18n("upstreamAllDown", { total: status.total })
          : homeI18n("upstreamDegraded", {
              healthy: status.healthy,
              total: status.total,
            }),
      to: `${UPSTREAMS}?name=${encodeURIComponent(name)}`,
    });
  });
  Object.keys(certificateInfos).forEach((name) => {
    const notAfter = certificateInfos[name]?.not_after;
    if (!notAfter) {
      return;
    }
    const state = certificateState(notAfter);
    if (!state) {
      return;
    }
    alerts.push({
      key: `certificate-${name}`,
      tone: state.tone,
      name,
      message: state.message,
      to: `${CERTIFICATES}?name=${encodeURIComponent(name)}`,
    });
  });
  // The run before this one did not end: it crashed, panicked or was
  // killed, and was started again. Said for as long as this one runs.
  const abnormalExit = basicInfo.abnormal_exit;
  if (abnormalExit) {
    const started = new Date(abnormalExit.started * 1000).toLocaleString();
    // A mark that could not be read says nothing of the run: no pid.
    const message = !abnormalExit.pid
      ? homeI18n("abnormalExitUnknown")
      : abnormalExit.panic
        ? homeI18n("abnormalExitPanic", {
            pid: abnormalExit.pid,
            started,
            panic: abnormalExit.panic,
          })
        : homeI18n("abnormalExit", { pid: abnormalExit.pid, started });
    alerts.push({
      key: "abnormal-exit",
      tone: "down",
      name: "pingap",
      message,
      title: message,
      to: HOME,
    });
  }
  alerts.sort((a, b) => (a.tone === b.tone ? 0 : a.tone === "down" ? -1 : 1));
  const hasMonitoredEntities =
    upstreamSummary.length > 0 || certificateSummary.length > 0;

  const entityCards: EntityCard[] = [
    {
      title: homeI18n("server"),
      path: SERVERS,
      count: serverSummary.length,
      unit: homeI18n("serverUnit"),
      summary: serverSummary,
    },
    ...(streamSummary.length > 0
      ? [
          {
            title: homeI18n("stream"),
            path: STREAMS,
            count: streamSummary.length,
            unit: homeI18n("streamUnit"),
            summary: streamSummary,
          },
        ]
      : []),
    {
      title: homeI18n("location"),
      path: LOCATIONS,
      count: locationSummary.length,
      unit: homeI18n("locationUnit"),
      summary: locationSummary,
    },
    {
      title: homeI18n("upstream"),
      path: UPSTREAMS,
      count: upstreamSummary.length,
      unit: homeI18n("upstreamUnit"),
      summary: upstreamSummary,
    },
    {
      title: homeI18n("plugin"),
      path: PLUGINS,
      count: pluginSummary.length,
      unit: homeI18n("pluginUnit"),
      summary: pluginSummary,
    },
    {
      title: homeI18n("certificate"),
      path: CERTIFICATES,
      count: certificateSummary.length,
      unit: homeI18n("certificateUnit"),
      summary: certificateSummary,
    },
    {
      title: homeI18n("storage"),
      path: STORAGES,
      count: storageSummary.length,
      unit: homeI18n("storageUnit"),
      summary: storageSummary,
    },
  ];

  const shortGitHash =
    basicInfo.git_hash && basicInfo.git_hash.length > 7
      ? basicInfo.git_hash.slice(0, 7)
      : basicInfo.git_hash || "";

  const buildTags = [
    basicInfo.features?.includes("rustls")
      ? "rustls"
      : basicInfo.features?.includes("openssl")
        ? "openssl"
        : "",
    basicInfo.features?.includes("tracing") ? "tracing" : "",
    basicInfo.features?.includes("full") ? "full" : "",
    shortGitHash,
  ].filter(Boolean);

  const dash = (v: string | number | undefined | null) =>
    v === undefined || v === null || v === "" ? "—" : String(v);

  const runtime = [
    { name: "uptime", value: formatUptime(basicInfo.start_time) || "—" },
    {
      name: "startTime",
      value: basicInfo.start_time
        ? new Date(basicInfo.start_time * 1000).toLocaleString()
        : "—",
    },
    { name: "pid", value: dash(basicInfo.pid) },
    { name: "user", value: dash(basicInfo.user) },
    { name: "group", value: dash(basicInfo.group) },
    { name: "arch", value: dash(basicInfo.arch) },
    { name: "kernel", value: dash(basicInfo.kernel) },
    { name: "rustc", value: dash(basicInfo.rustc_version) },
    {
      name: "machineCpu",
      value:
        basicInfo.cpus > 0
          ? `${basicInfo.cpus} / ${basicInfo.physical_cpus}`
          : "—",
    },
    {
      name: "machineMemory",
      value:
        basicInfo.used_memory && basicInfo.total_memory
          ? `${basicInfo.used_memory} / ${basicInfo.total_memory}`
          : "—",
    },
    { name: "tcpCount", value: basicInfo.tcp_count.toLocaleString() },
    { name: "tcp6Count", value: basicInfo.tcp6_count.toLocaleString() },
    { name: "fdCount", value: basicInfo.fd_count.toLocaleString() },
    {
      name: "enabledTracing",
      value: basicInfo.features.includes("tracing")
        ? homeI18n("yes")
        : homeI18n("no"),
    },
    {
      name: "enabledFull",
      value: basicInfo.features.includes("full")
        ? homeI18n("yes")
        : homeI18n("no"),
    },
    { name: "configHash", value: dash(basicInfo.config_hash) },
  ];

  // Drop empty placeholders and zeroed counters so the grid stays dense.
  const runtimeVisible = runtime.filter((item) => {
    if (item.value === "—") {
      return false;
    }
    if (
      ["tcpCount", "tcp6Count", "fdCount"].includes(item.name) &&
      item.value === "0"
    ) {
      return false;
    }
    return true;
  });

  // Uptime is already in the top bar on every page, so this line carries the
  // two facts that are not shown anywhere else at a glance: which build is
  // running and which process it is.
  const pathMeta = [
    basicInfo.version && `v${basicInfo.version}`,
    basicInfo.pid && `pid ${basicInfo.pid}`,
  ]
    .filter(Boolean)
    .join("  ·  ");

  return (
    <PageShell
      title={homeI18n("dashboard")}
      description={config.basic?.name || undefined}
      actions={
        (buildTags.length > 0 || !basicInfo.read_only) && (
          <div className="flex flex-wrap items-center gap-2">
            {buildTags.length > 0 && (
              <div className="hidden flex-wrap items-center gap-1.5 sm:flex">
                {buildTags.map((tag) => (
                  <span
                    key={tag}
                    className="machine hidden items-center rounded-md border border-border bg-card px-2 py-0.5 text-[11.5px] font-medium text-secondary-foreground sm:inline-flex"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            )}
            {!basicInfo.read_only && <QuickSiteWizard />}
          </div>
        )
      }
    >
      <TrafficPath
        title={homeI18n("pathTitle")}
        meta={pathMeta}
        stages={stages}
        health={health}
        meters={meters}
      />

      {/* What needs doing comes before what is only read. */}
      <section className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
        <div className="border-b border-border bg-surface-subtle px-4 py-2.5 sm:px-5">
          <h2 className="region-label">{homeI18n("attention")}</h2>
        </div>
        {alerts.length === 0 ? (
          hasMonitoredEntities ? (
            <p className="flex items-center gap-2.5 px-4 py-3.5 text-[14px] text-secondary-foreground sm:px-5">
              <CheckCircle2
                className="size-4 shrink-0 text-ok"
                strokeWidth={2}
              />
              {homeI18n("allClear")}
            </p>
          ) : (
            <p className="flex items-center gap-2.5 px-4 py-3.5 text-[14px] text-muted-foreground sm:px-5">
              <span
                aria-hidden="true"
                className="size-2 shrink-0 rounded-full bg-muted-foreground/50"
              />
              {homeI18n("allClearEmpty")}
            </p>
          )
        ) : (
          <ul className="divide-y divide-border-subtle">
            {alerts.map((alert) => (
              <li key={alert.key}>
                <Link
                  to={alert.to}
                  className={cn(
                    "flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-accent/60 sm:px-5",
                    alert.tone === "down" && "bg-down/[0.06]",
                  )}
                >
                  <span
                    className={cn(
                      "size-1.5 shrink-0 rounded-full",
                      alert.tone === "down" ? "bg-down" : "bg-warn",
                    )}
                  />
                  <span
                    className="max-w-[40%] shrink-0 truncate text-[14px] font-medium text-card-foreground sm:max-w-[260px]"
                    title={alert.name}
                  >
                    {alert.name}
                  </span>
                  <span
                    className={cn(
                      "min-w-0 flex-1 text-[14px] text-secondary-foreground",
                      alert.key === "abnormal-exit"
                        ? "break-words"
                        : "truncate",
                    )}
                    title={alert.title || alert.message}
                  >
                    {alert.message}
                  </span>
                  <ChevronRight className="ml-auto size-3.5 shrink-0 text-muted-foreground/75" />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      <TrafficPanel />

      <div className="mt-4 grid items-start gap-4 md:grid-cols-2 xl:grid-cols-3">
        {entityCards.map((item) => (
          <div
            key={item.title}
            className="flex flex-col overflow-hidden rounded-lg border border-border bg-card transition-colors hover:border-primary/45"
          >
            <div className="flex items-center justify-between gap-2 border-b border-border bg-surface-subtle px-4 py-2.5">
              <Link
                to={item.path}
                className="region-label transition-colors hover:text-foreground"
              >
                {item.title}
              </Link>
              <div className="flex items-center gap-2">
                <span className="figure text-[13px] text-muted-foreground">
                  <span className="font-medium text-foreground">
                    {item.count.toLocaleString()}
                  </span>{" "}
                  {item.unit}
                </span>
                {!basicInfo.read_only && (
                  <Link
                    to={`${item.path}?name=*`}
                    aria-label={`+ ${item.title}`}
                    className="inline-flex size-6 items-center justify-center rounded border border-border bg-card text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground"
                  >
                    <Plus className="size-3.5" />
                  </Link>
                )}
              </div>
            </div>
            {item.summary.length > 0 ? (
              <ul className="flex-1 divide-y divide-border-subtle px-4">
                {item.summary.slice(0, 4).map((entry) => (
                  <li key={entry.name}>
                    <Link
                      to={entry.link}
                      className="-mx-4 flex items-center justify-between gap-2 px-4 py-2 text-[13px] transition-colors hover:bg-accent/60"
                    >
                      <span
                        className={cn(
                          "max-w-[50%] shrink-0 truncate font-medium text-foreground",
                          entry.nameClass,
                        )}
                        title={entry.name}
                      >
                        {entry.name}
                      </span>
                      <span
                        className={cn(
                          "machine flex min-w-0 items-center gap-1.5",
                          entry.valueTone === "down"
                            ? "font-medium text-down"
                            : entry.valueTone === "warn"
                              ? "font-medium text-warn"
                              : "text-secondary-foreground",
                        )}
                        title={entry.valueTitle || entry.value}
                      >
                        {entry.valueTone && (
                          <span
                            className={cn(
                              "size-1.5 shrink-0 rounded-full",
                              entry.valueTone === "down"
                                ? "bg-down"
                                : "bg-warn",
                            )}
                          />
                        )}
                        <span className="truncate">{entry.value}</span>
                      </span>
                    </Link>
                  </li>
                ))}
                {item.summary.length > 4 && (
                  <li>
                    <Link
                      to={item.path}
                      className="figure -mx-4 block px-4 py-2 text-[13px] text-muted-foreground transition-colors hover:bg-accent/60 hover:text-primary"
                    >
                      +{item.summary.length - 4}
                    </Link>
                  </li>
                )}
              </ul>
            ) : (
              <div className="flex flex-1 items-center px-4 py-4">
                <Link
                  to={item.path}
                  className="text-[13px] text-muted-foreground underline-offset-2 hover:text-primary hover:underline"
                >
                  {homeI18n("configureHint")}
                </Link>
              </div>
            )}
          </div>
        ))}
      </div>

      {runtimeVisible.length > 0 && (
        <section className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
          <div className="border-b border-border bg-surface-subtle px-4 py-2.5 sm:px-5">
            <h2 className="region-label">{homeI18n("runtime")}</h2>
          </div>
          <div className="grid grid-cols-1 gap-px bg-border-subtle text-[13px] sm:grid-cols-2 lg:grid-cols-3">
            {runtimeVisible.map((item, idx) => {
              const isLast = idx === runtimeVisible.length - 1;
              const spanClass = isLast
                ? cn(
                    runtimeVisible.length % 2 === 1 && "sm:col-span-2",
                    runtimeVisible.length % 3 === 1
                      ? "lg:col-span-3"
                      : runtimeVisible.length % 3 === 2
                        ? "lg:col-span-2"
                        : "lg:col-span-1",
                  )
                : undefined;
              return (
                <div
                  key={item.name}
                  className={cn(
                    "flex min-w-0 items-center justify-between gap-3 bg-card px-4 py-2 sm:px-5",
                    spanClass,
                  )}
                >
                  <span className="shrink-0 text-muted-foreground">
                    {homeI18n(item.name)}
                  </span>
                  <span
                    className={cn(
                      "figure min-w-0 truncate text-right font-medium text-card-foreground",
                      item.value === "—" && "font-normal text-muted-foreground",
                    )}
                    title={item.value !== "—" ? item.value : undefined}
                  >
                    {item.value}
                  </span>
                </div>
              );
            })}
          </div>
        </section>
      )}
    </PageShell>
  );
}
