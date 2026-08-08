import useConfigState, { getLocationWeight } from "@/states/config";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FilePlus2, Activity, Cpu, MemoryStick, Network } from "lucide-react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  CERTIFICATES,
  LOCATIONS,
  PLUGINS,
  SERVERS,
  UPSTREAMS,
} from "@/routers";
import { LoadingPage } from "@/components/loading";
import useBasicState from "@/states/basic";
import { useI18n } from "@/i18n";
import { listify } from "radash";
import { Badge } from "@/components/ui/badge";
import { useAsync } from "react-async-hook";
import React from "react";
import { useShallow } from "zustand/react/shallow";
import { PageShell } from "@/components/page-shell";

interface Summary {
  name: string;
  value: string;
  link: string;
  nameClass?: string;
  extra?: React.ReactNode;
}

interface EntityCard {
  title: string;
  path: string;
  count: number;
  unit: string;
  summary: Summary[];
}

export default function Home() {
  const homeI18n = useI18n("home");
  const [config, initialized, getCertificateInfos] = useConfigState(
    useShallow((state) => [
      state.data,
      state.initialized,
      state.getCertificateInfos,
    ]),
  );
  const [basicInfo, fetchBasicInfo] = useBasicState(
    useShallow((state) => [state.data, state.fetch]),
  );
  const [validity, setValidity] = React.useState({} as Record<string, string>);

  // /basic was only fetched once when the app mounted, so every counter on this
  // page froze the moment it opened. Refresh while the dashboard is on screen —
  // scoped to this component, so no other page pays for it — and skip ticks for
  // a hidden tab, where nobody is reading the numbers.
  React.useEffect(() => {
    const refresh = () => {
      if (document.hidden) {
        return;
      }
      // A dropped poll is not worth a toast; the next tick retries.
      fetchBasicInfo().catch(() => {});
    };
    const timer = setInterval(refresh, 5000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [fetchBasicInfo]);

  useAsync(async () => {
    try {
      const infos = await getCertificateInfos();
      const formatDate = (value: number) => {
        const date = new Date(value * 1000);
        let month = `${date.getMonth() + 1}`;
        if (month.length === 1) {
          month = `0${month}`;
        }
        let day = `${date.getDate()}`;
        if (day.length === 1) {
          day = `0${day}`;
        }
        return `${date.getFullYear()}-${month}-${day}`;
      };
      const results = {} as Record<string, string>;
      Object.keys(infos).forEach((name) => {
        const data = infos[name];
        if (data) {
          results[name] =
            formatDate(data.not_before) +
            ` ${homeI18n("to")} ` +
            formatDate(data.not_after);
        }
      });
      setValidity(results);
    } catch {
      // Validity dates are decorative: the certificate card simply omits the
      // range. Not worth a toast on every visit to the dashboard.
    }
  }, []);
  if (!initialized) {
    return <LoadingPage />;
  }

  const serverSummary: Summary[] = [];
  if (config.servers) {
    listify(config.servers, (name, value) => {
      serverSummary.push({
        name,
        link: `${SERVERS}?name=${name}`,
        value: value.addr,
      });
    });
  }
  serverSummary.sort((a, b) => a.name.localeCompare(b.name));

  const locationSummary: Summary[] = [];
  const locationSummaryWeight: Record<string, number> = {};
  if (config.locations) {
    listify(config.locations, (name, value) => {
      const weight = getLocationWeight(value);
      locationSummaryWeight[name] = weight;
      const tmpArr: string[] = [];
      if (value.host) {
        tmpArr.push(`host: ${value.host}`);
      }
      tmpArr.push(`path: ${value.path || "/"}`);
      locationSummary.push({
        name,
        link: `${LOCATIONS}?name=${name}`,
        value: tmpArr.join(" "),
      });
    });
    locationSummary.sort((a, b) => {
      return (
        (locationSummaryWeight[b.name] || 0) -
        (locationSummaryWeight[a.name] || 0)
      );
    });
  }

  const upstreamSummary: Summary[] = [];
  if (config.upstreams) {
    listify(config.upstreams, (name, value) => {
      let desc = value.addrs.map((addr) => addr.split(" ")[0]).join(",");
      const status = basicInfo.upstream_healthy_status[name];
      let nameClass = "";
      let extra = <></>;
      if (status) {
        desc += ` (${status.healthy}/${status.total})`;
        if (status.healthy === 0) {
          nameClass = "text-rose-600 dark:text-rose-400";
        } else if (status.healthy < status.total) {
          nameClass = "text-amber-600 dark:text-amber-400";
        }
        if (status.unhealthy_backends.length > 0) {
          extra = (
            <ul className="mt-1 space-y-0.5 text-xs">
              {status.unhealthy_backends.map((backend) => (
                <li
                  key={backend}
                  className="relative pl-3 text-muted-foreground before:absolute before:left-0 before:top-1.5 before:h-1.5 before:w-1.5 before:rounded-full before:bg-rose-500 before:content-['']"
                >
                  {backend}
                </li>
              ))}
            </ul>
          );
        }
      }
      upstreamSummary.push({
        name,
        nameClass,
        link: `${UPSTREAMS}?name=${name}`,
        value: desc,
        extra,
      });
    });
  }
  upstreamSummary.sort((a, b) => a.name.localeCompare(b.name));

  const pluginSummary: Summary[] = [];
  if (config.plugins) {
    listify(config.plugins, (name, value) => {
      pluginSummary.push({
        name,
        link: `${PLUGINS}?name=${name}`,
        value: value.category as string,
      });
    });
  }
  pluginSummary.sort((a, b) => a.name.localeCompare(b.name));

  const certificateSummary: Summary[] = [];
  if (config.certificates) {
    listify(config.certificates, (name, value) => {
      let date = validity[name] || "";
      if (date) {
        date = ` (${date})`;
      }
      certificateSummary.push({
        name,
        link: `${CERTIFICATES}?name=${name}`,
        value: (value.domains || "") + date,
      });
    });
  }
  certificateSummary.sort((a, b) => a.name.localeCompare(b.name));

  const entityCards: EntityCard[] = [
    {
      title: homeI18n("server"),
      path: SERVERS,
      count: serverSummary.length,
      unit: homeI18n("serverUnit"),
      summary: serverSummary,
    },
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
  ];

  let git_hash = basicInfo.git_hash;
  if (git_hash.length > 7) {
    git_hash = git_hash.slice(0, 7);
  }

  // Runtime process thread count from OS; -1 means unavailable (e.g. non-Linux).
  const formatThreads = (n: number | undefined | null) =>
    n == null || n < 0 ? "—" : n.toLocaleString();

  const dash = (v: string | number | undefined | null) => {
    if (v === undefined || v === null || v === "") return "—";
    return String(v);
  };

  const statTiles = [
    {
      icon: Activity,
      label: homeI18n("processing"),
      value: basicInfo.processing.toLocaleString(),
      muted: false,
    },
    {
      icon: Network,
      label: homeI18n("accepted"),
      value: basicInfo.accepted.toLocaleString(),
      muted: false,
    },
    {
      icon: MemoryStick,
      label: homeI18n("memory"),
      value: basicInfo.memory || "—",
      muted: !basicInfo.memory,
    },
    {
      icon: Cpu,
      label: homeI18n("threads"),
      value: formatThreads(basicInfo.threads),
      muted: formatThreads(basicInfo.threads) === "—",
    },
  ];

  // Three columns like the design mock (interleaved for balanced reading).
  const basicInfos = [
    { name: "pid", value: dash(basicInfo.pid), mono: false },
    {
      name: "startTime",
      value: basicInfo.start_time
        ? new Date(basicInfo.start_time * 1000).toLocaleString()
        : "—",
      mono: false,
    },
    { name: "threads", value: formatThreads(basicInfo.threads), mono: false },
    {
      name: "machineCpu",
      value: `${basicInfo.cpus} / ${basicInfo.physical_cpus}`,
      mono: false,
    },
    { name: "memory", value: dash(basicInfo.memory), mono: false },
    {
      name: "machineMemory",
      value: `${basicInfo.used_memory} / ${basicInfo.total_memory}`,
      mono: false,
    },
    {
      name: "processing",
      value: basicInfo.processing.toLocaleString(),
      mono: false,
    },
    {
      name: "accepted",
      value: basicInfo.accepted.toLocaleString(),
      mono: false,
    },
    {
      name: "tcpCount",
      value: basicInfo.tcp_count.toLocaleString(),
      mono: false,
    },
    {
      name: "tcp6Count",
      value: basicInfo.tcp6_count.toLocaleString(),
      mono: false,
    },
    {
      name: "fdCount",
      value: basicInfo.fd_count.toLocaleString(),
      mono: false,
    },
    { name: "arch", value: dash(basicInfo.arch), mono: false },
    { name: "kernel", value: dash(basicInfo.kernel), mono: false },
    { name: "user", value: dash(basicInfo.user), mono: false },
    { name: "group", value: dash(basicInfo.group), mono: false },
    {
      name: "enabledTracing",
      value: basicInfo.features.includes("tracing")
        ? homeI18n("yes")
        : homeI18n("no"),
      mono: false,
    },
    {
      name: "enabledFull",
      value: basicInfo.features.includes("full")
        ? homeI18n("yes")
        : homeI18n("no"),
      mono: false,
    },
    { name: "rustc", value: dash(basicInfo.rustc_version), mono: false },
    { name: "git", value: dash(git_hash), mono: true },
    { name: "configHash", value: dash(basicInfo.config_hash), mono: true },
  ];

  // Split into 3 columns for the design grid.
  const colSize = Math.ceil(basicInfos.length / 3);
  const basicColumns = [
    basicInfos.slice(0, colSize),
    basicInfos.slice(colSize, colSize * 2),
    basicInfos.slice(colSize * 2),
  ];

  return (
    <PageShell
      title={homeI18n("dashboard")}
      description={
        basicInfo.version ? `Pingap ${basicInfo.version}` : "Pingap admin"
      }
      actions={
        <>
          {basicInfo.features?.includes("tracing") && (
            <Badge
              variant="secondary"
              className="rounded-full px-2.5 py-0.5 text-xs font-normal"
            >
              tracing
            </Badge>
          )}
          {basicInfo.features?.includes("full") && (
            <Badge
              variant="secondary"
              className="rounded-full px-2.5 py-0.5 text-xs font-normal"
            >
              full
            </Badge>
          )}
          {git_hash && (
            <Badge
              variant="outline"
              className="rounded-full px-2.5 py-0.5 font-mono text-xs font-normal"
            >
              {git_hash}
            </Badge>
          )}
        </>
      }
    >
      {/* Stat tiles — 4-up with icon chip */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {statTiles.map((tile) => (
          <Card
            key={tile.label}
            className="border-border/80 shadow-none transition-colors hover:border-border"
          >
            <CardContent className="flex items-center gap-3.5 p-5">
              <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-primary/12 text-primary">
                <tile.icon className="size-[18px]" strokeWidth={1.8} />
              </div>
              <div className="min-w-0">
                <p className="text-[13px] text-muted-foreground">
                  {tile.label}
                </p>
                <p
                  className={cn(
                    "truncate text-[22px] font-bold tabular-nums leading-tight",
                    tile.muted && "text-muted-foreground",
                  )}
                >
                  {tile.value}
                </p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Basic information — 3-column label/value rows */}
      <Card className="mt-4 border-border/80 shadow-none">
        <CardHeader className="px-6 pb-3 pt-5">
          <CardTitle className="text-[15px] font-semibold">
            {homeI18n("basic")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-6 pb-5">
          <div className="grid gap-x-10 text-[13.5px] sm:grid-cols-2 lg:grid-cols-3">
            {basicColumns.map((col, colIdx) => (
              <div key={colIdx}>
                {col.map((item, rowIdx) => {
                  const isLast = rowIdx === col.length - 1;
                  const empty = !item.value || item.value === "—";
                  return (
                    <div
                      key={item.name}
                      className={cn(
                        "flex items-center justify-between gap-3 py-[7px]",
                        !isLast && "border-b border-border/60",
                      )}
                    >
                      <span className="shrink-0 text-muted-foreground">
                        {homeI18n(item.name)}
                      </span>
                      <span
                        className={cn(
                          "min-w-0 truncate text-right tabular-nums",
                          empty && "text-muted-foreground",
                          item.mono && "font-mono text-[12.5px]",
                        )}
                      >
                        {item.value}
                      </span>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Entity summary cards */}
      <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-5">
        {entityCards.map((item) => (
          <Card
            key={item.title}
            className="group h-full border-border/80 shadow-none transition-colors hover:border-border"
          >
            <CardContent className="flex h-full flex-col gap-1.5 p-[18px]">
              <div className="flex items-center justify-between text-[13.5px]">
                <Link
                  to={item.path}
                  className="font-medium text-foreground hover:text-primary"
                >
                  {item.title}
                </Link>
                <Link
                  to={item.path}
                  className="text-muted-foreground opacity-70 transition-opacity hover:text-foreground group-hover:opacity-100"
                  aria-label={item.title}
                >
                  <FilePlus2 className="size-3.5" />
                </Link>
              </div>
              <div className="text-2xl font-bold tabular-nums">
                {item.count}{" "}
                <span className="text-[15px] font-medium text-muted-foreground">
                  {item.unit}
                </span>
              </div>
              {item.summary.length > 0 ? (
                <ul className="mt-1 max-h-28 space-y-1 overflow-auto text-[13px] text-muted-foreground">
                  {item.summary.slice(0, 4).map((entry) => (
                    <li key={entry.name} className="truncate">
                      <Link
                        to={entry.link}
                        className={cn(
                          "font-medium text-primary hover:underline",
                          entry.nameClass,
                        )}
                      >
                        {entry.name}
                      </Link>{" "}
                      <span>{entry.value}</span>
                      {entry.extra}
                    </li>
                  ))}
                  {item.summary.length > 4 && (
                    <li className="text-xs text-muted-foreground/80">
                      +{item.summary.length - 4}
                    </li>
                  )}
                </ul>
              ) : (
                <p className="text-[13px] text-muted-foreground">—</p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </PageShell>
  );
}
