import React from "react";
import { Link } from "react-router-dom";
import request from "@/helpers/request";
import { useI18n } from "@/i18n";
import { cn } from "@/lib/utils";
import { goToLogin, UPSTREAMS } from "@/routers";
import { Sparkline, TimeChart } from "@/components/time-chart";

interface UpstreamTraffic {
  requests: number[];
  errors: number[];
  /** The requests that got a response header: what the wait is of. */
  latency_count: number[];
  latency_avg: number[];
  latency_max: number[];
}

/** What `/api/traffic` answers: one value per bucket, the oldest first. */
interface Traffic {
  interval: number;
  time: number[];
  requests: number[];
  status_2xx: number[];
  status_3xx: number[];
  status_4xx: number[];
  status_5xx: number[];
  /** The requests the latency is of: not the upgraded connections. */
  latency_count: number[];
  latency_avg: number[];
  latency_p95: number[];
  latency_max: number[];
  upstreams: Record<string, UpstreamTraffic>;
}

/** The buckets of the last minute: six of ten seconds. */
const RECENT = 6;

const sum = (values: number[]) => values.reduce((a, b) => a + b, 0);

const formatRate = (value: number) =>
  value === 0
    ? "0"
    : value < 10
      ? value.toFixed(1)
      : Math.round(value).toLocaleString();

const formatMs = (value: number) =>
  value >= 1000 ? `${(value / 1000).toFixed(1)} s` : `${Math.round(value)} ms`;

const formatShare = (part: number, whole: number) =>
  whole === 0 ? "—" : `${((part / whole) * 100).toFixed(part ? 1 : 0)}%`;

/** The average of averages, each weighed by its number of requests. */
const weighted = (averages: number[], counts: number[]) => {
  const total = sum(counts);
  if (total === 0) {
    return 0;
  }
  return sum(averages.map((value, i) => value * counts[i])) / total;
};

/**
 * The requests of the last fifteen minutes: rate, status and latency over
 * time, and each upstream's share. Kept in memory by the process, so it
 * is there without Prometheus. Asked for every ten seconds, the length of
 * a bucket, while the page is on screen.
 */
export function TrafficPanel() {
  const homeI18n = useI18n("home");
  const [traffic, setTraffic] = React.useState<Traffic | null>(null);

  React.useEffect(() => {
    let stopped = false;
    // Without the token check of the other polls: this is the only load
    // of the panel, and an admin without credentials has no token at all.
    // A 401 sends the page to the login and stops the polling.
    const refresh = () => {
      if (stopped || document.hidden) {
        return;
      }
      request
        .get<Traffic>("/traffic")
        .then(({ data }) => {
          if (!stopped) {
            setTraffic(data);
          }
        })
        .catch((err: { status?: number }) => {
          if (err?.status === 401) {
            stopped = true;
            goToLogin();
          }
          // Anything else - an older process without the endpoint - leaves
          // the panel out rather than showing an error on the home page.
        });
    };
    refresh();
    const timer = setInterval(refresh, 10_000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      stopped = true;
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, []);

  if (!traffic || traffic.time.length < 2) {
    return null;
  }
  // The bucket under way is left out: half a bucket reads as a drop.
  const end = traffic.time.length - 1;
  const done = (values: number[]) => values.slice(0, end);
  const recent = (values: number[]) => done(values).slice(-RECENT);
  const perSecond = (values: number[]) =>
    done(values).map((value) => value / traffic.interval);
  const times = done(traffic.time);
  const seconds = RECENT * traffic.interval;

  const header = (
    <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-border px-4 py-2.5 sm:px-5">
      <h2 className="eyebrow">{homeI18n("traffic")}</h2>
      <span className="text-[12px] text-muted-foreground">
        {homeI18n("trafficWindow")}
      </span>
    </div>
  );

  if (sum(done(traffic.requests)) === 0) {
    return (
      <section className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
        {header}
        <p className="px-4 py-3.5 text-[13px] text-muted-foreground sm:px-5">
          {homeI18n("noTraffic")}
        </p>
      </section>
    );
  }

  const recentRequests = sum(recent(traffic.requests));
  const recentTimed = sum(recent(traffic.latency_count));
  const meters = [
    {
      label: homeI18n("trafficRate"),
      value: formatRate(recentRequests / seconds),
    },
    {
      label: homeI18n("traffic5xx"),
      value: formatShare(sum(recent(traffic.status_5xx)), recentRequests),
      tone: sum(recent(traffic.status_5xx)) > 0 ? "down" : undefined,
    },
    {
      label: homeI18n("traffic4xx"),
      value: formatShare(sum(recent(traffic.status_4xx)), recentRequests),
    },
    {
      label: homeI18n("trafficLatencyAvg"),
      value: recentTimed
        ? formatMs(
            weighted(
              recent(traffic.latency_avg),
              recent(traffic.latency_count),
            ),
          )
        : "—",
    },
    {
      label: homeI18n("trafficLatencyP95"),
      value: recentTimed
        ? formatMs(Math.max(...recent(traffic.latency_p95)))
        : "—",
    },
  ];

  const upstreams = Object.entries(traffic.upstreams)
    .map(([name, upstream]) => {
      const requests = sum(recent(upstream.requests));
      const timed = sum(recent(upstream.latency_count));
      return {
        name,
        rate: requests / seconds,
        errors: sum(recent(upstream.errors)),
        requests,
        timed,
        latency: weighted(
          recent(upstream.latency_avg),
          recent(upstream.latency_count),
        ),
        trend: done(upstream.requests),
      };
    })
    .sort((a, b) => b.requests - a.requests || a.name.localeCompare(b.name));

  return (
    <section className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
      {header}
      <div className="grid grid-cols-2 gap-x-6 gap-y-3 border-b border-border px-4 py-3 sm:grid-cols-3 sm:px-5 lg:grid-cols-5">
        {meters.map((meter) => (
          <div key={meter.label} className="flex flex-col gap-0.5">
            <span className="text-[11.5px] text-muted-foreground">
              {meter.label}
            </span>
            <span
              className={cn(
                "machine text-[18px] leading-tight font-semibold",
                meter.tone === "down" && "text-down",
              )}
            >
              {meter.value}
            </span>
          </div>
        ))}
      </div>
      <div className="grid gap-6 px-4 py-4 sm:px-5 lg:grid-cols-2">
        <TimeChart
          title={homeI18n("trafficRequests")}
          times={times}
          format={formatRate}
          series={[
            {
              key: "all",
              label: homeI18n("trafficAll"),
              values: perSecond(traffic.requests),
              className: "text-chart-1",
              area: true,
            },
            {
              key: "4xx",
              label: "4xx",
              values: perSecond(traffic.status_4xx),
              className: "text-warn",
            },
            {
              key: "5xx",
              label: "5xx",
              values: perSecond(traffic.status_5xx),
              className: "text-down",
            },
          ]}
        />
        <TimeChart
          title={homeI18n("trafficLatency")}
          times={times}
          format={formatMs}
          series={[
            {
              key: "avg",
              label: homeI18n("trafficAverage"),
              values: done(traffic.latency_avg),
              className: "text-chart-2",
              area: true,
            },
            {
              key: "p95",
              label: "p95",
              values: done(traffic.latency_p95),
              className: "text-chart-1",
            },
          ]}
        />
      </div>
      {upstreams.length > 0 && (
        <div className="overflow-x-auto border-t border-border">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="text-left text-[11.5px] text-muted-foreground">
                <th className="px-4 py-2 font-normal sm:px-5">
                  {homeI18n("trafficUpstream")}
                </th>
                <th className="px-3 py-2 text-right font-normal">
                  {homeI18n("trafficRate")}
                </th>
                <th className="px-3 py-2 text-right font-normal">
                  {homeI18n("trafficErrors")}
                </th>
                <th className="px-3 py-2 text-right font-normal">
                  {homeI18n("trafficWait")}
                </th>
                <th className="px-4 py-2 text-right font-normal sm:px-5">
                  {homeI18n("trafficTrend")}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {upstreams.map((upstream) => (
                <tr key={upstream.name}>
                  <td className="px-4 py-1.5 sm:px-5">
                    <Link
                      to={`${UPSTREAMS}?name=${encodeURIComponent(upstream.name)}`}
                      className="font-medium hover:text-primary hover:underline"
                    >
                      {upstream.name}
                    </Link>
                  </td>
                  <td className="machine px-3 py-1.5 text-right">
                    {formatRate(upstream.rate)}
                  </td>
                  <td
                    className={cn(
                      "machine px-3 py-1.5 text-right",
                      upstream.errors > 0 && "font-medium text-down",
                    )}
                  >
                    {formatShare(upstream.errors, upstream.requests)}
                  </td>
                  <td className="machine px-3 py-1.5 text-right">
                    {upstream.timed ? formatMs(upstream.latency) : "—"}
                  </td>
                  <td className="px-4 py-1.5 sm:px-5">
                    <Sparkline
                      values={upstream.trend}
                      className="ml-auto text-chart-1"
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="border-t border-border px-4 py-2 text-[11.5px] text-muted-foreground sm:px-5">
        {homeI18n("trafficNote")}
      </p>
    </section>
  );
}
