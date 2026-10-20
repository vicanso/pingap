import { Fragment } from "react";
import { Link } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

export interface PathStage {
  key: string;
  /** Stage name in the machine's vocabulary: LISTEN, ROUTE, POOL, ORIGIN. */
  label: string;
  value: string;
  unit: string;
  /** One line of evidence under the number — an address, a host, a count. */
  detail: string;
  detailTone?: "muted" | "ok" | "warn" | "down";
  to: string;
}

export interface PathHealth {
  up: number;
  total: number;
  /** One entry per backend, true when the health check passes. */
  ticks: boolean[];
}

/** Past this many backends the ticks stop being countable; show a ratio bar. */
const MAX_TICKS = 28;

const toneClass = {
  muted: "text-muted-foreground",
  ok: "text-ok",
  warn: "text-warn",
  down: "text-down",
} as const;

function HealthStrip({ health }: { health: PathHealth }) {
  if (health.total === 0) {
    return null;
  }
  if (health.total > MAX_TICKS) {
    const pct = (health.up / health.total) * 100;
    return (
      <div className="h-2.5 w-16 shrink-0 overflow-hidden rounded-[2px] bg-down/40">
        <div className="h-full bg-ok" style={{ width: `${pct}%` }} />
      </div>
    );
  }
  return (
    <div className="flex h-2.5 shrink-0 items-stretch gap-[3px]">
      {health.ticks.map((up, index) => (
        <span
          key={index}
          className={cn("w-[5px] rounded-[1px]", up ? "bg-ok" : "bg-down")}
        />
      ))}
    </div>
  );
}

function Stage({
  stage,
  health,
}: {
  stage: PathStage;
  health?: PathHealth;
}) {
  return (
    <Link
      to={stage.to}
      className="group -mx-1 flex flex-col gap-1.5 rounded-md px-3 py-2 outline-none transition-colors hover:bg-accent/50 focus-visible:ring-2 focus-visible:ring-ring lg:mx-0 lg:flex-1 lg:px-4"
    >
      <span className="region-label group-hover:text-foreground">{stage.label}</span>
      <span className="flex items-baseline gap-1.5">
        <span className="figure text-[28px] leading-none font-normal">
          {stage.value}
        </span>
        <span className="truncate text-[13px] text-muted-foreground">
          {stage.unit}
        </span>
      </span>
      {/*
        The strip sits on the detail line rather than above it: every stage
        then has exactly three rows, so the four numbers share a baseline and
        the connectors between them land level.
      */}
      <span className="flex min-w-0 items-center gap-2">
        {health && <HealthStrip health={health} />}
        <span
          className={cn(
            "truncate text-[13px]",
            toneClass[stage.detailTone ?? "muted"],
          )}
        >
          {stage.detail}
        </span>
      </span>
    </Link>
  );
}

/**
 * The dashboard's thesis: pingap is a path, and this is that path with live
 * numbers on it. A request meets a server, matches a location, picks an
 * upstream and lands on a backend — the same four stages the config file and
 * the proxy's own request lifecycle are built from. Each stage links to the
 * section that configures it, so the diagram is also the navigation.
 */
export function TrafficPath({
  title,
  meta,
  stages,
  health,
  meters,
}: {
  title: string;
  meta: string;
  stages: PathStage[];
  /** Attached to the last stage. */
  health: PathHealth;
  meters: { label: string; value: string; muted?: boolean; title?: string }[];
}) {
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b border-border px-4 py-2.5 sm:px-5">
        <h2 className="region-label">{title}</h2>
        <p className="figure text-[12px] text-muted-foreground">{meta}</p>
      </div>

      {/*
        Phones: two by two, in the order of the path; a strip that scrolled
        sideways cut the third stage off at the screen's edge.
        Desktop: one row with the connectors, filling the card width.
      */}
      <div className="grid grid-cols-2 gap-y-3 px-3 py-4 sm:px-4 lg:flex lg:items-stretch lg:gap-0 lg:py-6">
        {stages.map((stage, index) => (
          <Fragment key={stage.key}>
            {index > 0 && (
              <div
                className="hidden shrink-0 items-center lg:flex"
                aria-hidden="true"
              >
                <span className="h-px w-4 bg-muted-foreground/25 lg:w-8" />
                <ChevronRight className="-ml-1.5 size-3.5 text-muted-foreground/55" />
              </div>
            )}
            <div className="min-w-0 lg:flex-1">
              <Stage
                stage={stage}
                health={index === stages.length - 1 ? health : undefined}
              />
            </div>
          </Fragment>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-px border-t border-border bg-border sm:grid-cols-4">
        {meters.map((meter) => (
          <div
            key={meter.label}
            className="bg-card px-4 py-3 sm:px-5"
            title={meter.title}
          >
            <p className="region-label">{meter.label}</p>
            <p
              className={cn(
                "figure mt-1 truncate text-[16px] font-medium",
                meter.muted && "text-muted-foreground",
              )}
            >
              {meter.value}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
