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
  index,
}: {
  stage: PathStage;
  health?: PathHealth;
  index: number;
}) {
  return (
    <Link
      to={stage.to}
      className="group -mx-1 flex animate-rise flex-col gap-1.5 rounded-md px-3 py-2 outline-none transition-colors hover:bg-accent/50 focus-visible:ring-2 focus-visible:ring-ring md:mx-0 md:flex-1 md:px-4"
      style={{ animationDelay: `${index * 70}ms` }}
    >
      <span className="eyebrow group-hover:text-foreground">{stage.label}</span>
      <span className="flex items-baseline gap-1.5">
        <span className="machine text-[30px] leading-none font-semibold">
          {stage.value}
        </span>
        <span className="truncate text-[12.5px] text-muted-foreground">
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
            "truncate text-[12px]",
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
        <h2 className="eyebrow">{title}</h2>
        <p className="machine text-[11.5px] text-muted-foreground">{meta}</p>
      </div>

      {/*
        Phones: horizontal strip with chevrons so the path still reads left→right.
        Desktop: flex row that fills the card width.
      */}
      <div className="flex items-stretch gap-0 overflow-x-auto px-3 py-5 sm:px-4 md:overflow-visible md:py-6">
        {stages.map((stage, index) => (
          <Fragment key={stage.key}>
            {index > 0 && (
              <div
                className="flex shrink-0 items-center"
                aria-hidden="true"
              >
                <span className="hidden h-px w-4 bg-muted-foreground/25 md:block lg:w-8" />
                <ChevronRight className="size-3.5 text-muted-foreground/55 md:-ml-1.5" />
              </div>
            )}
            <div className="min-w-[42%] shrink-0 md:min-w-0 md:flex-1">
              <Stage
                stage={stage}
                index={index}
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
            <p className="eyebrow">{meter.label}</p>
            <p
              className={cn(
                "machine mt-1.5 truncate text-[15px] font-semibold",
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
