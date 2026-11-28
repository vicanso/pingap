import React from "react";
import { cn } from "@/lib/utils";

export interface ChartSeries {
  key: string;
  label: string;
  values: number[];
  /** A text colour class: the line is drawn in currentColor. */
  className: string;
  /** Filled under the line, faintly. */
  area?: boolean;
}

interface TimeChartProps {
  title: string;
  /** The start of each point, in seconds since the epoch. */
  times: number[];
  series: ChartSeries[];
  format: (value: number) => string;
  height?: number;
  /** Values displayed in the legend when not hovering (e.g. 1m summary). */
  defaultValues?: number[];
  /** Timestamp / window label shown when not hovering. */
  defaultTimeLabel?: string;
}

const WIDTH = 600;

/**
 * Rounds up `rawMax * 1.1` to a clean human-readable axis ceiling so peak
 * strokes sit comfortably below the top border instead of clipping flat.
 */
function niceMax(rawMax: number): number {
  if (!Number.isFinite(rawMax) || rawMax <= 0) {
    return 1;
  }
  const target = rawMax * 1.1;
  const exp = Math.floor(Math.log10(target));
  const magnitude = Math.pow(10, exp);
  const normalized = target / magnitude;
  const steps =
    exp >= 1
      ? [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]
      : [1, 2, 3, 4, 5, 6, 8, 10];
  const nice = steps.find((step) => step >= normalized - 1e-9) ?? 10;
  return Number((nice * magnitude).toPrecision(10));
}

function formatTickTime(epochSec: number): string {
  const date = new Date(epochSec * 1000);
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/**
 * A line for each series over the same times, drawn in SVG: no chart
 * library for two charts. The legend shows the values of the point under
 * the pointer, and the 1m summary (or last point) otherwise.
 */
export function TimeChart({
  title,
  times,
  series,
  format,
  height = 120,
  defaultValues,
  defaultTimeLabel,
}: TimeChartProps) {
  const [hovered, setHovered] = React.useState<number | null>(null);
  const count = times.length;
  const lastIndex = Math.max(0, count - 1);
  // Not held to a floor of 1: a tenth of a request a second is a line,
  // not a flat one at the bottom.
  const rawMax = Math.max(0, ...series.flatMap((item) => item.values));
  const scaleMax = niceMax(rawMax);
  const topPad = 6;
  const bottomPad = 2;
  const plotHeight = Math.max(1, height - topPad - bottomPad);
  const x = (i: number) => (count > 1 ? (i / (count - 1)) * WIDTH : 0);
  const y = (value: number) =>
    height - bottomPad - (value / scaleMax) * plotHeight;
  const points = (values: number[]) =>
    values.map((value, i) => `${x(i)},${y(value)}`).join(" ");

  // Pointer events: a finger on a phone moves the reading as a mouse does.
  const onMove = (event: React.PointerEvent<HTMLDivElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    if (count < 2 || rect.width === 0) {
      return;
    }
    const ratio = (event.clientX - rect.left) / rect.width;
    setHovered(
      Math.min(count - 1, Math.max(0, Math.round(ratio * (count - 1)))),
    );
  };

  const time =
    hovered !== null
      ? times[hovered]
        ? new Date(times[hovered] * 1000).toLocaleTimeString()
        : ""
      : (defaultTimeLabel ??
        (times[lastIndex]
          ? new Date(times[lastIndex] * 1000).toLocaleTimeString()
          : ""));

  const midLineY = y(scaleMax / 2);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3 className="region-label">{title}</h3>
        <span className="figure text-[12px] text-muted-foreground">{time}</span>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[12px]">
        {series.map((item, idx) => {
          const displayValue =
            hovered !== null
              ? (item.values[hovered] ?? 0)
              : (defaultValues?.[idx] ?? item.values[lastIndex] ?? 0);
          return (
            <span key={item.key} className="flex items-center gap-1.5">
              <span
                className={cn("size-2 rounded-full bg-current", item.className)}
              />
              <span className="text-muted-foreground">{item.label}</span>
              <span className="figure font-medium">{format(displayValue)}</span>
            </span>
          );
        })}
      </div>
      <div>
        {/* The top of the scale in a lane of its own: laid over the plot,
            it sat on the line whenever the line was high at the left. */}
        <span className="figure mb-1 block text-[11px] leading-4 text-muted-foreground">
          {format(scaleMax)}
        </span>
        <div
          className="relative"
          onPointerMove={onMove}
          onPointerLeave={() => setHovered(null)}
        >
          <svg
            viewBox={`0 0 ${WIDTH} ${height}`}
            preserveAspectRatio="none"
            className="block w-full"
            style={{ height }}
            role="img"
            aria-label={title}
          >
            <line
              x1={0}
              x2={WIDTH}
              y1={height - 0.5}
              y2={height - 0.5}
              className="stroke-border"
              vectorEffect="non-scaling-stroke"
            />
            <line
              x1={0}
              x2={WIDTH}
              y1={midLineY}
              y2={midLineY}
              className="stroke-border/60"
              strokeDasharray="3 4"
              vectorEffect="non-scaling-stroke"
            />
            {series.map((item) => (
              <g key={item.key} className={item.className}>
                {item.area && (
                  <polygon
                    points={`0,${height} ${points(item.values)} ${x(lastIndex)},${height}`}
                    fill="currentColor"
                    fillOpacity={0.08}
                  />
                )}
                <polyline
                  points={points(item.values)}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={1.5}
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                />
              </g>
            ))}
            {hovered !== null && (
              <line
                x1={x(hovered)}
                x2={x(hovered)}
                y1={0}
                y2={height}
                className="stroke-foreground/30"
                vectorEffect="non-scaling-stroke"
              />
            )}
          </svg>
        </div>
        {count >= 2 && (
          <div className="figure mt-1 flex items-center justify-between text-[11px] leading-4 text-muted-foreground">
            <span>{formatTickTime(times[0])}</span>
            {count >= 3 && (
              <span>{formatTickTime(times[Math.floor((count - 1) / 2)])}</span>
            )}
            <span>{formatTickTime(times[lastIndex])}</span>
          </div>
        )}
      </div>
    </div>
  );
}

/** A line without axes or legend, for a row of a table. */
export function Sparkline({
  values,
  className,
  width = 96,
  height = 22,
}: {
  values: number[];
  className?: string;
  width?: number;
  height?: number;
}) {
  const max = Math.max(0, ...values) || 1;
  const step = values.length > 1 ? width / (values.length - 1) : 0;
  const points = values
    .map(
      (value, i) => `${i * step},${height - (value / max) * (height - 2) - 1}`,
    )
    .join(" ");
  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className={cn("block shrink-0", className)}
      style={{ width, maxWidth: "100%", height }}
      aria-hidden="true"
    >
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.25}
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
