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
}

const WIDTH = 600;

/**
 * A line for each series over the same times, drawn in SVG: no chart
 * library for two charts. The legend shows the values of the point under
 * the pointer, and of the last point otherwise.
 */
export function TimeChart({
  title,
  times,
  series,
  format,
  height = 120,
}: TimeChartProps) {
  const [hovered, setHovered] = React.useState<number | null>(null);
  const count = times.length;
  const index = hovered ?? count - 1;
  // Not held to a floor of 1: a tenth of a request a second is a line,
  // not a flat one at the bottom.
  const max = Math.max(0, ...series.flatMap((item) => item.values)) || 1;
  const x = (i: number) => (count > 1 ? (i / (count - 1)) * WIDTH : 0);
  const y = (value: number) => height - (value / max) * (height - 4) - 2;
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

  const time = times[index]
    ? new Date(times[index] * 1000).toLocaleTimeString()
    : "";

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3 className="region-label">{title}</h3>
        <span className="figure text-[12px] text-muted-foreground">{time}</span>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[12px]">
        {series.map((item) => (
          <span key={item.key} className="flex items-center gap-1.5">
            <span
              className={cn("size-2 rounded-full bg-current", item.className)}
            />
            <span className="text-muted-foreground">{item.label}</span>
            <span className="figure font-medium">
              {format(item.values[index] ?? 0)}
            </span>
          </span>
        ))}
      </div>
      <div
        className="relative"
        onPointerMove={onMove}
        onPointerLeave={() => setHovered(null)}
      >
        {/* The top of the scale in a lane of its own: laid over the plot,
            it sat on the line whenever the line was high at the left. */}
        <span className="figure mb-1 block text-[11px] leading-4 text-muted-foreground">
          {format(max)}
        </span>
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
            y1={height / 2}
            y2={height / 2}
            className="stroke-border/60"
            strokeDasharray="3 4"
            vectorEffect="non-scaling-stroke"
          />
          {series.map((item) => (
            <g key={item.key} className={item.className}>
              {item.area && (
                <polygon
                  points={`0,${height} ${points(item.values)} ${x(count - 1)},${height}`}
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
      className={cn("block shrink-0", className)}
      style={{ width, height }}
      aria-hidden="true"
    >
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.25}
        strokeLinejoin="round"
      />
    </svg>
  );
}
