import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export interface SummaryField {
  label: string;
  value?: ReactNode;
  /** Prefer monospace for addrs, hashes, paths. */
  mono?: boolean;
}

interface ConfigEntitySummaryProps {
  fields: SummaryField[];
  className?: string;
}

/**
 * Read-only snapshot above an entity edit form — mirrors the design-mock
 * "Config — name" key/value grid so operators can scan without scrolling the form.
 */
export function ConfigEntitySummary({
  fields,
  className,
}: ConfigEntitySummaryProps) {
  const visible = fields.filter((f) => {
    if (f.value === undefined || f.value === null || f.value === "") {
      return false;
    }
    // Callers sometimes pass the em dash placeholder — treat it as absent.
    if (f.value === "—") {
      return false;
    }
    return true;
  });
  if (visible.length === 0) {
    return null;
  }

  const gridColsClass =
    visible.length === 1
      ? "grid-cols-1"
      : visible.length === 2
        ? "grid-cols-1 sm:grid-cols-2"
        : "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3";

  return (
    <Card className={cn("mb-4 overflow-hidden border-border p-0", className)}>
      <CardContent
        className={cn(
          "grid gap-px bg-border-subtle p-0 text-[12.5px]",
          gridColsClass,
        )}
      >
        {visible.map((field, idx) => {
          const empty =
            field.value === undefined ||
            field.value === null ||
            field.value === "" ||
            field.value === "—";
          const isLast = idx === visible.length - 1;
          const lastSpanClass =
            isLast && visible.length >= 3
              ? cn(
                  visible.length % 2 === 1 && "sm:col-span-2",
                  visible.length % 3 === 1
                    ? "lg:col-span-3"
                    : visible.length % 3 === 2
                      ? "lg:col-span-2"
                      : "lg:col-span-1",
                )
              : undefined;
          return (
            <div
              key={`${field.label}-${idx}`}
              className={cn(
                "flex min-w-0 items-baseline justify-between gap-3 bg-card px-4 py-2 sm:px-5",
                lastSpanClass,
              )}
            >
              <span className="shrink-0 text-muted-foreground">
                {field.label}
              </span>
              <span
                className={cn(
                  "min-w-0 truncate text-right font-medium text-card-foreground",
                  empty && "font-normal text-muted-foreground",
                  field.mono && "machine font-normal",
                )}
                title={
                  typeof field.value === "string" ||
                  typeof field.value === "number"
                    ? String(field.value)
                    : undefined
                }
              >
                {empty ? "—" : field.value}
              </span>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
