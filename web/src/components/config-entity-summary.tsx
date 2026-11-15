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

  const smFillers = visible.length % 2 === 1 ? 1 : 0;
  const lgFillers = (3 - (visible.length % 3)) % 3;

  return (
    <Card className={cn("mb-4 overflow-hidden border-border p-0", className)}>
      <CardContent className="grid gap-px bg-border/60 p-0 text-[12.5px] sm:grid-cols-2 lg:grid-cols-3">
        {visible.map((field, idx) => {
          const empty =
            field.value === undefined ||
            field.value === null ||
            field.value === "" ||
            field.value === "—";
          return (
            <div
              key={`${field.label}-${idx}`}
              className="flex items-baseline justify-between gap-3 bg-card px-4 py-2 sm:px-5"
            >
              <span className="shrink-0 text-muted-foreground">
                {field.label}
              </span>
              <span
                className={cn(
                  "min-w-0 truncate text-right font-medium",
                  empty && "font-normal text-muted-foreground",
                  field.mono && "machine font-normal",
                )}
              >
                {empty ? "—" : field.value}
              </span>
            </div>
          );
        })}
        {smFillers > 0 && (
          <div
            aria-hidden="true"
            className="hidden bg-card sm:block lg:hidden"
          />
        )}
        {Array.from({ length: lgFillers }).map((_, idx) => (
          <div
            key={`lg-filler-${idx}`}
            aria-hidden="true"
            className="hidden bg-card lg:block"
          />
        ))}
      </CardContent>
    </Card>
  );
}
