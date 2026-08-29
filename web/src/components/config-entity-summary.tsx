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
    return true;
  });
  if (visible.length === 0) {
    return null;
  }

  return (
    <Card className={cn("mb-4 overflow-hidden border-border", className)}>
      <CardContent className="grid gap-x-9 px-4 py-1 text-[12.5px] sm:grid-cols-2 sm:px-5 lg:grid-cols-3">
        {visible.map((field, idx) => {
          const empty =
            field.value === undefined ||
            field.value === null ||
            field.value === "" ||
            field.value === "—";
          return (
            <div
              key={`${field.label}-${idx}`}
              className="flex items-baseline justify-between gap-3 border-b border-border/50 py-[7px] last:border-b-0"
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
      </CardContent>
    </Card>
  );
}
