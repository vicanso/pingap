import { Link, useNavigate } from "react-router-dom";
import { ChevronRight, Plus, Search, X } from "lucide-react";

function matchesKeyword(value: unknown, keyword: string): boolean {
  if (value === null || value === undefined) {
    return false;
  }
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value).toLowerCase().includes(keyword);
  }
  if (Array.isArray(value)) {
    return value.some((item) => matchesKeyword(item, keyword));
  }
  if (typeof value === "object") {
    return Object.values(value).some((v) => matchesKeyword(v, keyword));
  }
  return false;
}
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageShell } from "@/components/page-shell";
import { cn } from "@/lib/utils";
import { useMemo, useState, type ReactNode } from "react";
import { useI18n } from "@/i18n";
import useBasicState from "@/states/basic";

export interface ConfigEntityColumn<T> {
  /** Unique per column; also the react key. */
  key: string;
  label: string;
  className?: string;
  render: (value: T, name: string) => ReactNode;
}

interface ConfigEntityListProps<T> {
  title: string;
  /** Already-formatted count line, e.g. "3 servers configured". */
  summary: string;
  nameLabel: string;
  addLabel: string;
  emptyText: string;
  /** Route of the category, e.g. "/servers". Rows link to `${basePath}?name=<name>`. */
  basePath: string;
  /** Sentinel that opens the create form, e.g. "*". */
  newValue: string;
  names: string[];
  values: Record<string, T>;
  columns: ConfigEntityColumn<T>[];
}

/** Value cell content with a muted em dash for anything empty, so columns stay aligned. */
export function EntityText({ value }: { value?: string | number | null }) {
  if (value === undefined || value === null || value === "") {
    return <span className="text-muted-foreground">—</span>;
  }
  return <>{value}</>;
}

/**
 * Overview of every entity of one config category: the landing view for a
 * sidebar category. Rows open the edit form, the button opens the create form.
 */
export function ConfigEntityList<T>({
  title,
  summary,
  nameLabel,
  addLabel,
  emptyText,
  basePath,
  newValue,
  names,
  values,
  columns,
}: ConfigEntityListProps<T>) {
  const navigate = useNavigate();
  const i18n = useI18n();
  // Nothing to create with an account that may only look.
  const readOnly = useBasicState((state) => state.data.read_only);
  const [filter, setFilter] = useState("");
  const keyword = filter.trim().toLowerCase();
  const filteredNames = useMemo(() => {
    if (!keyword) {
      return names;
    }
    return names.filter(
      (name) =>
        name.toLowerCase().includes(keyword) ||
        matchesKeyword(values[name], keyword),
    );
  }, [names, values, keyword]);

  const entityUrl = (name: string) =>
    `${basePath}?name=${encodeURIComponent(name)}`;

  return (
    <PageShell
      title={title}
      description={summary}
      // One create CTA only: empty state owns it when the list is empty;
      // the header button appears once there is already something to browse.
      actions={
        names.length > 0 && !readOnly ? (
          <Button asChild className="cursor-pointer">
            <Link to={entityUrl(newValue)}>
              <Plus className="size-4" />
              {addLabel}
            </Link>
          </Button>
        ) : undefined
      }
    >
      {names.length === 0 ? (
        // The frame of the list stays, with one sentence and the way to
        // the first entry; no picture.
        <div className="flex flex-col items-start rounded-lg border border-dashed border-border px-5 py-6">
          <p className="text-sm text-muted-foreground">{emptyText}</p>
          {!readOnly && (
            <Button asChild className="mt-4 cursor-pointer">
              <Link to={entityUrl(newValue)}>
                <Plus className="size-4" />
                {addLabel}
              </Link>
            </Button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {names.length >= 2 && (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="relative w-full max-w-sm">
                <Input
                  type="text"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder={i18n("listFilterPlaceholder")}
                  className="h-9 pl-8 pr-8"
                />
                <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground opacity-70" />
                {filter && (
                  <button
                    type="button"
                    onClick={() => setFilter("")}
                    aria-label={i18n("multiSelect.clear")}
                    className="absolute right-2 top-1/2 -translate-y-1/2 cursor-pointer rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
                  >
                    <X className="size-3.5" />
                  </button>
                )}
              </div>
              {keyword && (
                <span className="figure text-xs text-muted-foreground">
                  {filteredNames.length} / {names.length}
                </span>
              )}
            </div>
          )}
          {filteredNames.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border bg-card px-6 py-10 text-center text-sm text-muted-foreground">
              {i18n("listFilterEmpty")}
            </div>
          ) : (
            <div className="overflow-hidden rounded-lg border border-border bg-card">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>{nameLabel}</TableHead>
                    {columns.map((column) => (
                      <TableHead key={column.key} className={column.className}>
                        {column.label}
                      </TableHead>
                    ))}
                    <TableHead className="w-8" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredNames.map((name) => (
                    <TableRow
                      key={name}
                      className="group cursor-pointer transition-colors hover:bg-accent/60"
                      onClick={() => navigate(entityUrl(name))}
                    >
                      <TableCell className="py-3 font-medium">
                        {/* Link (not just the row handler) so the row is keyboard reachable. */}
                        <Link
                          to={entityUrl(name)}
                          className="outline-none hover:text-primary hover:underline focus-visible:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {name}
                        </Link>
                      </TableCell>
                      {columns.map((column) => (
                        <TableCell
                          key={column.key}
                          className={cn(
                            // Machine track: every cell but the name holds a
                            // value pingap reported or a value from the config.
                            "machine max-w-[320px] truncate py-3 text-[13px] text-secondary-foreground",
                            column.className,
                          )}
                        >
                          {column.render(values[name], name)}
                        </TableCell>
                      ))}
                      <TableCell className="w-8 py-3 pr-3 text-right">
                        <ChevronRight className="inline size-4 text-muted-foreground/75 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      )}
    </PageShell>
  );
}
