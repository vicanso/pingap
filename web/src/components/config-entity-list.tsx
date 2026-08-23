import { Link, useNavigate } from "react-router-dom";
import { Inbox, Plus, Search } from "lucide-react";
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
  const [filter, setFilter] = useState("");
  const keyword = filter.trim().toLowerCase();
  const filteredNames = useMemo(() => {
    if (!keyword) {
      return names;
    }
    return names.filter((name) => name.toLowerCase().includes(keyword));
  }, [names, keyword]);

  const entityUrl = (name: string) =>
    `${basePath}?name=${encodeURIComponent(name)}`;

  return (
    <PageShell
      title={title}
      description={summary}
      actions={
        <Button asChild className="cursor-pointer">
          <Link to={entityUrl(newValue)}>
            <Plus className="size-4" />
            {addLabel}
          </Link>
        </Button>
      }
    >
      {names.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border/80 bg-muted/20 px-6 py-14 text-center">
          <div className="mb-3 flex size-10 items-center justify-center rounded-xl bg-muted text-muted-foreground">
            <Inbox className="size-5" strokeWidth={1.8} />
          </div>
          <p className="max-w-xs text-sm text-muted-foreground">{emptyText}</p>
          <Button
            asChild
            variant="outline"
            size="sm"
            className="mt-4 cursor-pointer"
          >
            <Link to={entityUrl(newValue)}>
              <Plus className="size-4" />
              {addLabel}
            </Link>
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          {names.length >= 5 && (
            <div className="relative max-w-sm">
              <Input
                type="search"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder={i18n("listFilterPlaceholder")}
                className="h-9 pl-8"
              />
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground opacity-70" />
            </div>
          )}
          {filteredNames.length === 0 ? (
            <div className="rounded-xl border border-dashed border-border/80 bg-muted/10 px-6 py-10 text-center text-sm text-muted-foreground">
              {i18n("listFilterEmpty")}
            </div>
          ) : (
            <div className="overflow-hidden rounded-xl border border-border/80 bg-card shadow-none">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>{nameLabel}</TableHead>
                    {columns.map((column) => (
                      <TableHead key={column.key} className={column.className}>
                        {column.label}
                      </TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredNames.map((name) => (
                    <TableRow
                      key={name}
                      className="cursor-pointer transition-colors hover:bg-muted/40"
                      onClick={() => navigate(entityUrl(name))}
                    >
                      <TableCell className="font-medium">
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
                            "max-w-[320px] truncate text-[13px] text-muted-foreground",
                            column.className,
                          )}
                        >
                          {column.render(values[name], name)}
                        </TableCell>
                      ))}
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
