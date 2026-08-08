import { Link, useNavigate } from "react-router-dom";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
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
import type { ReactNode } from "react";

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
        <div className="rounded-xl border border-dashed p-10 text-center text-sm text-muted-foreground">
          {emptyText}
        </div>
      ) : (
        <div className="rounded-xl border bg-card">
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
              {names.map((name) => (
                <TableRow
                  key={name}
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() => navigate(entityUrl(name))}
                >
                  <TableCell className="font-medium">
                    {/* Link (not just the row handler) so the row is keyboard reachable. */}
                    <Link
                      to={entityUrl(name)}
                      className="outline-none hover:underline focus-visible:underline"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {name}
                    </Link>
                  </TableCell>
                  {columns.map((column) => (
                    <TableCell
                      key={column.key}
                      className={cn(
                        "max-w-[320px] truncate text-muted-foreground",
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
    </PageShell>
  );
}
