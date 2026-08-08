import { Link } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

interface PageShellProps {
  title: string;
  description?: string;
  /** Rendered at the top right, e.g. a create button or the history control. */
  actions?: ReactNode;
  /** Shown next to the title — the entity name, a `new` marker, feature pills. */
  badge?: ReactNode;
  /** Back link left of the title. Set on detail pages to return to the list. */
  backTo?: string;
  backLabel?: string;
  /**
   * `wide` for tables and the dashboard, `narrow` for forms — long label/value
   * rows get hard to read much past 1100px.
   */
  width?: "wide" | "narrow";
  /**
   * Fill the viewport instead of growing: the header stays put and `children`
   * own the scrolling. For pages whose body is a scroll region of its own.
   */
  fill?: boolean;
  children: ReactNode;
  className?: string;
}

/**
 * One container for every page: max width, padding, title block and scroll
 * model. Pages differ in their body, not in their frame.
 */
export function PageShell({
  title,
  description,
  actions,
  badge,
  backTo,
  backLabel,
  width = "wide",
  fill,
  children,
  className,
}: PageShellProps) {
  return (
    <div
      className={cn(
        "flex min-h-0 flex-1 flex-col",
        fill ? "overflow-hidden" : "overflow-auto",
      )}
    >
      <div
        className={cn(
          "mx-auto flex w-full flex-col px-4 py-5 md:px-6 md:py-6",
          width === "narrow" ? "max-w-[1100px]" : "max-w-[1400px]",
          fill ? "min-h-0 flex-1 overflow-hidden" : "pb-10",
          className,
        )}
      >
        <div className="mb-6 flex shrink-0 flex-wrap items-start gap-4">
          {backTo && (
            <Button
              asChild
              size="icon"
              variant="ghost"
              className="mt-0.5 size-8 shrink-0 cursor-pointer"
            >
              <Link to={backTo} title={backLabel} aria-label={backLabel}>
                <ArrowLeft className="size-4" />
              </Link>
            </Button>
          )}
          <div className="mr-auto min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-[28px] leading-none font-bold tracking-tight">
                {title}
              </h1>
              {badge}
            </div>
            {description && (
              <p className="mt-1.5 text-sm text-muted-foreground">
                {description}
              </p>
            )}
          </div>
          {actions && (
            <div className="flex flex-wrap items-center gap-2 pt-1">
              {actions}
            </div>
          )}
        </div>
        {fill ? (
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
            {children}
          </div>
        ) : (
          children
        )}
      </div>
    </div>
  );
}
