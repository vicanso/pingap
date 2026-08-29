import { useRouteError, isRouteErrorResponse } from "react-router-dom";
import { TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/i18n";
import { goToHome } from "@/routers";

function describe(error: unknown): string {
  if (isRouteErrorResponse(error)) {
    return `${error.status} ${error.statusText}`;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

/**
 * Rendered in place of a route that threw. Without it a render-time crash takes
 * the whole app down to a blank page with no way back but a manual reload.
 */
export default function RouteError() {
  const error = useRouteError();
  const i18n = useI18n("error");

  return (
    <div className="flex min-h-0 flex-1 items-center justify-center overflow-auto p-4 md:p-6">
      <div className="w-full max-w-md space-y-5 rounded-lg border border-border bg-card p-6 text-center">
        <div className="mx-auto flex size-11 items-center justify-center rounded-md bg-destructive/10 text-destructive">
          <TriangleAlert className="size-5" strokeWidth={1.8} />
        </div>
        <div className="space-y-1.5">
          <h1 className="text-lg font-semibold tracking-tight">
            {i18n("title")}
          </h1>
          <p className="text-sm leading-relaxed text-muted-foreground">
            {i18n("description")}
          </p>
        </div>
        <pre className="max-h-40 overflow-auto rounded-md bg-muted/60 p-3 text-left font-mono text-xs break-all whitespace-pre-wrap text-muted-foreground">
          {describe(error)}
        </pre>
        <div className="flex flex-col-reverse justify-center gap-2 sm:flex-row">
          <Button
            variant="outline"
            className="cursor-pointer"
            onClick={() => goToHome()}
          >
            {i18n("backHome")}
          </Button>
          <Button
            className="cursor-pointer"
            onClick={() => window.location.reload()}
          >
            {i18n("reload")}
          </Button>
        </div>
      </div>
    </div>
  );
}
