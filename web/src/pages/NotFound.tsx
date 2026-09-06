import { FileQuestion } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/i18n";
import { goToHome } from "@/routers";
import { Link } from "react-router-dom";

/**
 * In-shell 404 for unknown hash routes. Kept separate from RouteError so a
 * missing page does not look like a crash.
 */
export default function NotFound() {
  const i18n = useI18n("notFound");

  return (
    <div className="flex min-h-0 flex-1 items-center justify-center overflow-auto p-4 md:p-6">
      <div className="w-full max-w-md space-y-5 rounded-lg border border-border bg-card p-6 text-center">
        <div className="mx-auto flex size-11 items-center justify-center rounded-md bg-muted text-muted-foreground">
          <FileQuestion className="size-5" strokeWidth={1.8} />
        </div>
        <div className="space-y-1.5">
          <p className="eyebrow text-muted-foreground">{i18n("code")}</p>
          <h1 className="text-lg font-semibold tracking-tight">
            {i18n("title")}
          </h1>
          <p className="text-sm leading-relaxed text-muted-foreground">
            {i18n("description")}
          </p>
        </div>
        <div className="flex flex-col-reverse justify-center gap-2 sm:flex-row">
          <Button
            variant="outline"
            className="cursor-pointer"
            onClick={() => goToHome()}
          >
            {i18n("backHome")}
          </Button>
          <Button asChild className="cursor-pointer">
            <Link to="/config">{i18n("openConfig")}</Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
