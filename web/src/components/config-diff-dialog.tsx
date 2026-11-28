import { AlertTriangle, CheckCircle2, LoaderCircle } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { ConfigDiffResult } from "@/states/config";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export interface ConfigDiffDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  result: ConfigDiffResult | null;
  title?: string;
  description?: string;
  confirmLabel?: string;
  applying?: boolean;
  onConfirm: () => Promise<void> | void;
}

function diffLineClassName(line: string): string {
  if (line.startsWith("++ ")) {
    return "font-semibold text-emerald-600 dark:text-emerald-400";
  }
  if (line.startsWith("+ ")) {
    return "rounded-xs bg-emerald-500/10 px-1 text-emerald-700 dark:text-emerald-300";
  }
  if (line.startsWith("-- ")) {
    return "font-semibold text-destructive";
  }
  if (line.startsWith("- ")) {
    return "rounded-xs bg-destructive/10 px-1 text-destructive";
  }
  if (line.startsWith("[MODIFIED]")) {
    return "mt-1.5 font-semibold text-foreground first:mt-0";
  }
  return "text-muted-foreground";
}

export function ConfigDiffDialog({
  open,
  onOpenChange,
  result,
  title,
  description,
  confirmLabel,
  applying = false,
  onConfirm,
}: ConfigDiffDialogProps) {
  const { t } = useTranslation();

  const diffLines = result?.diff ?? [];
  const categories = result?.updated_categories ?? [];
  const restartItems = result?.left_for_restart ?? [];
  const needsRestart =
    Boolean(result?.restart_required) || restartItems.length > 0;
  const diffLineCount = diffLines.filter((line) => line.length > 0).length;

  const restartUnsupportedMessages: Record<string, string> = {
    container: t("restartUnsupportedContainer"),
    foreground: t("restartUnsupportedForeground"),
    platform: t("restartUnsupportedPlatform"),
  };
  const restartUnsupportedReason = result?.restart_unsupported
    ? restartUnsupportedMessages[result.restart_unsupported] ||
      result.restart_unsupported
    : "";

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!applying) {
          onOpenChange(nextOpen);
        }
      }}
    >
      <DialogContent className="flex max-h-[85vh] flex-col gap-4 sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{title || t("diffDialog.title")}</DialogTitle>
          <DialogDescription>
            {description || t("diffDialog.description")}
          </DialogDescription>
        </DialogHeader>

        {result && (
          <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2.5 text-xs">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-muted-foreground">
                  {t("diffDialog.categoriesLabel")}:
                </span>
                {categories.length > 0 ? (
                  categories.map((category) => (
                    <Badge
                      key={category}
                      variant="outline"
                      className="machine font-normal"
                    >
                      {category}
                    </Badge>
                  ))
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </div>
              <span className="figure text-muted-foreground">
                {t("diffDialog.linesCount", { count: diffLineCount })}
              </span>
            </div>

            {needsRestart ? (
              <div className="rounded-md border border-amber-500/40 bg-amber-500/[0.06] px-3.5 py-2.5 text-xs">
                <div className="flex items-center gap-1.5 font-medium text-amber-800 dark:text-amber-300">
                  <AlertTriangle className="size-3.5 shrink-0" />
                  <span>{t("diffDialog.restartRequiredTitle")}</span>
                </div>
                <p className="mt-1 text-amber-800/90 dark:text-amber-200/90">
                  {t("diffDialog.restartRequiredDesc")}
                </p>
                {restartItems.length > 0 && (
                  <div className="mt-2">
                    <div className="mb-1 font-medium text-amber-800/90 dark:text-amber-200/90">
                      {t("diffDialog.restartItemsLabel")}:
                    </div>
                    <ul className="machine max-h-28 space-y-0.5 overflow-y-auto overscroll-contain rounded border border-amber-500/25 bg-card/70 px-2.5 py-1.5 text-[11px] leading-relaxed text-foreground">
                      {restartItems.map((item, idx) => (
                        <li key={idx} className="break-all">
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {restartUnsupportedReason && (
                  <p className="mt-2 border-t border-amber-500/25 pt-2 text-amber-900 dark:text-amber-200">
                    {restartUnsupportedReason}
                  </p>
                )}
              </div>
            ) : (
              diffLines.length > 0 && (
                <div className="flex items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/[0.05] px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
                  <CheckCircle2 className="size-3.5 shrink-0" />
                  <span>{t("diffDialog.hotReloadOk")}</span>
                </div>
              )
            )}

            {diffLines.length === 0 ? (
              <div className="rounded-md border border-dashed border-border bg-muted/20 px-4 py-8 text-center text-sm text-muted-foreground">
                {t("diffDialog.noDiff")}
              </div>
            ) : (
              <pre className="machine min-h-[64px] max-h-[42vh] overflow-auto overscroll-contain rounded-md border border-border bg-muted/30 p-3 text-xs leading-relaxed whitespace-pre-wrap">
                {diffLines.map((line, idx) =>
                  line === "" ? (
                    <div key={idx} className="h-2" />
                  ) : (
                    <div key={idx} className={diffLineClassName(line)}>
                      {line}
                    </div>
                  ),
                )}
              </pre>
            )}
          </div>
        )}

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            className="cursor-pointer"
            disabled={applying}
            onClick={() => onOpenChange(false)}
          >
            {t("cancel")}
          </Button>
          <Button
            type="button"
            className="cursor-pointer"
            disabled={applying || !result}
            onClick={() => {
              void onConfirm();
            }}
          >
            {applying && <LoaderCircle className="mr-2 size-4 animate-spin" />}
            {confirmLabel || t("diffDialog.confirmApply")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
