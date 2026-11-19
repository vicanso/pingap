import useConfigState from "@/states/config";
import { formatError } from "@/helpers/util";
import { useAsync } from "react-async-hook";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useShallow } from "zustand/react/shallow";
import {
  AlertTriangle,
  Check,
  ClipboardCopy,
  LoaderCircle,
  Sparkles,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import request from "@/helpers/request";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { PageShell } from "@/components/page-shell";
import { goToHome } from "@/routers";
import React from "react";
import useBasicState from "@/states/basic";

/**
 * Module scope, not inside Config: a component created during render is a new
 * type on every render, so React would unmount and remount the whole panel —
 * losing the <pre> scroll position on each keystroke in the import tab.
 */
function CodePanel({
  content,
  onCopy,
}: {
  content: string;
  onCopy?: () => Promise<boolean> | void;
}) {
  const { t } = useTranslation();
  const [copied, setCopied] = React.useState(false);
  const timerRef = React.useRef<number | null>(null);

  React.useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
    };
  }, []);

  const linesCount = content ? content.split("\n").length : 0;

  return (
    <Card className="relative flex min-h-0 flex-1 flex-col gap-0 overflow-hidden border-border py-0">
      <div className="flex shrink-0 items-center justify-between border-b border-border bg-muted/30 px-4 py-1.5 text-xs text-muted-foreground">
        <span className="figure">
          {t("configPage.linesCount", { count: linesCount })}
        </span>
        {onCopy && content && (
          <Button
            className="h-7 cursor-pointer gap-1.5 px-2 text-xs"
            variant="ghost"
            size="sm"
            aria-label={t("header.copy")}
            onClick={async (e) => {
              e.preventDefault();
              const ok = await onCopy();
              if (ok !== false) {
                setCopied(true);
                if (timerRef.current !== null) {
                  window.clearTimeout(timerRef.current);
                }
                timerRef.current = window.setTimeout(() => {
                  setCopied(false);
                }, 1500);
              }
            }}
          >
            {copied ? (
              <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <ClipboardCopy className="h-3.5 w-3.5" />
            )}
          </Button>
        )}
      </div>
      <CardContent className="min-h-0 flex-1 overflow-hidden p-0">
        <pre className="h-full min-h-[min(60vh,480px)] overflow-auto p-4 font-mono text-[13px] leading-relaxed whitespace-pre-wrap sm:text-sm">
          {content || <span className="text-muted-foreground">—</span>}
        </pre>
      </CardContent>
    </Card>
  );
}

export default function Config() {
  const { t } = useTranslation();
  const [importing, setImporting] = React.useState(false);
  const [converting, setConverting] = React.useState(false);
  const [importFormat, setImportFormat] = React.useState<
    "toml" | "nginx" | "caddyfile"
  >("toml");
  const [sourceText, setSourceText] = React.useState("");
  const [convertWarnings, setConvertWarnings] = React.useState<string[]>([]);
  const [newToml, setNewToml] = React.useState("");
  // An import replaces the configuration: not for an account that may
  // only look.
  const readOnly = useBasicState((state) => state.data.read_only);
  const [
    fetchFullConfig,
    fetchConfig,
    importToml,
    fullToml,
    originalToml,
    hcl,
  ] = useConfigState(
    useShallow((state) => [
      state.fetchFullConfig,
      state.fetch,
      state.importToml,
      state.fullToml,
      state.originalToml,
      state.hcl,
    ]),
  );
  useAsync(async () => {
    try {
      await fetchFullConfig();
    } catch (err) {
      toast(t("fetchFail"), {
        description: formatError(err),
      });
    }
  }, []);

  const copyContent = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast(t("copyConfigSuccess"));
      return true;
    } catch (err) {
      toast(t("copyConfigFail"), {
        description: formatError(err),
      });
      return false;
    }
  };
  const copyToml = () => copyContent(originalToml);
  const copyFullToml = () => copyContent(fullToml);
  const copyHcl = () => copyContent(hcl);
  const handleConvertConfig = async () => {
    if (converting || !sourceText.trim()) {
      return;
    }
    setConverting(true);
    try {
      const res = await request.post<{ toml: string; warnings: string[] }>(
        "/convert-config",
        {
          format: importFormat,
          content: sourceText,
        },
      );
      setNewToml(res.data.toml || "");
      setConvertWarnings(res.data.warnings || []);
    } catch (err) {
      toast(t("configPage.convertFail"), {
        description: formatError(err),
      });
    } finally {
      setConverting(false);
    }
  };
  const handleImportToml = async (value: string) => {
    if (importing) {
      return;
    }
    const trimmed = value.trim();
    if (!trimmed) {
      toast(t("importFail"), {
        description: t("importEmpty"),
      });
      return;
    }
    setImporting(true);
    try {
      await importToml(trimmed);
      toast(t("importSuccess"), {
        description: t("importSuccessDescription"),
      });
      // An import replaces the whole config, so nothing on this page still
      // describes what is running. Reload it and show the dashboard.
      await fetchConfig();
      goToHome();
    } catch (err) {
      toast(t("importFail"), {
        description: formatError(err),
      });
    } finally {
      setImporting(false);
    }
  };

  const different = fullToml != originalToml;
  // The original and HCL, the full one when it differs, and the import for
  // an account that may change something.
  const tabCount = 2 + (different ? 1 : 0) + (readOnly ? 0 : 1);
  const tabClass =
    tabCount === 4
      ? "grid-cols-4"
      : tabCount === 3
        ? "grid-cols-3"
        : "grid-cols-2";
  let importText = t("import");
  if (importing) {
    importText += "...";
  }

  // Absolute fill: keeps TabsList out of the scroll region so it never scrolls away.
  const panelClass =
    "mt-0 absolute inset-0 flex flex-col data-[state=inactive]:hidden";

  return (
    <PageShell title={t("tomlTitle")} description={t("tomlDescription")} fill>
      <Tabs
        defaultValue="original"
        className="flex min-h-0 flex-1 flex-col overflow-hidden"
      >
        <TabsList className={cn("mb-3 grid h-10 w-full shrink-0", tabClass)}>
          <TabsTrigger value="original" className="cursor-pointer">
            {t("original")}
          </TabsTrigger>
          {different && (
            <TabsTrigger value="full" className="cursor-pointer gap-1.5">
              {t("full")}
              <span
                className="size-1.5 shrink-0 rounded-full bg-amber-500"
                title={t("configDiffHint")}
                aria-label={t("configDiffHint")}
              />
            </TabsTrigger>
          )}
          <TabsTrigger value="hcl" className="cursor-pointer">
            HCL
          </TabsTrigger>
          {!readOnly && (
            <TabsTrigger value="import" className="cursor-pointer">
              {t("import")}
            </TabsTrigger>
          )}
        </TabsList>

        {/* Fill remaining height under tabs; only the panel body scrolls */}
        <div className="relative min-h-0 flex-1">
          <TabsContent value="full" className={panelClass}>
            <CodePanel content={fullToml} onCopy={copyFullToml} />
          </TabsContent>
          <TabsContent value="original" className={panelClass}>
            <CodePanel content={originalToml} onCopy={copyToml} />
          </TabsContent>
          <TabsContent value="hcl" className={panelClass}>
            <CodePanel content={hcl} onCopy={copyHcl} />
          </TabsContent>
          <TabsContent value="import" className={panelClass}>
            <Card className="flex h-full min-h-0 flex-col overflow-hidden border-border">
              <CardHeader className="flex shrink-0 flex-row flex-wrap items-center justify-between gap-3 px-5 pt-5 pb-3">
                <CardTitle className="text-base">{t("import")}</CardTitle>
                <div className="flex items-center gap-2">
                  <Label className="text-xs text-muted-foreground">
                    {t("configPage.importFormat")}
                  </Label>
                  <Select
                    value={importFormat}
                    onValueChange={(value) => {
                      const fmt = value as "toml" | "nginx" | "caddyfile";
                      setImportFormat(fmt);
                      setConvertWarnings([]);
                    }}
                  >
                    <SelectTrigger className="h-8 w-40 cursor-pointer text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="toml">Pingap TOML</SelectItem>
                      <SelectItem value="nginx">Nginx (nginx.conf)</SelectItem>
                      <SelectItem value="caddyfile">Caddyfile</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardHeader>
              <CardContent className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden px-5 pb-5">
                {importFormat === "toml" ? (
                  <Textarea
                    autoFocus
                    className="min-h-0 flex-1 resize-none font-mono text-sm"
                    placeholder={t("configPage.tomlPlaceholder")}
                    value={newToml}
                    onChange={(e) => {
                      setNewToml(e.target.value);
                    }}
                  />
                ) : (
                  <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:grid-cols-2">
                    <div className="flex min-h-0 flex-col gap-2">
                      <div className="flex items-center justify-between">
                        <Label className="text-xs font-medium text-muted-foreground">
                          {importFormat === "nginx"
                            ? "nginx.conf"
                            : "Caddyfile"}
                        </Label>
                        <Button
                          type="button"
                          size="sm"
                          variant="secondary"
                          className="h-7 cursor-pointer gap-1.5 text-xs"
                          disabled={converting || !sourceText.trim()}
                          onClick={handleConvertConfig}
                        >
                          {converting ? (
                            <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Sparkles className="h-3.5 w-3.5" />
                          )}
                          {converting
                            ? t("configPage.converting")
                            : t("configPage.convertPreview")}
                        </Button>
                      </div>
                      <Textarea
                        autoFocus
                        className="min-h-0 flex-1 resize-none font-mono text-xs sm:text-sm"
                        placeholder={
                          importFormat === "nginx"
                            ? t("configPage.nginxPlaceholder")
                            : t("configPage.caddyPlaceholder")
                        }
                        value={sourceText}
                        onChange={(e) => setSourceText(e.target.value)}
                      />
                    </div>
                    <div className="flex min-h-0 flex-col gap-2">
                      <Label className="text-xs font-medium text-muted-foreground">
                        {t("configPage.convertedTomlPreview")}
                      </Label>
                      <Textarea
                        className="min-h-0 flex-1 resize-none font-mono text-xs sm:text-sm"
                        placeholder={t("configPage.previewPlaceholder")}
                        value={newToml}
                        onChange={(e) => setNewToml(e.target.value)}
                      />
                    </div>
                  </div>
                )}
                {convertWarnings.length > 0 && (
                  <div className="max-h-28 shrink-0 overflow-y-auto rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-200">
                    <div className="mb-1 flex items-center gap-1.5 font-medium">
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                      {t("configPage.convertWarnings", {
                        count: convertWarnings.length,
                      })}
                    </div>
                    <ul className="list-disc space-y-0.5 pl-4">
                      {convertWarnings.map((warning, idx) => (
                        <li key={idx}>{warning}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      className="w-full shrink-0 cursor-pointer sm:w-auto"
                      disabled={importing || !newToml.trim()}
                    >
                      {importing && (
                        <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                      )}
                      {importText}
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>
                        {t("configPage.importConfirmTitle")}
                      </AlertDialogTitle>
                      <AlertDialogDescription>
                        {t("configPage.importConfirmDescription")}
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel className="cursor-pointer">
                        {t("cancel")}
                      </AlertDialogCancel>
                      <AlertDialogAction
                        className="cursor-pointer"
                        onClick={() => {
                          handleImportToml(newToml.trim());
                        }}
                      >
                        {t("confirm")}
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </CardContent>
            </Card>
          </TabsContent>
        </div>
      </Tabs>
    </PageShell>
  );
}
