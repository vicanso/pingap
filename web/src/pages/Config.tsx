import useConfigState, {
  type ConfigDiffResult,
  type ConfigSnapshotItem,
} from "@/states/config";
import { formatError } from "@/helpers/util";
import { useAsync } from "react-async-hook";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useShallow } from "zustand/react/shallow";
import {
  AlertTriangle,
  Camera,
  Check,
  ChevronDown,
  ChevronUp,
  ClipboardCopy,
  Download,
  FileUp,
  GitCompare,
  LoaderCircle,
  RefreshCw,
  RotateCcw,
  Sparkles,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import request from "@/helpers/request";
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { PageShell } from "@/components/page-shell";
import { goToHome } from "@/routers";
import React from "react";
import useBasicState from "@/states/basic";
import { ConfigDiffDialog } from "@/components/config-diff-dialog";
import { Loading } from "@/components/loading";

type ImportSourceFormat = "toml" | "hcl" | "kdl" | "nginx" | "caddy";
type ConfigTabValue =
  | "original"
  | "full"
  | "hcl"
  | "kdl"
  | "snapshots"
  | "import";

function downloadTextFile(
  filename: string,
  content: string,
  mimeType = "text/plain;charset=utf-8",
) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

/**
 * Module scope, not inside Config: a component created during render is a new
 * type on every render, so React would unmount and remount the whole panel —
 * losing the <pre> scroll position on each keystroke in the import tab.
 */
function CodePanel({
  content,
  downloadFilename,
  onCopy,
}: {
  content: string;
  downloadFilename?: string;
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
        <div className="flex items-center gap-1">
          {downloadFilename && content && (
            <Button
              className="h-7 cursor-pointer gap-1.5 px-2 text-xs"
              variant="ghost"
              size="sm"
              aria-label={t("configPage.download")}
              title={t("configPage.download")}
              onClick={(e) => {
                e.preventDefault();
                downloadTextFile(downloadFilename, content);
              }}
            >
              <Download className="h-3.5 w-3.5" />
            </Button>
          )}
          {onCopy && content && (
            <Button
              className="h-7 cursor-pointer gap-1.5 px-2 text-xs"
              variant="ghost"
              size="sm"
              aria-label={t("header.copy")}
              title={t("header.copy")}
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
  const [activeTab, setActiveTab] = React.useState<ConfigTabValue>("original");
  const [importing, setImporting] = React.useState(false);
  const [previewingImport, setPreviewingImport] = React.useState(false);
  const [converting, setConverting] = React.useState(false);
  const [importFormat, setImportFormat] =
    React.useState<ImportSourceFormat>("toml");
  const [sourceText, setSourceText] = React.useState("");
  const [convertWarnings, setConvertWarnings] = React.useState<string[]>([]);
  const [importText, setImportText] = React.useState("");

  const [importDiffResult, setImportDiffResult] =
    React.useState<ConfigDiffResult | null>(null);
  const [importDiffOpen, setImportDiffOpen] = React.useState(false);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);

  const [snapshots, setSnapshots] = React.useState<ConfigSnapshotItem[]>([]);
  const [loadingSnapshots, setLoadingSnapshots] = React.useState(false);
  const [creatingSnapshot, setCreatingSnapshot] = React.useState(false);
  const [snapshotRemark, setSnapshotRemark] = React.useState("");
  const [expandedSnapshotId, setExpandedSnapshotId] = React.useState<
    string | null
  >(null);
  const [copiedSnapshotId, setCopiedSnapshotId] = React.useState<string | null>(
    null,
  );
  const [previewingSnapshotId, setPreviewingSnapshotId] = React.useState<
    string | null
  >(null);
  const [rollbackSnapshot, setRollbackSnapshot] =
    React.useState<ConfigSnapshotItem | null>(null);
  const [rollbackDiffResult, setRollbackDiffResult] =
    React.useState<ConfigDiffResult | null>(null);
  const [rollbackDiffOpen, setRollbackDiffOpen] = React.useState(false);
  const [rollingBack, setRollingBack] = React.useState(false);
  const snapshotCopyTimerRef = React.useRef<number | null>(null);

  React.useEffect(() => {
    return () => {
      if (snapshotCopyTimerRef.current !== null) {
        window.clearTimeout(snapshotCopyTimerRef.current);
      }
    };
  }, []);

  // An import replaces the configuration: not for an account that may
  // only look.
  const readOnly = useBasicState((state) => state.data.read_only);
  const [
    fetchFullConfig,
    importToml,
    previewImportDiff,
    getSnapshots,
    createSnapshot,
    fullToml,
    originalToml,
    hcl,
    kdl,
  ] = useConfigState(
    useShallow((state) => [
      state.fetchFullConfig,
      state.importToml,
      state.previewImportDiff,
      state.getSnapshots,
      state.createSnapshot,
      state.fullToml,
      state.originalToml,
      state.hcl,
      state.kdl,
    ]),
  );

  const loadSnapshots = React.useCallback(async () => {
    setLoadingSnapshots(true);
    try {
      const list = await getSnapshots();
      setSnapshots(list);
    } catch (err) {
      toast(t("fetchFail"), {
        description: formatError(err),
      });
    } finally {
      setLoadingSnapshots(false);
    }
  }, [getSnapshots, t]);

  useAsync(async () => {
    try {
      await fetchFullConfig();
    } catch (err) {
      toast(t("fetchFail"), {
        description: formatError(err),
      });
    }
    try {
      const list = await getSnapshots();
      setSnapshots(list);
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
  const copyKdl = () => copyContent(kdl);

  const hasLoadedConfig = Boolean(originalToml || fullToml || hcl || kdl);
  const handleExportBundle = () => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const bundle = {
      version: 1,
      exported_at: new Date().toISOString(),
      original_toml: originalToml,
      full_toml: fullToml,
      hcl,
      kdl,
    };
    downloadTextFile(
      `pingap-snapshot-${timestamp}.json`,
      JSON.stringify(bundle, null, 2),
      "application/json;charset=utf-8",
    );
  };

  const handleConvertConfig = async () => {
    if (converting || !sourceText.trim()) {
      return;
    }
    setConverting(true);
    try {
      const res = await request.post<{ toml: string; warnings: string[] }>(
        "/convert-config",
        {
          format: importFormat === "caddy" ? "caddyfile" : importFormat,
          content: sourceText,
        },
      );
      setImportText(res.data.toml || "");
      setConvertWarnings(res.data.warnings || []);
    } catch (err) {
      toast(t("configPage.convertFail"), {
        description: formatError(err),
      });
    } finally {
      setConverting(false);
    }
  };

  const effectiveImportFormat: "toml" | "hcl" | "kdl" =
    importFormat === "nginx" || importFormat === "caddy"
      ? "toml"
      : importFormat;

  const handlePreviewImportDiff = async () => {
    if (previewingImport || importing) {
      return;
    }
    const trimmed = importText.trim();
    if (!trimmed) {
      toast(t("importFail"), {
        description: t("importEmpty"),
      });
      return;
    }
    setPreviewingImport(true);
    try {
      const result = await previewImportDiff(trimmed, effectiveImportFormat);
      setImportDiffResult(result);
      setImportDiffOpen(true);
    } catch (err) {
      toast(t("diffDialog.previewFail"), {
        description: formatError(err),
      });
    } finally {
      setPreviewingImport(false);
    }
  };

  const handleConfirmImport = async () => {
    if (importing) {
      return;
    }
    const trimmed = importText.trim();
    if (!trimmed) {
      toast(t("importFail"), {
        description: t("importEmpty"),
      });
      return;
    }
    setImporting(true);
    try {
      await importToml(trimmed, effectiveImportFormat);
      setImportDiffOpen(false);
      toast(t("importSuccess"), {
        description: t("importSuccessDescription"),
      });
      // An import replaces the whole config, so nothing on this page still
      // describes what is running. Reload it and show the dashboard.
      goToHome();
    } catch (err) {
      toast(t("importFail"), {
        description: formatError(err),
      });
    } finally {
      setImporting(false);
    }
  };

  const handleLoadImportFile = async (
    e: React.ChangeEvent<HTMLInputElement>,
  ) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) {
      return;
    }
    try {
      const content = await file.text();
      const lowerName = file.name.toLowerCase();
      setConvertWarnings([]);

      if (lowerName.endsWith(".json")) {
        const parsed = JSON.parse(content) as {
          original_toml?: unknown;
          full_toml?: unknown;
          toml?: unknown;
        };
        const extracted =
          (typeof parsed.original_toml === "string" && parsed.original_toml) ||
          (typeof parsed.full_toml === "string" && parsed.full_toml) ||
          (typeof parsed.toml === "string" && parsed.toml) ||
          "";
        if (!extracted.trim()) {
          throw new Error(
            "JSON bundle does not contain original_toml, full_toml, or toml.",
          );
        }
        setImportFormat("toml");
        setImportText(extracted);
        return;
      }

      if (lowerName.endsWith(".hcl")) {
        setImportFormat("hcl");
        setImportText(content);
        return;
      }

      if (lowerName.endsWith(".kdl")) {
        setImportFormat("kdl");
        setImportText(content);
        return;
      }

      if (lowerName.endsWith(".toml")) {
        setImportFormat("toml");
        setImportText(content);
        return;
      }

      if (lowerName.endsWith(".conf") || lowerName.includes("nginx")) {
        setImportFormat("nginx");
        setSourceText(content);
        setImportText("");
        return;
      }

      if (lowerName.includes("caddy")) {
        setImportFormat("caddy");
        setSourceText(content);
        setImportText("");
        return;
      }

      if (importFormat === "nginx" || importFormat === "caddy") {
        setSourceText(content);
      } else {
        setImportText(content);
      }
    } catch (err) {
      toast(t("configPage.loadFileFail"), {
        description: formatError(err),
      });
    }
  };

  const handleCreateSnapshot = async () => {
    if (creatingSnapshot || readOnly) {
      return;
    }
    setCreatingSnapshot(true);
    try {
      await createSnapshot(snapshotRemark.trim() || undefined);
      setSnapshotRemark("");
      await loadSnapshots();
      toast.success(t("configPage.snapshotCreated"));
    } catch (err) {
      toast.error(t("configPage.snapshotCreateFail"), {
        description: formatError(err),
      });
    } finally {
      setCreatingSnapshot(false);
    }
  };

  const handlePreviewRollback = async (snap: ConfigSnapshotItem) => {
    if (previewingSnapshotId || rollingBack) {
      return;
    }
    setPreviewingSnapshotId(snap.id);
    try {
      const diff = await previewImportDiff(snap.toml, "toml");
      setRollbackSnapshot(snap);
      setRollbackDiffResult(diff);
      setRollbackDiffOpen(true);
    } catch (err) {
      toast.error(t("diffDialog.previewFail"), {
        description: formatError(err),
      });
    } finally {
      setPreviewingSnapshotId(null);
    }
  };

  const handleConfirmRollback = async () => {
    if (!rollbackSnapshot || rollingBack) {
      return;
    }
    setRollingBack(true);
    try {
      await importToml(rollbackSnapshot.toml, "toml");
      await fetchFullConfig();
      await loadSnapshots();
      setRollbackDiffOpen(false);
      setRollbackSnapshot(null);
      toast.success(t("configPage.snapshotRollbackSuccess"));
    } catch (err) {
      toast.error(t("importFail"), {
        description: formatError(err),
      });
    } finally {
      setRollingBack(false);
    }
  };

  const snapshotSourceLabel = (source: string) => {
    switch (source) {
      case "manual":
        return t("configPage.snapshotSourceManual");
      case "before_update":
        return t("configPage.snapshotSourceBeforeUpdate");
      case "before_delete":
        return t("configPage.snapshotSourceBeforeDelete");
      case "before_import":
        return t("configPage.snapshotSourceBeforeImport");
      case "before_quick_site":
        return t("configPage.snapshotSourceBeforeQuickSite");
      case "before_preset":
        return t("configPage.snapshotSourceBeforePreset");
      default:
        return source;
    }
  };

  const different = fullToml !== originalToml;
  // Original, HCL, KDL, Snapshots + optional Full (when it differs) + optional Import (when writable).
  const tabCount = 4 + (different ? 1 : 0) + (readOnly ? 0 : 1);
  const tabClass =
    tabCount === 6
      ? "grid-cols-3 h-auto sm:h-10 sm:grid-cols-6"
      : tabCount === 5
        ? "grid-cols-3 h-auto sm:h-10 sm:grid-cols-5"
        : "grid-cols-2 h-auto sm:h-10 sm:grid-cols-4";

  const nativeFormatPlaceholder =
    importFormat === "hcl"
      ? t("configPage.hclPlaceholder")
      : importFormat === "kdl"
        ? t("configPage.kdlPlaceholder")
        : t("configPage.tomlPlaceholder");

  // Absolute fill: keeps TabsList out of the scroll region so it never scrolls away.
  const panelClass =
    "mt-0 absolute inset-0 flex flex-col data-[state=inactive]:hidden";

  return (
    <PageShell
      title={t("tomlTitle")}
      description={t("tomlDescription")}
      fill
      actions={
        hasLoadedConfig ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="cursor-pointer gap-1.5"
            onClick={handleExportBundle}
          >
            <Download className="h-3.5 w-3.5" />
            {t("configPage.downloadBundle")}
          </Button>
        ) : undefined
      }
    >
      <Tabs
        value={activeTab}
        onValueChange={(value) => {
          const nextTab = value as ConfigTabValue;
          setActiveTab(nextTab);
          if (nextTab === "snapshots") {
            void loadSnapshots();
          }
        }}
        className="flex min-h-0 flex-1 flex-col overflow-hidden"
      >
        <TabsList className={cn("mb-3 grid w-full shrink-0", tabClass)}>
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
          <TabsTrigger value="kdl" className="cursor-pointer">
            {t("configPage.kdl")}
          </TabsTrigger>
          <TabsTrigger value="snapshots" className="cursor-pointer gap-1.5">
            {t("configPage.snapshots")}
            {snapshots.length > 0 && (
              <span className="figure rounded bg-muted px-1.5 text-[11px] text-muted-foreground">
                {snapshots.length}
              </span>
            )}
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
            <CodePanel
              content={fullToml}
              downloadFilename="pingap-full.toml"
              onCopy={copyFullToml}
            />
          </TabsContent>
          <TabsContent value="original" className={panelClass}>
            <CodePanel
              content={originalToml}
              downloadFilename="pingap-original.toml"
              onCopy={copyToml}
            />
          </TabsContent>
          <TabsContent value="hcl" className={panelClass}>
            <CodePanel
              content={hcl}
              downloadFilename="pingap.hcl"
              onCopy={copyHcl}
            />
          </TabsContent>
          <TabsContent value="kdl" className={panelClass}>
            <CodePanel
              content={kdl}
              downloadFilename="pingap.kdl"
              onCopy={copyKdl}
            />
          </TabsContent>
          <TabsContent value="snapshots" className={panelClass}>
            <Card className="flex h-full min-h-0 flex-col gap-0 overflow-hidden border-border py-0">
              <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border bg-muted/30 px-4 py-3">
                {!readOnly && (
                  <>
                    <Input
                      className="h-8 max-w-sm flex-1 bg-background text-xs sm:text-sm"
                      placeholder={t("configPage.snapshotRemarkPlaceholder")}
                      value={snapshotRemark}
                      onChange={(e) => setSnapshotRemark(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          void handleCreateSnapshot();
                        }
                      }}
                    />
                    <Button
                      type="button"
                      size="sm"
                      className="h-8 cursor-pointer gap-1.5"
                      disabled={creatingSnapshot}
                      onClick={() => {
                        void handleCreateSnapshot();
                      }}
                    >
                      {creatingSnapshot ? (
                        <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Camera className="h-3.5 w-3.5" />
                      )}
                      {t("configPage.snapshotCreate")}
                    </Button>
                  </>
                )}
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="ml-auto h-8 cursor-pointer gap-1.5"
                  disabled={loadingSnapshots}
                  onClick={() => {
                    void loadSnapshots();
                  }}
                >
                  <RefreshCw
                    className={cn(
                      "h-3.5 w-3.5",
                      loadingSnapshots && "animate-spin",
                    )}
                  />
                  {t("diagnostics.refresh")}
                </Button>
              </div>
              <CardContent className="min-h-0 flex-1 overflow-y-auto p-4">
                {loadingSnapshots && snapshots.length === 0 ? (
                  <Loading className="mt-4" />
                ) : snapshots.length === 0 ? (
                  <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-muted/20 px-4 py-12 text-center">
                    <p className="max-w-md text-sm text-muted-foreground">
                      {t("configPage.snapshotEmpty")}
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {snapshots.map((snap) => {
                      const isExpanded = expandedSnapshotId === snap.id;
                      const isCopied = copiedSnapshotId === snap.id;
                      const isPreviewing = previewingSnapshotId === snap.id;
                      return (
                        <div
                          key={snap.id}
                          className="rounded-lg border border-border bg-card p-4"
                        >
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div className="min-w-0 space-y-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="figure text-sm font-medium">
                                  {new Date(
                                    snap.created_at * 1000,
                                  ).toLocaleString()}
                                </span>
                                <Badge variant="outline" className="font-normal">
                                  {snapshotSourceLabel(snap.source)}
                                </Badge>
                                <span className="machine rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                                  {snap.hash}
                                </span>
                                <span className="figure text-xs text-muted-foreground">
                                  {t("configPage.linesCount", {
                                    count: snap.lines,
                                  })}
                                </span>
                              </div>
                              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                                <span className="machine">{snap.id}</span>
                                {snap.remark && (
                                  <>
                                    <span>·</span>
                                    <span className="text-foreground/80">
                                      {snap.remark}
                                    </span>
                                  </>
                                )}
                              </div>
                            </div>
                            <div className="flex flex-wrap items-center gap-1.5">
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                className="h-7 cursor-pointer gap-1 px-2 text-xs"
                                onClick={() => {
                                  setExpandedSnapshotId(
                                    isExpanded ? null : snap.id,
                                  );
                                }}
                              >
                                {isExpanded ? (
                                  <ChevronUp className="h-3.5 w-3.5" />
                                ) : (
                                  <ChevronDown className="h-3.5 w-3.5" />
                                )}
                                {isExpanded
                                  ? t("configPage.hideContent")
                                  : t("configPage.showContent")}
                              </Button>
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                className="h-7 cursor-pointer px-2 text-xs"
                                aria-label={t("header.copy")}
                                title={t("header.copy")}
                                onClick={async () => {
                                  const ok = await copyContent(snap.toml);
                                  if (ok) {
                                    setCopiedSnapshotId(snap.id);
                                    if (snapshotCopyTimerRef.current !== null) {
                                      window.clearTimeout(
                                        snapshotCopyTimerRef.current,
                                      );
                                    }
                                    snapshotCopyTimerRef.current =
                                      window.setTimeout(() => {
                                        setCopiedSnapshotId(null);
                                      }, 1500);
                                  }
                                }}
                              >
                                {isCopied ? (
                                  <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                                ) : (
                                  <ClipboardCopy className="h-3.5 w-3.5" />
                                )}
                              </Button>
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                className="h-7 cursor-pointer px-2 text-xs"
                                aria-label={t("configPage.download")}
                                title={t("configPage.download")}
                                onClick={() => {
                                  downloadTextFile(
                                    `pingap-snapshot-${snap.id}.toml`,
                                    snap.toml,
                                  );
                                }}
                              >
                                <Download className="h-3.5 w-3.5" />
                              </Button>
                              {!readOnly && (
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  className="h-7 cursor-pointer gap-1.5 px-2.5 text-xs"
                                  disabled={
                                    Boolean(previewingSnapshotId) || rollingBack
                                  }
                                  onClick={() => {
                                    void handlePreviewRollback(snap);
                                  }}
                                >
                                  {isPreviewing ? (
                                    <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
                                  ) : (
                                    <RotateCcw className="h-3.5 w-3.5" />
                                  )}
                                  {t("configPage.snapshotRollback")}
                                </Button>
                              )}
                            </div>
                          </div>
                          {isExpanded && (
                            <pre className="machine mt-3 max-h-64 overflow-auto rounded-md border border-border bg-muted/30 p-3 text-xs leading-relaxed whitespace-pre-wrap">
                              {snap.toml}
                            </pre>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
          <TabsContent value="import" className={panelClass}>
            <Card className="flex h-full min-h-0 flex-col overflow-hidden border-border">
              <CardHeader className="flex shrink-0 flex-row flex-wrap items-center justify-between gap-3 px-5 pt-5 pb-3">
                <CardTitle className="text-base">{t("import")}</CardTitle>
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".toml,.hcl,.kdl,.json,.conf,.txt"
                    className="hidden"
                    onChange={(e) => {
                      void handleLoadImportFile(e);
                    }}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-8 cursor-pointer gap-1.5 text-xs"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <FileUp className="h-3.5 w-3.5" />
                    {t("configPage.loadFile")}
                  </Button>
                  <Label className="text-xs text-muted-foreground">
                    {t("configPage.importFormat")}
                  </Label>
                  <Select
                    value={importFormat}
                    onValueChange={(value) => {
                      const fmt = value as ImportSourceFormat;
                      setImportFormat(fmt);
                      setConvertWarnings([]);
                    }}
                  >
                    <SelectTrigger className="h-8 w-44 cursor-pointer text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="toml">Pingap TOML</SelectItem>
                      <SelectItem value="hcl">Pingap HCL</SelectItem>
                      <SelectItem value="kdl">Pingap KDL</SelectItem>
                      <SelectItem value="nginx">Nginx (nginx.conf)</SelectItem>
                      <SelectItem value="caddy">Caddyfile</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardHeader>
              <CardContent className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden px-5 pb-5">
                {importFormat === "toml" ||
                importFormat === "hcl" ||
                importFormat === "kdl" ? (
                  <Textarea
                    autoFocus
                    className="min-h-0 flex-1 resize-none font-mono text-sm"
                    placeholder={nativeFormatPlaceholder}
                    value={importText}
                    onChange={(e) => {
                      setImportText(e.target.value);
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
                        value={importText}
                        onChange={(e) => setImportText(e.target.value)}
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
                <Button
                  type="button"
                  className="w-full shrink-0 cursor-pointer gap-2 sm:w-auto"
                  disabled={previewingImport || importing || !importText.trim()}
                  onClick={() => {
                    void handlePreviewImportDiff();
                  }}
                >
                  {previewingImport || importing ? (
                    <LoaderCircle className="h-4 w-4 animate-spin" />
                  ) : (
                    <GitCompare className="h-4 w-4" />
                  )}
                  {t("configPage.previewAndImport")}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </div>
      </Tabs>

      <ConfigDiffDialog
        open={importDiffOpen}
        onOpenChange={setImportDiffOpen}
        result={importDiffResult}
        title={t("configPage.importConfirmTitle")}
        description={t("configPage.importConfirmDescription")}
        confirmLabel={t("diffDialog.confirmImport")}
        applying={importing}
        onConfirm={handleConfirmImport}
      />

      <ConfigDiffDialog
        open={rollbackDiffOpen}
        onOpenChange={setRollbackDiffOpen}
        result={rollbackDiffResult}
        title={t("configPage.snapshotRollback")}
        description={
          rollbackSnapshot
            ? `${new Date(rollbackSnapshot.created_at * 1000).toLocaleString()} (${rollbackSnapshot.hash})`
            : undefined
        }
        confirmLabel={t("diffDialog.confirmRollback")}
        applying={rollingBack}
        onConfirm={handleConfirmRollback}
      />
    </PageShell>
  );
}
