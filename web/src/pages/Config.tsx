import useConfigState from "@/states/config";
import { formatError } from "@/helpers/util";
import { useAsync } from "react-async-hook";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useShallow } from "zustand/react/shallow";
import { ClipboardCopy, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { PageShell } from "@/components/page-shell";
import React from "react";

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
  onCopy?: () => void;
}) {
  return (
    <Card className="relative flex h-full min-h-0 flex-col overflow-hidden border-border/80 shadow-none">
      {onCopy && content && (
        <Button
          className="absolute top-3 right-3 z-10 cursor-pointer"
          variant="secondary"
          size="icon"
          onClick={async (e) => {
            e.preventDefault();
            onCopy();
          }}
        >
          <ClipboardCopy className="h-4 w-4" />
        </Button>
      )}
      <CardContent className="min-h-0 flex-1 overflow-hidden p-0">
        <pre className="h-full overflow-auto p-4 font-mono text-xs leading-relaxed whitespace-pre-wrap sm:text-sm">
          {content || <span className="text-muted-foreground">—</span>}
        </pre>
      </CardContent>
    </Card>
  );
}

export default function Config() {
  const { t } = useTranslation();
  const [importing, setImporting] = React.useState(false);
  const [newToml, setNewToml] = React.useState("");
  const [fetchFullConfig, importToml, fullToml, originalToml, hcl] =
    useConfigState(
      useShallow((state) => [
        state.fetchFullConfig,
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

  const copyToml = async () => {
    try {
      await navigator.clipboard.writeText(originalToml);
      toast(t("copyConfigSuccess"));
    } catch (err) {
      toast(t("copyConfigFail"), {
        description: formatError(err),
      });
    }
  };
  const copyHcl = async () => {
    try {
      await navigator.clipboard.writeText(hcl);
      toast(t("copyConfigSuccess"));
    } catch (err) {
      toast(t("copyConfigFail"), {
        description: formatError(err),
      });
    }
  };
  const handleImportToml = async (value: string) => {
    if (importing) {
      return;
    }
    setImporting(true);
    try {
      await importToml(value);
      toast(t("importSuccess"));
    } catch (err) {
      toast(t("importFail"), {
        description: formatError(err),
      });
    } finally {
      setImporting(false);
    }
  };

  const different = fullToml != originalToml;
  let tabClass = "grid-cols-3";
  if (different) {
    tabClass = "grid-cols-4";
  }
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
            <TabsTrigger value="full" className="cursor-pointer">
              {t("full")}
            </TabsTrigger>
          )}
          <TabsTrigger value="hcl" className="cursor-pointer">
            HCL
          </TabsTrigger>
          <TabsTrigger value="import" className="cursor-pointer">
            {t("import")}
          </TabsTrigger>
        </TabsList>

        {/* Fill remaining height under tabs; only the panel body scrolls */}
        <div className="relative min-h-0 flex-1">
          <TabsContent value="full" className={panelClass}>
            <CodePanel content={fullToml} />
          </TabsContent>
          <TabsContent value="original" className={panelClass}>
            <CodePanel content={originalToml} onCopy={copyToml} />
          </TabsContent>
          <TabsContent value="hcl" className={panelClass}>
            <CodePanel content={hcl} onCopy={copyHcl} />
          </TabsContent>
          <TabsContent value="import" className={panelClass}>
            <Card className="flex h-full min-h-0 flex-col overflow-hidden border-border/80 shadow-none">
              <CardHeader className="shrink-0 pb-3">
                <CardTitle className="text-base">{t("import")}</CardTitle>
              </CardHeader>
              <CardContent className="flex min-h-0 flex-1 flex-col gap-4 overflow-hidden">
                <Textarea
                  autoFocus
                  className="min-h-0 flex-1 resize-none font-mono text-sm"
                  placeholder="paste TOML config…"
                  onChange={(e) => {
                    const value = e.target.value.trim();
                    setNewToml(value);
                  }}
                />
                <Button
                  className="w-full shrink-0 cursor-pointer sm:w-auto"
                  disabled={importing || !newToml}
                  onClick={() => {
                    handleImportToml(newToml);
                  }}
                >
                  {importing && (
                    <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                  )}
                  {importText}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </div>
      </Tabs>
    </PageShell>
  );
}
