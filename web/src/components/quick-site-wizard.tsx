import React, { useMemo, useState } from "react";
import { LoaderCircle, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { useShallow } from "zustand/react/shallow";
import { useI18n } from "@/i18n";
import useConfigState, { type QuickSitePayload } from "@/states/config";
import { formatError } from "@/helpers/util";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";

function splitCommaList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function suggestSiteName(domainsInput: string): string {
  const first = splitCommaList(domainsInput)[0] || "";
  if (!first) {
    return "";
  }
  const stripped = first.replace(/^\*\./, "").replace(/^www\./i, "");
  const firstLabel = stripped.split(".")[0] || stripped;
  return firstLabel
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

interface QuickSiteWizardProps {
  variant?: "default" | "outline";
  size?: "default" | "sm";
}

export function QuickSiteWizard({
  variant = "default",
  size = "sm",
}: QuickSiteWizardProps) {
  const wizardI18n = useI18n("quickSite");
  const commonI18n = useI18n();
  const [config, createQuickSite] = useConfigState(
    useShallow((state) => [state.data, state.createQuickSite]),
  );

  const existingServers = useMemo(
    () => Object.keys(config.servers || {}).sort(),
    [config.servers],
  );

  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [nameTouched, setNameTouched] = useState(false);

  const [name, setName] = useState("");
  const [domainsInput, setDomainsInput] = useState("");
  const [upstreamsInput, setUpstreamsInput] = useState("");
  const [path, setPath] = useState("/");
  const [serverMode, setServerMode] = useState<"new" | "existing">("new");
  const [existingServer, setExistingServer] = useState("");
  const [addr, setAddr] = useState("");
  const [tlsMode, setTlsMode] = useState<"none" | "acme" | "custom">("none");
  const [tlsCert, setTlsCert] = useState("");
  const [tlsKey, setTlsKey] = useState("");
  const [enableProxyHeaders, setEnableProxyHeaders] = useState(true);
  const [enableCompression, setEnableCompression] = useState(true);
  const [enableSecurityHeaders, setEnableSecurityHeaders] = useState(true);

  const resetForm = () => {
    setNameTouched(false);
    setName("");
    setDomainsInput("");
    setUpstreamsInput("");
    setPath("/");
    setServerMode("new");
    setExistingServer(existingServers[0] || "");
    setAddr("");
    setTlsMode("none");
    setTlsCert("");
    setTlsKey("");
    setEnableProxyHeaders(true);
    setEnableCompression(true);
    setEnableSecurityHeaders(true);
  };

  const handleOpenChange = (nextOpen: boolean) => {
    setOpen(nextOpen);
    if (nextOpen) {
      resetForm();
    }
  };

  const handleDomainsChange = (value: string) => {
    setDomainsInput(value);
    if (!nameTouched) {
      setName(suggestSiteName(value));
    }
  };

  const effectiveName = name.trim() || "<name>";
  const effectiveAddr =
    addr.trim() || (tlsMode === "none" ? "0.0.0.0:80" : "0.0.0.0:443");

  const previewItems = useMemo(() => {
    const items: string[] = [
      `Upstream: ${effectiveName}`,
      `Location: ${effectiveName}`,
    ];
    if (tlsMode !== "none") {
      items.push(`Certificate: ${effectiveName}`);
    }
    if (enableCompression) {
      items.push(`Plugin: ${effectiveName}-compression`);
    }
    if (enableSecurityHeaders) {
      items.push(`Plugin: ${effectiveName}-security-headers`);
    }
    if (serverMode === "existing" && existingServer) {
      items.push(wizardI18n("previewAttachServer", { server: existingServer }));
    } else {
      items.push(`Server: ${effectiveName} (${effectiveAddr})`);
    }
    return items;
  }, [
    effectiveName,
    effectiveAddr,
    tlsMode,
    enableCompression,
    enableSecurityHeaders,
    serverMode,
    existingServer,
    wizardI18n,
  ]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedName = name.trim();
    const upstreams = splitCommaList(upstreamsInput);
    const domains = splitCommaList(domainsInput);

    if (!trimmedName) {
      toast.error(wizardI18n("nameRequired"));
      return;
    }
    if (upstreams.length === 0) {
      toast.error(wizardI18n("upstreamsRequired"));
      return;
    }
    if (tlsMode === "acme" && domains.length === 0) {
      toast.error(wizardI18n("domainsRequiredForAcme"));
      return;
    }
    if (tlsMode === "custom" && (!tlsCert.trim() || !tlsKey.trim())) {
      toast.error(wizardI18n("customTlsRequired"));
      return;
    }

    const payload: QuickSitePayload = {
      name: trimmedName,
      domains,
      upstreams,
      path: path.trim() || "/",
      tls_mode: tlsMode,
      enable_reverse_proxy_headers: enableProxyHeaders,
      enable_compression: enableCompression,
      enable_security_headers: enableSecurityHeaders,
    };
    if (serverMode === "existing" && existingServer) {
      payload.existing_server = existingServer;
    } else if (addr.trim()) {
      payload.addr = addr.trim();
    }
    if (tlsMode === "custom") {
      payload.tls_cert = tlsCert.trim();
      payload.tls_key = tlsKey.trim();
    }

    setSubmitting(true);
    try {
      const result = await createQuickSite(payload);
      toast.success(wizardI18n("createSuccessTitle"), {
        description: wizardI18n("createSuccessDescription", {
          server: result.server,
          location: result.location,
          upstream: result.upstream,
        }),
      });
      setOpen(false);
    } catch (err) {
      toast.error(wizardI18n("createFailTitle"), {
        description: formatError(err),
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button variant={variant} size={size} className="cursor-pointer">
          <Sparkles className="size-3.5" />
          {wizardI18n("trigger")}
        </Button>
      </DialogTrigger>
      <DialogContent className="flex max-h-[90dvh] flex-col gap-0 overflow-hidden p-0 sm:max-w-xl">
        <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-10 text-left sm:px-6">
          <DialogTitle>{wizardI18n("title")}</DialogTitle>
          <DialogDescription>{wizardI18n("description")}</DialogDescription>
        </DialogHeader>

        <form
          onSubmit={handleSubmit}
          className="flex min-h-0 flex-1 flex-col overflow-hidden"
        >
          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto overscroll-contain px-5 py-4 sm:px-6">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="qs-domains">{wizardI18n("domainsLabel")}</Label>
                <Input
                  id="qs-domains"
                  value={domainsInput}
                  onChange={(e) => handleDomainsChange(e.target.value)}
                  placeholder={wizardI18n("domainsPlaceholder")}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="qs-name">{wizardI18n("nameLabel")}</Label>
                <Input
                  id="qs-name"
                  value={name}
                  onChange={(e) => {
                    setNameTouched(true);
                    setName(e.target.value);
                  }}
                  placeholder={wizardI18n("namePlaceholder")}
                  required
                />
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="qs-upstreams">
                  {wizardI18n("upstreamsLabel")}
                </Label>
                <Input
                  id="qs-upstreams"
                  value={upstreamsInput}
                  onChange={(e) => setUpstreamsInput(e.target.value)}
                  placeholder={wizardI18n("upstreamsPlaceholder")}
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="qs-path">{wizardI18n("pathLabel")}</Label>
                <Input
                  id="qs-path"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  placeholder="/"
                />
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>{wizardI18n("tlsModeLabel")}</Label>
                <Select
                  value={tlsMode}
                  onValueChange={(v) =>
                    setTlsMode(v as "none" | "acme" | "custom")
                  }
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">
                      {wizardI18n("tlsModeNone")}
                    </SelectItem>
                    <SelectItem value="acme">
                      {wizardI18n("tlsModeAcme")}
                    </SelectItem>
                    <SelectItem value="custom">
                      {wizardI18n("tlsModeCustom")}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {existingServers.length > 0 ? (
                <div className="space-y-1.5">
                  <Label>{wizardI18n("serverTargetLabel")}</Label>
                  <Select
                    value={serverMode}
                    onValueChange={(v) => {
                      const next = v as "new" | "existing";
                      setServerMode(next);
                      if (next === "existing" && !existingServer) {
                        setExistingServer(existingServers[0]);
                      }
                    }}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="new">
                        {wizardI18n("serverTargetNew")}
                      </SelectItem>
                      <SelectItem value="existing">
                        {wizardI18n("serverTargetExisting")}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              ) : (
                <div className="space-y-1.5">
                  <Label htmlFor="qs-addr">{wizardI18n("addrLabel")}</Label>
                  <Input
                    id="qs-addr"
                    value={addr}
                    onChange={(e) => setAddr(e.target.value)}
                    placeholder={effectiveAddr}
                  />
                </div>
              )}
            </div>

            {existingServers.length > 0 && (
              <div className="space-y-1.5">
                {serverMode === "existing" ? (
                  <>
                    <Label>{wizardI18n("existingServerLabel")}</Label>
                    <Select
                      value={existingServer}
                      onValueChange={setExistingServer}
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {existingServers.map((srv) => (
                          <SelectItem key={srv} value={srv}>
                            {srv} ({config.servers?.[srv]?.addr || ""})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </>
                ) : (
                  <>
                    <Label htmlFor="qs-addr">{wizardI18n("addrLabel")}</Label>
                    <Input
                      id="qs-addr"
                      value={addr}
                      onChange={(e) => setAddr(e.target.value)}
                      placeholder={effectiveAddr}
                    />
                  </>
                )}
              </div>
            )}

            {tlsMode === "custom" && (
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="qs-cert">{wizardI18n("tlsCertLabel")}</Label>
                  <Textarea
                    id="qs-cert"
                    rows={3}
                    value={tlsCert}
                    onChange={(e) => setTlsCert(e.target.value)}
                    placeholder={wizardI18n("tlsCertPlaceholder")}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="qs-key">{wizardI18n("tlsKeyLabel")}</Label>
                  <Textarea
                    id="qs-key"
                    rows={3}
                    value={tlsKey}
                    onChange={(e) => setTlsKey(e.target.value)}
                    placeholder={wizardI18n("tlsKeyPlaceholder")}
                  />
                </div>
              </div>
            )}

            <Separator />

            <div className="space-y-2.5">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">
                    {wizardI18n("reverseProxyHeadersLabel")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {wizardI18n("reverseProxyHeadersHint")}
                  </p>
                </div>
                <Switch
                  className="shrink-0"
                  checked={enableProxyHeaders}
                  onCheckedChange={setEnableProxyHeaders}
                />
              </div>

              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">
                    {wizardI18n("compressionLabel")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {wizardI18n("compressionHint")}
                  </p>
                </div>
                <Switch
                  className="shrink-0"
                  checked={enableCompression}
                  onCheckedChange={setEnableCompression}
                />
              </div>

              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">
                    {wizardI18n("securityHeadersLabel")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {wizardI18n("securityHeadersHint")}
                  </p>
                </div>
                <Switch
                  className="shrink-0"
                  checked={enableSecurityHeaders}
                  onCheckedChange={setEnableSecurityHeaders}
                />
              </div>
            </div>

            <div className="rounded-md border border-border bg-muted/40 px-3 py-2.5">
              <p className="mb-1.5 text-xs font-medium text-muted-foreground">
                {wizardI18n("previewTitle")}
              </p>
              <div className="flex flex-wrap gap-1.5">
                {previewItems.map((item) => (
                  <span
                    key={item}
                    className="machine max-w-full break-all rounded border border-border bg-card px-2 py-0.5 text-[11.5px] text-secondary-foreground"
                  >
                    {item}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <DialogFooter className="shrink-0 border-t border-border bg-surface-subtle px-5 py-3.5 sm:px-6">
            <Button
              type="button"
              variant="outline"
              onClick={() => setOpen(false)}
              disabled={submitting}
            >
              {commonI18n("cancel")}
            </Button>
            <Button type="submit" disabled={submitting}>
              {submitting && <LoaderCircle className="size-4 animate-spin" />}
              {wizardI18n("submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
