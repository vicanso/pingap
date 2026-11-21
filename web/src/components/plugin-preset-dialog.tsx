import React, { useMemo, useState } from "react";
import { Layers, LoaderCircle, ShieldCheck, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useShallow } from "zustand/react/shallow";
import { useI18n } from "@/i18n";
import useConfigState, {
  type ApplyPluginPresetPayload,
  type PresetPluginDef,
} from "@/states/config";
import { formatError } from "@/helpers/util";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";

type BuiltinRecipe = "access_list" | "hardening" | "api_guard" | "static_perf";

interface SavedPresetTemplate {
  name: string;
  description?: string;
  plugin_names: string[];
  plugins: PresetPluginDef[];
  created_at?: number;
}

interface PluginPresetDialogProps {
  defaultLocations?: string[];
  variant?: "default" | "outline";
  size?: "default" | "sm";
  triggerLabel?: string;
}

function splitTokens(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function encodeBasicAuthLine(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    return "";
  }
  if (trimmed.includes(":")) {
    const bytes = new TextEncoder().encode(trimmed);
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary);
  }
  return trimmed;
}

function parseSavedTemplates(
  storages?: Record<
    string,
    {
      category: string;
      value: string;
      remark?: string;
      created_at?: number;
    }
  >,
): SavedPresetTemplate[] {
  if (!storages) {
    return [];
  }
  const templates: SavedPresetTemplate[] = [];
  for (const name of Object.keys(storages).sort()) {
    const item = storages[name];
    if (item?.category !== "plugin_preset") {
      continue;
    }
    try {
      const parsed = JSON.parse(item.value) as {
        description?: string;
        plugin_names?: unknown;
        plugins?: unknown;
      };
      const pluginNames = Array.isArray(parsed.plugin_names)
        ? parsed.plugin_names.filter(
            (v): v is string => typeof v === "string" && v.length > 0,
          )
        : [];
      const plugins = Array.isArray(parsed.plugins)
        ? (parsed.plugins as PresetPluginDef[]).filter(
            (p) =>
              p &&
              typeof p.name === "string" &&
              typeof p.config === "object" &&
              p.config !== null,
          )
        : [];
      templates.push({
        name,
        description: parsed.description || item.remark,
        plugin_names: pluginNames,
        plugins,
        created_at: item.created_at,
      });
    } catch {
      templates.push({
        name,
        description: item.remark,
        plugin_names: [],
        plugins: [],
        created_at: item.created_at,
      });
    }
  }
  return templates;
}

const DEFAULT_PREFIX_BY_RECIPE: Record<BuiltinRecipe, string> = {
  access_list: "acl",
  hardening: "hardening",
  api_guard: "api-guard",
  static_perf: "static-opt",
};

export function PluginPresetDialog({
  defaultLocations = [],
  variant = "outline",
  size = "default",
  triggerLabel,
}: PluginPresetDialogProps) {
  const presetI18n = useI18n("pluginPreset");
  const commonI18n = useI18n();
  const [config, applyPluginPreset, remove] = useConfigState(
    useShallow((state) => [state.data, state.applyPluginPreset, state.remove]),
  );

  const locationNames = useMemo(
    () => Object.keys(config.locations || {}).sort(),
    [config.locations],
  );
  const existingPluginNames = useMemo(
    () => Object.keys(config.plugins || {}).sort(),
    [config.plugins],
  );
  const savedTemplates = useMemo(
    () => parseSavedTemplates(config.storages),
    [config.storages],
  );

  const [open, setOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"builtin" | "saved">("builtin");
  const [submitting, setSubmitting] = useState(false);

  // Built-in recipe state
  const [recipe, setRecipe] = useState<BuiltinRecipe>("access_list");
  const [prefix, setPrefix] = useState("acl");
  const [prefixTouched, setPrefixTouched] = useState(false);
  const [allowIpsInput, setAllowIpsInput] = useState(
    "127.0.0.1, 10.0.0.0/8, 192.168.0.0/16",
  );
  const [basicAuthInput, setBasicAuthInput] = useState("");
  const [enableUriBlock, setEnableUriBlock] = useState(false);
  const [uriBlockDryRun, setUriBlockDryRun] = useState(true);
  const [enableSecurityHeaders, setEnableSecurityHeaders] = useState(true);
  const [rateMax, setRateMax] = useState("120");
  const [corsOrigin, setCorsOrigin] = useState("*");
  const [overwritePlugins, setOverwritePlugins] = useState(false);
  const [saveAsTemplate, setSaveAsTemplate] = useState(false);
  const [templateName, setTemplateName] = useState("");
  const [templateDesc, setTemplateDesc] = useState("");
  const [selectedLocations, setSelectedLocations] =
    useState<string[]>(defaultLocations);
  const [position, setPosition] = useState<"prepend" | "append">("prepend");

  // Saved template tab state
  const [selectedTemplateName, setSelectedTemplateName] = useState("");
  const [mountLocations, setMountLocations] =
    useState<string[]>(defaultLocations);
  const [mountPosition, setMountPosition] = useState<"prepend" | "append">(
    "prepend",
  );
  const [newTplName, setNewTplName] = useState("");
  const [newTplDesc, setNewTplDesc] = useState("");
  const [newTplPlugins, setNewTplPlugins] = useState<string[]>([]);

  const handleOpenChange = (nextOpen: boolean) => {
    setOpen(nextOpen);
    if (nextOpen) {
      setActiveTab("builtin");
      setRecipe("access_list");
      setPrefix("acl");
      setPrefixTouched(false);
      setAllowIpsInput("127.0.0.1, 10.0.0.0/8, 192.168.0.0/16");
      setBasicAuthInput("");
      setEnableUriBlock(false);
      setUriBlockDryRun(true);
      setEnableSecurityHeaders(true);
      setRateMax("120");
      setCorsOrigin("*");
      setOverwritePlugins(false);
      setSaveAsTemplate(false);
      setTemplateName("");
      setTemplateDesc("");
      setSelectedLocations(defaultLocations);
      setPosition("prepend");
      setSelectedTemplateName(savedTemplates[0]?.name || "");
      setMountLocations(defaultLocations);
      setMountPosition("prepend");
      setNewTplName("");
      setNewTplDesc("");
      setNewTplPlugins([]);
    }
  };

  const handleRecipeChange = (next: BuiltinRecipe) => {
    setRecipe(next);
    if (!prefixTouched) {
      setPrefix(DEFAULT_PREFIX_BY_RECIPE[next]);
    }
    if (next === "hardening") {
      setEnableUriBlock(true);
    }
  };

  const effectivePrefix =
    prefix.trim() || templateName.trim() || DEFAULT_PREFIX_BY_RECIPE[recipe];

  const builtPlugins = useMemo((): PresetPluginDef[] => {
    const defs: PresetPluginDef[] = [];
    const pfx = effectivePrefix;
    if (recipe === "access_list") {
      if (enableUriBlock) {
        defs.push({
          name: `${pfx}-uri-block`,
          config: {
            category: "uri_block",
            presets: ["common"],
            status: 404,
            message: "Not Found",
            dry_run: uriBlockDryRun,
          },
        });
      }
      const ips = splitTokens(allowIpsInput);
      if (ips.length > 0) {
        defs.push({
          name: `${pfx}-ip-allow`,
          config: {
            category: "ip_restriction",
            type: "allow",
            ip_list: ips,
          },
        });
      }
      const auths = basicAuthInput
        .split(/\n+/)
        .map(encodeBasicAuthLine)
        .filter((v) => v.length > 0);
      if (auths.length > 0) {
        defs.push({
          name: `${pfx}-basic-auth`,
          config: {
            category: "basic_auth",
            authorizations: auths,
            hide_credentials: true,
          },
        });
      }
      if (enableSecurityHeaders) {
        defs.push({
          name: `${pfx}-security-headers`,
          config: {
            category: "response_headers",
            preset: "security",
            always: true,
          },
        });
      }
      return defs;
    }

    if (recipe === "hardening") {
      defs.push({
        name: `${pfx}-uri-block`,
        config: {
          category: "uri_block",
          presets: ["common"],
          status: 404,
          message: "Not Found",
          dry_run: uriBlockDryRun,
        },
      });
      defs.push({
        name: `${pfx}-rate-limit`,
        config: {
          category: "limit",
          type: "rate",
          mode: "exact",
          tag: "ip",
          max: Math.max(1, Number(rateMax) || 120),
          interval: "1m",
        },
      });
      defs.push({
        name: `${pfx}-security-headers`,
        config: {
          category: "response_headers",
          preset: "security",
          always: true,
        },
      });
      return defs;
    }

    if (recipe === "api_guard") {
      defs.push({
        name: `${pfx}-rate-limit`,
        config: {
          category: "limit",
          type: "rate",
          mode: "exact",
          tag: "ip",
          max: Math.max(1, Number(rateMax) || 120),
          interval: "1m",
        },
      });
      defs.push({
        name: `${pfx}-cors`,
        config: {
          category: "cors",
          allow_origin: corsOrigin.trim() || "*",
          allow_methods: "GET, POST, PUT, PATCH, DELETE, OPTIONS",
          allow_headers: "Content-Type, Authorization",
          max_age: "1h",
        },
      });
      defs.push({
        name: `${pfx}-security-headers`,
        config: {
          category: "response_headers",
          preset: "security",
          always: true,
        },
      });
      return defs;
    }

    defs.push({
      name: `${pfx}-compression`,
      config: {
        category: "compression",
        gzip_level: 6,
        br_level: 6,
        zstd_level: 3,
      },
    });
    defs.push({
      name: `${pfx}-security-headers`,
      config: {
        category: "response_headers",
        preset: "security",
        always: true,
      },
    });
    return defs;
  }, [
    recipe,
    effectivePrefix,
    allowIpsInput,
    basicAuthInput,
    enableUriBlock,
    uriBlockDryRun,
    enableSecurityHeaders,
    rateMax,
    corsOrigin,
  ]);

  const toggleLocation = (
    list: string[],
    setList: React.Dispatch<React.SetStateAction<string[]>>,
    name: string,
    checked: boolean,
  ) => {
    setList(
      checked
        ? list.includes(name)
          ? list
          : [...list, name]
        : list.filter((item) => item !== name),
    );
  };

  const handleApplyBuiltin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!prefix.trim() && (!saveAsTemplate || !templateName.trim())) {
      toast.error(presetI18n("prefixRequired"));
      return;
    }
    if (saveAsTemplate && !templateName.trim()) {
      toast.error(presetI18n("templateNameRequired"));
      return;
    }
    if (builtPlugins.length === 0) {
      toast.error(presetI18n("accessListEmpty"));
      return;
    }
    const payload: ApplyPluginPresetPayload = {
      plugins: builtPlugins,
      locations: selectedLocations,
      position,
      overwrite_plugins: overwritePlugins,
    };
    if (saveAsTemplate) {
      payload.save_preset_name = templateName.trim();
      if (templateDesc.trim()) {
        payload.save_preset_description = templateDesc.trim();
      }
    }
    setSubmitting(true);
    try {
      const res = await applyPluginPreset(payload);
      toast.success(presetI18n("applySuccessTitle"), {
        description: presetI18n("applySuccessDescription", {
          created: res.created_plugins.length,
          reused: res.reused_plugins.length,
          locations: res.updated_locations.length,
        }),
      });
      setOpen(false);
    } catch (err) {
      toast.error(presetI18n("applyFailTitle"), {
        description: formatError(err),
      });
    } finally {
      setSubmitting(false);
    }
  };

  const selectedTemplate =
    savedTemplates.find((item) => item.name === selectedTemplateName) ||
    savedTemplates[0];

  const handleMountSaved = async () => {
    if (!selectedTemplate) {
      return;
    }
    setSubmitting(true);
    try {
      const res = await applyPluginPreset({
        plugins: selectedTemplate.plugins,
        plugin_names: selectedTemplate.plugin_names,
        locations: mountLocations,
        position: mountPosition,
        overwrite_plugins: false,
      });
      toast.success(presetI18n("applySuccessTitle"), {
        description: presetI18n("applySuccessDescription", {
          created: res.created_plugins.length,
          reused: res.reused_plugins.length,
          locations: res.updated_locations.length,
        }),
      });
      setOpen(false);
    } catch (err) {
      toast.error(presetI18n("applyFailTitle"), {
        description: formatError(err),
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteTemplate = async (name: string) => {
    setSubmitting(true);
    try {
      await remove("storage", name);
      toast.success(presetI18n("deleteTemplateSuccess", { name }));
      if (selectedTemplateName === name) {
        setSelectedTemplateName("");
      }
    } catch (err) {
      toast.error(presetI18n("deleteTemplateFail"), {
        description: formatError(err),
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleSaveFromExisting = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTplName.trim()) {
      toast.error(presetI18n("templateNameRequired"));
      return;
    }
    if (newTplPlugins.length === 0) {
      toast.error(presetI18n("templatePluginsRequired"));
      return;
    }
    setSubmitting(true);
    try {
      await applyPluginPreset({
        save_preset_name: newTplName.trim(),
        save_preset_description: newTplDesc.trim() || undefined,
        plugin_names: newTplPlugins,
        locations: [],
      });
      toast.success(
        presetI18n("saveTemplateSuccess", { name: newTplName.trim() }),
      );
      setSelectedTemplateName(newTplName.trim());
      setNewTplName("");
      setNewTplDesc("");
      setNewTplPlugins([]);
    } catch (err) {
      toast.error(presetI18n("applyFailTitle"), {
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
          <ShieldCheck className="size-4" />
          {triggerLabel || presetI18n("trigger")}
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Layers className="size-4 text-primary" />
            {presetI18n("title")}
          </DialogTitle>
          <DialogDescription>{presetI18n("description")}</DialogDescription>
        </DialogHeader>

        <Tabs
          value={activeTab}
          onValueChange={(v) => setActiveTab(v as "builtin" | "saved")}
        >
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="builtin" className="cursor-pointer">
              {presetI18n("tabBuiltin")}
            </TabsTrigger>
            <TabsTrigger value="saved" className="cursor-pointer">
              {presetI18n("tabSaved")} ({savedTemplates.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="builtin" className="mt-4">
            <form onSubmit={handleApplyBuiltin} className="space-y-4">
              <div className="space-y-2">
                <Label>{presetI18n("builtinSelectLabel")}</Label>
                <div className="grid gap-2 sm:grid-cols-2">
                  {(
                    [
                      [
                        "access_list",
                        presetI18n("recipeAccessList"),
                        presetI18n("recipeAccessListDesc"),
                      ],
                      [
                        "hardening",
                        presetI18n("recipeHardening"),
                        presetI18n("recipeHardeningDesc"),
                      ],
                      [
                        "api_guard",
                        presetI18n("recipeApiGuard"),
                        presetI18n("recipeApiGuardDesc"),
                      ],
                      [
                        "static_perf",
                        presetI18n("recipeStaticPerf"),
                        presetI18n("recipeStaticPerfDesc"),
                      ],
                    ] as const
                  ).map(([key, title, desc]) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => handleRecipeChange(key)}
                      className={`cursor-pointer rounded-md border p-2.5 text-left transition-colors ${
                        recipe === key
                          ? "border-primary bg-primary/5"
                          : "border-border hover:bg-accent/50"
                      }`}
                    >
                      <p className="text-sm font-medium">{title}</p>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        {desc}
                      </p>
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="preset-prefix">
                    {presetI18n("prefixLabel")}
                  </Label>
                  <Input
                    id="preset-prefix"
                    value={prefix}
                    onChange={(e) => {
                      setPrefixTouched(true);
                      setPrefix(e.target.value);
                    }}
                    placeholder={presetI18n("prefixPlaceholder")}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>{presetI18n("positionLabel")}</Label>
                  <Select
                    value={position}
                    onValueChange={(v) =>
                      setPosition(v as "prepend" | "append")
                    }
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="prepend">
                        {presetI18n("positionPrepend")}
                      </SelectItem>
                      <SelectItem value="append">
                        {presetI18n("positionAppend")}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {recipe === "access_list" && (
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <Label htmlFor="preset-ips">
                      {presetI18n("allowIpsLabel")}
                    </Label>
                    <Textarea
                      id="preset-ips"
                      rows={2}
                      value={allowIpsInput}
                      onChange={(e) => setAllowIpsInput(e.target.value)}
                      placeholder={presetI18n("allowIpsPlaceholder")}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="preset-auth">
                      {presetI18n("basicAuthLabel")}
                    </Label>
                    <Textarea
                      id="preset-auth"
                      rows={2}
                      value={basicAuthInput}
                      onChange={(e) => setBasicAuthInput(e.target.value)}
                      placeholder={presetI18n("basicAuthPlaceholder")}
                    />
                    <p className="text-xs text-muted-foreground">
                      {presetI18n("basicAuthHint")}
                    </p>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <Label htmlFor="preset-sec-hdr" className="font-normal">
                      {presetI18n("enableSecurityHeadersLabel")}
                    </Label>
                    <Switch
                      id="preset-sec-hdr"
                      checked={enableSecurityHeaders}
                      onCheckedChange={setEnableSecurityHeaders}
                    />
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <Label htmlFor="preset-uri-blk" className="font-normal">
                      {presetI18n("enableUriBlockLabel")}
                    </Label>
                    <Switch
                      id="preset-uri-blk"
                      checked={enableUriBlock}
                      onCheckedChange={setEnableUriBlock}
                    />
                  </div>
                </div>
              )}

              {(recipe === "hardening" || recipe === "api_guard") && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label htmlFor="preset-rate">
                      {presetI18n("rateMaxLabel")}
                    </Label>
                    <Input
                      id="preset-rate"
                      type="number"
                      min={1}
                      value={rateMax}
                      onChange={(e) => setRateMax(e.target.value)}
                    />
                  </div>
                  {recipe === "api_guard" && (
                    <div className="space-y-1.5">
                      <Label htmlFor="preset-cors">
                        {presetI18n("corsOriginLabel")}
                      </Label>
                      <Input
                        id="preset-cors"
                        value={corsOrigin}
                        onChange={(e) => setCorsOrigin(e.target.value)}
                      />
                    </div>
                  )}
                </div>
              )}

              {((recipe === "access_list" && enableUriBlock) ||
                recipe === "hardening") && (
                <div className="flex items-center justify-between gap-3">
                  <Label htmlFor="preset-dry-run" className="font-normal">
                    {presetI18n("uriBlockDryRunLabel")}
                  </Label>
                  <Switch
                    id="preset-dry-run"
                    checked={uriBlockDryRun}
                    onCheckedChange={setUriBlockDryRun}
                  />
                </div>
              )}

              <div className="flex items-center justify-between gap-3">
                <Label htmlFor="preset-overwrite" className="font-normal">
                  {presetI18n("overwritePluginsLabel")}
                </Label>
                <Switch
                  id="preset-overwrite"
                  checked={overwritePlugins}
                  onCheckedChange={setOverwritePlugins}
                />
              </div>

              <Separator />

              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-3">
                  <Label htmlFor="preset-save-tpl" className="font-medium">
                    {presetI18n("saveAsTemplateLabel")}
                  </Label>
                  <Switch
                    id="preset-save-tpl"
                    checked={saveAsTemplate}
                    onCheckedChange={setSaveAsTemplate}
                  />
                </div>
                {saveAsTemplate && (
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label htmlFor="preset-tpl-name">
                        {presetI18n("templateNameLabel")}
                      </Label>
                      <Input
                        id="preset-tpl-name"
                        value={templateName}
                        onChange={(e) => setTemplateName(e.target.value)}
                        placeholder={presetI18n("templateNamePlaceholder")}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="preset-tpl-desc">
                        {presetI18n("templateDescLabel")}
                      </Label>
                      <Input
                        id="preset-tpl-desc"
                        value={templateDesc}
                        onChange={(e) => setTemplateDesc(e.target.value)}
                        placeholder={presetI18n("templateDescPlaceholder")}
                      />
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>{presetI18n("locationsLabel")}</Label>
                  {locationNames.length > 0 && (
                    <div className="flex items-center gap-2 text-xs">
                      <button
                        type="button"
                        className="cursor-pointer text-primary hover:underline"
                        onClick={() => setSelectedLocations(locationNames)}
                      >
                        {presetI18n("selectAll")}
                      </button>
                      <button
                        type="button"
                        className="cursor-pointer text-muted-foreground hover:underline"
                        onClick={() => setSelectedLocations([])}
                      >
                        {presetI18n("clearAll")}
                      </button>
                    </div>
                  )}
                </div>
                {locationNames.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    {presetI18n("noLocations")}
                  </p>
                ) : (
                  <div className="grid max-h-32 grid-cols-2 gap-1.5 overflow-y-auto rounded-md border border-border p-2 sm:grid-cols-3">
                    {locationNames.map((loc) => (
                      <label
                        key={loc}
                        className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-xs hover:bg-accent/50"
                      >
                        <Checkbox
                          checked={selectedLocations.includes(loc)}
                          onCheckedChange={(checked) =>
                            toggleLocation(
                              selectedLocations,
                              setSelectedLocations,
                              loc,
                              checked === true,
                            )
                          }
                        />
                        <span className="machine truncate">{loc}</span>
                      </label>
                    ))}
                  </div>
                )}
              </div>

              <div className="rounded-md border border-border bg-muted/40 px-3 py-2.5">
                <p className="mb-1.5 text-xs font-medium text-muted-foreground">
                  {presetI18n("previewPluginsLabel")}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {builtPlugins.map((item) => (
                    <Badge
                      key={item.name}
                      variant="secondary"
                      className="machine font-normal"
                    >
                      {item.name} ({String(item.config.category)})
                    </Badge>
                  ))}
                </div>
              </div>

              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setOpen(false)}
                  disabled={submitting}
                >
                  {commonI18n("cancel")}
                </Button>
                <Button type="submit" disabled={submitting}>
                  {submitting && (
                    <LoaderCircle className="size-4 animate-spin" />
                  )}
                  {presetI18n("applySubmit")}
                </Button>
              </DialogFooter>
            </form>
          </TabsContent>

          <TabsContent value="saved" className="mt-4 space-y-4">
            {savedTemplates.length === 0 ? (
              <div className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
                {presetI18n("savedEmpty")}
              </div>
            ) : (
              <div className="space-y-3">
                <div className="max-h-48 space-y-2 overflow-y-auto">
                  {savedTemplates.map((tpl) => {
                    const active = selectedTemplate?.name === tpl.name;
                    return (
                      <div
                        key={tpl.name}
                        className={`flex items-start justify-between gap-3 rounded-md border p-2.5 transition-colors ${
                          active
                            ? "border-primary bg-primary/5"
                            : "border-border hover:bg-accent/40"
                        }`}
                      >
                        <button
                          type="button"
                          className="min-w-0 flex-1 cursor-pointer text-left"
                          onClick={() => setSelectedTemplateName(tpl.name)}
                        >
                          <p className="text-sm font-medium">{tpl.name}</p>
                          {tpl.description && (
                            <p className="text-xs text-muted-foreground">
                              {tpl.description}
                            </p>
                          )}
                          <div className="mt-1.5 flex flex-wrap gap-1">
                            {tpl.plugin_names.map((p) => (
                              <Badge
                                key={p}
                                variant="secondary"
                                className="machine text-[11px] font-normal"
                              >
                                {p}
                              </Badge>
                            ))}
                          </div>
                        </button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          disabled={submitting}
                          className="size-7 shrink-0 cursor-pointer text-muted-foreground hover:text-destructive"
                          onClick={() => handleDeleteTemplate(tpl.name)}
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    );
                  })}
                </div>

                {selectedTemplate && (
                  <div className="space-y-3 rounded-md border border-border p-3">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-sm font-medium">
                        {presetI18n("mountTitle")}: {selectedTemplate.name}
                      </p>
                      <Select
                        value={mountPosition}
                        onValueChange={(v) =>
                          setMountPosition(v as "prepend" | "append")
                        }
                      >
                        <SelectTrigger className="w-56">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="prepend">
                            {presetI18n("positionPrepend")}
                          </SelectItem>
                          <SelectItem value="append">
                            {presetI18n("positionAppend")}
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    {locationNames.length > 0 && (
                      <div className="grid max-h-28 grid-cols-2 gap-1.5 overflow-y-auto rounded border border-border p-2 sm:grid-cols-3">
                        {locationNames.map((loc) => (
                          <label
                            key={loc}
                            className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-xs hover:bg-accent/50"
                          >
                            <Checkbox
                              checked={mountLocations.includes(loc)}
                              onCheckedChange={(checked) =>
                                toggleLocation(
                                  mountLocations,
                                  setMountLocations,
                                  loc,
                                  checked === true,
                                )
                              }
                            />
                            <span className="machine truncate">{loc}</span>
                          </label>
                        ))}
                      </div>
                    )}
                    <div className="flex justify-end">
                      <Button
                        type="button"
                        disabled={submitting || mountLocations.length === 0}
                        onClick={handleMountSaved}
                      >
                        {submitting && (
                          <LoaderCircle className="size-4 animate-spin" />
                        )}
                        {presetI18n("mountSubmit")}
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}

            <Separator />

            <form onSubmit={handleSaveFromExisting} className="space-y-3">
              <div>
                <p className="text-sm font-medium">
                  {presetI18n("createFromExistingTitle")}
                </p>
                <p className="text-xs text-muted-foreground">
                  {presetI18n("createFromExistingHint")}
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="existing-tpl-name">
                    {presetI18n("templateNameLabel")}
                  </Label>
                  <Input
                    id="existing-tpl-name"
                    value={newTplName}
                    onChange={(e) => setNewTplName(e.target.value)}
                    placeholder={presetI18n("templateNamePlaceholder")}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="existing-tpl-desc">
                    {presetI18n("templateDescLabel")}
                  </Label>
                  <Input
                    id="existing-tpl-desc"
                    value={newTplDesc}
                    onChange={(e) => setNewTplDesc(e.target.value)}
                    placeholder={presetI18n("templateDescPlaceholder")}
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label>{presetI18n("selectPluginsLabel")}</Label>
                <div className="grid max-h-32 grid-cols-2 gap-1.5 overflow-y-auto rounded-md border border-border p-2 sm:grid-cols-3">
                  {existingPluginNames.map((name) => (
                    <label
                      key={name}
                      className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-xs hover:bg-accent/50"
                    >
                      <Checkbox
                        checked={newTplPlugins.includes(name)}
                        onCheckedChange={(checked) =>
                          toggleLocation(
                            newTplPlugins,
                            setNewTplPlugins,
                            name,
                            checked === true,
                          )
                        }
                      />
                      <span className="machine truncate">{name}</span>
                    </label>
                  ))}
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" variant="secondary" disabled={submitting}>
                  {submitting && (
                    <LoaderCircle className="size-4 animate-spin" />
                  )}
                  {presetI18n("saveTemplateOnlySubmit")}
                </Button>
              </DialogFooter>
            </form>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
