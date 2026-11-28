import React from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useShallow } from "zustand/react/shallow";
import {
  Activity,
  AppWindow,
  Container,
  FileCode2,
  LayoutDashboard,
  Network,
  PlugZap,
  Plus,
  Server,
  ShieldCheck,
  TrendingUpDown,
  Webhook,
} from "lucide-react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { cn } from "@/lib/utils";
import useConfigState from "@/states/config";
import useBasicState from "@/states/basic";
import { useI18n } from "@/i18n";
import {
  BASIC,
  CERTIFICATES,
  CONFIG,
  DIAGNOSTICS,
  HOME,
  LOCATIONS,
  PLUGINS,
  SERVERS,
  STORAGES,
  STREAMS,
  UPSTREAMS,
} from "@/routers";

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const { t } = useTranslation();
  const cmdI18n = useI18n("commandPalette");
  const navI18n = useI18n("nav");
  const serverI18n = useI18n("server");
  const streamI18n = useI18n("stream");
  const locationI18n = useI18n("location");
  const upstreamI18n = useI18n("upstream");
  const pluginI18n = useI18n("plugin");
  const certificateI18n = useI18n("certificate");
  const storageI18n = useI18n("storage");
  const navigate = useNavigate();

  const [config] = useConfigState(useShallow((state) => [state.data]));
  const basicInfo = useBasicState((state) => state.data);

  React.useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onOpenChange]);

  const go = (to: string) => {
    onOpenChange(false);
    navigate(to);
  };

  const pages = [
    {
      label: navI18n("home"),
      to: HOME,
      icon: LayoutDashboard,
      keywords: ["dashboard", "overview", "home"],
    },
    {
      label: navI18n("server"),
      to: SERVERS,
      icon: Server,
      keywords: ["servers", "listen", "ports"],
    },
    {
      label: navI18n("stream"),
      to: STREAMS,
      icon: Network,
      keywords: ["streams", "tcp", "sni", "l4", "passthrough"],
    },
    {
      label: navI18n("location"),
      to: LOCATIONS,
      icon: Webhook,
      keywords: ["locations", "routes", "proxy"],
    },
    {
      label: navI18n("upstream"),
      to: UPSTREAMS,
      icon: TrendingUpDown,
      keywords: ["upstreams", "backends", "pools"],
    },
    {
      label: navI18n("plugin"),
      to: PLUGINS,
      icon: PlugZap,
      keywords: ["plugins", "middleware"],
    },
    {
      label: navI18n("certificate"),
      to: CERTIFICATES,
      icon: ShieldCheck,
      keywords: ["certificates", "tls", "ssl", "acme"],
    },
    {
      label: navI18n("basic"),
      to: BASIC,
      icon: AppWindow,
      keywords: ["basic", "threads", "logs"],
    },
    {
      label: navI18n("storage"),
      to: STORAGES,
      icon: Container,
      keywords: ["storages", "secrets"],
    },
    {
      label: t("tomlTitle"),
      to: CONFIG,
      icon: FileCode2,
      keywords: ["config", "toml", "hcl", "import"],
    },
    {
      label: navI18n("diagnostics"),
      to: DIAGNOSTICS,
      icon: Activity,
      keywords: [
        "diagnostics",
        "debug",
        "route",
        "simulator",
        "events",
        "5xx",
        "dry_run",
      ],
    },
  ];

  const entities: {
    id: string;
    name: string;
    category: string;
    detail?: string;
    tone?: "warn" | "down";
    to: string;
    icon: React.ComponentType<{ className?: string }>;
  }[] = [];

  Object.entries(config.servers || {})
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([name, server]) => {
      entities.push({
        id: `server:${name}`,
        name,
        category: navI18n("server"),
        detail: server.addr,
        to: `${SERVERS}?name=${encodeURIComponent(name)}`,
        icon: Server,
      });
    });

  Object.entries(config.streams || {})
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([name, stream]) => {
      entities.push({
        id: `stream:${name}`,
        name,
        category: navI18n("stream"),
        detail: stream.addr,
        to: `${STREAMS}?name=${encodeURIComponent(name)}`,
        icon: Network,
      });
    });

  Object.entries(config.locations || {})
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([name, loc]) => {
      entities.push({
        id: `location:${name}`,
        name,
        category: navI18n("location"),
        detail: [loc.host, loc.path || "/"].filter(Boolean).join(" "),
        to: `${LOCATIONS}?name=${encodeURIComponent(name)}`,
        icon: Webhook,
      });
    });

  Object.entries(config.upstreams || {})
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([name, upstream]) => {
      const status = basicInfo.upstream_healthy_status?.[name];
      const tone = status
        ? status.healthy === 0
          ? "down"
          : status.healthy < status.total
            ? "warn"
            : undefined
        : undefined;
      entities.push({
        id: `upstream:${name}`,
        name,
        category: navI18n("upstream"),
        detail: (upstream.addrs || []).map((a) => a.split(" ")[0]).join(", "),
        tone,
        to: `${UPSTREAMS}?name=${encodeURIComponent(name)}`,
        icon: TrendingUpDown,
      });
    });

  Object.entries(config.plugins || {})
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([name, plugin]) => {
      entities.push({
        id: `plugin:${name}`,
        name,
        category: navI18n("plugin"),
        detail: (plugin.category as string) || "",
        to: `${PLUGINS}?name=${encodeURIComponent(name)}`,
        icon: PlugZap,
      });
    });

  Object.entries(config.certificates || {})
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([name, cert]) => {
      entities.push({
        id: `certificate:${name}`,
        name,
        category: navI18n("certificate"),
        detail: cert.domains,
        to: `${CERTIFICATES}?name=${encodeURIComponent(name)}`,
        icon: ShieldCheck,
      });
    });

  Object.entries(config.storages || {})
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([name, storage]) => {
      entities.push({
        id: `storage:${name}`,
        name,
        category: navI18n("storage"),
        detail: storage.category,
        to: `${STORAGES}?name=${encodeURIComponent(name)}`,
        icon: Container,
      });
    });

  const creates = basicInfo.read_only
    ? []
    : [
        {
          label: serverI18n("add"),
          to: `${SERVERS}?name=*`,
          keywords: ["new", "add", "create", "server"],
        },
        {
          label: streamI18n("add"),
          to: `${STREAMS}?name=*`,
          keywords: ["new", "add", "create", "stream", "tcp", "sni"],
        },
        {
          label: locationI18n("add"),
          to: `${LOCATIONS}?name=*`,
          keywords: ["new", "add", "create", "location"],
        },
        {
          label: upstreamI18n("add"),
          to: `${UPSTREAMS}?name=*`,
          keywords: ["new", "add", "create", "upstream"],
        },
        {
          label: pluginI18n("add"),
          to: `${PLUGINS}?name=*`,
          keywords: ["new", "add", "create", "plugin"],
        },
        {
          label: certificateI18n("add"),
          to: `${CERTIFICATES}?name=*`,
          keywords: ["new", "add", "create", "certificate"],
        },
        {
          label: storageI18n("add"),
          to: `${STORAGES}?name=*`,
          keywords: ["new", "add", "create", "storage"],
        },
      ];

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("header.search")}
      description={cmdI18n("placeholder")}
    >
      <CommandInput
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        enterKeyHint="search"
        placeholder={cmdI18n("placeholder")}
      />
      <CommandList className="max-h-[380px]">
        <CommandEmpty>{cmdI18n("empty")}</CommandEmpty>
        <CommandGroup heading={cmdI18n("pagesGroup")}>
          {pages.map((page) => {
            const Icon = page.icon;
            return (
              <CommandItem
                key={page.to}
                value={`page ${page.label}`}
                keywords={page.keywords}
                className="cursor-pointer"
                onSelect={() => go(page.to)}
              >
                <Icon className="size-4 shrink-0" />
                <span>{page.label}</span>
              </CommandItem>
            );
          })}
        </CommandGroup>

        {entities.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading={cmdI18n("entitiesGroup")}>
              {entities.map((entity) => {
                const Icon = entity.icon;
                return (
                  <CommandItem
                    key={entity.id}
                    value={`${entity.category} ${entity.name} ${entity.detail || ""}`}
                    keywords={[
                      entity.category,
                      entity.name,
                      entity.detail || "",
                    ]}
                    className="cursor-pointer"
                    onSelect={() => go(entity.to)}
                  >
                    <Icon className="size-4 shrink-0" />
                    <span
                      className="min-w-0 flex-1 truncate font-medium"
                      title={entity.name}
                    >
                      {entity.name}
                    </span>
                    {entity.tone && (
                      <span
                        className={cn(
                          "size-1.5 shrink-0 rounded-full",
                          entity.tone === "down" ? "bg-down" : "bg-warn",
                        )}
                      />
                    )}
                    {entity.detail && (
                      <span
                        className="machine ml-2 max-w-[42%] shrink-0 truncate text-xs text-muted-foreground"
                        title={entity.detail}
                      >
                        {entity.detail}
                      </span>
                    )}
                  </CommandItem>
                );
              })}
            </CommandGroup>
          </>
        )}

        {creates.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading={cmdI18n("createGroup")}>
              {creates.map((item) => (
                <CommandItem
                  key={item.to}
                  value={`create ${item.label}`}
                  keywords={item.keywords}
                  className="cursor-pointer"
                  onSelect={() => go(item.to)}
                >
                  <Plus className="size-4 shrink-0" />
                  <span>{item.label}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  );
}
