import * as React from "react";
import { Check, Search, X } from "lucide-react";
import { pascal } from "radash";
import { Input } from "@/components/ui/input";
import { ExFormOption, PluginCategory } from "@/constants";
import { useI18n } from "@/i18n";
import { cn } from "@/lib/utils";

type PluginGroupId = "auth" | "guard" | "traffic" | "content" | "system";
type GroupFilter = "all" | PluginGroupId;

const CATEGORY_TO_GROUP: Record<string, PluginGroupId> = {
  [PluginCategory.KEY_AUTH]: "auth",
  [PluginCategory.BASIC_AUTH]: "auth",
  [PluginCategory.COMBINED_AUTH]: "auth",
  [PluginCategory.JWT]: "auth",
  [PluginCategory.HMAC_AUTH]: "auth",
  [PluginCategory.FORWARD_AUTH]: "auth",
  [PluginCategory.OIDC]: "auth",
  [PluginCategory.CSRF]: "auth",
  [PluginCategory.CORS]: "auth",

  [PluginCategory.LIMIT]: "guard",
  [PluginCategory.IP_RESTRICTION]: "guard",
  [PluginCategory.UA_RESTRICTION]: "guard",
  [PluginCategory.JA4_RESTRICTION]: "guard",
  [PluginCategory.REFERER_RESTRICTION]: "guard",
  [PluginCategory.GEO_RESTRICTION]: "guard",
  [PluginCategory.URI_BLOCK]: "guard",
  [PluginCategory.BANDWIDTH_LIMIT]: "guard",

  [PluginCategory.CACHE]: "traffic",
  [PluginCategory.REDIRECT]: "traffic",
  [PluginCategory.TRAFFIC_SPLITTING]: "traffic",
  [PluginCategory.MIRROR]: "traffic",
  [PluginCategory.MAINTENANCE]: "traffic",
  [PluginCategory.ERROR_PAGE]: "traffic",
  [PluginCategory.PING]: "traffic",
  [PluginCategory.MOCK]: "traffic",
  [PluginCategory.HEALTH]: "traffic",

  [PluginCategory.COMPRESSION]: "content",
  [PluginCategory.ACCEPT_ENCODING]: "content",
  [PluginCategory.DIRECTORY]: "content",
  [PluginCategory.SUB_FILTER]: "content",
  [PluginCategory.IMAGE_OPTIM]: "content",
  [PluginCategory.REQUEST_ID]: "content",
  [PluginCategory.REQUEST_HEADERS]: "content",
  [PluginCategory.RESPONSE_HEADERS]: "content",

  [PluginCategory.ADMIN]: "system",
  [PluginCategory.STATS]: "system",
};

const GROUP_DEFS: { id: GroupFilter; labelKey: string }[] = [
  { id: "all", labelKey: "groupAll" },
  { id: "auth", labelKey: "groupAuth" },
  { id: "guard", labelKey: "groupGuard" },
  { id: "traffic", labelKey: "groupTraffic" },
  { id: "content", labelKey: "groupContent" },
  { id: "system", labelKey: "groupSystem" },
];

function resolveGroup(slug: string): PluginGroupId {
  return CATEGORY_TO_GROUP[slug] || "system";
}

function getOptionValue(opt: ExFormOption): string {
  if (typeof opt.value === "string") {
    return opt.value;
  }
  return opt.option;
}

export interface PluginCategoryPickerProps {
  options: ExFormOption[];
  value: string;
  disabled?: boolean;
  onChange: (value: string) => void;
}

export function PluginCategoryPicker({
  options,
  value,
  disabled,
  onChange,
}: PluginCategoryPickerProps) {
  const pluginI18n = useI18n("plugin");
  const [query, setQuery] = React.useState("");
  const [group, setGroup] = React.useState<GroupFilter>("all");

  const normalized = React.useMemo(() => {
    return options.map((opt) => {
      const slug = getOptionValue(opt);
      const displayName =
        opt.label && opt.label !== slug ? opt.label : pascal(slug);
      const itemGroup = resolveGroup(slug);
      return {
        slug,
        displayName,
        group: itemGroup,
      };
    });
  }, [options]);

  const groupCounts = React.useMemo(() => {
    const counts: Record<GroupFilter, number> = {
      all: normalized.length,
      auth: 0,
      guard: 0,
      traffic: 0,
      content: 0,
      system: 0,
    };
    for (const item of normalized) {
      counts[item.group] += 1;
    }
    return counts;
  }, [normalized]);

  const filtered = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    return normalized.filter((item) => {
      if (group !== "all" && item.group !== group) {
        return false;
      }
      if (!q) {
        return true;
      }
      return (
        item.slug.toLowerCase().includes(q) ||
        item.displayName.toLowerCase().includes(q)
      );
    });
  }, [normalized, group, query]);

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative w-full sm:max-w-sm">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="text"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            enterKeyHint="search"
            value={query}
            disabled={disabled}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={pluginI18n("categorySearchPlaceholder")}
            className="h-8 pl-8 pr-7 text-base sm:text-[13px]"
          />
          {query && (
            <button
              type="button"
              disabled={disabled}
              onClick={() => setQuery("")}
              aria-label="Clear filter"
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
            >
              <X className="size-3.5" />
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1">
          {GROUP_DEFS.map((def) => {
            const count = groupCounts[def.id];
            if (def.id !== "all" && count === 0) {
              return null;
            }
            const active = group === def.id;
            return (
              <button
                key={def.id}
                type="button"
                disabled={disabled}
                onClick={() => setGroup(def.id)}
                className={cn(
                  "inline-flex cursor-pointer items-center gap-1.5 rounded-md border px-2 py-1 text-[12px] transition-colors",
                  active
                    ? "border-foreground/30 bg-foreground/8 font-medium text-foreground"
                    : "border-border bg-card text-muted-foreground hover:border-border/80 hover:text-foreground",
                  disabled && "pointer-events-none opacity-50",
                )}
              >
                <span>{pluginI18n(def.labelKey)}</span>
                <span className="figure text-[11px] opacity-70">{count}</span>
              </button>
            );
          })}
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="rounded-md border border-dashed border-border bg-card/50 px-4 py-6 text-center text-[13px] text-muted-foreground">
          {pluginI18n("categoryEmpty")}
        </div>
      ) : (
        <div className="grid max-h-72 gap-2 overflow-y-auto overscroll-contain p-0.5 pr-1 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map((item) => {
            const selected = item.slug === value;
            return (
              <button
                key={item.slug}
                type="button"
                disabled={disabled}
                onClick={() => onChange(item.slug)}
                aria-pressed={selected}
                className={cn(
                  "group flex cursor-pointer items-center justify-between gap-2 rounded-md border px-3 py-2 text-left transition-colors",
                  selected
                    ? "border-primary bg-primary/[0.06] ring-1 ring-primary/20"
                    : "border-border bg-card hover:border-foreground/25 hover:bg-accent/40",
                  disabled && "pointer-events-none opacity-60",
                )}
              >
                <span className="min-w-0">
                  <span
                    className={cn(
                      "block truncate text-[13px] font-medium",
                      selected ? "text-foreground" : "text-foreground/90",
                    )}
                  >
                    {item.displayName}
                  </span>
                  <span className="machine block truncate text-[11.5px] text-muted-foreground">
                    {item.slug}
                  </span>
                </span>
                <span
                  className={cn(
                    "flex size-4 shrink-0 items-center justify-center rounded-full border transition-colors",
                    selected
                      ? "border-primary bg-primary text-primary-foreground"
                      : "border-border bg-background text-transparent group-hover:border-muted-foreground/40",
                  )}
                >
                  <Check className="size-2.5 stroke-[2.5]" />
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
