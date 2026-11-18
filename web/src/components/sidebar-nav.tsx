import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";
import {
  AppWindow,
  Server,
  Webhook,
  TrendingUpDown,
  PlugZap,
  ShieldCheck,
  Container,
  Search,
  LayoutDashboard,
  X,
} from "lucide-react";
import {
  HOME,
  BASIC,
  SERVERS,
  LOCATIONS,
  UPSTREAMS,
  PLUGINS,
  CERTIFICATES,
  STORAGES,
} from "@/routers.tsx";
import useConfigState from "@/states/config";
import useBasicState from "@/states/basic";
import { useI18n } from "@/i18n";
import { daysUntil } from "@/helpers/util";
import { Input } from "@/components/ui/input";
import React from "react";
import { useShallow } from "zustand/react/shallow";
import { useLocation } from "react-router-dom";
import {
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubItem,
  SidebarMenuSubButton,
  useSidebar,
} from "@/components/ui/sidebar";
import {
  Popover,
  PopoverAnchor,
  PopoverContent,
} from "@/components/ui/popover";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

type NavGroup = "path" | "policy" | "system";

type BadgeTone = "neutral" | "warn" | "down";

interface NavLink {
  title: string;
  label?: string;
  badgeTone?: BadgeTone;
  badgeTitle?: string;
  icon?: LucideIcon;
  path: string;
  variant: "default" | "ghost";
  group: NavGroup;
  children?: NavLink[];
}

function badgeToneClasses(tone?: BadgeTone) {
  switch (tone) {
    case "down":
      return "border border-down/30 bg-down/15 text-down";
    case "warn":
      return "border border-warn/30 bg-warn/15 text-warn";
    default:
      return "bg-sidebar-accent text-muted-foreground";
  }
}

/** Highlight the first case-insensitive match of `keyword` inside `text`. */
function HighlightMatch({ text, keyword }: { text: string; keyword: string }) {
  if (!keyword) {
    return <>{text}</>;
  }
  const lower = text.toLowerCase();
  const idx = lower.indexOf(keyword);
  if (idx < 0) {
    return <>{text}</>;
  }
  return (
    <>
      {text.slice(0, idx)}
      <mark className="rounded-sm bg-primary/20 px-0.5 text-inherit">
        {text.slice(idx, idx + keyword.length)}
      </mark>
      {text.slice(idx + keyword.length)}
    </>
  );
}

/** Square icon control for the collapsed rail (centered by SidebarMenu items-center). */
const CollapsedIconLink = React.forwardRef<
  HTMLAnchorElement,
  {
    to: string;
    title: string;
    isActive: boolean;
    children: React.ReactNode;
    className?: string;
    onMouseEnter?: React.MouseEventHandler;
    onMouseLeave?: React.MouseEventHandler;
    onKeyDown?: React.KeyboardEventHandler;
  }
>(function CollapsedIconLink(
  {
    to,
    title,
    isActive,
    children,
    className,
    onMouseEnter,
    onMouseLeave,
    onKeyDown,
  },
  ref,
) {
  return (
    <Link
      ref={ref}
      to={to}
      title={title}
      aria-label={title}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      onKeyDown={onKeyDown}
      className={cn(
        // Fixed square only — no w-full. Parent ul uses items-center when collapsed.
        "relative flex size-8 shrink-0 items-center justify-center rounded-md outline-none",
        "text-sidebar-foreground transition-colors",
        "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
        "focus-visible:ring-2 focus-visible:ring-sidebar-ring",
        isActive &&
          "bg-sidebar-accent font-medium text-sidebar-accent-foreground before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-[3px] before:rounded-full before:bg-primary",
        className,
      )}
    >
      {children}
    </Link>
  );
});

/** Flyout for a nav category when the sidebar is icon-collapsed. */
function CollapsedNavFlyout({
  item,
  isActive,
  currentName,
}: {
  item: NavLink;
  isActive: boolean;
  currentName: string | null;
}) {
  const [open, setOpen] = React.useState(false);
  const closeTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const contentRef = React.useRef<HTMLDivElement>(null);
  const anchorRef = React.useRef<HTMLAnchorElement>(null);
  const openedByKey = React.useRef(false);
  const Icon = item.icon;

  const clearClose = () => {
    if (closeTimer.current) {
      clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  };

  const openNow = () => {
    clearClose();
    setOpen(true);
  };

  const closeLater = () => {
    clearClose();
    closeTimer.current = setTimeout(() => setOpen(false), 120);
  };

  React.useEffect(() => {
    return () => clearClose();
  }, []);

  // Submenu keys, the same shape as a menubar: the rail icon is reachable by
  // Tab and Enter still follows it to the category list, ArrowRight/ArrowDown
  // opens the flyout and moves focus into it, Escape closes and comes back.
  //
  // Opening on plain focus was tried and dropped: two adjacent flyouts are two
  // Radix layers, and tabbing between them left both dismissed.
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowDown") {
      return;
    }
    e.preventDefault();
    openedByKey.current = true;
    openNow();
    // The content mounts on open, so focus it on the next frame.
    requestAnimationFrame(() => {
      contentRef.current?.querySelector<HTMLElement>("a")?.focus();
    });
  };

  const hasChildren = (item.children?.length ?? 0) > 0;

  // No children: tooltip with the category name.
  if (!hasChildren) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <CollapsedIconLink
            to={item.path}
            title={item.title}
            isActive={isActive}
          >
            {Icon && <Icon className="size-4 shrink-0" />}
            {(item.badgeTone === "down" || item.badgeTone === "warn") && (
              <span
                className={cn(
                  "absolute top-1 right-1 size-1.5 rounded-full",
                  item.badgeTone === "down" ? "bg-down" : "bg-warn",
                )}
              />
            )}
          </CollapsedIconLink>
        </TooltipTrigger>
        <TooltipContent side="right" align="center" sideOffset={8}>
          {item.title}
        </TooltipContent>
      </Tooltip>
    );
  }

  // PopoverAnchor on the link itself — no extra inline-flex wrapper to break centering.
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverAnchor asChild>
        <CollapsedIconLink
          ref={anchorRef}
          to={item.path}
          title={item.title}
          isActive={isActive}
          onMouseEnter={openNow}
          onMouseLeave={closeLater}
          onKeyDown={handleKeyDown}
        >
          {Icon && <Icon className="size-4 shrink-0" />}
          {(item.badgeTone === "down" || item.badgeTone === "warn") && (
            <span
              className={cn(
                "absolute top-1 right-1 size-1.5 rounded-full",
                item.badgeTone === "down" ? "bg-down" : "bg-warn",
              )}
            />
          )}
        </CollapsedIconLink>
      </PopoverAnchor>
      <PopoverContent
        ref={contentRef}
        side="right"
        align="start"
        sideOffset={10}
        className="w-52 p-1.5"
        onOpenAutoFocus={(e) => e.preventDefault()}
        onCloseAutoFocus={(e) => {
          // Radix returns focus to its trigger, and this popover has only an
          // anchor. Put it back on the rail icon, but only when a key opened
          // the flyout — hovering away must not steal focus.
          e.preventDefault();
          if (openedByKey.current) {
            openedByKey.current = false;
            anchorRef.current?.focus();
          }
        }}
        onMouseEnter={openNow}
        onMouseLeave={closeLater}
        onFocusCapture={clearClose}
        onBlurCapture={closeLater}
      >
        <Link
          to={item.path}
          className={cn(
            "mb-1 flex items-center gap-2 rounded-md px-2 py-1.5 text-sm font-medium outline-none",
            "hover:bg-accent hover:text-accent-foreground",
            isActive && "bg-accent text-accent-foreground",
          )}
          onClick={() => setOpen(false)}
        >
          {Icon && <Icon className="size-4 shrink-0" />}
          <span className="truncate">{item.title}</span>
          {item.label && (
            <span
              className={cn(
                "figure ml-auto inline-flex h-5 min-w-5 shrink-0 items-center justify-center rounded-full px-1.5 text-[11px] font-medium",
                badgeToneClasses(item.badgeTone),
              )}
              title={item.badgeTitle}
            >
              {item.label}
            </span>
          )}
        </Link>
        <div className="max-h-72 space-y-0.5 overflow-y-auto border-t border-border pt-1">
          {item.children!.map((child) => {
            const selected = currentName === child.title;
            return (
              <Link
                key={child.title}
                to={child.path}
                className={cn(
                  "block truncate rounded-md px-2 py-1.5 text-sm outline-none",
                  "hover:bg-accent hover:text-accent-foreground",
                  selected && "bg-accent font-medium text-accent-foreground",
                )}
                onClick={() => setOpen(false)}
              >
                {child.title}
              </Link>
            );
          })}
        </div>
      </PopoverContent>
    </Popover>
  );
}

export function MainSidebar({
  className,
  sidebarOpen,
  onOpenCommandPalette,
}: React.HTMLAttributes<HTMLDivElement> & {
  sidebarOpen: boolean;
  onOpenCommandPalette?: () => void;
}) {
  const navI18n = useI18n("nav");
  // The mobile sheet is always full width, so the icon-rail rendering driven by
  // the desktop collapse toggle would strand tiny icon squares at its left edge.
  const { isMobile, setOpenMobile } = useSidebar();
  const expanded = sidebarOpen || isMobile;
  const closeMobileNav = () => {
    if (isMobile) {
      setOpenMobile(false);
    }
  };
  const [keyword, setKeyword] = React.useState("");
  // The search box only renders while expanded. Applying a leftover keyword on
  // the collapsed rail silently empties every flyout with no visible box to
  // clear it, so ignore it there — the input is controlled, so collapsing and
  // expanding again brings both the text and the filter back together.
  // Normalise where it is used, not on the way in, so the box shows exactly
  // what was typed instead of eating case and trailing spaces mid-word.
  const activeKeyword = expanded ? keyword.trim().toLowerCase() : "";
  const [config, initialized, certificateInfos] = useConfigState(
    useShallow((state) => [
      state.data,
      state.initialized,
      state.certificateInfos,
    ]),
  );
  const basicInfo = useBasicState((state) => state.data);

  // Read straight from the router instead of mirroring it into state via an
  // effect: it is derived, so the copy only added a render behind the URL.
  const location = useLocation();
  const pathname = location.pathname;

  const getVariant = (path: string) => {
    if (path === `${pathname}${location.search}`) {
      return "default";
    }
    return "ghost";
  };

  const servers = Object.keys(config.servers || {}).sort();
  const locations = Object.keys(config.locations || {}).sort();
  const upstreams = Object.keys(config.upstreams || {}).sort();
  const plugins = Object.keys(config.plugins || {}).sort();
  const certificates = Object.keys(config.certificates || {}).sort();
  const storages = Object.keys(config.storages || {}).sort();

  const unhealthyStatuses = Object.values(
    basicInfo.upstream_healthy_status || {},
  ).filter((status) => status.healthy < status.total);
  const upstreamsDown = unhealthyStatuses.length;
  const upstreamAllDown = unhealthyStatuses.some(
    (status) => status.healthy === 0,
  );

  let certAlertCount = 0;
  let certHasCritical = false;
  certificates.forEach((name) => {
    const info = certificateInfos[name];
    if (!info) {
      return;
    }
    const days = daysUntil(info.not_after);
    if (days <= 30) {
      certAlertCount += 1;
      if (days <= 7) {
        certHasCritical = true;
      }
    }
  });

  const badgeMeta = (
    category:
      "server" | "location" | "upstream" | "plugin" | "certificate" | "storage",
    count: number,
  ): { label: string; badgeTone?: BadgeTone; badgeTitle?: string } => {
    if (!initialized || count === 0) {
      return { label: "" };
    }
    if (category === "upstream" && upstreamsDown > 0) {
      return {
        label: count.toString(),
        badgeTone: upstreamAllDown ? "down" : "warn",
        badgeTitle: navI18n("upstreamsDown", { count: upstreamsDown }),
      };
    }
    if (category === "certificate" && certAlertCount > 0) {
      return {
        label: count.toString(),
        badgeTone: certHasCritical ? "down" : "warn",
        badgeTitle: navI18n("certsAlert", { count: certAlertCount }),
      };
    }
    return {
      label: count.toString(),
      badgeTone: "neutral",
    };
  };

  const serverBadge = badgeMeta("server", servers.length);
  const locationBadge = badgeMeta("location", locations.length);
  const upstreamBadge = badgeMeta("upstream", upstreams.length);
  const pluginBadge = badgeMeta("plugin", plugins.length);
  const certBadge = badgeMeta("certificate", certificates.length);
  const storageBadge = badgeMeta("storage", storages.length);

  // Expanded: only expand children for the active route (or when searching).
  // Collapsed: always build full lists so hover flyouts have content.
  const generateChildren = (baseUrl: string, items: string[]) => {
    if (expanded && !activeKeyword && !pathname.startsWith(baseUrl)) {
      return [] as NavLink[];
    }
    const arr: NavLink[] = [];
    items.forEach((item) => {
      if (activeKeyword && !item.toLowerCase().includes(activeKeyword)) {
        return;
      }
      const path = `${baseUrl}?name=${item}`;
      arr.push({
        title: item,
        variant: getVariant(path),
        label: "",
        path,
      } as NavLink);
    });
    return arr;
  };

  // Dashboard is reached via the Pingap brand in the sidebar header, not a nav item.
  //
  // Order is the request's own order — a request meets a server, then a
  // location, then an upstream — so the nav teaches the pipeline instead of
  // listing seven unrelated config sections alphabetically.
  const items: NavLink[] = [
    {
      title: navI18n("server"),
      icon: Server,
      variant: getVariant(SERVERS),
      ...serverBadge,
      path: SERVERS,
      group: "path",
      children: generateChildren(SERVERS, servers),
    },
    {
      title: navI18n("location"),
      icon: Webhook,
      variant: getVariant(LOCATIONS),
      ...locationBadge,
      path: LOCATIONS,
      group: "path",
      children: generateChildren(LOCATIONS, locations),
    },
    {
      title: navI18n("upstream"),
      icon: TrendingUpDown,
      variant: getVariant(UPSTREAMS),
      ...upstreamBadge,
      path: UPSTREAMS,
      group: "path",
      children: generateChildren(UPSTREAMS, upstreams),
    },
    {
      title: navI18n("plugin"),
      icon: PlugZap,
      variant: getVariant(PLUGINS),
      ...pluginBadge,
      path: PLUGINS,
      group: "policy",
      children: generateChildren(PLUGINS, plugins),
    },
    {
      title: navI18n("certificate"),
      icon: ShieldCheck,
      variant: getVariant(CERTIFICATES),
      ...certBadge,
      path: CERTIFICATES,
      group: "policy",
      children: generateChildren(CERTIFICATES, certificates),
    },
    {
      title: navI18n("basic"),
      icon: AppWindow,
      variant: getVariant(BASIC),
      path: BASIC,
      group: "system",
    },
    {
      title: navI18n("storage"),
      icon: Container,
      variant: getVariant(STORAGES),
      ...storageBadge,
      path: STORAGES,
      group: "system",
      children: generateChildren(STORAGES, storages),
    },
  ];

  const groups: { key: NavGroup; label: string }[] = [
    { key: "path", label: navI18n("groupPath") },
    { key: "policy", label: navI18n("groupPolicy") },
    { key: "system", label: navI18n("groupSystem") },
  ];

  const urlParams = new URLSearchParams(location.search);
  const currentName = urlParams.get("name");
  const matchCount = items.reduce(
    (total, item) => total + (item.children?.length ?? 0),
    0,
  );

  const renderMenuSub = (subItems: NavLink[] | undefined) => {
    if (!subItems || subItems.length == 0) {
      return <></>;
    }

    return (
      <SidebarMenuSub>
        {subItems.map((item) => {
          const isSelected = currentName === item.title;
          return (
            <SidebarMenuSubItem key={item.title}>
              <SidebarMenuSubButton isActive={isSelected} asChild>
                <Link
                  to={item.path}
                  className="w-full"
                  onClick={closeMobileNav}
                  aria-current={isSelected ? "page" : undefined}
                >
                  <span className="truncate">
                    <HighlightMatch text={item.title} keyword={activeKeyword} />
                  </span>
                </Link>
              </SidebarMenuSubButton>
            </SidebarMenuSubItem>
          );
        })}
      </SidebarMenuSub>
    );
  };

  return (
    <SidebarContent className={className}>
      <SidebarGroup>
        {expanded ? (
          <div className="relative m-2 mt-0">
            <Input
              type="text"
              placeholder={navI18n("searchPlaceholder")}
              className="h-9 border-border bg-card/60 pr-12 pl-8 focus-visible:bg-card"
              value={keyword}
              onChange={(e) => {
                setKeyword(e.target.value);
              }}
            />
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 select-none text-muted-foreground opacity-70" />
            {keyword ? (
              <button
                type="button"
                aria-label={navI18n("searchPlaceholder")}
                className="absolute right-2 top-1/2 -translate-y-1/2 cursor-pointer rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                onClick={() => setKeyword("")}
              >
                <X className="size-3.5" />
              </button>
            ) : (
              onOpenCommandPalette && (
                <button
                  type="button"
                  onClick={onOpenCommandPalette}
                  className="machine absolute right-2 top-1/2 -translate-y-1/2 cursor-pointer rounded border border-border bg-background/80 px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground hover:text-foreground"
                >
                  ⌘K
                </button>
              )
            )}
          </div>
        ) : (
          onOpenCommandPalette && (
            <div className="mb-1 flex justify-center">
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    aria-label={navI18n("searchPlaceholder")}
                    onClick={onOpenCommandPalette}
                    className="flex size-8 shrink-0 cursor-pointer items-center justify-center rounded-md text-sidebar-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2 focus-visible:ring-sidebar-ring outline-none"
                  >
                    <Search className="size-4" />
                  </button>
                </TooltipTrigger>
                <TooltipContent side="right" align="center" sideOffset={8}>
                  {navI18n("searchPlaceholder")} (⌘K)
                </TooltipContent>
              </Tooltip>
            </div>
          )
        )}
        {!activeKeyword && (
          <SidebarGroupContent className="mb-2">
            <SidebarMenu>
              <SidebarMenuItem>
                {expanded ? (
                  <SidebarMenuButton
                    className="h-9 gap-2.5 px-3"
                    isActive={pathname === HOME}
                    asChild
                  >
                    <Link
                      to={HOME}
                      onClick={closeMobileNav}
                      aria-current={pathname === HOME ? "page" : undefined}
                    >
                      <LayoutDashboard />
                      <span>{navI18n("home")}</span>
                    </Link>
                  </SidebarMenuButton>
                ) : (
                  <CollapsedNavFlyout
                    item={{
                      title: navI18n("home"),
                      icon: LayoutDashboard,
                      path: HOME,
                      variant: pathname === HOME ? "default" : "ghost",
                      group: "path",
                    }}
                    isActive={pathname === HOME}
                    currentName={currentName}
                  />
                )}
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        )}
        {expanded && activeKeyword && matchCount === 0 && (
          <p className="mx-2 mb-2 text-xs text-muted-foreground">
            {navI18n("searchEmpty")}
          </p>
        )}
        {groups.map((group, groupIdx) => {
          // While searching, drop parents with no matching children (and bare
          // leaf items whose own title does not match) so the list stays tight.
          const groupItems = items.filter((item) => {
            if (item.group !== group.key) {
              return false;
            }
            if (!activeKeyword) {
              return true;
            }
            const titleHit = item.title.toLowerCase().includes(activeKeyword);
            const childHit = (item.children?.length ?? 0) > 0;
            return titleHit || childHit;
          });
          if (groupItems.length === 0) {
            return null;
          }
          return (
            <SidebarGroupContent key={group.key}>
              {expanded ? (
                <p
                  className={cn(
                    "px-3 pb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground/85",
                    groupIdx > 0 && "pt-4",
                  )}
                >
                  {group.label}
                </p>
              ) : (
                groupIdx > 0 && (
                  <div className="mx-auto my-2 h-px w-5 bg-sidebar-border" />
                )
              )}
              <SidebarMenu>
                {groupItems.map((item) => {
                  const isActive =
                    item.variant === "default" ||
                    (item.path !== HOME && pathname.startsWith(item.path));
                  return (
                    <SidebarMenuItem key={item.title}>
                      {expanded ? (
                        <>
                          <SidebarMenuButton
                            className="h-9 gap-2.5 px-3"
                            isActive={isActive}
                            asChild
                          >
                            <Link
                              to={item.path}
                              onClick={closeMobileNav}
                              aria-current={isActive ? "page" : undefined}
                            >
                              {item.icon && <item.icon />}
                              <span>
                                <HighlightMatch
                                  text={item.title}
                                  keyword={activeKeyword}
                                />
                              </span>
                              {item.label && (
                                <span
                                  className={cn(
                                    "figure ml-auto inline-flex h-5 min-w-5 shrink-0 items-center justify-center rounded-full px-1.5 text-[11.5px] font-medium",
                                    badgeToneClasses(item.badgeTone),
                                  )}
                                  title={item.badgeTitle}
                                >
                                  {item.label}
                                </span>
                              )}
                            </Link>
                          </SidebarMenuButton>
                          {renderMenuSub(item.children)}
                        </>
                      ) : (
                        <CollapsedNavFlyout
                          item={item}
                          isActive={isActive}
                          currentName={currentName}
                        />
                      )}
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          );
        })}
      </SidebarGroup>
    </SidebarContent>
  );
}
