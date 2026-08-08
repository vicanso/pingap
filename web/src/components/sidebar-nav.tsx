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
import { useI18n } from "@/i18n";
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

interface NavLink {
  title: string;
  label?: string;
  icon?: LucideIcon;
  path: string;
  variant: "default" | "ghost";
  children?: NavLink[];
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
        "flex size-8 shrink-0 items-center justify-center rounded-md outline-none",
        "text-sidebar-foreground transition-colors",
        "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
        "focus-visible:ring-2 focus-visible:ring-sidebar-ring",
        isActive &&
          "bg-sidebar-accent font-medium text-sidebar-accent-foreground",
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
            <span className="ml-auto text-[11px] tabular-nums text-muted-foreground">
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
}: React.HTMLAttributes<HTMLDivElement> & {
  sidebarOpen: boolean;
}) {
  const navI18n = useI18n("nav");
  // The mobile sheet is always full width, so the icon-rail rendering driven by
  // the desktop collapse toggle would strand tiny icon squares at its left edge.
  const { isMobile } = useSidebar();
  const expanded = sidebarOpen || isMobile;
  const [keyword, setKeyword] = React.useState("");
  // The search box only renders while expanded. Applying a leftover keyword on
  // the collapsed rail silently empties every flyout with no visible box to
  // clear it, so ignore it there — the input is controlled, so collapsing and
  // expanding again brings both the text and the filter back together.
  // Normalise where it is used, not on the way in, so the box shows exactly
  // what was typed instead of eating case and trailing spaces mid-word.
  const activeKeyword = expanded ? keyword.trim().toLowerCase() : "";
  const [config, initialized] = useConfigState(
    useShallow((state) => [state.data, state.initialized]),
  );

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
  const getLabel = (category: string) => {
    if (!initialized) {
      return "--";
    }
    switch (category) {
      case "server": {
        return servers.length.toString();
      }
      case "location": {
        return locations.length.toString();
      }
      case "upstream": {
        return upstreams.length.toString();
      }
      case "plugin": {
        return plugins.length.toString();
      }
      case "certificate": {
        return certificates.length.toString();
      }
      case "storage": {
        return storages.length.toString();
      }
      default: {
        return "--";
      }
    }
  };

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
  const items: NavLink[] = [
    {
      title: navI18n("basic"),
      icon: AppWindow,
      variant: getVariant(BASIC),
      path: BASIC,
    },
    {
      title: navI18n("server"),
      icon: Server,
      variant: getVariant(SERVERS),
      label: getLabel("server"),
      path: SERVERS,
      children: generateChildren(SERVERS, servers),
    },
    {
      title: navI18n("location"),
      icon: Webhook,
      variant: getVariant(LOCATIONS),
      label: getLabel("location"),
      path: LOCATIONS,
      children: generateChildren(LOCATIONS, locations),
    },
    {
      title: navI18n("upstream"),
      icon: TrendingUpDown,
      variant: getVariant(UPSTREAMS),
      label: getLabel("upstream"),
      path: UPSTREAMS,
      children: generateChildren(UPSTREAMS, upstreams),
    },
    {
      title: navI18n("plugin"),
      icon: PlugZap,
      variant: getVariant(PLUGINS),
      label: getLabel("plugin"),
      path: PLUGINS,
      children: generateChildren(PLUGINS, plugins),
    },
    {
      title: navI18n("certificate"),
      icon: ShieldCheck,
      variant: getVariant(CERTIFICATES),
      label: getLabel("certificate"),
      path: CERTIFICATES,
      children: generateChildren(CERTIFICATES, certificates),
    },
    {
      title: navI18n("storage"),
      icon: Container,
      variant: getVariant(STORAGES),
      label: getLabel("storage"),
      path: STORAGES,
      children: generateChildren(STORAGES, storages),
    },
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
                <Link to={item.path} className="w-full">
                  <span className="truncate">{item.title}</span>
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
        {expanded && (
          <div className="m-2 mt-0 relative">
            <Input
              type="search"
              placeholder={navI18n("searchPlaceholder")}
              className="pl-8"
              value={keyword}
              onChange={(e) => {
                setKeyword(e.target.value);
              }}
            />
            <Search className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 select-none opacity-50" />
          </div>
        )}
        {expanded && activeKeyword && matchCount === 0 && (
          <p className="mx-2 mb-2 text-xs text-muted-foreground">
            {navI18n("searchEmpty")}
          </p>
        )}
        <SidebarGroupContent>
          <SidebarMenu>
            {items.map((item) => {
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
                        <Link to={item.path}>
                          {item.icon && <item.icon />}
                          <span>{item.title}</span>
                          {item.label && (
                            <span
                              className={cn(
                                // Fixed min width so badges line up even when counts differ (0 vs 10).
                                "ml-auto inline-flex h-5 min-w-5 shrink-0 items-center justify-center rounded-full bg-sidebar-accent px-1.5 text-[11px] tabular-nums text-muted-foreground",
                                isActive &&
                                  "bg-sidebar-primary/15 text-sidebar-primary",
                              )}
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
      </SidebarGroup>
    </SidebarContent>
  );
}
