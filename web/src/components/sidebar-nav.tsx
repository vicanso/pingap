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
import router, {
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
import React, { useEffect } from "react";
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
} from "@/components/ui/sidebar";

interface NavLink {
  title: string;
  label?: string;
  icon?: LucideIcon;
  path: string;
  variant: "default" | "ghost";
  children?: NavLink[];
}

export function MainSidebar({
  className,
  sidebarOpen,
}: React.HTMLAttributes<HTMLDivElement> & {
  sidebarOpen: boolean;
}) {
  const navI18n = useI18n("nav");
  const [keyword, setKeyword] = React.useState("");
  const [pathname, setPathname] = React.useState(
    router.state.location.pathname,
  );
  const [config, initialized] = useConfigState(
    useShallow((state) => [state.data, state.initialized]),
  );

  const location = useLocation();

  useEffect(() => {
    setPathname(location.pathname);
  }, [location]);

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

  const generateChildren = (baseUrl: string, items: string[]) => {
    if (!keyword && !pathname.startsWith(baseUrl)) {
      return [] as NavLink[];
    }
    const arr: NavLink[] = [];
    items.forEach((item) => {
      if (keyword && !item.toLowerCase().includes(keyword)) {
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
  const items = [
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

  const renderMenuSub = (items: NavLink[] | undefined) => {
    if (!items || items.length == 0) {
      return <></>;
    }

    // get name from url
    const urlParams = new URLSearchParams(location.search);
    const currentName = urlParams.get("name");
    return (
      <SidebarMenuSub>
        {items.map((item) => {
          // check if the item is selected
          const isSelected = currentName === item.title;
          return (
            <SidebarMenuSubItem key={item.title}>
              <SidebarMenuSubButton
                className="h-9!"
                isActive={isSelected}
                asChild
              >
                <Link to={item.path}>
                  <span>{item.title}</span>
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
        {sidebarOpen && (
          <div className="m-2 mt-0 relative">
            <Input
              type="search"
              placeholder={navI18n("searchPlaceholder")}
              className="pl-8"
              onChange={(e) => {
                setKeyword(e.target.value.trim().toLowerCase());
              }}
            />
            <Search className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 select-none opacity-50" />
          </div>
        )}
        <SidebarGroupContent>
          <SidebarMenu>
            {items.map((item) => (
              <SidebarMenuItem key={item.title}>
                <SidebarMenuButton className="h-10!" asChild>
                  <Link to={item.path}>
                    <item.icon />
                    <span>{item.title}</span>
                    {item.label && (
                      <span
                        className={cn(
                          "ml-auto",
                          item.variant === "default" &&
                            "text-background dark:text-white",
                        )}
                      >
                        {item.label}
                      </span>
                    )}
                  </Link>
                </SidebarMenuButton>
                {renderMenuSub(item.children)}
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
        </SidebarGroupContent>
      </SidebarGroup>
    </SidebarContent>
  );
}
