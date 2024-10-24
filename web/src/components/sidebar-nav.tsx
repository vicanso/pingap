import { cn } from "@/lib/utils";
import { Nav, NavLink } from "@/components/nav";
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
  UPSTREMAS,
  PLUGINS,
  CERTIFICATES,
  STORAGES,
} from "@/routers.tsx";
import useConfigState from "@/states/config";
import { useI18n } from "@/i18n";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import React, { useEffect } from "react";
import { useLocation } from "react-router-dom";

export function MainSidebar({
  className,
}: React.HTMLAttributes<HTMLDivElement>) {
  const navI18n = useI18n("nav");
  const [keyword, setKeyword] = React.useState("");
  const [pathname, setPathname] = React.useState(
    router.state.location.pathname,
  );
  const [config, initialized] = useConfigState((state) => [
    state.data,
    state.initialized,
  ]);

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
  const nav = (
    <Nav
      size="lg"
      isCollapsed={false}
      links={[
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
          variant: getVariant(UPSTREMAS),
          label: getLabel("upstream"),
          path: UPSTREMAS,
          children: generateChildren(UPSTREMAS, upstreams),
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
      ]}
    ></Nav>
  );
  return (
    <div className={cn("pb-12", className)}>
      <ScrollArea className="h-full">
        <div className="m-2 mb-0 relative">
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
        {nav}
      </ScrollArea>
    </div>
  );
}
