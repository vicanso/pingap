import { cn } from "@/lib/utils";
import { Nav, NavLink } from "@/components/nav";
import {
  AppWindow,
  Server,
  Webhook,
  TrendingUpDown,
  PlugZap,
  ShieldCheck,
} from "lucide-react";
import router, {
  BASIC,
  SERVERS,
  LOCATIONS,
  UPSTREMAS,
  PLUGINS,
  CERTIFICATES,
} from "@/routers.tsx";
import useConfigState from "@/states/config";
import { useI18n } from "@/i18n";
import { ScrollArea } from "@/components/ui/scroll-area";

export function MainSidebar({
  className,
}: React.HTMLAttributes<HTMLDivElement>) {
  const navI18n = useI18n("nav");
  const { pathname, search } = router.state.location;
  const getVariant = (path: string) => {
    if (path === `${pathname}${search}`) {
      return "default";
    }
    return "ghost";
  };
  const [config, initialized] = useConfigState((state) => [
    state.data,
    state.initialized,
  ]);

  const servers = Object.keys(config.servers || {}).sort();
  const locations = Object.keys(config.locations || {}).sort();
  const upstreams = Object.keys(config.upstreams || {}).sort();
  const plugins = Object.keys(config.plugins || {}).sort();
  const certificates = Object.keys(config.certificates || {}).sort();
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
      default: {
        return "--";
      }
    }
  };

  const generateChildren = (baseUrl: string, items: string[]) => {
    if (!pathname.startsWith(baseUrl)) {
      return [] as NavLink[];
    }
    return items.map((item) => {
      const path = `${baseUrl}?name=${item}`;
      return {
        title: item,
        variant: getVariant(path),
        label: "",
        path,
      } as NavLink;
    });
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
      ]}
    ></Nav>
  );
  return (
    <div className={cn("pb-12", className)}>
      <ScrollArea className="h-full">{nav}</ScrollArea>
    </div>
  );
}
