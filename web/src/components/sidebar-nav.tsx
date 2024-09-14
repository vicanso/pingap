import { cn } from "@/lib/utils";
import { useTranslation } from "react-i18next";
import { Nav } from "@/components/nav";
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

export function MainSidebar({
  className,
}: React.HTMLAttributes<HTMLDivElement>) {
  const { t } = useTranslation();
  const { pathname } = router.state.location;
  const getVariant = (path: string) => {
    if (pathname.startsWith(path)) {
      return "default";
    }
    return "ghost";
  };
  const [config, initialized] = useConfigState((state) => [
    state.data,
    state.initialized,
  ]);
  const getLabel = (category: string) => {
    if (!initialized) {
      return "--";
    }
    switch (category) {
      case "server": {
        return Object.keys(config.servers || {}).length.toString();
      }
      case "location": {
        return Object.keys(config.locations || {}).length.toString();
      }
      case "upstream": {
        return Object.keys(config.upstreams || {}).length.toString();
      }
      case "plugin": {
        return Object.keys(config.plugins || {}).length.toString();
      }
      case "certificate": {
        return Object.keys(config.certificates || {}).length.toString();
      }
      default: {
        return "--";
      }
    }
  };
  const nav = (
    <Nav
      size="lg"
      isCollapsed={false}
      links={[
        {
          title: t("nav.basic"),
          icon: AppWindow,
          variant: getVariant(BASIC),
          path: BASIC,
        },
        {
          title: t("nav.server"),
          icon: Server,
          variant: getVariant(SERVERS),
          label: getLabel("server"),
          path: SERVERS,
        },
        {
          title: t("nav.location"),
          icon: Webhook,
          variant: getVariant(LOCATIONS),
          label: getLabel("location"),
          path: LOCATIONS,
        },
        {
          title: t("nav.upstream"),
          icon: TrendingUpDown,
          variant: getVariant(UPSTREMAS),
          label: getLabel("upstream"),
          path: UPSTREMAS,
        },
        {
          title: t("nav.plugin"),
          icon: PlugZap,
          variant: getVariant(PLUGINS),
          label: getLabel("plugin"),
          path: PLUGINS,
        },
        {
          title: t("nav.certificate"),
          icon: ShieldCheck,
          variant: getVariant(CERTIFICATES),
          label: getLabel("certificate"),
          path: CERTIFICATES,
        },
      ]}
    ></Nav>
  );
  return <div className={cn("pb-12", className)}>{nav}</div>;
}
