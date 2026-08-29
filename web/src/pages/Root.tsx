import { Outlet, useLocation } from "react-router-dom";
import {
  Sidebar,
  SidebarHeader,
  SidebarProvider,
  SidebarInset,
  useSidebar,
} from "@/components/ui/sidebar";
import { MainSidebar } from "@/components/sidebar-nav";
import { MainHeader } from "@/components/header";
import Logo from "@/assets/pingap.png";
import useBasicState from "@/states/basic";
import { useShallow } from "zustand/react/shallow";
import useConfigState from "@/states/config";
import { Button } from "@/components/ui/button";
import { LoaderCircle } from "lucide-react";
import { toast } from "sonner";
import { goToHome, goToLogin, HOME } from "@/routers";
import { cn } from "@/lib/utils";
import { useAsync } from "react-async-hook";
import HTTPError from "@/helpers/http-error";
import { formatError } from "@/helpers/util";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import { useIsMobile } from "@/hooks/use-mobile";

/** Brand row lives under SidebarProvider so it can close the mobile sheet. */
function BrandHeader({
  showBrand,
  initialized,
  version,
}: {
  showBrand: boolean;
  initialized: boolean;
  version?: string;
}) {
  const { isMobile, setOpenMobile } = useSidebar();
  const goHome = () => {
    if (isMobile) {
      setOpenMobile(false);
    }
    goToHome();
  };
  // The dashboard has no nav entry — it is reached through this row — so
  // without this the console showed no "you are here" at all on its own
  // landing page.
  const onDashboard = useLocation().pathname === HOME;

  return (
    <SidebarHeader className="h-12 shrink-0 justify-center border-b border-sidebar-border p-0">
      <div
        className={
          showBrand
            ? "flex h-full items-center gap-1.5 px-3"
            : "flex h-full w-full items-center justify-center"
        }
      >
        <Button
          size="icon"
          variant="ghost"
          aria-current={onDashboard ? "page" : undefined}
          className={cn(
            "size-8 shrink-0 cursor-pointer rounded-md",
            onDashboard && "bg-sidebar-primary/12 hover:bg-sidebar-primary/18",
          )}
          onClick={goHome}
        >
          <img
            width={20}
            height={20}
            src={Logo}
            alt="Pingap"
            className="rounded-md"
          />
        </Button>
        {showBrand && (
          <button
            type="button"
            className="flex min-w-0 flex-1 cursor-pointer items-center gap-1.5 text-left"
            onClick={(e) => {
              e.preventDefault();
              goHome();
            }}
          >
            <span
              className={cn(
                "truncate text-base font-semibold tracking-tight",
                onDashboard ? "text-sidebar-primary" : "text-foreground",
              )}
            >
              Pingap
            </span>
            {!initialized && (
              <LoaderCircle className="h-3.5 w-3.5 shrink-0 animate-spin text-muted-foreground" />
            )}
            {version && (
              <span className="machine truncate rounded-full bg-sidebar-accent px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
                {version}
              </span>
            )}
          </button>
        )}
      </div>
    </SidebarHeader>
  );
}

export default function Root() {
  const key = "sidebarOpen";
  const sidebarOpen = window.localStorage.getItem(key);
  const [open, setOpen] = useState(sidebarOpen == "true" || !sidebarOpen);
  // The mobile sheet is always full width; ignore the desktop collapse state there.
  const isMobile = useIsMobile();
  const showBrand = open || isMobile;
  const { t } = useTranslation();
  const [fetchBasicInfo, basicInfo] = useBasicState(
    useShallow((state) => [state.fetch, state.data]),
  );
  const [fetchConfig, initialized] = useConfigState(
    useShallow((state) => [state.fetch, state.initialized]),
  );

  useAsync(async () => {
    try {
      await fetchBasicInfo();
      await fetchConfig();
    } catch (err) {
      const status = ((err as HTTPError)?.status || 0) as number;
      if (status == 401) {
        goToLogin();
        return;
      }
      toast(t("fetchFail"), {
        description: formatError(err),
      });
    }
  }, []);

  return (
    <SidebarProvider
      open={open}
      onOpenChange={(open) => {
        window.localStorage.setItem(key, open.toString());
        setOpen(open);
      }}
    >
      <Sidebar collapsible="icon" className="border-r border-sidebar-border">
        {/* h-12 matches MainHeader so brand row and top bar share one baseline */}
        <BrandHeader
          showBrand={showBrand}
          initialized={initialized}
          version={basicInfo.version}
        />
        <MainSidebar sidebarOpen={open} />
      </Sidebar>

      <SidebarInset className="min-h-0 overflow-hidden bg-background">
        <MainHeader />
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
