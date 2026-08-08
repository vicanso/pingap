import { Outlet } from "react-router-dom";
import {
  Sidebar,
  SidebarHeader,
  SidebarProvider,
  SidebarInset,
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
import { goToHome, goToLogin } from "@/routers";
import { useAsync } from "react-async-hook";
import HTTPError from "@/helpers/http-error";
import { formatError } from "@/helpers/util";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import { useIsMobile } from "@/hooks/use-mobile";

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
              className="size-8 shrink-0 cursor-pointer rounded-lg"
              onClick={() => {
                goToHome();
              }}
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
                className="flex min-w-0 flex-1 items-center gap-1.5 text-left cursor-pointer"
                onClick={(e) => {
                  e.preventDefault();
                  goToHome();
                }}
              >
                <span className="truncate text-base font-semibold tracking-tight text-sidebar-foreground">
                  Pingap
                </span>
                {!initialized && (
                  <LoaderCircle className="h-3.5 w-3.5 shrink-0 animate-spin text-muted-foreground" />
                )}
                {basicInfo.version && (
                  <span className="truncate rounded-full bg-sidebar-accent px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
                    {basicInfo.version}
                  </span>
                )}
              </button>
            )}
          </div>
        </SidebarHeader>
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
