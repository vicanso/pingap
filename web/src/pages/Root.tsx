import { Outlet } from "react-router-dom";
import {
  Sidebar,
  SidebarHeader,
  SidebarProvider,
  SidebarInset,
} from "@/components/ui/sidebar";
import { MainSidebar } from "@/components/sidebar-nav";
import { MainHeader } from "@/components/header";
import { useTheme } from "@/components/theme-provider";
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

export default function Root() {
  const key = "sidebarOpen";
  const sidebarOpen = window.localStorage.getItem(key);
  const [open, setOpen] = useState(sidebarOpen == "true" || !sidebarOpen);
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
      {/* Sidebar Component */}
      <Sidebar collapsible="icon">
        <SidebarHeader>
          {/* Logo or app name can go here */}
          <div className="text-lg font-bold border-b flex items-center">
            <Button
              size="icon"
              variant="ghost"
              className="cursor-pointer"
              onClick={() => {
                goToHome();
              }}
            >
              <img width={24} src={Logo} />
            </Button>
            {open && (
              <Button
                variant="link"
                className="px-0 cursor-pointer"
                onClick={(e) => {
                  e.preventDefault();
                  goToHome();
                }}
              >
                Pingap
                {!initialized && (
                  <LoaderCircle className="ml-2 h-4 w-4 inline animate-spin" />
                )}
                <span>{basicInfo.version}</span>
              </Button>
            )}
          </div>
        </SidebarHeader>
        <MainSidebar sidebarOpen={open} />
      </Sidebar>

      {/* Main Content - Using SidebarInset for proper spacing */}
      <SidebarInset>
        <MainHeader />
        <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
