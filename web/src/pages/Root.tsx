import { Outlet } from "react-router-dom";
import {
  Sidebar,
  SidebarHeader,
  SidebarProvider,
  SidebarTrigger,
  SidebarInset,
} from "@/components/ui/sidebar";
import { MainSidebar } from "@/components/sidebar-nav";
import { MainHeader } from "@/components/header";
import { useTheme } from "@/components/theme-provider";
import Logo from "@/assets/pingap.png";
import LogoLight from "@/assets/pingap-light.png";
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

export default function Root() {
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

  const { theme } = useTheme();

  let logoData = Logo;
  if (
    theme === "light" ||
    document.documentElement.className.includes("light")
  ) {
    logoData = LogoLight;
  }
  return (
    <SidebarProvider defaultOpen={true}>
      <div className="flex min-h-screen w-full">
        {/* Sidebar Toggle Button - Shown on mobile */}
        <div className="fixed top-4 left-4 z-40 md:hidden">
          <SidebarTrigger />
        </div>

        {/* Sidebar Component */}
        <Sidebar>
          <SidebarHeader>
            {/* Logo or app name can go here */}
            <div className="text-lg font-bold border-b">
              <img
                style={{
                  float: "left",
                  width: "32px",
                  marginRight: "10px",
                }}
                src={logoData}
              />
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
            </div>
          </SidebarHeader>
          <MainSidebar />
        </Sidebar>

        {/* Main Content - Using SidebarInset for proper spacing */}
        <SidebarInset>
          <div className="p-4 pt-0 w-full">
            <MainHeader />
            <Outlet />
          </div>
        </SidebarInset>
      </div>
    </SidebarProvider>
  );
}
