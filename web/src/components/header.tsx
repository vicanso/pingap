import React from "react";
import { cn } from "@/lib/utils";
import { Check, Sun, Moon, SunMoon, LoaderCircle, Cog } from "lucide-react";
import { Link } from "react-router-dom";
import { HOME } from "@/routers";
import { useTheme } from "@/components/theme-provider";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useTranslation } from "react-i18next";
import Logo from "@/assets/pingap.png";
import useBasicState from "@/states/basic";
import useConfigState from "@/states/config";
import { useAsync } from "react-async-hook";
import { useToast } from "@/hooks/use-toast";
import { formatError } from "@/helpers/util";

export function MainHeader({
  className,
}: React.HTMLAttributes<HTMLDivElement>) {
  const { t } = useTranslation();
  const iconClassName = "mr-2 h-4 w-4";
  const { setTheme, theme } = useTheme();
  const [fetchBasicInfo, basicInfo] = useBasicState((state) => [
    state.fetch,
    state.data,
  ]);
  const [fetchConfig, initialized] = useConfigState((state) => [
    state.fetch,
    state.initialized,
  ]);
  const { toast } = useToast();
  useAsync(async () => {
    try {
      await fetchBasicInfo();
      await fetchConfig();
    } catch (err) {
      toast({
        title: t("fetchFail"),
        description: formatError(err),
      });
    }
  }, []);

  const tips = (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="link">
          <Cog />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuGroup>
          <DropdownMenuItem
            className="cursor-pointer"
            onClick={() => {
              setTheme("system");
            }}
          >
            {theme == "system" && <Check className={iconClassName} />}
            {theme != "system" && <SunMoon className={iconClassName} />}
            <span>{t("themeSystem")}</span>
          </DropdownMenuItem>
          <DropdownMenuItem
            className="cursor-pointer"
            onClick={() => {
              setTheme("dark");
            }}
          >
            {theme == "dark" && <Check className={iconClassName} />}
            {theme != "dark" && <Moon className={iconClassName} />}
            <span>{t("themeDark")}</span>
          </DropdownMenuItem>
          <DropdownMenuItem
            className="cursor-pointer"
            onClick={() => {
              setTheme("light");
            }}
          >
            {theme == "light" && <Check className={iconClassName} />}
            {theme != "light" && <Sun className={iconClassName} />}
            <span>{t("themeLight")}</span>
          </DropdownMenuItem>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );

  return (
    <header
      className={cn(
        "sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60",
        className,
      )}
    >
      <div className="ml-2 flex h-14 items-center">
        <img
          style={{
            float: "left",
            width: "32px",
            marginRight: "10px",
          }}
          src={Logo}
        />
        <Link to={HOME} className="font-bold">
          Pingap
          {!initialized && (
            <LoaderCircle className="ml-2 h-4 w-4 inline animate-spin" />
          )}
          <span className="ml-2">{basicInfo.version}</span>
        </Link>
        <div className="flex flex-1 items-center justify-between space-x-2 md:justify-end mr-5">
          {tips}
        </div>
      </div>
    </header>
  );
}
