import React from "react";
import { cn } from "@/lib/utils";
import {
  Check,
  Sun,
  Moon,
  SunMoon,
  LoaderCircle,
  Cog,
  Languages,
  FileCode2,
} from "lucide-react";
import { goToConfig, goToHome } from "@/routers";
import { useTheme } from "@/components/theme-provider";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useTranslation } from "react-i18next";
import Logo from "@/assets/pingap.png";
import useBasicState from "@/states/basic";
import useConfigState from "@/states/config";
import { useAsync } from "react-async-hook";
import { useToast } from "@/hooks/use-toast";
import { formatError } from "@/helpers/util";
import i18n from "@/i18n";

export function MainHeader({
  className,
}: React.HTMLAttributes<HTMLDivElement>) {
  const { t } = useTranslation();
  const iconClassName = "mr-2 h-4 w-4";
  const { setTheme, theme } = useTheme();
  const lang = i18n.language;
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
  const zhLang = "zh";
  const enLang = "en";

  const tips = (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon">
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
          <DropdownMenuSeparator />
          <DropdownMenuItem
            className="cursor-pointer"
            onClick={() => {
              i18n.changeLanguage(zhLang);
            }}
          >
            {lang == zhLang && <Check className={iconClassName} />}
            {lang != zhLang && <Languages className={iconClassName} />}
            中文
          </DropdownMenuItem>
          <DropdownMenuItem
            className="cursor-pointe"
            onClick={() => {
              i18n.changeLanguage(enLang);
            }}
          >
            {lang == enLang && <Check className={iconClassName} />}
            {lang != enLang && <Languages className={iconClassName} />}
            English
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
        <Button
          variant="link"
          className="px-0"
          onClick={(e) => {
            e.preventDefault();
            goToHome();
          }}
        >
          Pingap
          {!initialized && (
            <LoaderCircle className="ml-2 h-4 w-4 inline animate-spin" />
          )}
          <span className="ml-2">{basicInfo.version}</span>
        </Button>
        <div className="flex flex-1 items-center space-x-2 justify-end mr-5">
          <Button
            variant="ghost"
            size="icon"
            onClick={(e) => {
              e.preventDefault();
              goToConfig();
            }}
          >
            <FileCode2 />
          </Button>
          {tips}
        </div>
      </div>
    </header>
  );
}
