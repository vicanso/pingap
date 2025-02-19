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
  AudioWaveform,
  ClipboardCopy,
} from "lucide-react";
import { goToConfig, goToHome, goToLogin } from "@/routers";
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
import LogoLight from "@/assets/pingap-light.png";
import useBasicState from "@/states/basic";
import useConfigState from "@/states/config";
import { useShallow } from "zustand/react/shallow";

import { useAsync } from "react-async-hook";
import { useToast } from "@/hooks/use-toast";
import { formatError } from "@/helpers/util";
import i18n from "@/i18n";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import request from "@/helpers/request";
import HTTPError from "@/helpers/http-error";

export function MainHeader({
  className,
}: React.HTMLAttributes<HTMLDivElement>) {
  const { t } = useTranslation();
  const { toast } = useToast();

  const iconClassName = "mr-2 h-4 w-4";
  const { setTheme, theme } = useTheme();
  const lang = i18n.language;
  const [aesType, setAesType] = React.useState("encrypt");
  const [aesProcessing, setAesProcessing] = React.useState(false);
  const [aesData, setAesData] = React.useState({
    key: "",
    data: "",
  });
  const [aesResult, setAesResult] = React.useState("");

  const [fetchBasicInfo, basicInfo] = useBasicState(
    useShallow((state) => [state.fetch, state.data]),
  );
  const [fetchConfig, initialized] = useConfigState(
    useShallow((state) => [state.fetch, state.initialized]),
  );

  const handleAes = async () => {
    const secret = aesData.key;
    const value = aesData.data;
    if (!secret || !value) {
      setAesResult("");
      return;
    }
    const key = `${secret}-${value}`;
    setAesProcessing(true);
    try {
      const { data } = await request.post<{
        value: string;
      }>("/aes", {
        category: aesType,
        key: secret,
        data: value,
      });
      if (key == `${secret}-${value}`) {
        setAesResult(data.value);
        await navigator.clipboard.writeText(data.value);
      }
    } catch (err) {
      toast({
        title: t("aesFail"),
        description: formatError(err),
      });
    } finally {
      if (key == `${secret}-${value}`) {
        setAesProcessing(false);
      }
    }
  };

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

  let logoData = Logo;
  if (theme === "light" || document.documentElement.className.includes("light")) {
    logoData = LogoLight;
  }



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
          src={logoData}
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
          <span>{basicInfo.version}</span>
        </Button>
        <div className="flex flex-1 items-center space-x-2 justify-end mr-5">
          <Popover>
            <PopoverTrigger asChild>
              <Button variant="ghost" size="icon">
                <AudioWaveform />
              </Button>
            </PopoverTrigger>
            <PopoverContent className="w-[400px]" align="end">
              <div className="grid gap-4">
                <div className="space-y-2">
                  <h4 className="font-medium leading-none">{t("aesGcm")}</h4>
                  <p className="text-sm text-muted-foreground">
                    {t("aesTips")}
                  </p>
                </div>
                <div className="grid gap-2">
                  <RadioGroup
                    className="flex flex-wrap items-start"
                    onValueChange={(option) => {
                      setAesType(option);
                    }}
                    defaultValue={aesType}
                  >
                    <RadioGroupItem value="encrypt" id="encrypt" />
                    <Label className="pl-2 cursor-pointer" htmlFor="encrypt">
                      {t("encrypt")}
                    </Label>
                    <RadioGroupItem value="decrypt" id="decrypt" />
                    <Label className="pl-2 cursor-pointer" htmlFor="decrypt">
                      {t("decrypt")}
                    </Label>
                  </RadioGroup>
                  <div className="flex">
                    <Label
                      htmlFor="secret"
                      className="flex-none leading-9 mr-4"
                    >
                      {t("secret")}
                    </Label>
                    <Input
                      id="secret"
                      className="grow"
                      onChange={(e) => {
                        aesData.key = e.target.value.trim();
                        setAesData(aesData);
                      }}
                    />
                  </div>
                  <div className="flex">
                    <Label htmlFor="value" className="flex-none leading-9 mr-4">
                      {t("value")}
                    </Label>
                    <Input
                      id="value"
                      className="grow"
                      onChange={(e) => {
                        aesData.data = e.target.value.trim();
                        setAesData(aesData);
                      }}
                    />
                  </div>
                  <div className="flex">
                    <Label htmlFor="value" className="flex-none leading-9 mr-4">
                      {t("result")}
                    </Label>
                    <p className="grow text-sm text-muted-foreground leading-9 relative">
                      <Button
                        className="absolute right-0"
                        variant="ghost"
                        size="icon"
                        onClick={async (e) => {
                          e.preventDefault();
                          handleAes();
                        }}
                      >
                        <ClipboardCopy />
                      </Button>
                      {!aesProcessing && (
                        <Input
                          id="value"
                          className="grow"
                          value={aesResult}
                          readOnly
                        />
                      )}
                      {aesProcessing && (
                        <LoaderCircle className="ml-2 h-4 w-4 inline animate-spin" />
                      )}
                    </p>
                  </div>
                </div>
              </div>
            </PopoverContent>
          </Popover>
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
