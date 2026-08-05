import React from "react";
import { cn } from "@/lib/utils";
import {
  Check,
  Sun,
  Moon,
  SunMoon,
  LoaderCircle,
  Cog,
  FileCode2,
  AudioWaveform,
  ClipboardCopy,
  PowerOff,
} from "lucide-react";
import { goToConfig } from "@/routers";
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
import { toast } from "sonner";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import request from "@/helpers/request";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { SidebarTrigger } from "@/components/ui/sidebar";
import useBasicState from "@/states/basic";
import { useShallow } from "zustand/react/shallow";
export function MainHeader({
  className,
}: React.HTMLAttributes<HTMLDivElement>) {
  const { t } = useTranslation();

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

  const [base64Type, setBase64Type] = React.useState("encode");
  const [base64Data, setBase64Data] = React.useState("");

  const [restart] = useBasicState(useShallow((state) => [state.restart]));

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
      toast(t("aesFail"), {
        description: formatError(err),
      });
    } finally {
      if (key == `${secret}-${value}`) {
        setAesProcessing(false);
      }
    }
  };

  const confirmRestart = async () => {
    await restart();
    toast(t("restartSuccess"));
  };

  const zhLang = "zh";
  const enLang = "en";

  const isZh = lang === zhLang || lang.startsWith("zh");

  // Design mock: segmented 中文 / EN control in a padded pill.
  const languageSwitch = (
    <div
      className="flex gap-0.5 rounded-lg border border-border bg-muted/60 p-[3px]"
      role="group"
      aria-label="Language"
    >
      <button
        type="button"
        className={cn(
          "cursor-pointer rounded-md px-3 py-1 text-[12.5px] font-medium transition-colors",
          isZh
            ? "bg-background text-foreground shadow-sm"
            : "text-muted-foreground hover:text-foreground",
        )}
        aria-pressed={isZh}
        onClick={() => {
          i18n.changeLanguage(zhLang);
        }}
      >
        中文
      </button>
      <button
        type="button"
        className={cn(
          "cursor-pointer rounded-md px-3 py-1 text-[12.5px] font-medium transition-colors",
          !isZh
            ? "bg-background text-foreground shadow-sm"
            : "text-muted-foreground hover:text-foreground",
        )}
        aria-pressed={!isZh}
        onClick={() => {
          i18n.changeLanguage(enLang);
        }}
      >
        EN
      </button>
    </div>
  );

  const iconBtnClass =
    "size-8 shrink-0 cursor-pointer text-muted-foreground hover:text-foreground";

  const settingsMenu = (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={iconBtnClass}
          aria-label="Settings"
        >
          <Cog className="size-4" strokeWidth={1.8} />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
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
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={(e) => e.preventDefault()}>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <button
                type="button"
                className="flex w-full cursor-pointer items-center text-sm"
              >
                <PowerOff className={iconClassName} />
                <span>{t("restart")}</span>
              </button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{t("restartTitle")}</AlertDialogTitle>
                <AlertDialogDescription>
                  {t("restartDescription")}
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
                <AlertDialogAction onClick={confirmRestart}>
                  {t("confirm")}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );

  const aesTab = (
    <TabsContent value="aes" className="mt-2">
      <div className="grid gap-4">
        <div className="space-y-2">
          <h4 className="font-medium leading-none">{t("aesGcm")}</h4>
          <p className="text-sm text-muted-foreground">{t("aesTips")}</p>
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
            <Label htmlFor="secret" className="flex-none leading-9 mr-4">
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
                <Input id="value" className="grow" value={aesResult} readOnly />
              )}
              {aesProcessing && (
                <LoaderCircle className="ml-2 h-4 w-4 inline animate-spin" />
              )}
            </p>
          </div>
        </div>
      </div>
    </TabsContent>
  );

  const base64Tab = (
    <TabsContent value="base64" className="mt-2">
      <div className="grid gap-4">
        <div className="space-y-2">
          <h4 className="font-medium leading-none">{t("base64")}</h4>
          <p className="text-sm text-muted-foreground">{t("base64Tips")}</p>
        </div>
        <div className="grid gap-2">
          <RadioGroup
            className="flex flex-wrap items-start"
            onValueChange={(option) => {
              setBase64Type(option);
            }}
            defaultValue={base64Type}
          >
            <RadioGroupItem value="encode" id="encode" />
            <Label className="pl-2 cursor-pointer" htmlFor="encode">
              {t("encode")}
            </Label>
            <RadioGroupItem value="decode" id="decode" />
            <Label className="pl-2 cursor-pointer" htmlFor="decode">
              {t("decode")}
            </Label>
          </RadioGroup>
          <div className="flex">
            <Label htmlFor="value" className="flex-none leading-9 mr-4">
              {t("value")}
            </Label>
            <Input
              id="value"
              className="grow"
              onChange={(e) => {
                const value = e.target.value.trim();
                try {
                  if (base64Type == "encode") {
                    setBase64Data(window.btoa(value));
                  } else {
                    setBase64Data(window.atob(value));
                  }
                } catch (err) {
                  console.error(err);
                  setBase64Data("");
                }
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
                  await navigator.clipboard.writeText(base64Data);
                }}
              >
                <ClipboardCopy />
              </Button>
              <Input id="value" className="grow" value={base64Data} readOnly />
            </p>
          </div>
        </div>
      </div>
    </TabsContent>
  );

  return (
    <header
      className={cn(
        "flex h-12 shrink-0 items-center gap-2 border-b px-5 transition-[width,height] ease-linear",
        className,
      )}
    >
      <SidebarTrigger className={cn(iconBtnClass, "-ml-1")} />
      <div className="flex-1" />
      <div className="flex items-center gap-2">
        {languageSwitch}
        <Popover>
          <PopoverTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className={iconBtnClass}
              aria-label="Tools"
            >
              <AudioWaveform className="size-4" strokeWidth={1.8} />
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-[400px]" align="end">
            <Tabs defaultValue="base64" className="w-full">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="base64">Base64</TabsTrigger>
                <TabsTrigger value="aes">AES</TabsTrigger>
              </TabsList>
              {base64Tab}
              {aesTab}
            </Tabs>
          </PopoverContent>
        </Popover>
        <Button
          variant="ghost"
          size="icon"
          className={iconBtnClass}
          aria-label="Config"
          onClick={(e) => {
            e.preventDefault();
            goToConfig();
          }}
        >
          <FileCode2 className="size-4" strokeWidth={1.8} />
        </Button>
        {settingsMenu}
      </div>
    </header>
  );
}
