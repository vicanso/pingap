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
  Wrench,
  ClipboardCopy,
  PowerOff,
  Search,
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import request from "@/helpers/request";
import { formatUptime } from "@/helpers/util";
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
  onOpenCommandPalette,
}: React.HTMLAttributes<HTMLDivElement> & {
  onOpenCommandPalette?: () => void;
}) {
  const { t } = useTranslation();

  const iconClassName = "mr-2 h-4 w-4";
  const { setTheme, theme } = useTheme();
  const lang = i18n.language;
  const [aesType, setAesType] = React.useState<"encrypt" | "decrypt">(
    "encrypt",
  );
  const [aesProcessing, setAesProcessing] = React.useState(false);
  const [aesData, setAesData] = React.useState({
    key: "",
    data: "",
  });
  const [aesResult, setAesResult] = React.useState("");

  const [base64Type, setBase64Type] = React.useState<"encode" | "decode">(
    "encode",
  );
  const [base64Input, setBase64Input] = React.useState("");
  const [base64Data, setBase64Data] = React.useState("");

  const [restart, basicInfo, initialized] = useBasicState(
    useShallow((state) => [state.restart, state.data, state.initialized]),
  );

  // Uptime is derived from a fixed start_time, so it only advances if something
  // re-renders. The dashboard polls /basic every 5s; every other page would
  // otherwise freeze this readout, which is worse than not showing it.
  const [, setTick] = React.useState(0);
  React.useEffect(() => {
    const timer = setInterval(() => setTick((n) => n + 1), 30_000);
    return () => clearInterval(timer);
  }, []);

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
    // A restart that is refused says why: a new address that cannot be
    // bound, a replacement that did not come up.
    try {
      toast(t("restartPending"));
      await restart();
      toast(t("restartSuccess"));
    } catch (err) {
      toast(t("restartFail"), {
        description: formatError(err),
      });
    }
  };
  // Where this process cannot be restarted from the page - the first
  // process of a container, one in the foreground - the page says so
  // instead of offering it.
  const restartUnsupported: Record<string, string> = {
    container: t("restartUnsupportedContainer"),
    foreground: t("restartUnsupportedForeground"),
    platform: t("restartUnsupportedPlatform"),
  };
  const noRestart = basicInfo.restart_unsupported
    ? restartUnsupported[basicInfo.restart_unsupported] ||
      restartUnsupported.foreground
    : "";

  const zhLang = "zh";
  const enLang = "en";

  const isZh = lang === zhLang || lang.startsWith("zh");

  // Design mock: segmented 中文 / EN control in a padded pill.
  // Compact padding on small screens so the bar stays one row.
  const languageSwitch = (
    <div
      className="flex gap-0.5 rounded-lg bg-accent p-[3px]"
      role="group"
      aria-label="Language"
    >
      <button
        type="button"
        className={cn(
          "cursor-pointer rounded-md px-2 py-1 text-[12.5px] font-medium transition-colors sm:px-3",
          isZh
            ? "bg-card text-foreground"
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
          "cursor-pointer rounded-md px-2 py-1 text-[12.5px] font-medium transition-colors sm:px-3",
          !isZh
            ? "bg-card text-foreground"
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

  // Proof of life, on every page. While you are half-way through editing an
  // upstream the one thing worth keeping on screen is that the process is
  // still up and still taking traffic.
  const uptime = formatUptime(basicInfo.start_time);
  const liveReadout = initialized && basicInfo.start_time > 0 && (
    <div className="figure flex min-w-0 items-center gap-2 text-[13px] text-muted-foreground">
      {/* Still: a state, not an alarm that pulses on every page. */}
      <span className="inline-flex size-1.5 shrink-0 rounded-full bg-ok" />
      <span className="font-medium text-foreground">{t("header.live")}</span>
      <span className="hidden text-border sm:inline">/</span>
      <span className="hidden sm:inline">{uptime}</span>
      <span className="hidden text-border md:inline">/</span>
      <span className="hidden truncate md:inline">
        {basicInfo.processing.toLocaleString()} {t("header.active")}
      </span>
    </div>
  );

  const computeBase64 = (mode: "encode" | "decode", raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed) {
      setBase64Data("");
      return;
    }
    try {
      setBase64Data(
        mode === "encode" ? window.btoa(trimmed) : window.atob(trimmed),
      );
    } catch {
      // Half-typed or non-base64 input is the normal case here,
      // not a fault: just show nothing until it decodes.
      setBase64Data("");
    }
  };

  const copyText = async (value: string) => {
    if (!value) {
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      toast.success(t("header.copied"));
    } catch (err) {
      toast(t("copyConfigFail"), {
        description: formatError(err),
      });
    }
  };

  const settingsMenu = (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className={iconBtnClass}
              aria-label={t("header.settings")}
            >
              <Cog className="size-4" strokeWidth={1.8} />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent side="bottom">{t("header.settings")}</TooltipContent>
      </Tooltip>
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
        {/* Language joins Settings on small screens to free the top bar. */}
        <DropdownMenuSeparator className="sm:hidden" />
        <DropdownMenuGroup className="sm:hidden">
          <DropdownMenuItem
            className="cursor-pointer"
            onClick={() => i18n.changeLanguage(zhLang)}
          >
            {isZh && <Check className={iconClassName} />}
            <span>中文</span>
          </DropdownMenuItem>
          <DropdownMenuItem
            className="cursor-pointer"
            onClick={() => i18n.changeLanguage(enLang)}
          >
            {!isZh && <Check className={iconClassName} />}
            <span>EN</span>
          </DropdownMenuItem>
        </DropdownMenuGroup>
        {!basicInfo.read_only && <DropdownMenuSeparator />}
        {!basicInfo.read_only && (
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
                  <AlertDialogTitle>
                    {noRestart
                      ? t("restartUnsupportedTitle")
                      : t("restartTitle")}
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    {noRestart || t("restartDescription")}
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>
                    {noRestart ? t("confirm") : t("cancel")}
                  </AlertDialogCancel>
                  {!noRestart && (
                    <AlertDialogAction onClick={confirmRestart}>
                      {t("confirm")}
                    </AlertDialogAction>
                  )}
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );

  const aesTab = (
    <TabsContent value="aes" className="mt-3">
      <div className="space-y-3">
        <div>
          <h4 className="text-sm font-medium leading-none">{t("aesGcm")}</h4>
          <p className="mt-1 text-xs text-muted-foreground">{t("aesTips")}</p>
        </div>
        <div
          className="inline-flex rounded-lg bg-accent p-[3px]"
          role="group"
          aria-label={t("aesGcm")}
        >
          {(["encrypt", "decrypt"] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              className={cn(
                "cursor-pointer rounded-md px-3 py-1 text-xs font-medium transition-colors",
                aesType === mode
                  ? "bg-card text-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
              aria-pressed={aesType === mode}
              onClick={() => setAesType(mode)}
            >
              {t(mode)}
            </button>
          ))}
        </div>
        <div className="space-y-2.5">
          <div className="space-y-1">
            <Label
              htmlFor="aes-secret"
              className="text-xs text-muted-foreground"
            >
              {t("secret")}
            </Label>
            <Input
              id="aes-secret"
              className="machine"
              value={aesData.key}
              onChange={(e) => {
                const key = e.target.value.trim();
                setAesData((prev) => ({ ...prev, key }));
              }}
            />
          </div>
          <div className="space-y-1">
            <Label
              htmlFor="aes-input"
              className="text-xs text-muted-foreground"
            >
              {t("value")}
            </Label>
            <Input
              id="aes-input"
              className="machine"
              value={aesData.data}
              onChange={(e) => {
                const data = e.target.value.trim();
                setAesData((prev) => ({ ...prev, data }));
              }}
            />
          </div>
          <Button
            type="button"
            size="sm"
            className="w-full cursor-pointer"
            disabled={aesProcessing || !aesData.key || !aesData.data}
            onClick={(e) => {
              e.preventDefault();
              handleAes();
            }}
          >
            {aesProcessing && (
              <LoaderCircle className="mr-2 size-3.5 animate-spin" />
            )}
            {t("header.computeAndCopy")}
          </Button>
          <div className="space-y-1">
            <Label
              htmlFor="aes-output"
              className="text-xs text-muted-foreground"
            >
              {t("result")}
            </Label>
            <div className="relative">
              <Input
                id="aes-output"
                className="machine pr-9"
                value={aesResult}
                readOnly
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={t("header.copy")}
                disabled={!aesResult}
                className="absolute right-0.5 top-1/2 size-8 -translate-y-1/2 cursor-pointer text-muted-foreground hover:text-foreground"
                onClick={(e) => {
                  e.preventDefault();
                  copyText(aesResult);
                }}
              >
                <ClipboardCopy className="size-3.5" />
              </Button>
            </div>
          </div>
        </div>
      </div>
    </TabsContent>
  );

  const base64Tab = (
    <TabsContent value="base64" className="mt-3">
      <div className="space-y-3">
        <div>
          <h4 className="text-sm font-medium leading-none">{t("base64")}</h4>
          <p className="mt-1 text-xs text-muted-foreground">
            {t("base64Tips")}
          </p>
        </div>
        <div
          className="inline-flex rounded-lg bg-accent p-[3px]"
          role="group"
          aria-label={t("base64")}
        >
          {(["encode", "decode"] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              className={cn(
                "cursor-pointer rounded-md px-3 py-1 text-xs font-medium transition-colors",
                base64Type === mode
                  ? "bg-card text-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
              aria-pressed={base64Type === mode}
              onClick={() => {
                setBase64Type(mode);
                computeBase64(mode, base64Input);
              }}
            >
              {t(mode)}
            </button>
          ))}
        </div>
        <div className="space-y-2.5">
          <div className="space-y-1">
            <Label
              htmlFor="b64-input"
              className="text-xs text-muted-foreground"
            >
              {t("value")}
            </Label>
            <Input
              id="b64-input"
              className="machine"
              value={base64Input}
              onChange={(e) => {
                const raw = e.target.value;
                setBase64Input(raw);
                computeBase64(base64Type, raw);
              }}
            />
          </div>
          <div className="space-y-1">
            <Label
              htmlFor="b64-output"
              className="text-xs text-muted-foreground"
            >
              {t("result")}
            </Label>
            <div className="relative">
              <Input
                id="b64-output"
                className="machine pr-9"
                value={base64Data}
                readOnly
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={t("header.copy")}
                disabled={!base64Data}
                className="absolute right-0.5 top-1/2 size-8 -translate-y-1/2 cursor-pointer text-muted-foreground hover:text-foreground"
                onClick={(e) => {
                  e.preventDefault();
                  copyText(base64Data);
                }}
              >
                <ClipboardCopy className="size-3.5" />
              </Button>
            </div>
          </div>
        </div>
      </div>
    </TabsContent>
  );

  return (
    <TooltipProvider delayDuration={200}>
      <header
        className={cn(
          "flex h-12 shrink-0 items-center gap-1.5 bg-background px-3 transition-[width,height] ease-linear sm:gap-2 sm:px-5",
          className,
        )}
      >
        <SidebarTrigger className={cn(iconBtnClass, "-ml-0.5")} />
        <div className="mx-1 h-4 w-px shrink-0 bg-border" />
        {liveReadout}
        <div className="flex-1" />
        <div className="flex items-center gap-1 sm:gap-2">
          {onOpenCommandPalette && (
            <button
              type="button"
              onClick={onOpenCommandPalette}
              className="hidden h-8 cursor-pointer items-center gap-2 rounded-md border border-border bg-card/70 px-2.5 text-xs text-muted-foreground transition-colors hover:bg-card hover:text-foreground md:inline-flex"
            >
              <Search className="size-3.5 shrink-0" />
              <span>{t("header.search")}</span>
              <kbd className="machine rounded border border-border bg-muted px-1 py-0.5 text-[10px] leading-none">
                ⌘K
              </kbd>
            </button>
          )}
          {/* Language pill is wide; on phones it moves into Settings. */}
          <div className="hidden sm:block">{languageSwitch}</div>
          <Popover>
            <Tooltip>
              <TooltipTrigger asChild>
                <PopoverTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className={iconBtnClass}
                    aria-label={t("header.tools")}
                  >
                    <Wrench className="size-4" strokeWidth={1.8} />
                  </Button>
                </PopoverTrigger>
              </TooltipTrigger>
              <TooltipContent side="bottom">{t("header.tools")}</TooltipContent>
            </Tooltip>
            <PopoverContent
              className="w-[min(400px,calc(100vw-2rem))]"
              align="end"
            >
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
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className={iconBtnClass}
                aria-label={t("header.config")}
                onClick={(e) => {
                  e.preventDefault();
                  goToConfig();
                }}
              >
                <FileCode2 className="size-4" strokeWidth={1.8} />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">{t("header.config")}</TooltipContent>
          </Tooltip>
          {settingsMenu}
        </div>
      </header>
    </TooltipProvider>
  );
}
