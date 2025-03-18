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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import request from "@/helpers/request";

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

  const [base64Type, setBase64Type] = React.useState("encode");
  const [base64Data, setBase64Data] = React.useState("");

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



  const aesTab = <TabsContent value="aes" className="mt-2">
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
  </TabsContent>

  const base64Tab = <TabsContent value="base64" className="mt-2">
    <div className="grid gap-4">
      <div className="space-y-2">
        <h4 className="font-medium leading-none">{t("base64")}</h4>
        <p className="text-sm text-muted-foreground">
          {t("base64Tips")}
        </p>
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
            <Input
              id="value"
              className="grow"
              value={base64Data}
              readOnly
            />
          </p>
        </div>
      </div>
    </div>
  </TabsContent>

  return (
    <header
      className={cn(
        "border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60",
        className,
      )}
    >
      <div className="ml-2 flex h-11 items-center">
        <div className="flex flex-1 items-center space-x-2 justify-end mr-2">
          <Popover>
            <PopoverTrigger asChild>
              <Button variant="ghost" size="icon">
                <AudioWaveform />
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
