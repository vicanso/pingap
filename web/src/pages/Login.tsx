import { useI18n } from "@/i18n";
import { useTranslation } from "react-i18next";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import React from "react";
import { saveLoginToken } from "@/states/token";
import useBasicState from "@/states/basic";
import { goToHome } from "@/routers";
import useConfigState from "@/states/config";
import { formatError } from "@/helpers/util";
import { useShallow } from "zustand/react/shallow";
import { toast } from "sonner";
import Logo from "@/assets/pingap.png";
import { useTheme } from "@/components/theme-provider";
import { cn } from "@/lib/utils";
import { Eye, EyeOff, LoaderCircle, Monitor, Moon, Sun } from "lucide-react";

export default function Login() {
  const loginI18n = useI18n("login");
  const { t, i18n } = useTranslation();
  const { theme, setTheme } = useTheme();

  const [account, setAccount] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [showPassword, setShowPassword] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [fetchBasicInfo] = useBasicState(useShallow((state) => [state.fetch]));
  const [fetchConfig] = useConfigState(useShallow((state) => [state.fetch]));
  const isZh = i18n.language === "zh" || i18n.language.startsWith("zh");
  const handleLogin = async () => {
    if (loading) return;
    setLoading(true);
    try {
      await saveLoginToken(account, password);
      await fetchBasicInfo();
      await fetchConfig();
      goToHome();
    } catch (err) {
      toast(loginI18n("fail"), {
        description: formatError(err),
      });
    } finally {
      setLoading(false);
    }
  };
  // Top aligned rather than centred, and high on the page: this route renders
  // without the app shell, so the 96px gap that used to line the card up under
  // the header is now the padding itself and the card lands in the same place.
  return (
    <div className="min-h-svh overflow-auto overscroll-contain bg-background">
      <div className="mx-auto w-full max-w-[400px] pt-[max(6rem,calc(2rem+env(safe-area-inset-top)))] pr-[max(1rem,env(safe-area-inset-right))] pb-[max(2.5rem,env(safe-area-inset-bottom))] pl-[max(1rem,env(safe-area-inset-left))]">
        <div className="mb-5 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <span className="flex size-8 items-center justify-center rounded-md border border-border bg-card">
              <img src={Logo} alt="" className="size-5 rounded-sm" />
            </span>
            <span className="text-[15px] font-semibold tracking-tight">
              Pingap
            </span>
            <span className="region-label ml-0.5">admin</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="inline-flex items-center rounded-md border border-border bg-muted/40 p-0.5 text-[11px]">
              <button
                type="button"
                aria-pressed={isZh}
                onClick={() => i18n.changeLanguage("zh")}
                className={cn(
                  "cursor-pointer rounded-sm px-1.5 py-0.5 font-medium transition-colors",
                  isZh
                    ? "bg-card text-foreground shadow-2xs"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                中文
              </button>
              <button
                type="button"
                aria-pressed={!isZh}
                onClick={() => i18n.changeLanguage("en")}
                className={cn(
                  "cursor-pointer rounded-sm px-1.5 py-0.5 font-medium transition-colors",
                  !isZh
                    ? "bg-card text-foreground shadow-2xs"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                EN
              </button>
            </div>
            <div className="inline-flex items-center rounded-md border border-border bg-muted/40 p-0.5">
              {(
                [
                  { id: "light", Icon: Sun, label: t("themeLight") },
                  { id: "dark", Icon: Moon, label: t("themeDark") },
                  { id: "system", Icon: Monitor, label: t("themeSystem") },
                ] as const
              ).map(({ id, Icon, label }) => {
                const active = theme === id;
                return (
                  <button
                    key={id}
                    type="button"
                    aria-label={label}
                    aria-pressed={active}
                    title={label}
                    onClick={() => setTheme(id)}
                    className={cn(
                      "cursor-pointer rounded-sm p-1 transition-colors",
                      active
                        ? "bg-card text-foreground shadow-2xs"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    <Icon className="size-3.5" />
                  </button>
                );
              })}
            </div>
          </div>
        </div>
        <Card className="w-full border-border">
          <CardHeader className="space-y-0 px-5 pt-5 pb-4">
            <h1 className="text-xl leading-7 font-semibold tracking-tight">
              {loginI18n("title")}
            </h1>
            <CardDescription className="mt-1.5 text-[13px]">
              {loginI18n("description")}
            </CardDescription>
          </CardHeader>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleLogin();
            }}
          >
            <CardContent className="space-y-4 px-5">
              <div className="space-y-2">
                <Label htmlFor="account">{loginI18n("account")}</Label>
                <Input
                  id="account"
                  autoFocus
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  enterKeyHint="next"
                  autoComplete="username"
                  className="h-10"
                  onChange={(e) => {
                    setAccount(e.target.value.trim());
                  }}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">{loginI18n("password")}</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    enterKeyHint="go"
                    autoComplete="current-password"
                    className="h-10 pr-9"
                    onChange={(e) => {
                      setPassword(e.target.value.trim());
                    }}
                  />
                  <button
                    type="button"
                    aria-label={loginI18n(
                      showPassword ? "hidePassword" : "showPassword",
                    )}
                    title={loginI18n(
                      showPassword ? "hidePassword" : "showPassword",
                    )}
                    onClick={() => setShowPassword((prev) => !prev)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 cursor-pointer rounded-sm p-1 text-muted-foreground hover:text-foreground"
                  >
                    {showPassword ? (
                      <EyeOff className="size-4" />
                    ) : (
                      <Eye className="size-4" />
                    )}
                  </button>
                </div>
              </div>
            </CardContent>
            <CardFooter className="px-5 pt-5 pb-5">
              <Button
                type="submit"
                className="h-10 w-full cursor-pointer"
                disabled={loading || !account || !password}
              >
                {loading && (
                  <LoaderCircle className="mr-2 size-4 animate-spin" />
                )}
                {loginI18n("submit")}
              </Button>
            </CardFooter>
          </form>
        </Card>
      </div>
    </div>
  );
}
