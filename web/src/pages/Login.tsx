import { useI18n } from "@/i18n";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
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

export default function Login() {
  const loginI18n = useI18n("login");

  const [account, setAccount] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [fetchBasicInfo] = useBasicState(useShallow((state) => [state.fetch]));
  const [fetchConfig] = useConfigState(useShallow((state) => [state.fetch]));
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
  return (
    <div className="flex min-h-svh flex-col items-center justify-center bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-primary/10 via-background to-background p-4">
      <Card className="w-full max-w-md border-border/80 shadow-lg">
        <CardHeader className="space-y-3 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border bg-card shadow-sm">
            <img src={Logo} alt="Pingap" className="h-8 w-8 rounded-md" />
          </div>
          <div>
            <CardTitle className="text-xl tracking-tight">
              {loginI18n("title")}
            </CardTitle>
            <CardDescription className="mt-1">
              {loginI18n("description")}
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="account">{loginI18n("account")}</Label>
            <Input
              id="account"
              autoFocus
              autoComplete="username"
              className="h-10"
              onChange={(e) => {
                setAccount(e.target.value.trim());
              }}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">{loginI18n("password")}</Label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              className="h-10"
              onChange={(e) => {
                setPassword(e.target.value.trim());
              }}
              onKeyDown={(e) => {
                if (e.code == "Enter") {
                  handleLogin();
                }
              }}
            />
          </div>
        </CardContent>
        <CardFooter>
          <Button
            className="h-10 w-full cursor-pointer"
            disabled={loading || !account || !password}
            onClick={(e) => {
              e.preventDefault();
              handleLogin();
            }}
          >
            {loading ? "…" : loginI18n("submit")}
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
