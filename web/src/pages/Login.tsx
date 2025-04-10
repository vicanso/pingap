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

export default function Login() {
  const loginI18n = useI18n("login");

  const [account, setAccount] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [fetchBasicInfo] = useBasicState(useShallow((state) => [state.fetch]));
  const [fetchConfig] = useConfigState(useShallow((state) => [state.fetch]));
  const handleLogin = async () => {
    try {
      await saveLoginToken(account, password);
      await fetchBasicInfo();
      await fetchConfig();
      goToHome();
    } catch (err) {
      toast(loginI18n("fail"), {
        description: formatError(err),
      });
    }
  };
  return (
    <div className="grow overflow-auto p-4">
      <div className="flex justify-center mt-10">
        <Card className="w-[500px] self-center">
          <CardHeader>
            <CardTitle>{loginI18n("title")}</CardTitle>
            <CardDescription>{loginI18n("description")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="space-y-1">
              <Label htmlFor="account">{loginI18n("account")}</Label>
              <Input
                id="account"
                autoFocus
                onChange={(e) => {
                  setAccount(e.target.value.trim());
                }}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="password">{loginI18n("password")}</Label>
              <Input
                id="password"
                type="password"
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
              className="w-[100px]"
              onClick={(e) => {
                e.preventDefault();
                handleLogin();
              }}
            >
              {loginI18n("submit")}
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
